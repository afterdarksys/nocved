//! nocved CLI: `run`, `check`, `version`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

use nocved::config::Config;
use nocved::daemon;

const USAGE: &str = "usage: nocved run [--config PATH]\n       nocved check [--config PATH]   (poll every source once, send nothing)\n       nocved version";

fn config_path(args: &[String]) -> Result<PathBuf, String> {
    match args {
        [] => Ok(PathBuf::from("/etc/nocved/config.json")),
        [flag, p] if flag == "--config" => Ok(PathBuf::from(p)),
        _ => Err(USAGE.into()),
    }
}

fn check(cfg: &Config) -> Result<(), String> {
    let key = cfg.load_key()?;
    println!(
        "config ok; host={} store={} key_fp={}",
        cfg.host_name()?,
        cfg.store_url,
        key.fingerprint()
    );
    let mut sources = daemon::build_sources(cfg)?;
    let now = daemon::now_ms();
    for s in &mut sources {
        let mut evs = Vec::new();
        s.poll(now, &mut evs);
        let flagged = evs
            .iter()
            .filter(|e| {
                e.max_severity()
                    .is_some_and(|v| v >= nocve_proto::Severity::High)
            })
            .count();
        let h = s.health();
        println!(
            "{:<12} {:<11} events={:<5} high+={:<3} {}",
            s.id(),
            format!("{:?}", h.status).to_lowercase(),
            evs.len(),
            flagged,
            h.detail
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    // The release profile unwinds (the store needs catch_unwind). The sensor
    // keeps abort-on-panic: a panicking shipper thread must not leave a
    // half-alive sensor; systemd restarts it (Restart=always) and the store
    // sees the restart in the heartbeat/boot data.
    std::panic::set_hook(Box::new(|info| {
        eprintln!("nocved: fatal: {info}");
        std::process::abort();
    }));
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("version") => {
            println!("nocved {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("check") => config_path(&args[1..])
            .and_then(|p| Config::load(&p))
            .and_then(|c| check(&c)),
        Some("run") => config_path(&args[1..])
            .and_then(|p| Config::load(&p))
            .and_then(|c| {
                let key = c.load_key()?;
                // systemd stops us with SIGTERM; state is flushed every iteration,
                // so default termination loses at most the current poll.
                let stop = AtomicBool::new(false);
                daemon::run(&c, &key, &stop)
            }),
        _ => Err(USAGE.into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nocved: {e}");
            ExitCode::FAILURE
        }
    }
}
