//! nocved CLI: `run`, `check`, `status`, `version`, `help`. Output follows
//! `docs/output-contract.md`: human text by default, `--json` for one JSON
//! document on stdout, errors on stderr.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

use nocve_proto::cli::{self, CliError, Output};
use nocved::config::Config;
use nocved::daemon;
use serde_json::{Value, json};

const TOOL: &str = "nocved";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_CONFIG: &str = "/etc/nocved/config.json";

const EXIT_CODES: &str = "exit codes:
  0  success
  1  runtime or configuration failure (config, key, state, I/O)
  2  usage error (unknown command or option, missing value)";

const OUTPUT_OPTS: &str = "output options (every command):
  --json              one JSON document on stdout; errors as one JSON line on stderr
  --format json|text  same as --json, or human text (the default)
  -h, --help          show this help and exit 0";

const HELP: &str = "nocved: continuous host behaviour sensor (push-only)

usage: nocved <command> [options]

commands:
  run      run the sensor (daemon; deploy/nocved.service)
  check    poll every source once and print coverage; sends nothing
  status   read the running sensor's local status file
  version  print the version (also --version)
  help     show help for a command (nocved help <command>)";

const HELP_RUN: &str = "usage: nocved run [--config PATH]

Runs the sensor until stopped. Events are chained into the spool under
state_dir and shipped to store_url. Every 30 s (and on a clean stop) it
rewrites <state_dir>/status.json (0600) for `nocved status`. Logs go to
stderr; stdout stays empty, also with --json.

options:
  --config PATH  config file (default /etc/nocved/config.json)";

const HELP_CHECK: &str = "usage: nocved check [--config PATH]

Loads the config and key, polls every enabled source once, prints each
source's coverage. Sends nothing to the store.

options:
  --config PATH  config file (default /etc/nocved/config.json)";

const HELP_STATUS: &str = "usage: nocved status [--config PATH]

Reads <state_dir>/status.json written by `nocved run` (no lock, no writes)
and reports stale: true when it is older than 90 s (3 x the 30 s interval).
A stale status still exits 0; check the stale field.

options:
  --config PATH  config file (default /etc/nocved/config.json)";

const HELP_VERSION: &str = "usage: nocved version";

fn help_for(cmd: Option<&str>) -> Option<&'static str> {
    match cmd {
        None | Some("help") => Some(HELP),
        Some("run") => Some(HELP_RUN),
        Some("check") => Some(HELP_CHECK),
        Some("status") => Some(HELP_STATUS),
        Some("version") => Some(HELP_VERSION),
        Some(_) => None,
    }
}

fn config_path(args: &[String]) -> Result<PathBuf, CliError> {
    match args {
        [] => Ok(PathBuf::from(DEFAULT_CONFIG)),
        [flag, p] if flag == "--config" => Ok(PathBuf::from(p)),
        [flag] if flag == "--config" => Err(CliError::usage("--config needs a value")),
        [a, ..] if a != "--config" => Err(CliError::usage(format!(
            "unknown option {a} (see nocved --help)"
        ))),
        _ => Err(CliError::usage(
            "unexpected arguments after --config PATH (see nocved --help)",
        )),
    }
}

fn load_config(args: &[String]) -> Result<Config, CliError> {
    let p = config_path(args)?;
    Config::load(&p).map_err(CliError::config)
}

fn check(cfg: &Config, out: &Output) -> Result<(), CliError> {
    let key = cfg.load_key().map_err(CliError::config)?;
    let host = cfg.host_name().map_err(CliError::config)?;
    if !out.json {
        println!(
            "config ok; host={host} store={} key_fp={}",
            cfg.store_url,
            key.fingerprint()
        );
    }
    let mut sources = daemon::build_sources(cfg).map_err(CliError::config)?;
    let now = daemon::now_ms();
    let mut rows = Vec::new();
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
        let status = format!("{:?}", h.status).to_lowercase();
        if out.json {
            rows.push(json!({
                "id": s.id(),
                "status": status,
                "events": evs.len(),
                "high_plus": flagged,
                "detail": h.detail,
            }));
        } else {
            println!(
                "{:<12} {:<11} events={:<5} high+={:<3} {}",
                s.id(),
                status,
                evs.len(),
                flagged,
                h.detail
            );
        }
    }
    if out.json {
        out.emit(
            "nocved.check",
            json!({
                "host": host,
                "store_url": cfg.store_url,
                "key_fp": key.fingerprint(),
                "sources": rows,
            }),
        )?;
    }
    Ok(())
}

fn ago(now: i64, v: Option<i64>) -> String {
    v.map_or_else(
        || "never".into(),
        |t| format!("{} s ago", now.saturating_sub(t) / 1000),
    )
}

fn status(cfg: &Config, out: &Output) -> Result<(), CliError> {
    let now = daemon::now_ms();
    let st = cli::read_status(&daemon::status_path(cfg), daemon::STATUS_KIND, now)?;
    if out.json {
        return out.emit(daemon::STATUS_KIND, Value::Object(st));
    }
    let num = |k: &str| st.get(k).and_then(Value::as_i64);
    let text = |k: &str| cli::sanitize(st.get(k).and_then(Value::as_str).unwrap_or("?"));
    let stale = st.get("stale").and_then(Value::as_bool).unwrap_or(true);
    let mut s = format!(
        "nocved {} (pid {}, host {}), updated {}{}\n",
        text("state"),
        num("pid").unwrap_or(0),
        text("host"),
        ago(now, num("updated_at_ms")),
        if stale {
            "  STALE: no update for over 90 s"
        } else {
            ""
        }
    );
    s.push_str(&format!(
        "spool {} events / {} bytes, dropped_total {}\nlast tick {}, heartbeat ok {}, batch shipped {}\n",
        num("spool_events").unwrap_or(0),
        num("spool_bytes").unwrap_or(0),
        num("dropped_total").unwrap_or(0),
        ago(now, num("last_tick_ms")),
        ago(now, num("last_heartbeat_ok_ms")),
        ago(now, num("last_ship_ok_ms")),
    ));
    for c in st
        .get("coverage")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let f = |k: &str| cli::sanitize(c.get(k).and_then(Value::as_str).unwrap_or(""));
        s.push_str(&format!(
            "{:<12} {:<11} {}\n",
            f("source"),
            f("status"),
            f("detail")
        ));
    }
    cli::write_stdout(s.trim_end())
}

fn dispatch(cmd: Option<&str>, rest: &[String], out: &Output) -> Result<(), CliError> {
    match cmd {
        Some("version") if rest.is_empty() => {
            if out.json {
                out.emit("nocved.version", json!({ "version": VERSION }))
            } else {
                cli::write_stdout(&format!("nocved {VERSION}"))
            }
        }
        Some("version") => Err(CliError::usage("version takes no options")),
        Some("help") => match rest {
            [] => out.help("nocved.help", &full_help(HELP)),
            [c] => help_for(Some(c))
                .ok_or_else(|| CliError::usage(format!("unknown command {c}")))
                .and_then(|h| out.help("nocved.help", &full_help(h))),
            _ => Err(CliError::usage("usage: nocved help [command]")),
        },
        Some("check") => load_config(rest).and_then(|c| check(&c, out)),
        Some("status") => load_config(rest).and_then(|c| status(&c, out)),
        Some("run") => {
            let c = load_config(rest)?;
            let key = c.load_key().map_err(CliError::config)?;
            // systemd stops us with SIGTERM; state is flushed every iteration,
            // so default termination loses at most the current poll.
            let stop = AtomicBool::new(false);
            daemon::run(&c, &key, &stop).map_err(CliError::io)
        }
        None => Err(CliError::usage("missing command (see nocved --help)")),
        Some(c) => Err(CliError::usage(format!(
            "unknown command {c} (see nocved --help)"
        ))),
    }
}

fn full_help(h: &str) -> String {
    format!("{h}\n\n{OUTPUT_OPTS}\n\n{EXIT_CODES}\n")
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
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let (json, flag_err) = cli::take_format(&mut args);
    let out = Output {
        tool: TOOL,
        version: VERSION,
        json,
    };
    let cmd = args.first().map(String::as_str);
    let known = help_for(cmd).is_some();
    // Error lines name a known command only; never echo an unknown one there.
    let shown_cmd = cmd.filter(|_| known);
    if let Some(e) = flag_err {
        return out.fail(shown_cmd, &e);
    }
    let result = if cmd == Some("--version") && args.len() == 1 {
        dispatch(Some("version"), &[], &out)
    } else if cli::wants_help(&args) {
        // `nocved -h`, `nocved run --help`: help for the named command.
        let named = cmd.filter(|c| !c.starts_with('-'));
        match help_for(named) {
            Some(h) => out.help("nocved.help", &full_help(h)),
            None => Err(CliError::usage(format!(
                "unknown command {} (see nocved --help)",
                named.unwrap_or("")
            ))),
        }
    } else {
        dispatch(cmd, args.get(1..).unwrap_or(&[]), &out)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => out.fail(shown_cmd, &e),
    }
}
