//! Output contract (docs/output-contract.md) for the `nocved` binary: every
//! subcommand with `--json`, the JSON error line, help, and the local status
//! file that `run` writes and `status` reads.
//!
//! `nocved run` is not run as a process here (it never exits and wants a
//! store); `daemon::run` is run in-process with a stop flag instead, against a
//! closed loopback port, to produce the status file.

#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: panics are the assertion mechanism

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use nocve_proto::cli::status_doc;
use nocve_proto::{Token, TokenKind};
use serde_json::Value;

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let o = Command::new(env!("CARGO_BIN_EXE_nocved"))
        .args(args)
        .output()
        .unwrap();
    Run {
        code: o.status.code().unwrap(),
        stdout: String::from_utf8(o.stdout).unwrap(),
        stderr: String::from_utf8(o.stderr).unwrap(),
    }
}

fn ok_json(args: &[&str], kind: &str) -> serde_json::Map<String, Value> {
    let r = run(args);
    assert_eq!(r.code, 0, "{args:?}: {}", r.stderr);
    assert_eq!(r.stdout.matches('\n').count(), 1, "one line: {}", r.stdout);
    assert!(
        r.stdout.starts_with(&format!(
            r#"{{"schema_version":1,"kind":"{kind}","tool":"nocved","tool_version":"{}""#,
            env!("CARGO_PKG_VERSION")
        )),
        "envelope first: {}",
        r.stdout
    );
    match serde_json::from_str(&r.stdout).unwrap() {
        Value::Object(m) => m,
        v => panic!("not an object: {v}"),
    }
}

fn err_json(args: &[&str], category: &str, code: i32) -> Value {
    let r = run(args);
    assert_eq!(r.code, code, "{args:?}: {}", r.stderr);
    assert_eq!(r.stdout, "", "{args:?}: stdout must stay empty");
    assert_eq!(r.stderr.lines().count(), 1, "one line: {}", r.stderr);
    let v: Value = serde_json::from_str(r.stderr.trim_end()).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["kind"], "error");
    assert_eq!(v["tool"], "nocved");
    assert!(v.get("command").is_some());
    assert_eq!(v["category"], category);
    assert!(v["message"].as_str().is_some_and(|m| !m.is_empty()));
    assert_eq!(v["exit_code"], code);
    v
}

/// A config (0600) with a key, an empty fixture root, and a store on a
/// closed loopback port. Returns (config path, state dir).
fn fixture(d: &Path) -> (PathBuf, PathBuf) {
    let root = d.join("root");
    std::fs::create_dir_all(root.join("proc")).unwrap();
    let key = Token::generate(TokenKind::Host).unwrap();
    let key_path = d.join("key");
    std::fs::write(&key_path, key.expose()).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let state = d.join("state");
    let cfg = serde_json::json!({
        "store_url": "http://127.0.0.1:9",
        "key_file": key_path,
        "host": "ns2",
        "state_dir": state,
        "root": root,
    });
    let cfg_path = d.join("config.json");
    std::fs::write(&cfg_path, cfg.to_string()).unwrap();
    std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (cfg_path, state)
}

/// Runs the sensor in-process for a moment, then stops it.
fn run_daemon_briefly(cfg_path: &Path) {
    let cfg = nocved::config::Config::load(cfg_path).unwrap();
    let key = cfg.load_key().unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        let h = s.spawn(|| nocved::daemon::run(&cfg, &key, &stop));
        std::thread::sleep(Duration::from_millis(1500));
        stop.store(true, Ordering::Relaxed);
        h.join().unwrap().unwrap();
    });
}

#[test]
fn every_subcommand_speaks_json() {
    let d = tempfile::tempdir().unwrap();
    let (cfg, state) = fixture(d.path());
    let cfg = cfg.to_str().unwrap();
    let v = ok_json(&["version", "--json"], "nocved.version");
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    ok_json(&["help", "--format", "json"], "nocved.help");

    let c = ok_json(&["check", "--config", cfg, "--json"], "nocved.check");
    assert_eq!(c["host"], "ns2");
    assert_eq!(c["store_url"], "http://127.0.0.1:9");
    assert!(c["key_fp"].is_string());
    let ids: Vec<&str> = c["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"process"), "{ids:?}");

    run_daemon_briefly(Path::new(cfg));
    let path = state.join("status.json");
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(
        raw.starts_with(
            r#"{"schema_version":1,"kind":"nocved.status","tool":"nocved","tool_version":"#
        ),
        "{raw}"
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let st = ok_json(&["status", "--config", cfg, "--json"], "nocved.status");
    assert_eq!(st["stale"], false);
    assert_eq!(st["state"], "stopped", "written again on stop");
    assert_eq!(st["host"], "ns2");
    for k in [
        "spool_events",
        "spool_bytes",
        "dropped_total",
        "updated_at_ms",
        "started_at_ms",
    ] {
        assert!(st[k].is_u64(), "{k}: {st:?}");
    }
    assert!(st["last_tick_ms"].is_u64());
    assert!(st["last_heartbeat_ok_ms"].is_null(), "store is down");
    assert!(st["coverage"].as_array().is_some_and(|c| !c.is_empty()));

    let r = run(&["status", "--config", cfg]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.starts_with("nocved stopped"), "{}", r.stdout);
    assert!(!r.stdout.contains("STALE"));
}

#[test]
fn status_reports_stale_files() {
    let d = tempfile::tempdir().unwrap();
    let (cfg, state) = fixture(d.path());
    std::fs::create_dir_all(&state).unwrap();
    let doc = status_doc(
        "nocved",
        "0.1.0",
        "nocved.status",
        1_000,
        serde_json::json!({"state": "running", "dropped_total": 7}),
    );
    std::fs::write(state.join("status.json"), doc).unwrap();
    let cfg = cfg.to_str().unwrap();
    let st = ok_json(&["status", "--config", cfg, "--json"], "nocved.status");
    assert_eq!(st["stale"], true);
    assert_eq!(st["dropped_total"], 7);
    let r = run(&["status", "--config", cfg]);
    assert!(r.stdout.contains("STALE"), "{}", r.stdout);
}

#[test]
fn errors_are_one_json_line_on_stderr() {
    let d = tempfile::tempdir().unwrap();
    let (cfg, _) = fixture(d.path());
    let cfg = cfg.to_str().unwrap();
    let v = err_json(&["--json", "frob"], "usage", 2);
    assert!(v["command"].is_null());
    err_json(&["--json"], "usage", 2);
    let v = err_json(&["check", "--json", "--bogus"], "usage", 2);
    assert_eq!(v["command"], "check");
    err_json(&["run", "--json", "--config"], "usage", 2);
    err_json(&["version", "extra", "--json"], "usage", 2);
    err_json(&["--format", "yaml", "--json", "version"], "usage", 2);
    // Configuration errors keep the historical exit 1.
    let v = err_json(
        &["check", "--json", "--config", "/nonexistent/c.json"],
        "config",
        1,
    );
    assert_eq!(v["command"], "check");
    err_json(
        &["run", "--json", "--config", "/nonexistent/c.json"],
        "config",
        1,
    );
    let open = d.path().join("open.json");
    std::fs::copy(cfg, &open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o666)).unwrap();
    err_json(
        &["check", "--json", "--config", open.to_str().unwrap()],
        "config",
        1,
    );
    // No status file yet: a runtime (I/O) failure.
    err_json(&["status", "--json", "--config", cfg], "io", 1);

    let r = run(&["frob\u{1b}[2J"]);
    assert_eq!(r.code, 2);
    assert_eq!(r.stdout, "");
    assert_eq!(r.stderr.lines().count(), 1);
    assert!(
        r.stderr
            .starts_with("nocved: unknown command frob\\u{1b}[2J"),
        "{}",
        r.stderr
    );
}

#[test]
fn help_exits_zero_and_names_every_command() {
    for args in [&["--help"][..], &["-h"], &["help"]] {
        let r = run(args);
        assert_eq!(r.code, 0);
        for c in [
            "run",
            "check",
            "status",
            "version",
            "help",
            "exit codes",
            "--json",
        ] {
            assert!(r.stdout.contains(c), "{args:?} lacks {c}");
        }
    }
    for args in [
        &["run", "--help"][..],
        &["check", "-h"],
        &["status", "--help"],
        &["version", "-h"],
        &["help", "run"],
    ] {
        let r = run(args);
        assert_eq!(r.code, 0, "{args:?}");
        assert!(r.stdout.contains("usage: nocved"), "{args:?}");
        assert!(r.stdout.contains("exit codes:"), "{args:?}");
    }
    let r = run(&["--version"]);
    assert_eq!(
        (r.code, r.stdout.as_str()),
        (0, concat!("nocved ", env!("CARGO_PKG_VERSION"), "\n"))
    );
}
