//! Docker Engine API over the unix socket. Read-only: a fixed allowlist of
//! GET paths (`/events`, `/containers/json`, `/containers/{id}/json`), HTTP/1.0
//! so the daemon closes every response, bounded bodies and timeouts.
//!
//! Threats: the Docker socket is root-equivalent. This client can only send
//! the allowlisted GETs; any other path is refused before connecting.
//! `Privileged: true` and `NetworkMode` exactly `host` are signals on the
//! inspect body this client already fetches. No other HostConfig field is read.

use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nocve_proto::{
    ContainerInfo, Coverage, CoverageStatus, Event, EventData, Indicators, Severity, Signal,
};

use super::{Ctx, MAX_EVENTS_PER_POLL, Source, cap_events, coverage};
use crate::config::DockerConfig;

const MAX_BODY: usize = 4 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(2);
const MAX_INSPECT_PER_POLL: usize = 50;
const SEEN_CAP: usize = 4096;

fn is_id(s: &str) -> bool {
    (12..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The only requests this client will make.
#[must_use]
pub fn path_allowed(path: &str) -> bool {
    if path.starts_with("/events?") || path == "/containers/json?all=1" {
        return !path.contains(['\r', '\n', ' ']);
    }
    path.strip_prefix("/containers/")
        .and_then(|r| r.strip_suffix("/json"))
        .is_some_and(is_id)
}

/// GET over the unix socket. Returns (status, body).
pub fn docker_get(sock: &Path, path: &str) -> Result<(u16, Vec<u8>), String> {
    if !path_allowed(path) {
        return Err(format!("refusing docker path {path}"));
    }
    let mut s =
        UnixStream::connect(sock).map_err(|e| format!("connect {}: {e}", sock.display()))?;
    s.set_read_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    write!(
        s,
        "GET {path} HTTP/1.0\r\nHost: docker\r\nUser-Agent: nocved\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    s.take(MAX_BODY as u64 + 16 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read: {e}"))?;
    parse_response(&buf)
}

/// Minimal HTTP/1.x response parser (status line, headers, identity or
/// chunked body).
pub fn parse_response(buf: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no header terminator")?;
    let head = String::from_utf8_lossy(&buf[..end]);
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or("bad status line")?;
    let chunked = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    let body = &buf[end + 4..];
    if body.len() > MAX_BODY {
        return Err("docker response too large".into());
    }
    if !chunked {
        return Ok((status, body.to_vec()));
    }
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let nl = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("bad chunk")?;
        let size_str = String::from_utf8_lossy(&rest[..nl]);
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "bad chunk size")?;
        rest = &rest[nl + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size || out.len() + size > MAX_BODY {
            return Err("truncated or oversized chunk".into());
        }
        out.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..).unwrap_or(&[]);
    }
    Ok((status, out))
}

fn s(v: &serde_json::Value, ptr: &str) -> Option<String> {
    v.pointer(ptr).and_then(|x| x.as_str()).map(str::to_owned)
}

/// Builds container info from `/containers/{id}/json`.
#[must_use]
pub fn parse_inspect(v: &serde_json::Value) -> Option<ContainerInfo> {
    let id = s(v, "/Id")?;
    Some(ContainerInfo {
        id: id.chars().take(12).collect(),
        name: s(v, "/Name")
            .unwrap_or_default()
            .trim_start_matches('/')
            .to_owned(),
        image: s(v, "/Config/Image").unwrap_or_default(),
        image_id: s(v, "/Image"),
        restart_policy: s(v, "/HostConfig/RestartPolicy/Name"),
        privileged: v
            .pointer("/HostConfig/Privileged")
            .and_then(serde_json::Value::as_bool),
        network_mode: s(v, "/HostConfig/NetworkMode"),
        created: s(v, "/Created"),
    })
}

#[must_use]
pub fn container_signals(ind: &Indicators, c: &ContainerInfo) -> Vec<Signal> {
    let mut sig = Vec::new();
    if ind.container_masquerade(&c.name) {
        sig.push(Signal::new(
            "docker.masquerade_name",
            Severity::High,
            format!(
                "container named like a system daemon: {} (image {})",
                c.name, c.image
            ),
        ));
    }
    if ind.proxyware_image(&c.image) {
        sig.push(Signal::new(
            "docker.proxyware_image",
            Severity::Critical,
            format!("proxyware image {}", c.image),
        ));
    }
    if ind.miner_image(&c.image) {
        sig.push(Signal::new(
            "docker.miner_image",
            Severity::Critical,
            format!("miner image {}", c.image),
        ));
    }
    if c.privileged == Some(true) {
        sig.push(Signal::new(
            "docker.privileged",
            Severity::High,
            format!("container {} is privileged (image {})", c.name, c.image),
        ));
    }
    if c.network_mode.as_deref() == Some("host") {
        sig.push(Signal::new(
            "docker.host_network",
            Severity::High,
            format!("container {} shares the host network namespace", c.name),
        ));
    }
    sig
}

/// One docker event line -> (action, id, name, image).
#[must_use]
pub fn parse_event_line(line: &str) -> Option<(String, String, String, String, i64)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if s(&v, "/Type").as_deref() != Some("container") {
        return None;
    }
    let action = s(&v, "/Action")?;
    let id = s(&v, "/Actor/ID").or_else(|| s(&v, "/id"))?;
    let name = s(&v, "/Actor/Attributes/name").unwrap_or_default();
    let image = s(&v, "/Actor/Attributes/image")
        .or_else(|| s(&v, "/from"))
        .unwrap_or_default();
    let nano = v
        .get("timeNano")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    Some((action, id, name, image, nano))
}

pub struct DockerSource {
    ctx: Ctx,
    cfg: DockerConfig,
    socket: PathBuf,
    since: Option<i64>,
    seen: HashSet<(String, String, i64)>,
    seen_order: VecDeque<(String, String, i64)>,
    health: Coverage,
}

impl DockerSource {
    #[must_use]
    pub fn new(ctx: Ctx, cfg: DockerConfig) -> Self {
        let socket = ctx.path(&cfg.socket);
        Self {
            ctx,
            cfg,
            socket,
            since: None,
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
            health: coverage("docker", CoverageStatus::Skipped, "not polled yet"),
        }
    }

    fn inspect(&self, id: &str) -> Option<ContainerInfo> {
        let (st, body) = docker_get(&self.socket, &format!("/containers/{id}/json")).ok()?;
        if st != 200 {
            return None;
        }
        parse_inspect(&serde_json::from_slice(&body).ok()?)
    }

    fn baseline(&mut self, now_ms: i64, evs: &mut Vec<Event>) -> Result<(), String> {
        let (st, body) = docker_get(&self.socket, "/containers/json?all=1")?;
        if st != 200 {
            return Err(format!("/containers/json status {st}"));
        }
        let list: Vec<serde_json::Value> =
            serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        for c in list.iter().take(MAX_EVENTS_PER_POLL) {
            let Some(id) = s(c, "/Id") else { continue };
            if !is_id(&id) {
                continue;
            }
            let info = self.inspect(&id).unwrap_or_else(|| ContainerInfo {
                id: id.chars().take(12).collect(),
                name: c
                    .pointer("/Names/0")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .trim_start_matches('/')
                    .to_owned(),
                image: s(c, "/Image").unwrap_or_default(),
                image_id: s(c, "/ImageID"),
                restart_policy: None,
                privileged: None,
                network_mode: None,
                created: None,
            });
            let sig = container_signals(&self.ctx.ind, &info);
            evs.push(
                Event::new(now_ms, "docker", EventData::ContainerSeen(info)).with_signals(sig),
            );
        }
        Ok(())
    }
}

impl Source for DockerSource {
    fn id(&self) -> &'static str {
        "docker"
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(if self.cfg.interval_secs == 0 {
            5
        } else {
            self.cfg.interval_secs
        })
    }

    fn poll(&mut self, now_ms: i64, out: &mut Vec<Event>) {
        if !self.socket.exists() {
            self.health = coverage("docker", CoverageStatus::Unsupported, "no docker socket");
            return;
        }
        let mut evs = Vec::new();
        let now_s = now_ms / 1000;
        let Some(since) = self.since else {
            match self.baseline(now_ms, &mut evs) {
                Ok(()) => {
                    self.since = Some(now_s);
                    self.health = coverage("docker", CoverageStatus::Completed, "baseline taken");
                }
                Err(e) => self.health = coverage("docker", CoverageStatus::Failed, e),
            }
            cap_events("docker", now_ms, evs, MAX_EVENTS_PER_POLL, out);
            return;
        };
        let filters = "%7B%22type%22%3A%5B%22container%22%5D%2C%22event%22%3A%5B%22create%22%2C%22start%22%5D%7D";
        let path = format!("/events?since={since}&until={now_s}&filters={filters}");
        match docker_get(&self.socket, &path) {
            Ok((200, body)) => {
                let text = String::from_utf8_lossy(&body);
                let mut inspected = 0usize;
                for line in text.lines().filter(|l| !l.trim().is_empty()) {
                    let Some((action, id, name, image, nano)) = parse_event_line(line) else {
                        continue;
                    };
                    if action != "create" && action != "start" {
                        continue;
                    }
                    let key = (action.clone(), id.clone(), nano);
                    if self.seen.contains(&key) {
                        continue;
                    }
                    if self.seen_order.len() >= SEEN_CAP
                        && let Some(o) = self.seen_order.pop_front()
                    {
                        self.seen.remove(&o);
                    }
                    self.seen.insert(key.clone());
                    self.seen_order.push_back(key);
                    let info = if inspected < MAX_INSPECT_PER_POLL && is_id(&id) {
                        inspected += 1;
                        self.inspect(&id)
                    } else {
                        None
                    };
                    let info = info.unwrap_or_else(|| ContainerInfo {
                        id: id.chars().take(12).collect(),
                        name,
                        image,
                        image_id: None,
                        restart_policy: None,
                        privileged: None,
                        network_mode: None,
                        created: None,
                    });
                    let sig = container_signals(&self.ctx.ind, &info);
                    let data = if action == "create" {
                        EventData::ContainerCreate(info)
                    } else {
                        EventData::ContainerStart(info)
                    };
                    evs.push(Event::new(now_ms, "docker", data).with_signals(sig));
                }
                self.since = Some(now_s);
                self.health = coverage("docker", CoverageStatus::Completed, "events ok");
            }
            Ok((st, _)) => {
                self.health = coverage(
                    "docker",
                    CoverageStatus::Failed,
                    format!("/events status {st}"),
                )
            }
            Err(e) => self.health = coverage("docker", CoverageStatus::Failed, e),
        }
        cap_events("docker", now_ms, evs, MAX_EVENTS_PER_POLL, out);
    }

    fn health(&self) -> Coverage {
        self.health.clone()
    }
}

/// Minimal fake Docker daemon on a unix socket for tests (serves canned JSON).
#[cfg(any(test, feature = "testutil"))]
pub mod fake {
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    pub struct FakeDocker {
        pub routes: Arc<Mutex<HashMap<String, String>>>,
        pub events: Arc<Mutex<Vec<String>>>,
        pub requests: Arc<Mutex<Vec<String>>>,
    }

    impl FakeDocker {
        /// Serves `/containers/json?all=1`, `/containers/{id}/json` from
        /// `routes` and `/events...` by draining `events`.
        pub fn start(sock: &Path) -> std::io::Result<Self> {
            let l = UnixListener::bind(sock)?;
            let me = Self::default();
            let st = me.clone();
            std::thread::spawn(move || {
                for c in l.incoming() {
                    let Ok(mut c) = c else { break };
                    let mut r = BufReader::new(match c.try_clone() {
                        Ok(x) => x,
                        Err(_) => continue,
                    });
                    let mut first = String::new();
                    if r.read_line(&mut first).is_err() {
                        continue;
                    }
                    loop {
                        let mut h = String::new();
                        if r.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                            break;
                        }
                    }
                    let path = first.split_whitespace().nth(1).unwrap_or("").to_owned();
                    if let Ok(mut q) = st.requests.lock() {
                        q.push(path.clone());
                    }
                    let body = if path.starts_with("/events") {
                        st.events
                            .lock()
                            .map(|mut e| e.drain(..).collect::<Vec<_>>().join("\n"))
                            .unwrap_or_default()
                    } else {
                        st.routes
                            .lock()
                            .ok()
                            .and_then(|r| r.get(&path).cloned())
                            .unwrap_or_default()
                    };
                    let status = if body.is_empty() && !path.starts_with("/events") {
                        "404 Not Found"
                    } else {
                        "200 OK"
                    };
                    let _ignored = write!(
                        c,
                        "HTTP/1.0 {status}\r\nContent-Type: application/json\r\n\r\n{body}"
                    );
                }
            });
            Ok(me)
        }

        pub fn route(&self, path: &str, body: &str) {
            if let Ok(mut r) = self.routes.lock() {
                r.insert(path.to_owned(), body.to_owned());
            }
        }

        pub fn push_event(&self, line: &str) {
            if let Ok(mut e) = self.events.lock() {
                e.push(line.to_owned());
            }
        }

        #[must_use]
        pub fn inspect_json(id: &str, name: &str, image: &str, restart: &str) -> String {
            format!(
                r#"{{"Id":"{id}","Name":"/{name}","Created":"2026-09-28T23:43:00Z","Image":"sha256:e163ee86","Config":{{"Image":"{image}","Env":["SECRET=should-never-be-read"]}},"HostConfig":{{"RestartPolicy":{{"Name":"{restart}"}},"Privileged":false,"NetworkMode":"bridge"}}}}"#
            )
        }

        #[must_use]
        pub fn event_json(action: &str, id: &str, name: &str, image: &str, nano: i64) -> String {
            format!(
                r#"{{"Type":"container","Action":"{action}","Actor":{{"ID":"{id}","Attributes":{{"name":"{name}","image":"{image}"}}}},"time":{},"timeNano":{nano}}}"#,
                nano / 1_000_000_000
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeDocker;
    use super::*;
    use std::sync::Arc;

    #[test]
    fn allowlist_blocks_everything_else() {
        assert!(path_allowed("/containers/json?all=1"));
        assert!(path_allowed(&format!(
            "/containers/{}/json",
            "a".repeat(64)
        )));
        assert!(path_allowed("/events?since=1&until=2"));
        assert!(!path_allowed("/containers/create"));
        assert!(!path_allowed("/containers/abc/json"));
        assert!(!path_allowed(&format!(
            "/containers/{}/exec",
            "a".repeat(64)
        )));
        assert!(!path_allowed("/events?x=1 HTTP/1.1\r\n"));
        assert!(docker_get(Path::new("/nonexistent"), "/images/json").is_err());
    }

    #[test]
    fn parses_chunked_and_identity_responses() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n").unwrap();
        assert_eq!(r, (200, b"hello world".to_vec()));
        let r = parse_response(b"HTTP/1.0 404 Not Found\r\n\r\n{}").unwrap();
        assert_eq!(r, (404, b"{}".to_vec()));
        assert!(parse_response(b"garbage").is_err());
        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\nabc")
                .is_err()
        );
    }

    #[test]
    fn incident_proxyware_containers_flagged_normal_not() {
        let ind = nocve_proto::Indicators::builtin().unwrap();
        let bad = parse_inspect(
            &serde_json::from_str(&FakeDocker::inspect_json(
                &"b".repeat(64),
                "systemd-networkd",
                "bitping/bitpingd:latest",
                "no",
            ))
            .unwrap(),
        )
        .unwrap();
        let rules: Vec<String> = container_signals(&ind, &bad)
            .into_iter()
            .map(|s| s.rule)
            .collect();
        assert_eq!(
            rules,
            vec!["docker.masquerade_name", "docker.proxyware_image"]
        );
        assert_eq!(bad.restart_policy.as_deref(), Some("no"));
        let ok = parse_inspect(
            &serde_json::from_str(&FakeDocker::inspect_json(
                &"c".repeat(64),
                "afterdark-login",
                "afterdark/login:1.4",
                "always",
            ))
            .unwrap(),
        )
        .unwrap();
        assert!(container_signals(&ind, &ok).is_empty());
        let host = parse_inspect(&serde_json::json!({
            "Id": "d".repeat(64),
            "Name": "/app",
            "Config": {"Image": "app:1"},
            "HostConfig": {"Privileged": true, "NetworkMode": "host"}
        }))
        .unwrap();
        let host_rules: Vec<String> = container_signals(&ind, &host)
            .into_iter()
            .map(|s| s.rule)
            .collect();
        assert_eq!(host_rules, vec!["docker.privileged", "docker.host_network"]);
        assert!(
            !serde_json::to_string(&bad)
                .unwrap()
                .contains("should-never-be-read"),
            "env never copied"
        );
    }

    #[test]
    fn source_baseline_then_events_via_fake_socket() {
        let d = tempfile::Builder::new()
            .prefix("nd")
            .tempdir_in("/tmp")
            .unwrap();
        let sock = d.path().join("docker.sock");
        let fd = FakeDocker::start(&sock).unwrap();
        let id1 = "1".repeat(64);
        let id2 = "2".repeat(64);
        fd.route(
            "/containers/json?all=1",
            &format!(r#"[{{"Id":"{id1}","Names":["/traefik"],"Image":"traefik:v3"}}]"#),
        );
        fd.route(
            &format!("/containers/{id1}/json"),
            &FakeDocker::inspect_json(&id1, "traefik", "traefik:v3", "always"),
        );
        fd.route(
            &format!("/containers/{id2}/json"),
            &FakeDocker::inspect_json(&id2, "kworker-events", "traffmonetizer/cli_v2:latest", "no"),
        );
        let ctx = Ctx {
            root: PathBuf::from("/"),
            ind: Arc::new(nocve_proto::Indicators::builtin().unwrap()),
        };
        let cfg = DockerConfig {
            socket: sock.display().to_string(),
            ..DockerConfig::default()
        };
        let mut s = DockerSource::new(ctx, cfg);
        let mut out = Vec::new();
        s.poll(1_000_000, &mut out);
        assert_eq!(out.len(), 1);
        assert!(out[0].signals.is_empty());
        fd.push_event(&FakeDocker::event_json(
            "create",
            &id2,
            "kworker-events",
            "traffmonetizer/cli_v2:latest",
            1_000_001_000_000_000,
        ));
        fd.push_event(&FakeDocker::event_json(
            "start",
            &id2,
            "kworker-events",
            "traffmonetizer/cli_v2:latest",
            1_000_002_000_000_000,
        ));
        fd.push_event(r#"{"Type":"network","Action":"connect"}"#);
        s.poll(1_005_000, &mut out);
        let kinds: Vec<&str> = out.iter().map(Event::kind).collect();
        assert_eq!(
            kinds,
            vec!["container.seen", "container.create", "container.start"]
        );
        assert_eq!(out[2].max_severity(), Some(Severity::Critical));
        let reqs = fd.requests.lock().unwrap().clone();
        assert!(reqs.iter().all(|r| path_allowed(r)), "{reqs:?}");
    }
}
