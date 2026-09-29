//! SSH authentication events from /var/log/auth.log (Debian) and
//! /var/log/secure (RHEL), with log-tamper detection.
//!
//! Privacy: raw lines are never shipped. Usernames from `invalid user` lines
//! are attacker-supplied (and sometimes a mistyped password) so they are
//! replaced by `<invalid>`.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use nocve_proto::{Coverage, CoverageStatus, Event, EventData, Severity, Signal, SshAuthInfo};

use super::tail::{Anomaly, Tailer};
use super::{Ctx, MAX_EVENTS_PER_POLL, Source, cap_events, coverage};
use crate::config::AuthlogConfig;
use crate::fsutil::read_prefix;
use crate::procfs;

const TRACK_CAP: usize = 4096;
const ORPHAN_GRACE_MS: i64 = 5_000;
const FIRST_TRY_WINDOW_MS: i64 = 3_600_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogLine {
    pub time: String,
    pub host: Option<String>,
    pub prog: String,
    pub pid: Option<u32>,
    pub msg: String,
}

const MONTHS: &[&str] = &[
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Parses traditional (`Sep 19 18:29:39 host prog[pid]: msg`) and RFC 3339
/// (`2026-09-19T18:29:39.123+00:00 host prog[pid]: msg`) syslog lines.
#[must_use]
pub fn parse_syslog(line: &str) -> Option<SyslogLine> {
    let (time, rest) =
        if line.len() > 16 && MONTHS.contains(&line.get(..3)?) && line.as_bytes()[15] == b' ' {
            (line.get(..15)?.to_owned(), &line[16..])
        } else {
            let (t, r) = line.split_once(' ')?;
            if !(t.len() >= 19 && t.as_bytes()[4] == b'-' && t.as_bytes()[10] == b'T') {
                return None;
            }
            (t.to_owned(), r)
        };
    let (host, rest) = rest.split_once(' ')?;
    let (tag, msg) = rest.split_once(": ")?;
    let (prog, pid) = match tag.split_once('[') {
        Some((p, r)) => (p, r.strip_suffix(']').and_then(|v| v.parse().ok())),
        None => (tag, None),
    };
    Some(SyslogLine {
        time,
        host: Some(host.to_owned()),
        prog: prog.to_owned(),
        pid,
        msg: msg.to_owned(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshdMsg {
    Auth {
        accepted: bool,
        method: String,
        user: String,
        invalid: bool,
        ip: String,
        port: Option<u16>,
        key_fp: Option<String>,
    },
    Session {
        opened: bool,
        user: String,
    },
}

#[must_use]
pub fn parse_sshd(msg: &str) -> Option<SshdMsg> {
    if let Some(r) = msg.strip_prefix("pam_unix(sshd:session): session ") {
        let (opened, r) = if let Some(r) = r.strip_prefix("opened for user ") {
            (true, r)
        } else {
            (false, r.strip_prefix("closed for user ")?)
        };
        let user = r.split([' ', '(']).next()?.to_owned();
        return Some(SshdMsg::Session { opened, user });
    }
    let (accepted, r) = if let Some(r) = msg.strip_prefix("Accepted ") {
        (true, r)
    } else {
        (false, msg.strip_prefix("Failed ")?)
    };
    let (left, right) = r.rsplit_once(" from ")?;
    let (method, who) = left.split_once(" for ")?;
    let (invalid, user) = match who.strip_prefix("invalid user ") {
        Some(u) => (true, u),
        None => (false, who),
    };
    let mut t = right.split_whitespace();
    let ip = t.next()?.to_owned();
    ip.parse::<std::net::IpAddr>().ok()?;
    let port = if t.next() == Some("port") {
        t.next().and_then(|p| p.parse().ok())
    } else {
        None
    };
    let rest: Vec<&str> = t.collect();
    let key_fp = rest
        .iter()
        .position(|w| w.ends_with(':'))
        .and_then(|i| rest.get(i + 2))
        .map(|s| (*s).to_owned());
    Some(SshdMsg::Auth {
        accepted,
        method: method.to_owned(),
        user: if invalid {
            "<invalid>".to_owned()
        } else {
            user.to_owned()
        },
        invalid,
        ip,
        port,
        key_fp,
    })
}

pub struct AuthlogSource {
    ctx: Ctx,
    cfg: AuthlogConfig,
    tailers: Vec<Tailer>,
    accepted_pids: HashMap<u32, i64>,
    accepted_order: VecDeque<u32>,
    failed_ip: HashMap<String, i64>,
    failed_order: VecDeque<String>,
    started_ms: Option<i64>,
    last_line_ms: i64,
    silence_flagged: bool,
    last_session_check_ms: i64,
    health: Coverage,
}

impl AuthlogSource {
    #[must_use]
    pub fn new(ctx: Ctx, cfg: AuthlogConfig) -> Self {
        let tailers = cfg
            .paths
            .iter()
            .map(|p| Tailer::new(ctx.path(p), true))
            .collect();
        Self {
            ctx,
            cfg,
            tailers,
            accepted_pids: HashMap::new(),
            accepted_order: VecDeque::new(),
            failed_ip: HashMap::new(),
            failed_order: VecDeque::new(),
            started_ms: None,
            last_line_ms: 0,
            silence_flagged: false,
            last_session_check_ms: i64::MIN / 2,
            health: coverage("authlog", CoverageStatus::Skipped, "not polled yet"),
        }
    }

    fn live_ssh_sessions(&self) -> usize {
        let proc_dir = self.ctx.path("/proc");
        procfs::list_pids(&proc_dir, 65_536)
            .into_iter()
            .filter(|pid| {
                read_prefix(&proc_dir.join(pid.to_string()).join("cmdline"), 256)
                    .map(|b| procfs::parse_cmdline(&b).join(" "))
                    .is_ok_and(|c| c.starts_with("sshd: ") && c.contains('@'))
            })
            .count()
    }

    fn handle_line(
        &mut self,
        now_ms: i64,
        path: &str,
        line: &str,
        hidden: bool,
        evs: &mut Vec<Event>,
    ) {
        let Some(l) = parse_syslog(line) else {
            return;
        };
        if !l.prog.starts_with("sshd") {
            return;
        }
        let Some(m) = parse_sshd(&l.msg) else {
            return;
        };
        let mut signals = Vec::new();
        if hidden {
            signals.push(Signal::new(
                "authlog.hidden_line",
                Severity::High,
                "line was written to an auth log inode that had been removed from view",
            ));
        }
        match m {
            SshdMsg::Auth {
                accepted,
                method,
                user,
                invalid,
                ip,
                port,
                key_fp,
            } => {
                if accepted {
                    if let Some(pid) = l.pid {
                        if self.accepted_order.len() >= TRACK_CAP
                            && let Some(o) = self.accepted_order.pop_front()
                        {
                            self.accepted_pids.remove(&o);
                        }
                        self.accepted_pids.insert(pid, now_ms);
                        self.accepted_order.push_back(pid);
                    }
                    let password =
                        method == "password" || method.starts_with("keyboard-interactive");
                    if password && user == "root" {
                        signals.push(Signal::new(
                            "ssh.root_password_login",
                            Severity::High,
                            format!("root logged in with a password from {ip}"),
                        ));
                    }
                    let failed_recently = self
                        .failed_ip
                        .get(&ip)
                        .is_some_and(|t| now_ms - t < FIRST_TRY_WINDOW_MS);
                    if password && !failed_recently {
                        signals.push(Signal::new(
                            "ssh.password_first_try",
                            Severity::High,
                            format!("password accepted on the first try from {ip}: the credential was known"),
                        ));
                    }
                } else {
                    if self.failed_order.len() >= TRACK_CAP
                        && let Some(o) = self.failed_order.pop_front()
                    {
                        self.failed_ip.remove(&o);
                    }
                    self.failed_ip.insert(ip.clone(), now_ms);
                    self.failed_order.push_back(ip.clone());
                }
                evs.push(
                    Event::new(
                        now_ms,
                        "authlog",
                        EventData::SshAuth(SshAuthInfo {
                            outcome: if accepted { "accepted" } else { "failed" }.into(),
                            method,
                            user,
                            invalid_user: invalid,
                            src_ip: ip,
                            src_port: port,
                            sshd_pid: l.pid,
                            key_fp,
                            log_time: l.time,
                            log_host: l.host,
                            path: path.to_owned(),
                        }),
                    )
                    .with_signals(signals),
                );
            }
            SshdMsg::Session { opened, user } => {
                let in_grace = self
                    .started_ms
                    .is_some_and(|s| now_ms - s < ORPHAN_GRACE_MS);
                if opened && !in_grace && l.pid.is_none_or(|p| !self.accepted_pids.contains_key(&p))
                {
                    signals.push(Signal::new(
                        "authlog.orphan_session",
                        Severity::High,
                        format!("sshd session opened for {user} with no Accepted line: auth.log lines were deleted"),
                    ));
                }
                evs.push(
                    Event::new(
                        now_ms,
                        "authlog",
                        EventData::SshSession {
                            action: if opened { "opened" } else { "closed" }.into(),
                            user,
                            sshd_pid: l.pid,
                            log_time: l.time,
                            path: path.to_owned(),
                        },
                    )
                    .with_signals(signals),
                );
            }
        }
    }
}

fn tamper(now_ms: i64, path: &str, rule: &str, reason: &str, detail: String) -> Event {
    Event::new(
        now_ms,
        "authlog",
        EventData::LogTamper {
            path: path.to_owned(),
            reason: reason.to_owned(),
            detail: detail.clone(),
        },
    )
    .with_signals(vec![Signal::new(rule, Severity::High, detail)])
}

impl Source for AuthlogSource {
    fn id(&self) -> &'static str {
        "authlog"
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(if self.cfg.interval_secs == 0 {
            2
        } else {
            self.cfg.interval_secs
        })
    }

    fn poll(&mut self, now_ms: i64, out: &mut Vec<Event>) {
        if self.started_ms.is_none() {
            self.started_ms = Some(now_ms);
            self.last_line_ms = now_ms;
        }
        let mut evs = Vec::new();
        let mut got_line = false;
        let mut open = Vec::new();
        let mut tailers = std::mem::take(&mut self.tailers);
        for t in &mut tailers {
            let o = t.poll();
            let shown = t.path().strip_prefix(&self.ctx.root).map_or_else(
                |_| t.path().display().to_string(),
                |p| format!("/{}", p.display()),
            );
            for a in &o.anomalies {
                let ev = match a {
                    Anomaly::Truncated { from, to } => tamper(
                        now_ms,
                        &shown,
                        "authlog.truncated",
                        "truncated",
                        format!("{shown} shrank from {from} to {to} bytes"),
                    ),
                    Anomaly::Replaced {
                        old_inode,
                        new_inode,
                        old_unlinked,
                    } => tamper(
                        now_ms,
                        &shown,
                        "authlog.replaced",
                        "replaced",
                        format!(
                            "{shown} replaced in place (inode {old_inode} -> {new_inode}, old unlinked: {old_unlinked}); typical of sed -i"
                        ),
                    ),
                    Anomaly::Deleted => tamper(
                        now_ms,
                        &shown,
                        "authlog.deleted",
                        "deleted",
                        format!("{shown} was deleted"),
                    ),
                    Anomaly::Symlink => tamper(
                        now_ms,
                        &shown,
                        "authlog.symlink",
                        "symlink",
                        format!("{shown} is now a symlink (not followed)"),
                    ),
                };
                evs.push(ev);
            }
            got_line |= !o.lines.is_empty();
            for (i, line) in o.lines.iter().enumerate() {
                self.handle_line(now_ms, &shown, line, i < o.orphan_lines, &mut evs);
            }
            if t.is_open() {
                open.push(shown);
            }
        }
        self.tailers = tailers;
        if got_line {
            self.last_line_ms = now_ms;
            self.silence_flagged = false;
        }
        let silence_ms = i64::try_from(self.cfg.silence_secs)
            .unwrap_or(i64::MAX / 2)
            .saturating_mul(1000);
        if !open.is_empty()
            && !self.silence_flagged
            && now_ms - self.last_line_ms >= silence_ms
            && now_ms - self.last_session_check_ms >= 60_000
        {
            self.last_session_check_ms = now_ms;
            let live = self.live_ssh_sessions();
            if live > 0 {
                self.silence_flagged = true;
                let secs = (now_ms - self.last_line_ms) / 1000;
                evs.push(tamper(
                    now_ms,
                    &open.join(","),
                    "authlog.silent_with_sessions",
                    "silent_with_sessions",
                    format!("no auth log lines for {secs}s while {live} ssh session(s) are live"),
                ));
            }
        }
        cap_events("authlog", now_ms, evs, MAX_EVENTS_PER_POLL, out);
        self.health = if open.is_empty() {
            coverage(
                "authlog",
                CoverageStatus::Unsupported,
                "no auth.log or secure (journald-only host?)",
            )
        } else {
            coverage(
                "authlog",
                CoverageStatus::Completed,
                format!("tailing {}", open.join(", ")),
            )
        };
    }

    fn health(&self) -> Coverage {
        self.health.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Arc;

    fn src(root: &std::path::Path) -> AuthlogSource {
        let ctx = Ctx {
            root: root.to_path_buf(),
            ind: Arc::new(nocve_proto::Indicators::builtin().unwrap()),
        };
        AuthlogSource::new(ctx, AuthlogConfig::default())
    }

    fn append(p: &std::path::Path, s: &[u8]) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .unwrap()
            .write_all(s)
            .unwrap();
    }

    #[test]
    fn parses_debian10_and_debian12_formats() {
        let l = parse_syslog("Sep 19 18:29:39 gdns2 sshd[1234]: Accepted password for root from 104.28.205.21 port 51234 ssh2").unwrap();
        assert_eq!(l.time, "Sep 19 18:29:39");
        assert_eq!(l.host.as_deref(), Some("gdns2"));
        assert_eq!(l.pid, Some(1234));
        let l2 = parse_syslog("2026-09-19T18:29:39.123456+00:00 gdns2 sshd[9]: Failed password for root from 185.121.108.3 port 1 ssh2").unwrap();
        assert_eq!(l2.pid, Some(9));
        assert!(parse_syslog("garbage").is_none());
        assert!(parse_syslog("").is_none());
    }

    #[test]
    fn parses_sshd_messages() {
        assert_eq!(
            parse_sshd(
                "Accepted publickey for root from 1.2.3.4 port 5 ssh2: ED25519 SHA256:abcdef"
            ),
            Some(SshdMsg::Auth {
                accepted: true,
                method: "publickey".into(),
                user: "root".into(),
                invalid: false,
                ip: "1.2.3.4".into(),
                port: Some(5),
                key_fp: Some("SHA256:abcdef".into())
            })
        );
        let Some(SshdMsg::Auth { user, invalid, .. }) =
            parse_sshd("Failed password for invalid user hunter2 from from 1.2.3.4 port 22 ssh2")
        else {
            panic!()
        };
        assert!(invalid);
        assert_eq!(user, "<invalid>", "attacker-supplied names are not shipped");
        assert_eq!(
            parse_sshd("pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)"),
            Some(SshdMsg::Session {
                opened: true,
                user: "root".into()
            })
        );
        assert_eq!(
            parse_sshd("pam_unix(sshd:session): session opened for user root by (uid=0)"),
            Some(SshdMsg::Session {
                opened: true,
                user: "root".into()
            })
        );
        assert!(parse_sshd("Accepted password for root from notanip port 1 ssh2").is_none());
        assert!(parse_sshd("Received disconnect from 1.2.3.4").is_none());
    }

    #[test]
    fn first_try_root_password_and_orphan_session() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("var/log/auth.log");
        append(&p, b"");
        let mut s = src(d.path());
        let mut out = Vec::new();
        s.poll(0, &mut out);
        append(&p, b"Sep 20 19:18:40 gdns2 sshd[100]: Failed password for root from 185.121.108.3 port 1 ssh2\n");
        append(&p, b"Sep 20 19:18:45 gdns2 sshd[101]: Accepted password for root from 185.121.108.3 port 2 ssh2\n");
        append(&p, b"Sep 20 19:18:46 gdns2 sshd[101]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)\n");
        append(&p, b"Sep 20 19:18:50 gdns2 sshd[102]: Accepted password for root from 104.28.205.21 port 3 ssh2\n");
        append(&p, b"Sep 20 19:18:51 gdns2 sshd[11649]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)\n");
        s.poll(10_000, &mut out);
        let rules: Vec<Vec<&str>> = out
            .iter()
            .map(|e| e.signals.iter().map(|s| s.rule.as_str()).collect())
            .collect();
        assert_eq!(rules[0], Vec::<&str>::new());
        assert_eq!(
            rules[1],
            vec!["ssh.root_password_login"],
            "failed before: not first try"
        );
        assert!(rules[2].is_empty(), "session with Accepted is fine");
        assert_eq!(
            rules[3],
            vec!["ssh.root_password_login", "ssh.password_first_try"]
        );
        assert_eq!(rules[4], vec!["authlog.orphan_session"]);
    }

    #[test]
    fn nul_runs_and_rotation_regression() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("var/log/auth.log");
        append(&p, b"");
        let mut s = src(d.path());
        let mut out = Vec::new();
        s.poll(0, &mut out);
        let mut b = vec![0u8; 3000];
        b.extend_from_slice(b"Sep 21 05:10:01 gdns1 sshd[5]: Accepted publickey for root from 10.0.0.5 port 1 ssh2: RSA SHA256:x\n");
        append(&p, &b);
        s.poll(6_000, &mut out);
        std::fs::rename(&p, d.path().join("var/log/auth.log.1")).unwrap();
        append(&p, b"Sep 22 00:00:01 gdns1 sshd[6]: Failed password for root from 185.121.108.3 port 1 ssh2\n");
        s.poll(8_000, &mut out);
        let kinds: Vec<&str> = out.iter().map(Event::kind).collect();
        assert_eq!(kinds, vec!["ssh.auth", "ssh.auth"], "{out:?}");
        assert!(out.iter().all(|e| e.signals.is_empty()));
    }

    #[test]
    fn sed_i_and_silence_with_live_sessions() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("var/log/auth.log");
        append(&p, b"");
        let fp = crate::testutil::FakeProc::new(d.path());
        fp.add(
            4000,
            1,
            0,
            "sshd",
            "/usr/sbin/sshd",
            &["sshd: root@pts/0"],
            10,
            0,
        );
        let mut s = src(d.path());
        let mut out = Vec::new();
        s.poll(0, &mut out);
        let tmp = d.path().join("var/log/sedAbc");
        std::fs::write(&tmp, b"").unwrap();
        std::fs::rename(&tmp, &p).unwrap();
        s.poll(2_000, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].signals[0].rule, "authlog.replaced");
        s.poll(1_900_000, &mut out);
        assert_eq!(
            out.last().unwrap().signals[0].rule,
            "authlog.silent_with_sessions"
        );
        let n = out.len();
        s.poll(2_000_000, &mut out);
        assert_eq!(out.len(), n, "flagged once per silence");
    }

    #[test]
    fn journald_only_host_is_unsupported() {
        let d = tempfile::tempdir().unwrap();
        let mut s = src(d.path());
        let mut out = Vec::new();
        s.poll(0, &mut out);
        assert_eq!(s.health().status, CoverageStatus::Unsupported);
    }
}
