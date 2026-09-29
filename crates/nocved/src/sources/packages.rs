//! Package installs from /var/log/dpkg.log and /var/log/apt/history.log.
//! Flags secret-hunting / recon tooling (the incident's `apt-get install -y
//! unzip p7zip-full fd-find` on 7 hosts). Upgrades are never flagged.

use std::time::Duration;

use nocve_proto::mask::mask_line;
use nocve_proto::{Coverage, CoverageStatus, Event, EventData, Indicators, Severity, Signal};

use super::tail::Tailer;
use super::{Ctx, MAX_EVENTS_PER_POLL, Source, cap_events, coverage};
use crate::config::SourceToggle;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpkgLine {
    pub time: String,
    pub action: String,
    pub package: String,
    pub arch: Option<String>,
    pub old: Option<String>,
    pub new: Option<String>,
}

/// `2026-09-20 19:18:52 install unzip:amd64 <none> 6.0-26+deb10u1`
#[must_use]
pub fn parse_dpkg(line: &str) -> Option<DpkgLine> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 4 {
        return None;
    }
    let action = f[2];
    if !matches!(action, "install" | "upgrade" | "remove" | "purge") {
        return None;
    }
    let (package, arch) = match f[3].split_once(':') {
        Some((p, a)) => (p.to_owned(), Some(a.to_owned())),
        None => (f[3].to_owned(), None),
    };
    let ver = |i: usize| {
        f.get(i)
            .filter(|v| **v != "<none>")
            .map(|v| (*v).to_owned())
    };
    Some(DpkgLine {
        time: format!("{} {}", f[0], f[1]),
        action: action.to_owned(),
        package,
        arch,
        old: ver(4),
        new: ver(5),
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AptTxn {
    pub start_date: String,
    pub commandline: Option<String>,
    pub requested_by: Option<String>,
    /// (package, automatic)
    pub install: Vec<(String, bool)>,
    pub upgrade: Vec<String>,
    pub remove: Vec<String>,
}

/// Splits `unzip:amd64 (6.0-26), p7zip:amd64 (16.02, automatic)`.
#[must_use]
pub fn parse_pkg_list(s: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    let mut paren = String::new();
    for ch in s.chars() {
        match ch {
            '(' => {
                depth += 1;
                paren.clear();
            }
            ')' => depth -= 1,
            ',' if depth == 0 => {
                let name = cur.trim().to_owned();
                if !name.is_empty() {
                    out.push((name, paren.contains("automatic")));
                }
                cur.clear();
                paren.clear();
            }
            _ if depth > 0 => paren.push(ch),
            _ => cur.push(ch),
        }
        if out.len() >= 2000 {
            break;
        }
    }
    let name = cur.trim().to_owned();
    if !name.is_empty() {
        out.push((name, paren.contains("automatic")));
    }
    out
}

/// Incremental parser for apt history.log blocks.
#[derive(Debug, Default)]
pub struct AptParser {
    cur: Option<AptTxn>,
}

impl AptParser {
    /// Feeds one line; returns a finished transaction on `End-Date:` (or when a
    /// new `Start-Date:` arrives without an end).
    pub fn feed(&mut self, line: &str) -> Option<AptTxn> {
        let (k, v) = line.split_once(": ")?;
        let v = v.trim();
        match k {
            "Start-Date" => {
                let done = self.cur.take();
                self.cur = Some(AptTxn {
                    start_date: v.split_whitespace().collect::<Vec<_>>().join(" "),
                    ..AptTxn::default()
                });
                done
            }
            "End-Date" => self.cur.take(),
            _ => {
                let t = self.cur.as_mut()?;
                match k {
                    "Commandline" => t.commandline = Some(mask_line(v)),
                    "Requested-By" => t.requested_by = Some(v.chars().take(128).collect()),
                    "Install" => t.install = parse_pkg_list(v),
                    "Upgrade" => t.upgrade = parse_pkg_list(v).into_iter().map(|p| p.0).collect(),
                    "Remove" | "Purge" => {
                        t.remove.extend(parse_pkg_list(v).into_iter().map(|p| p.0))
                    }
                    _ => {}
                }
                None
            }
        }
    }
}

#[must_use]
pub fn txn_signals(ind: &Indicators, t: &AptTxn) -> Vec<Signal> {
    let explicit: Vec<&str> = t
        .install
        .iter()
        .filter(|(_, auto)| !auto)
        .map(|(p, _)| p.as_str())
        .filter(|p| ind.secret_tool(p).is_some())
        .collect();
    let strong = t
        .install
        .iter()
        .any(|(p, _)| ind.secret_tool(p) == Some(true));
    let mut s = Vec::new();
    if explicit.len() >= 2 {
        s.push(Signal::new(
            "pkg.secret_hunting_toolkit",
            Severity::High,
            format!("installed together: {}", explicit.join(", ")),
        ));
    } else if strong {
        s.push(Signal::new(
            "pkg.secret_hunting_tool",
            Severity::High,
            "offensive/recon tool installed",
        ));
    } else if let Some(p) = explicit.first() {
        s.push(Signal::new(
            "pkg.secret_hunting_tool",
            Severity::Medium,
            format!("{p} installed"),
        ));
    }
    s
}

pub struct PackagesSource {
    ctx: Ctx,
    cfg: SourceToggle,
    dpkg: Tailer,
    apt: Tailer,
    parser: AptParser,
    health: Coverage,
}

impl PackagesSource {
    #[must_use]
    pub fn new(ctx: Ctx, cfg: SourceToggle) -> Self {
        let dpkg = Tailer::new(ctx.path("/var/log/dpkg.log"), true);
        let apt = Tailer::new(ctx.path("/var/log/apt/history.log"), true);
        Self {
            ctx,
            cfg,
            dpkg,
            apt,
            parser: AptParser::default(),
            health: coverage("packages", CoverageStatus::Skipped, "not polled yet"),
        }
    }
}

impl Source for PackagesSource {
    fn id(&self) -> &'static str {
        "packages"
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(if self.cfg.interval_secs == 0 {
            5
        } else {
            self.cfg.interval_secs
        })
    }

    fn poll(&mut self, now_ms: i64, out: &mut Vec<Event>) {
        let mut evs = Vec::new();
        for line in self.dpkg.poll().lines {
            let Some(d) = parse_dpkg(&line) else { continue };
            let mut sig = Vec::new();
            if d.action == "install" {
                match self.ctx.ind.secret_tool(&d.package) {
                    Some(true) => sig.push(Signal::new(
                        "pkg.secret_hunting_tool",
                        Severity::High,
                        format!("{} installed", d.package),
                    )),
                    Some(false) => sig.push(Signal::new(
                        "pkg.secret_hunting_tool",
                        Severity::Medium,
                        format!("{} installed", d.package),
                    )),
                    None => {}
                }
            }
            evs.push(
                Event::new(
                    now_ms,
                    "packages",
                    EventData::PackageChange {
                        action: d.action,
                        package: d.package,
                        arch: d.arch,
                        version_old: d.old,
                        version_new: d.new,
                        log_time: d.time,
                    },
                )
                .with_signals(sig),
            );
        }
        for line in self.apt.poll().lines {
            if let Some(t) = self.parser.feed(&line) {
                let sig = txn_signals(&self.ctx.ind, &t);
                evs.push(
                    Event::new(
                        now_ms,
                        "packages",
                        EventData::PackageTransaction {
                            start_date: t.start_date,
                            commandline: t.commandline,
                            requested_by: t.requested_by,
                            install: t.install.into_iter().map(|p| p.0).collect(),
                            upgrade: t.upgrade,
                            remove: t.remove,
                        },
                    )
                    .with_signals(sig),
                );
            }
        }
        cap_events("packages", now_ms, evs, MAX_EVENTS_PER_POLL, out);
        self.health = match (self.dpkg.is_open(), self.apt.is_open()) {
            (true, true) => coverage(
                "packages",
                CoverageStatus::Completed,
                "dpkg.log + apt history.log",
            ),
            (false, false) => coverage(
                "packages",
                CoverageStatus::Unsupported,
                "no dpkg.log or apt history.log",
            ),
            _ => coverage(
                "packages",
                CoverageStatus::Partial,
                "only one of dpkg.log / apt history.log",
            ),
        };
    }

    fn health(&self) -> Coverage {
        self.health.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ind() -> Indicators {
        Indicators::builtin().unwrap()
    }

    #[test]
    fn dpkg_lines() {
        assert_eq!(
            parse_dpkg("2026-09-20 19:18:52 install unzip:amd64 <none> 6.0-26+deb10u1"),
            Some(DpkgLine {
                time: "2026-09-20 19:18:52".into(),
                action: "install".into(),
                package: "unzip".into(),
                arch: Some("amd64".into()),
                old: None,
                new: Some("6.0-26+deb10u1".into())
            })
        );
        assert!(parse_dpkg("2026-09-20 19:18:52 status installed unzip:amd64 6.0-26").is_none());
        assert!(parse_dpkg("2026-09-20 19:18:52 configure unzip:amd64 6.0 <none>").is_none());
        assert!(parse_dpkg("").is_none());
    }

    #[test]
    fn incident_apt_transaction_is_high() {
        let mut p = AptParser::default();
        let lines = [
            "Start-Date: 2026-09-20  19:18:47",
            "Commandline: apt-get install -y unzip p7zip-full fd-find",
            "Install: p7zip:amd64 (16.02+dfsg-6, automatic), unzip:amd64 (6.0-23+deb10u2), p7zip-full:amd64 (16.02+dfsg-6), fd-find:amd64 (7.2.0-2)",
            "End-Date: 2026-09-20  19:18:52",
        ];
        let mut done = None;
        for l in lines {
            done = done.or(p.feed(l));
        }
        let t = done.unwrap();
        assert_eq!(t.start_date, "2026-09-20 19:18:47");
        assert_eq!(t.install.len(), 4);
        assert_eq!(t.install[0], ("p7zip:amd64".into(), true));
        let s = txn_signals(&ind(), &t);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].rule, "pkg.secret_hunting_toolkit");
        assert_eq!(s[0].severity, Severity::High);
    }

    #[test]
    fn normal_apt_upgrade_is_not_flagged() {
        let mut p = AptParser::default();
        let mut done = None;
        for l in [
            "Start-Date: 2026-09-15  06:25:01",
            "Commandline: /usr/bin/unattended-upgrade",
            "Upgrade: libc6:amd64 (2.28-10+deb10u2, 2.28-10+deb10u3), unzip:amd64 (6.0-23, 6.0-23+deb10u3), openssh-server:amd64 (1:7.9p1-10+deb10u3, 1:7.9p1-10+deb10u4)",
            "End-Date: 2026-09-15  06:25:40",
        ] {
            done = done.or(p.feed(l));
        }
        let t = done.unwrap();
        assert_eq!(t.upgrade.len(), 3);
        assert!(txn_signals(&ind(), &t).is_empty());
        assert!(
            parse_dpkg("2026-09-15 06:25:10 upgrade unzip:amd64 6.0-23 6.0-23+deb10u3").is_some()
        );
    }

    #[test]
    fn missing_end_date_flushes_on_next_start_and_commandline_masked() {
        let mut p = AptParser::default();
        assert!(p.feed("Start-Date: a").is_none());
        assert!(
            p.feed(
                "Commandline: apt-get -o Acquire::http::Proxy=http://u:pw@proxy:3128 install nmap"
            )
            .is_none()
        );
        assert!(p.feed("Install: nmap:amd64 (7.70)").is_none());
        let t = p.feed("Start-Date: b").unwrap();
        assert!(
            !t.commandline.clone().unwrap().contains(":pw@"),
            "{:?}",
            t.commandline
        );
        assert_eq!(
            txn_signals(&ind(), &t)[0].severity,
            Severity::High,
            "strong tool"
        );
        assert!(p.feed("garbage line").is_none());
    }

    #[test]
    fn single_weak_tool_is_medium() {
        let t = AptTxn {
            install: vec![("unzip:amd64".into(), false)],
            ..AptTxn::default()
        };
        assert_eq!(txn_signals(&ind(), &t)[0].severity, Severity::Medium);
    }
}
