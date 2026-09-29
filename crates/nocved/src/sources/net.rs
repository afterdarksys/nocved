//! New outbound connections to public destinations, per network namespace,
//! with pid attribution via the /proc/*/fd socket inode map. Resolves nothing.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

use nocve_proto::{Coverage, CoverageStatus, Event, EventData, NetConnInfo, Severity, Signal};

use super::{Ctx, MAX_EVENTS_PER_POLL, Source, cap_events, coverage};
use crate::config::NetConfig;
use crate::fsutil::read_prefix;
use crate::procfs::{self, Sock};

const DEDUPE_CAP: usize = 16_384;
const DEDUPE_TTL_MS: i64 = 3_600_000;
const INODE_SCAN_MIN_MS: i64 = 10_000;
const MAX_FDS_SCANNED: usize = 1_000_000;
const MAX_SOCKS_PER_TABLE: usize = 65_536;

pub struct NetSource {
    ctx: Ctx,
    cfg: NetConfig,
    /// (exe, remote ip, remote port) -> first seen
    seen_dest: HashMap<(String, IpAddr, u16), i64>,
    dest_order: VecDeque<(String, IpAddr, u16)>,
    handled_inodes: HashSet<u64>,
    inode_pid: HashMap<u64, u32>,
    last_scan_ms: Option<i64>,
    health: Coverage,
}

impl NetSource {
    #[must_use]
    pub fn new(ctx: Ctx, cfg: NetConfig) -> Self {
        Self {
            ctx,
            cfg,
            seen_dest: HashMap::new(),
            dest_order: VecDeque::new(),
            handled_inodes: HashSet::new(),
            inode_pid: HashMap::new(),
            last_scan_ms: None,
            health: coverage("net", CoverageStatus::Skipped, "not polled yet"),
        }
    }

    /// One representative pid per network namespace (plus pid-less fallback).
    fn namespaces(&self) -> Vec<(Option<String>, std::path::PathBuf)> {
        let proc_dir = self.ctx.path("/proc");
        let mut by_ns: HashMap<String, u32> = HashMap::new();
        for pid in procfs::list_pids(&proc_dir, 65_536) {
            if let Some(ns) =
                procfs::readlink_string(&proc_dir.join(pid.to_string()).join("ns/net"))
            {
                by_ns.entry(ns).or_insert(pid);
            }
        }
        if by_ns.is_empty() {
            return vec![(None, proc_dir.join("net"))];
        }
        let mut v: Vec<_> = by_ns
            .into_iter()
            .map(|(ns, pid)| (Some(ns), proc_dir.join(pid.to_string()).join("net")))
            .collect();
        v.sort();
        v
    }

    fn scan_inodes(&mut self) {
        self.inode_pid.clear();
        let proc_dir = self.ctx.path("/proc");
        let mut n = 0usize;
        for pid in procfs::list_pids(&proc_dir, 65_536) {
            let Ok(rd) = std::fs::read_dir(proc_dir.join(pid.to_string()).join("fd")) else {
                continue;
            };
            for e in rd.filter_map(Result::ok) {
                n += 1;
                if n > MAX_FDS_SCANNED {
                    return;
                }
                if let Some(ino) =
                    procfs::readlink_string(&e.path()).and_then(|t| procfs::socket_inode(&t))
                {
                    self.inode_pid.insert(ino, pid);
                }
            }
        }
    }

    fn remember(&mut self, key: (String, IpAddr, u16), now_ms: i64) -> bool {
        if let Some(t) = self.seen_dest.get(&key)
            && now_ms - t < DEDUPE_TTL_MS
        {
            return false;
        }
        while self.dest_order.len() >= DEDUPE_CAP {
            if let Some(old) = self.dest_order.pop_front() {
                self.seen_dest.remove(&old);
            }
        }
        self.seen_dest.insert(key.clone(), now_ms);
        self.dest_order.push_back(key);
        true
    }
}

#[must_use]
pub fn net_signals(ind: &nocve_proto::Indicators, ip: IpAddr, port: u16) -> Vec<Signal> {
    let mut s = Vec::new();
    if let Some(label) = ind.pool_ip(ip) {
        s.push(Signal::new(
            "net.miner_pool_ip",
            Severity::Critical,
            format!("connection to mining pool {ip}:{port} ({label})"),
        ));
    }
    if ind.pool_port(port) {
        s.push(Signal::new(
            "net.miner_pool_port",
            Severity::High,
            format!("connection to common mining-pool port {port}"),
        ));
    }
    s
}

impl Source for NetSource {
    fn id(&self) -> &'static str {
        "net"
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(if self.cfg.interval_secs == 0 {
            5
        } else {
            self.cfg.interval_secs
        })
    }

    fn poll(&mut self, now_ms: i64, out: &mut Vec<Event>) {
        if self.ctx.no_procfs() {
            self.health = coverage(
                "net",
                CoverageStatus::Unsupported,
                "no /proc on this platform",
            );
            return;
        }
        let mut candidates: Vec<(Option<String>, Sock)> = Vec::new();
        let mut tables = 0usize;
        let nss = self.namespaces();
        for (ns, dir) in &nss {
            let mut listening: HashSet<u16> = HashSet::new();
            let mut socks = Vec::new();
            for (file, proto, v6) in [
                ("tcp", "tcp", false),
                ("tcp6", "tcp6", true),
                ("udp", "udp", false),
                ("udp6", "udp6", true),
            ] {
                if let Ok(b) = read_prefix(&dir.join(file), 16 * 1024 * 1024) {
                    tables += 1;
                    for s in procfs::parse_net(&b, proto, v6, MAX_SOCKS_PER_TABLE) {
                        if s.proto.starts_with("tcp") && s.state == procfs::TCP_LISTEN {
                            listening.insert(s.local_port);
                        } else {
                            socks.push(s);
                        }
                    }
                }
            }
            for s in socks {
                let tcp = s.proto.starts_with("tcp");
                let active = if tcp {
                    s.state == procfs::TCP_ESTABLISHED || s.state == procfs::TCP_SYN_SENT
                } else {
                    s.remote_port != 0
                };
                if !active || s.remote.is_unspecified() || listening.contains(&s.local_port) {
                    continue;
                }
                if !self.cfg.include_private && !procfs::is_public(s.remote) {
                    continue;
                }
                if self.handled_inodes.contains(&s.inode) {
                    continue;
                }
                candidates.push((ns.clone(), s));
            }
        }
        if tables == 0 {
            self.health = coverage(
                "net",
                CoverageStatus::Failed,
                "no /proc/net tables readable",
            );
            return;
        }
        let unresolved = candidates
            .iter()
            .any(|(_, s)| !self.inode_pid.contains_key(&s.inode));
        if unresolved
            && self
                .last_scan_ms
                .is_none_or(|t| now_ms - t >= INODE_SCAN_MIN_MS)
        {
            self.scan_inodes();
            self.last_scan_ms = Some(now_ms);
        }
        let mut evs = Vec::new();
        for (ns, s) in candidates {
            if self.handled_inodes.len() > 262_144 {
                self.handled_inodes.clear();
            }
            self.handled_inodes.insert(s.inode);
            let pid = self.inode_pid.get(&s.inode).copied();
            let exe = pid.and_then(|p| {
                procfs::readlink_string(&self.ctx.path("/proc").join(p.to_string()).join("exe"))
                    .map(|t| procfs::split_deleted(&t).0)
            });
            let key = (
                exe.clone().unwrap_or_else(|| "?".into()),
                s.remote,
                s.remote_port,
            );
            if !self.remember(key, now_ms) {
                continue;
            }
            let signals = net_signals(&self.ctx.ind, s.remote, s.remote_port);
            evs.push(
                Event::new(
                    now_ms,
                    "net",
                    EventData::NetConnect(NetConnInfo {
                        proto: s.proto.to_owned(),
                        local: format!("{}:{}", s.local, s.local_port),
                        remote_ip: s.remote.to_string(),
                        remote_port: s.remote_port,
                        state: procfs::tcp_state_name(s.state).to_owned(),
                        pid,
                        exe,
                        netns: ns,
                        inode: s.inode,
                    }),
                )
                .with_signals(signals),
            );
        }
        cap_events("net", now_ms, evs, MAX_EVENTS_PER_POLL, out);
        self.health = coverage(
            "net",
            CoverageStatus::Completed,
            format!("{} network namespace(s)", nss.len()),
        );
    }

    fn health(&self) -> Coverage {
        self.health.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeProc;
    use std::sync::Arc;

    #[test]
    fn miner_pool_connection_attributed_and_deduped() {
        let d = tempfile::tempdir().unwrap();
        let fp = FakeProc::new(d.path());
        fp.add(
            7570,
            1,
            0,
            "irqbalance-core",
            "/opt/.cache/irqbalance-core",
            &["/opt/.cache/irqbalance-core"],
            5,
            0,
        );
        fp.add_socket(7570, 12, 991_122);
        fp.set_net(
            7570,
            "tcp",
            &[
                FakeProc::tcp_row(
                    [108, 165, 123, 229],
                    25438,
                    [104, 243, 43, 115],
                    443,
                    1,
                    991_122,
                ),
                FakeProc::tcp_row([0, 0, 0, 0], 22, [0, 0, 0, 0], 0, 0x0A, 5),
                FakeProc::tcp_row([108, 165, 123, 229], 22, [185, 121, 108, 3], 51000, 1, 6),
                FakeProc::tcp_row([172, 17, 0, 2], 40000, [172, 17, 0, 3], 5432, 1, 7),
            ],
        );
        let ctx = Ctx {
            root: d.path().to_path_buf(),
            ind: Arc::new(nocve_proto::Indicators::builtin().unwrap()),
        };
        let mut s = NetSource::new(ctx, NetConfig::default());
        let mut out = Vec::new();
        s.poll(0, &mut out);
        assert_eq!(
            out.len(),
            1,
            "inbound ssh and private docker traffic ignored: {out:?}"
        );
        let EventData::NetConnect(c) = &out[0].data else {
            panic!()
        };
        assert_eq!(c.pid, Some(7570));
        assert_eq!(c.exe.as_deref(), Some("/opt/.cache/irqbalance-core"));
        assert_eq!(out[0].max_severity(), Some(Severity::Critical));
        s.poll(5000, &mut out);
        assert_eq!(out.len(), 1, "same connection not re-reported");
    }

    #[test]
    fn pool_port_on_unknown_ip_is_high() {
        let ind = nocve_proto::Indicators::builtin().unwrap();
        let s = net_signals(&ind, "198.51.100.7".parse().unwrap(), 3333);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].severity, Severity::High);
        assert!(net_signals(&ind, "1.1.1.1".parse().unwrap(), 443).is_empty());
    }
}
