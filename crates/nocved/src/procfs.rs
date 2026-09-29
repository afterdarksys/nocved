//! Pure parsers for /proc files. All inputs are untrusted and bounded.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// USER_HZ is fixed at 100 by the Linux userspace ABI on x86_64/aarch64.
pub const CLK_TCK: u64 = 100;
const PF_KTHREAD: u64 = 0x0020_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub pid: u32,
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    pub flags: u64,
    pub utime: u64,
    pub stime: u64,
    pub start_ticks: u64,
}

impl Stat {
    #[must_use]
    pub fn is_kernel_thread(&self) -> bool {
        self.flags & PF_KTHREAD != 0 || self.ppid == 2 || self.pid == 2
    }
    #[must_use]
    pub fn cpu_ticks(&self) -> u64 {
        self.utime.saturating_add(self.stime)
    }
}

/// Parses /proc/<pid>/stat. `comm` may contain spaces and ')' so the last ')'
/// ends it.
#[must_use]
pub fn parse_stat(bytes: &[u8]) -> Option<Stat> {
    let s = String::from_utf8_lossy(bytes);
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    if close < open {
        return None;
    }
    let pid = s[..open].trim().parse().ok()?;
    let comm = s[open + 1..close].to_owned();
    let rest: Vec<&str> = s[close + 1..].split_whitespace().collect();
    // rest[0] = state (field 3); field N is rest[N-3].
    let f = |n: usize| rest.get(n - 3).and_then(|v| v.parse::<u64>().ok());
    Some(Stat {
        pid,
        comm,
        state: rest.first()?.chars().next()?,
        ppid: u32::try_from(f(4)?).ok()?,
        flags: f(9)?,
        utime: f(14)?,
        stime: f(15)?,
        start_ticks: f(22)?,
    })
}

/// Real uid from /proc/<pid>/status.
#[must_use]
pub fn parse_status_uid(bytes: &[u8]) -> Option<u32> {
    let s = String::from_utf8_lossy(bytes);
    s.lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|r| r.split_whitespace().next())
        .and_then(|v| v.parse().ok())
}

#[must_use]
pub fn parse_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .take(256)
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect()
}

/// Container id from /proc/<pid>/cgroup (docker, containerd, k3s/cri).
#[must_use]
pub fn parse_cgroup_container(bytes: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(bytes);
    for line in s.lines() {
        let path = line.rsplit(':').next().unwrap_or("");
        for seg in path.split('/').rev() {
            let seg = seg.strip_suffix(".scope").unwrap_or(seg);
            let id = seg
                .strip_prefix("docker-")
                .or_else(|| seg.strip_prefix("cri-containerd-"))
                .or_else(|| seg.strip_prefix("crio-"))
                .unwrap_or(seg);
            if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Some(id[..12].to_owned());
            }
        }
    }
    None
}

/// /proc/stat `btime` (boot time, Unix seconds).
#[must_use]
pub fn parse_btime(bytes: &[u8]) -> Option<i64> {
    String::from_utf8_lossy(bytes)
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse().ok())
}

/// readlink result for /proc/<pid>/exe: (path, deleted flag).
#[must_use]
pub fn split_deleted(target: &str) -> (String, bool) {
    match target.strip_suffix(" (deleted)") {
        Some(p) => (p.to_owned(), true),
        None => (target.to_owned(), false),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sock {
    pub proto: &'static str,
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
    pub state: u8,
    pub inode: u64,
}

pub const TCP_ESTABLISHED: u8 = 0x01;
pub const TCP_SYN_SENT: u8 = 0x02;
pub const TCP_LISTEN: u8 = 0x0A;

#[must_use]
pub fn tcp_state_name(s: u8) -> &'static str {
    match s {
        0x01 => "established",
        0x02 => "syn_sent",
        0x0A => "listen",
        0x06 => "time_wait",
        0x08 => "close_wait",
        _ => "other",
    }
}

fn parse_addr(s: &str, v6: bool) -> Option<(IpAddr, u16)> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    if v6 {
        if a.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        // Four 32-bit words, each in host (little-endian) byte order.
        for w in 0..4 {
            let word = u32::from_str_radix(&a[w * 8..w * 8 + 8], 16).ok()?;
            bytes[w * 4..w * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        let ip = Ipv6Addr::from(bytes);
        Some((ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4), port))
    } else {
        let word = u32::from_str_radix(a, 16).ok()?;
        Some((IpAddr::V4(Ipv4Addr::from(word.to_le_bytes())), port))
    }
}

/// Parses /proc/net/{tcp,tcp6,udp,udp6}. Malformed rows are skipped.
#[must_use]
pub fn parse_net(bytes: &[u8], proto: &'static str, v6: bool, max: usize) -> Vec<Sock> {
    let s = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    for line in s.lines().skip(1) {
        if out.len() >= max {
            break;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (Some((local, lp)), Some((remote, rp))) = (parse_addr(f[1], v6), parse_addr(f[2], v6))
        else {
            continue;
        };
        let (Ok(state), Ok(inode)) = (u8::from_str_radix(f[3], 16), f[9].parse::<u64>()) else {
            continue;
        };
        out.push(Sock {
            proto,
            local,
            local_port: lp,
            remote,
            remote_port: rp,
            state,
            inode,
        });
    }
    out
}

/// "socket:[12345]" -> 12345
#[must_use]
pub fn socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Public (routable) address?
#[must_use]
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || o[0] == 100 && (64..128).contains(&o[1]) // CGNAT
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // ULA
                || (s[0] & 0xffc0) == 0xfe80) // link-local
        }
    }
}

/// Numeric pid directories under <root>/proc, capped.
#[must_use]
pub fn list_pids(proc_dir: &Path, cap: usize) -> Vec<u32> {
    let Ok(rd) = std::fs::read_dir(proc_dir) else {
        return Vec::new();
    };
    let mut v: Vec<u32> = rd
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
        .take(cap)
        .collect();
    v.sort_unstable();
    v
}

#[must_use]
pub fn readlink_string(p: &Path) -> Option<String> {
    std::fs::read_link(p)
        .ok()
        .map(|t: PathBuf| t.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_with_spaces_and_parens_in_comm() {
        let s = b"7570 (irqbalance) core)) S 1 7570 7570 0 -1 4194560 100 0 0 0 68200 300 0 0 20 0 8 0 5000 8285424 600 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n";
        let st = parse_stat(s);
        assert!(st.is_some());
        let st = st.unwrap_or_else(|| unreachable!());
        assert_eq!(st.pid, 7570);
        assert_eq!(st.comm, "irqbalance) core)");
        assert_eq!(st.ppid, 1);
        assert_eq!(st.utime, 68200);
        assert_eq!(st.start_ticks, 5000);
        assert!(!st.is_kernel_thread());
        assert!(parse_stat(b"garbage").is_none());
        assert!(parse_stat(b"12 (x) S").is_none());
    }

    #[test]
    fn kernel_thread_flag() {
        let s = b"45 (kworker/0:1) I 2 0 0 0 -1 69238880 0 0 0 0 0 1 0 0 20 0 1 0 60 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 0 0 0 0 0 0\n";
        assert!(parse_stat(s).is_some_and(|s| s.is_kernel_thread()));
    }

    #[test]
    fn net_v4_v6_and_mapped() {
        let tcp = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: E57BA56C:635E 732BF368:01BB 01 00000000:00000000 00:00000000 00000000     0        0 991122 1 0000000000000000 20 4 30 10 -1\n   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1000 1\n bad line\n";
        let v = parse_net(tcp, "tcp", false, 100);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].local, IpAddr::V4(Ipv4Addr::new(108, 165, 123, 229)));
        assert_eq!(v[0].local_port, 25438);
        assert_eq!(v[0].remote, IpAddr::V4(Ipv4Addr::new(104, 243, 43, 115)));
        assert_eq!(v[0].remote_port, 443);
        assert_eq!(v[0].inode, 991122);
        assert_eq!(v[1].state, TCP_LISTEN);
        let tcp6 = b"hdr\n   0: 0000000000000000FFFF0000E57BA56C:A000 0000000000000000FFFF0000732BF368:0D05 01 0:0 0:0 0 0 0 42 1\n";
        let v6 = parse_net(tcp6, "tcp6", true, 100);
        assert_eq!(v6[0].remote, IpAddr::V4(Ipv4Addr::new(104, 243, 43, 115)));
        assert_eq!(v6[0].remote_port, 3333);
    }

    #[test]
    fn public_ranges() {
        assert!(is_public(IpAddr::V4(Ipv4Addr::new(104, 243, 43, 115))));
        for ip in [
            [10, 0, 0, 1],
            [172, 17, 0, 2],
            [192, 168, 1, 1],
            [127, 0, 0, 1],
            [169, 254, 1, 1],
            [100, 64, 0, 1],
        ] {
            assert!(!is_public(IpAddr::V4(Ipv4Addr::from(ip))), "{ip:?}");
        }
    }

    #[test]
    fn cgroup_container_ids() {
        let id = "a".repeat(64);
        assert_eq!(
            parse_cgroup_container(format!("0::/system.slice/docker-{id}.scope\n").as_bytes()),
            Some("a".repeat(12))
        );
        assert_eq!(
            parse_cgroup_container(format!("12:pids:/docker/{id}\n").as_bytes()),
            Some("a".repeat(12))
        );
        assert_eq!(
            parse_cgroup_container(b"0::/user.slice/session-1.scope\n"),
            None
        );
    }

    #[test]
    fn misc() {
        assert_eq!(
            parse_cmdline(b"/opt/.cache/x\0--config=/c.json\0"),
            vec!["/opt/.cache/x", "--config=/c.json"]
        );
        assert_eq!(
            parse_status_uid(b"Name:\tx\nUid:\t1000\t1000\t1000\t1000\n"),
            Some(1000)
        );
        assert_eq!(
            parse_btime(b"cpu 1 2\nbtime 1758300000\n"),
            Some(1_758_300_000)
        );
        assert_eq!(split_deleted("/tmp/x (deleted)"), ("/tmp/x".into(), true));
        assert_eq!(socket_inode("socket:[991122]"), Some(991_122));
        assert_eq!(socket_inode("pipe:[1]"), None);
    }
}
