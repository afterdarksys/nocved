//! Process starts/exits and sustained CPU by /proc polling diff.
//! Misses processes shorter than the interval (DESIGN.md section 2).

use std::collections::HashMap;
use std::time::Duration;

use nocve_proto::mask::mask_argv;
use nocve_proto::{Coverage, CoverageStatus, Event, EventData, ProcessInfo, Severity, Signal};

use super::{Ctx, MAX_EVENTS_PER_POLL, Source, cap_events, coverage};
use crate::config::ProcessConfig;
use crate::fsutil::read_prefix;
use crate::procfs::{self, CLK_TCK};

pub const MAX_TRACKED: usize = 65_536;
const FIRST_POLL_CAP: usize = 8_000;

struct Tracked {
    start_ticks: u64,
    name: String,
    exe: Option<String>,
    suspicious_exe: bool,
    last_ticks: u64,
    last_ms: i64,
    hot_since: Option<i64>,
    cpu_reported: bool,
    started_at_ms: Option<i64>,
}

pub struct ProcessSource {
    ctx: Ctx,
    cfg: ProcessConfig,
    tracked: HashMap<u32, Tracked>,
    btime: Option<i64>,
    first: bool,
    health: Coverage,
}

impl ProcessSource {
    #[must_use]
    pub fn new(ctx: Ctx, cfg: ProcessConfig) -> Self {
        Self {
            ctx,
            cfg,
            tracked: HashMap::new(),
            btime: None,
            first: true,
            health: coverage("process", CoverageStatus::Skipped, "not polled yet"),
        }
    }

    fn read_info(&self, pid: u32, st: &procfs::Stat) -> (ProcessInfo, Vec<String>) {
        let base = self.ctx.path("/proc").join(pid.to_string());
        let uid = read_prefix(&base.join("status"), 4096)
            .ok()
            .and_then(|b| procfs::parse_status_uid(&b))
            .unwrap_or(u32::MAX);
        let argv = read_prefix(&base.join("cmdline"), 16 * 1024)
            .map(|b| procfs::parse_cmdline(&b))
            .unwrap_or_default();
        let (exe, exe_deleted) = match procfs::readlink_string(&base.join("exe")) {
            Some(t) => {
                let (p, d) = procfs::split_deleted(&t);
                (Some(p), d)
            }
            None => (None, false),
        };
        let cwd = procfs::readlink_string(&base.join("cwd"));
        let container_id = read_prefix(&base.join("cgroup"), 8192)
            .ok()
            .and_then(|b| procfs::parse_cgroup_container(&b));
        let started_at_ms = self
            .btime
            .map(|b| b * 1000 + i64::try_from(st.start_ticks * 1000 / CLK_TCK).unwrap_or(0));
        (
            ProcessInfo {
                pid,
                ppid: st.ppid,
                uid,
                name: st.comm.clone(),
                exe,
                exe_deleted,
                cmdline: mask_argv(&argv),
                cwd,
                start_ticks: st.start_ticks,
                started_at_ms,
                container_id,
            },
            argv,
        )
    }
}

/// Signals for a newly seen process. `argv` is the unmasked command line; it
/// is inspected here and never stored.
#[must_use]
pub fn process_signals(
    ind: &nocve_proto::Indicators,
    info: &ProcessInfo,
    argv: &[String],
) -> Vec<Signal> {
    let mut sig = Vec::new();
    let exe = info.exe.as_deref();
    let hidden = exe.is_some_and(|e| ind.in_hidden_or_temp_dir(e));
    let allow = exe.is_some_and(|e| ind.allowlisted(e));
    let system = exe.is_some_and(|e| ind.is_system_exe(e));
    let argv0 = argv
        .first()
        .map(|a| a.rsplit('/').next().unwrap_or(a).to_owned())
        .unwrap_or_default();
    if let Some(e) = exe {
        if hidden {
            sig.push(Signal::new(
                "proc.exe_hidden_dir",
                Severity::Medium,
                format!("executable runs from a hidden or temp directory: {e}"),
            ));
        }
        let masq = ind
            .masquerade_name(&info.name)
            .or_else(|| ind.masquerade_name(&argv0));
        if let Some(m) = masq
            && !system
            && !allow
        {
            sig.push(Signal::new(
                "proc.masquerade",
                Severity::High,
                format!(
                    "name '{}' looks like kernel thread/system daemon '{m}' but exe is {e}",
                    info.name
                ),
            ));
        }
        let base = e.rsplit('/').next().unwrap_or(e).to_ascii_lowercase();
        if base.contains("xmrig") {
            sig.push(Signal::new(
                "proc.miner_cmdline",
                Severity::Critical,
                format!("miner binary name: {e}"),
            ));
        }
    }
    if info.exe_deleted {
        sig.push(Signal::new(
            "proc.exe_deleted",
            if hidden {
                Severity::High
            } else {
                Severity::Medium
            },
            "executable was deleted from disk while running",
        ));
    }
    const READERS: &[&str] = &[
        "grep",
        "egrep",
        "zgrep",
        "rg",
        "less",
        "more",
        "cat",
        "vi",
        "vim",
        "nano",
        "awk",
        "sed",
        "fd",
        "fdfind",
        "find",
        "journalctl",
        "tail",
        "head",
    ];
    if !READERS.contains(&argv0.as_str())
        && let Some(m) = ind.miner_cmdline_marker(&argv[argv.len().min(1)..])
    {
        sig.push(Signal::new(
            "proc.miner_cmdline",
            Severity::Critical,
            format!("miner command-line marker '{m}'"),
        ));
    }
    sig
}

impl Source for ProcessSource {
    fn id(&self) -> &'static str {
        "process"
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(if self.cfg.interval_secs == 0 {
            2
        } else {
            self.cfg.interval_secs
        })
    }

    fn poll(&mut self, now_ms: i64, out: &mut Vec<Event>) {
        if self.ctx.no_procfs() {
            self.health = coverage(
                "process",
                CoverageStatus::Unsupported,
                "no /proc on this platform",
            );
            return;
        }
        if self.btime.is_none() {
            self.btime = read_prefix(&self.ctx.path("/proc/stat"), 64 * 1024)
                .ok()
                .and_then(|b| procfs::parse_btime(&b));
        }
        let proc_dir = self.ctx.path("/proc");
        let pids = procfs::list_pids(&proc_dir, MAX_TRACKED);
        let mut evs = Vec::new();
        let mut seen = std::collections::HashSet::with_capacity(pids.len());
        let mut unreadable = 0usize;
        for pid in pids {
            let Some(st) = read_prefix(&proc_dir.join(pid.to_string()).join("stat"), 4096)
                .ok()
                .and_then(|b| procfs::parse_stat(&b))
            else {
                unreadable += 1;
                continue;
            };
            if st.is_kernel_thread() {
                continue;
            }
            seen.insert(pid);
            let ticks = st.cpu_ticks();
            let known = self
                .tracked
                .get(&pid)
                .is_some_and(|t| t.start_ticks == st.start_ticks);
            if !known {
                if let Some(old) = self.tracked.remove(&pid)
                    && self.cfg.emit_exits
                {
                    evs.push(exit_event(now_ms, pid, &old));
                }
                let (info, argv) = self.read_info(pid, &st);
                let signals = process_signals(&self.ctx.ind, &info, &argv);
                let suspicious_exe = signals.iter().any(|s| {
                    matches!(
                        s.rule.as_str(),
                        "proc.exe_hidden_dir" | "proc.masquerade" | "proc.exe_deleted"
                    )
                });
                if self.tracked.len() < MAX_TRACKED {
                    self.tracked.insert(
                        pid,
                        Tracked {
                            start_ticks: st.start_ticks,
                            name: info.name.clone(),
                            exe: info.exe.clone(),
                            suspicious_exe,
                            last_ticks: ticks,
                            last_ms: now_ms,
                            hot_since: None,
                            cpu_reported: false,
                            started_at_ms: info.started_at_ms,
                        },
                    );
                }
                evs.push(
                    Event::new(now_ms, "process", EventData::ProcessStart(info))
                        .with_signals(signals),
                );
                continue;
            }
            let Some(t) = self.tracked.get_mut(&pid) else {
                continue;
            };
            let dt_ms = now_ms - t.last_ms;
            if dt_ms > 0 {
                let dticks = ticks.saturating_sub(t.last_ticks);
                let pct = dticks * 1000 * 100 / CLK_TCK / u64::try_from(dt_ms).unwrap_or(1);
                let pct = u32::try_from(pct).unwrap_or(u32::MAX);
                t.last_ticks = ticks;
                t.last_ms = now_ms;
                if pct >= self.cfg.cpu_threshold_pct {
                    let since = *t.hot_since.get_or_insert(now_ms - dt_ms);
                    let window = i64::from(self.cfg.cpu_window_secs) * 1000;
                    if !t.cpu_reported && now_ms - since >= window {
                        t.cpu_reported = true;
                        let sev = if t.suspicious_exe {
                            Severity::High
                        } else {
                            Severity::Medium
                        };
                        evs.push(
                            Event::new(
                                now_ms,
                                "process",
                                EventData::ProcessCpu {
                                    pid,
                                    name: t.name.clone(),
                                    exe: t.exe.clone(),
                                    cpu_pct: pct,
                                    window_secs: self.cfg.cpu_window_secs,
                                },
                            )
                            .with_signals(vec![Signal::new(
                                "proc.high_cpu",
                                sev,
                                format!("{pct}% CPU sustained for {}s", self.cfg.cpu_window_secs),
                            )]),
                        );
                    }
                } else {
                    t.hot_since = None;
                    t.cpu_reported = false;
                }
            }
        }
        let gone: Vec<u32> = self
            .tracked
            .keys()
            .copied()
            .filter(|p| !seen.contains(p))
            .collect();
        for pid in gone {
            if let Some(old) = self.tracked.remove(&pid)
                && self.cfg.emit_exits
            {
                evs.push(exit_event(now_ms, pid, &old));
            }
        }
        let cap = if self.first {
            FIRST_POLL_CAP
        } else {
            MAX_EVENTS_PER_POLL
        };
        self.first = false;
        cap_events("process", now_ms, evs, cap, out);
        self.health = if unreadable > 0 {
            coverage(
                "process",
                CoverageStatus::Partial,
                format!("{unreadable} pid(s) unreadable (exited or denied)"),
            )
        } else {
            coverage(
                "process",
                CoverageStatus::Completed,
                format!("{} processes tracked", self.tracked.len()),
            )
        };
    }

    fn health(&self) -> Coverage {
        self.health.clone()
    }
}

fn exit_event(now_ms: i64, pid: u32, t: &Tracked) -> Event {
    Event::new(
        now_ms,
        "process",
        EventData::ProcessExit {
            pid,
            name: t.name.clone(),
            exe: t.exe.clone(),
            start_ticks: t.start_ticks,
            lifetime_ms: t.started_at_ms.map(|s| now_ms - s),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeProc;
    use std::sync::Arc;

    fn ctx(root: &std::path::Path) -> Ctx {
        Ctx {
            root: root.to_path_buf(),
            ind: Arc::new(nocve_proto::Indicators::builtin().unwrap()),
        }
    }

    fn rules(e: &Event) -> Vec<&str> {
        e.signals.iter().map(|s| s.rule.as_str()).collect()
    }

    #[test]
    fn incident_miner_flags_masquerade_hidden_and_cpu() {
        let d = tempfile::tempdir().unwrap();
        let fp = FakeProc::new(d.path());
        fp.add(
            7570,
            1,
            0,
            "irqbalance-core",
            "/opt/.cache/irqbalance-core",
            &[
                "/opt/.cache/irqbalance-core",
                "--config=/opt/.cache/config.json",
            ],
            5000,
            0,
        );
        let mut s = ProcessSource::new(ctx(d.path()), ProcessConfig::default());
        let mut out = Vec::new();
        s.poll(1_000_000, &mut out);
        assert_eq!(out.len(), 1);
        let r = rules(&out[0]);
        assert!(
            r.contains(&"proc.masquerade") && r.contains(&"proc.exe_hidden_dir"),
            "{r:?}"
        );
        assert_eq!(out[0].max_severity(), Some(Severity::High));
        // 682% CPU: 6.82 cores -> 682 ticks per second.
        for i in 1..=31 {
            fp.set_cpu(7570, 5000, 682 * 2 * i);
            s.poll(1_000_000 + 2000 * i64::try_from(i).unwrap(), &mut out);
        }
        let cpu: Vec<&Event> = out.iter().filter(|e| e.kind() == "process.cpu").collect();
        assert_eq!(cpu.len(), 1, "reported once");
        assert_eq!(cpu[0].max_severity(), Some(Severity::High));
        fp.remove(7570);
        s.poll(1_070_000, &mut out);
        assert_eq!(out.last().map(Event::kind), Some("process.exit"));
    }

    #[test]
    fn playwright_chrome_is_not_a_miner_even_at_high_cpu() {
        let d = tempfile::tempdir().unwrap();
        let fp = FakeProc::new(d.path());
        let exe = "/root/.cache/ms-playwright/chromium-1105/chrome-linux/chrome";
        fp.add(
            900,
            1,
            0,
            "chrome",
            exe,
            &[exe, "--headless", "--no-sandbox"],
            100,
            0,
        );
        let mut s = ProcessSource::new(ctx(d.path()), ProcessConfig::default());
        let mut out = Vec::new();
        s.poll(0, &mut out);
        for i in 1..=31i64 {
            fp.set_cpu(900, 100, u64::try_from(190 * i).unwrap());
            s.poll(2000 * i, &mut out);
        }
        for e in &out {
            for sgn in &e.signals {
                assert!(
                    !sgn.rule.contains("miner")
                        && sgn.rule != "proc.masquerade"
                        && sgn.rule != "proc.exe_hidden_dir",
                    "{sgn:?}"
                );
                assert!(sgn.severity < Severity::High, "{sgn:?}");
            }
        }
        assert!(
            out.iter().any(|e| e.kind() == "process.cpu"),
            "high CPU still reported (medium)"
        );
    }

    #[test]
    fn system_daemon_and_kernel_threads_quiet() {
        let d = tempfile::tempdir().unwrap();
        let fp = FakeProc::new(d.path());
        fp.add(
            500,
            1,
            0,
            "systemd-journal",
            "/usr/lib/systemd/systemd-journald",
            &["/lib/systemd/systemd-journald"],
            10,
            0,
        );
        fp.add_kthread(45, "kworker/0:1");
        let mut s = ProcessSource::new(ctx(d.path()), ProcessConfig::default());
        let mut out = Vec::new();
        s.poll(0, &mut out);
        assert_eq!(out.len(), 1);
        assert!(out[0].signals.is_empty());
    }

    #[test]
    fn deleted_exe_in_tmp_and_miner_args() {
        let d = tempfile::tempdir().unwrap();
        let fp = FakeProc::new(d.path());
        fp.add(
            77,
            1,
            1000,
            "x",
            "/tmp/.x/x (deleted)",
            &[
                "./x",
                "-o",
                "stratum+tcp://1.2.3.4:3333",
                "--donate-level=1",
                "--pass=secretpw",
            ],
            10,
            0,
        );
        fp.add(
            78,
            1,
            0,
            "grep",
            "/usr/bin/grep",
            &["grep", "-r", "stratum+tcp://", "/var/log"],
            10,
            0,
        );
        let mut s = ProcessSource::new(ctx(d.path()), ProcessConfig::default());
        let mut out = Vec::new();
        s.poll(0, &mut out);
        let x = out
            .iter()
            .find(|e| matches!(&e.data, EventData::ProcessStart(p) if p.pid == 77))
            .unwrap();
        let r = rules(x);
        assert!(
            r.contains(&"proc.exe_deleted") && r.contains(&"proc.miner_cmdline"),
            "{r:?}"
        );
        let json = serde_json::to_string(x).unwrap();
        assert!(!json.contains("secretpw"), "cmdline must be masked: {json}");
        let g = out
            .iter()
            .find(|e| matches!(&e.data, EventData::ProcessStart(p) if p.pid == 78))
            .unwrap();
        assert!(
            g.signals.is_empty(),
            "grep for a miner marker is not a miner"
        );
    }

    #[test]
    fn pid_reuse_is_exit_plus_start() {
        let d = tempfile::tempdir().unwrap();
        let fp = FakeProc::new(d.path());
        fp.add(10, 1, 0, "a", "/usr/bin/a", &["a"], 10, 0);
        let mut s = ProcessSource::new(ctx(d.path()), ProcessConfig::default());
        let mut out = Vec::new();
        s.poll(0, &mut out);
        fp.add(10, 1, 0, "b", "/usr/bin/b", &["b"], 20, 0);
        s.poll(2000, &mut out);
        let kinds: Vec<&str> = out.iter().map(Event::kind).collect();
        assert_eq!(
            kinds,
            vec!["process.start", "process.exit", "process.start"]
        );
    }
}
