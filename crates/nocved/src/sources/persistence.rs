//! Persistence-location watch: stat + SHA-256 (never content) of cron,
//! anacron, at spools, systemd unit dirs (including per-user units and
//! linger), ld.so.preload and ld.so.conf.d, authorized_keys, sshd config,
//! account files, sudoers, PAM, shell init, D-Bus system policy, polkit,
//! udev, tmpfiles and modprobe; lstat of shell history files for `-> /dev/null`.
//!
//! Threats: a rooted host can hide paths from this walk or forge inode
//! timestamps. The walk reports partial coverage when an entry cap, a nested
//! directory cap, or an unreadable directory drops paths. Content is hashed
//! with `O_NOFOLLOW`, so a symlink is recorded as a link and not followed.
//! File bytes are never emitted. Vendor unit trees, `/run`, and cgroupfs are
//! outside this source: aftercve snapshots service units, and a live cgroup
//! tree is not a 30-second hash set.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use nocve_proto::{
    Coverage, CoverageStatus, Event, EventData, FileDigest, PersistEntry, Severity, Signal,
};
use sha2::{Digest, Sha256};

use super::{Ctx, MAX_EVENTS_PER_POLL, Source, cap_events, coverage};
use crate::config::SourceToggle;
use crate::fsutil::open_nofollow;

pub const MAX_HASH_BYTES: u64 = 1024 * 1024;
const MAX_ENTRIES: usize = 8192;
const BASELINE_CAP: usize = 512;
const MAX_HOMES: usize = 200;

const FILES: &[(&str, &str)] = &[
    ("/etc/crontab", "cron"),
    ("/etc/anacrontab", "cron"),
    ("/etc/ld.so.preload", "ld_preload"),
    ("/etc/ld.so.conf", "ld_preload"),
    ("/etc/passwd", "accounts"),
    ("/etc/shadow", "accounts"),
    ("/etc/group", "accounts"),
    ("/etc/gshadow", "accounts"),
    ("/etc/sudoers", "sudo"),
    ("/etc/rc.local", "shell_init"),
    ("/etc/environment", "shell_init"),
    ("/etc/profile", "shell_init"),
    ("/etc/bash.bashrc", "shell_init"),
    ("/etc/zsh/zshenv", "shell_init"),
    ("/etc/zsh/zshrc", "shell_init"),
    ("/etc/ssh/sshd_config", "sshd"),
    ("/root/.ssh/authorized_keys", "ssh_keys"),
    ("/root/.ssh/authorized_keys2", "ssh_keys"),
    ("/root/.bashrc", "shell_init"),
    ("/root/.profile", "shell_init"),
    ("/root/.bash_profile", "shell_init"),
];

const DIRS: &[(&str, &str)] = &[
    ("/etc/cron.d", "cron"),
    ("/etc/cron.hourly", "cron"),
    ("/etc/cron.daily", "cron"),
    ("/etc/cron.weekly", "cron"),
    ("/etc/cron.monthly", "cron"),
    ("/var/spool/cron/crontabs", "cron"),
    ("/var/spool/cron", "cron"),
    ("/var/spool/at", "at"),
    ("/var/spool/cron/atjobs", "at"),
    ("/etc/systemd/system", "systemd"),
    ("/usr/local/lib/systemd/system", "systemd"),
    ("/etc/systemd/user", "systemd"),
    ("/root/.config/systemd/user", "systemd"),
    ("/var/lib/systemd/linger", "systemd"),
    ("/etc/ssh/sshd_config.d", "sshd"),
    ("/etc/sudoers.d", "sudo"),
    ("/etc/profile.d", "shell_init"),
    ("/etc/pam.d", "pam"),
    ("/etc/update-motd.d", "shell_init"),
    ("/etc/ld.so.conf.d", "ld_preload"),
    ("/etc/dbus-1/system.d", "dbus"),
    ("/etc/dbus-1/system-services", "dbus"),
    ("/etc/polkit-1/rules.d", "polkit"),
    ("/etc/polkit-1/localauthority", "polkit"),
    ("/etc/udev/rules.d", "udev"),
    ("/etc/tmpfiles.d", "tmpfiles"),
    ("/etc/modprobe.d", "modprobe"),
    ("/etc/modules-load.d", "modprobe"),
];

const HISTORY_FILES: &[&str] = &[
    ".bash_history",
    ".zsh_history",
    ".history",
    ".sh_history",
    ".ash_history",
    ".python_history",
    ".mysql_history",
    ".psql_history",
];

fn severity_for(category: &str) -> Severity {
    match category {
        "ld_preload" | "ssh_keys" | "sudo" | "accounts" | "sshd" | "pam" | "dbus" | "polkit"
        | "udev" | "modprobe" => Severity::High,
        _ => Severity::Medium,
    }
}

struct TargetWalk {
    items: Vec<(String, String)>,
    hit_entry_cap: bool,
    hit_child_cap: bool,
    unreadable: bool,
}

impl TargetWalk {
    fn push(&mut self, path: String, cat: &str) -> bool {
        if self.items.len() >= MAX_ENTRIES {
            self.hit_entry_cap = true;
            false
        } else {
            self.items.push((path, cat.to_owned()));
            true
        }
    }

    fn capped(&self) -> bool {
        self.hit_entry_cap || self.hit_child_cap || self.unreadable
    }
}

pub struct PersistenceSource {
    ctx: Ctx,
    cfg: SourceToggle,
    known: Option<BTreeMap<String, (String, FileDigest)>>,
    devnull_reported: HashSet<(String, u64)>,
    health: Coverage,
}

impl PersistenceSource {
    #[must_use]
    pub fn new(ctx: Ctx, cfg: SourceToggle) -> Self {
        Self {
            ctx,
            cfg,
            known: None,
            devnull_reported: HashSet::new(),
            health: coverage("persistence", CoverageStatus::Skipped, "not polled yet"),
        }
    }

    fn homes(&self) -> Vec<(String, PathBuf)> {
        let mut v = vec![("/root".to_owned(), self.ctx.path("/root"))];
        if let Ok(rd) = std::fs::read_dir(self.ctx.path("/home")) {
            for e in rd.filter_map(Result::ok).take(MAX_HOMES) {
                let name = e.file_name().to_string_lossy().into_owned();
                v.push((format!("/home/{name}"), e.path()));
            }
        }
        v
    }

    fn targets(&self) -> TargetWalk {
        let mut walk = TargetWalk {
            items: FILES
                .iter()
                .map(|(p, c)| ((*p).to_owned(), (*c).to_owned()))
                .collect(),
            hit_entry_cap: false,
            hit_child_cap: false,
            unreadable: false,
        };
        for (shown, _) in self.homes().into_iter().skip(1) {
            if !walk.push(format!("{shown}/.ssh/authorized_keys"), "ssh_keys") {
                break;
            }
            if !walk.push(format!("{shown}/.ssh/authorized_keys2"), "ssh_keys") {
                break;
            }
            self.add_dir(
                &mut walk,
                &format!("{shown}/.config/systemd/user"),
                "systemd",
            );
        }
        for (dir, cat) in DIRS {
            self.add_dir(&mut walk, dir, cat);
        }
        walk
    }

    /// One directory level, plus one nested level for systemd drop-ins and
    /// spool directories. Missing directories are normal; any other read
    /// error is a coverage gap.
    fn add_dir(&self, walk: &mut TargetWalk, dir: &str, cat: &str) {
        if walk.hit_entry_cap {
            return;
        }
        let rd = match std::fs::read_dir(self.ctx.path(dir)) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => {
                walk.unreadable = true;
                return;
            }
        };
        let mut names: Vec<String> = rd
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for n in names {
            if walk.hit_entry_cap {
                return;
            }
            let p = format!("{dir}/{n}");
            if let Ok(m) = std::fs::symlink_metadata(self.ctx.path(&p))
                && m.is_dir()
            {
                match std::fs::read_dir(self.ctx.path(&p)) {
                    Ok(sub) => {
                        let mut children = Vec::new();
                        for e in sub.filter_map(Result::ok) {
                            children.push(e.file_name().to_string_lossy().into_owned());
                            if children.len() > 1024 {
                                walk.hit_child_cap = true;
                                break;
                            }
                        }
                        children.truncate(1024);
                        children.sort();
                        for c in children {
                            if !walk.push(format!("{p}/{c}"), cat) {
                                return;
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => walk.unreadable = true,
                }
            }
            if !walk.push(p, cat) {
                return;
            }
        }
    }

    fn digest(&self, shown: &str, prev: Option<&FileDigest>) -> Option<FileDigest> {
        let path = self.ctx.path(shown);
        let m = std::fs::symlink_metadata(&path).ok()?;
        let ft = m.file_type();
        let kind = if ft.is_symlink() {
            "symlink"
        } else if ft.is_dir() {
            "dir"
        } else if ft.is_file() {
            "file"
        } else {
            "other"
        };
        let link_target = if ft.is_symlink() {
            std::fs::read_link(&path)
                .ok()
                .map(|t| t.to_string_lossy().into_owned())
        } else {
            None
        };
        let unchanged = prev.is_some_and(|p| {
            p.size == m.size() && p.mtime == m.mtime() && p.ctime == m.ctime() && p.inode == m.ino()
        });
        let sha256 = if !ft.is_file() {
            None
        } else if unchanged {
            prev.and_then(|p| p.sha256.clone())
        } else if m.size() <= MAX_HASH_BYTES {
            hash_file(&path)
        } else {
            None
        };
        Some(FileDigest {
            kind: kind.into(),
            size: m.size(),
            mode: m.mode(),
            uid: m.uid(),
            mtime: m.mtime(),
            ctime: m.ctime(),
            inode: m.ino(),
            sha256,
            link_target,
        })
    }

    fn history_devnull(&mut self, now_ms: i64, evs: &mut Vec<Event>) {
        for (shown_home, home) in self.homes() {
            for h in HISTORY_FILES {
                let p = home.join(h);
                let Ok(m) = std::fs::symlink_metadata(&p) else {
                    continue;
                };
                let target = if m.file_type().is_symlink() {
                    std::fs::read_link(&p)
                        .ok()
                        .map(|t| t.to_string_lossy().into_owned())
                } else if m.file_type().is_char_device() {
                    Some("<character device>".to_owned())
                } else {
                    None
                };
                let Some(target) = target else { continue };
                if target != "/dev/null" && target != "<character device>" {
                    continue;
                }
                let shown = format!("{shown_home}/{h}");
                if !self.devnull_reported.insert((shown.clone(), m.ino())) {
                    continue;
                }
                evs.push(
                    Event::new(
                        now_ms,
                        "persistence",
                        EventData::HistoryDevnull {
                            path: shown.clone(),
                            target,
                        },
                    )
                    .with_signals(vec![Signal::new(
                        "history.devnull",
                        Severity::High,
                        format!("{shown} discards shell history (anti-forensics)"),
                    )]),
                );
            }
        }
    }
}

fn hash_file(path: &Path) -> Option<String> {
    let f = open_nofollow(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 16 * 1024];
    let mut r = f.take(MAX_HASH_BYTES);
    loop {
        let n = r.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex::encode(h.finalize()))
}

impl Source for PersistenceSource {
    fn id(&self) -> &'static str {
        "persistence"
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(if self.cfg.interval_secs == 0 {
            30
        } else {
            self.cfg.interval_secs
        })
    }

    fn poll(&mut self, now_ms: i64, out: &mut Vec<Event>) {
        let mut evs = Vec::new();
        self.history_devnull(now_ms, &mut evs);
        let mut now_map = BTreeMap::new();
        let prev_map = self.known.take();
        let walk = self.targets();
        let capped = walk.capped();
        for (shown, cat) in walk.items {
            let prev = prev_map
                .as_ref()
                .and_then(|m| m.get(&shown))
                .map(|(_, d)| d);
            if let Some(d) = self.digest(&shown, prev) {
                now_map.insert(shown, (cat, d));
            }
        }
        match &prev_map {
            None => {
                let entries: Vec<PersistEntry> = now_map
                    .iter()
                    .take(BASELINE_CAP)
                    .map(|(p, (c, d))| PersistEntry {
                        path: p.clone(),
                        category: c.clone(),
                        digest: d.clone(),
                    })
                    .collect();
                let mut sig = Vec::new();
                if now_map
                    .get("/etc/ld.so.preload")
                    .is_some_and(|(_, d)| d.size > 0)
                {
                    sig.push(Signal::new(
                        "persist.ld_preload_present",
                        Severity::High,
                        "/etc/ld.so.preload exists and is not empty",
                    ));
                }
                evs.push(
                    Event::new(
                        now_ms,
                        "persistence",
                        EventData::PersistenceBaseline {
                            entries,
                            truncated: now_map.len() > BASELINE_CAP,
                        },
                    )
                    .with_signals(sig),
                );
            }
            Some(prev) => {
                for (p, (cat, d)) in &now_map {
                    let change = match prev.get(p) {
                        None => "added",
                        Some((_, old))
                            if old.sha256 != d.sha256
                                || old.kind != d.kind
                                || old.link_target != d.link_target
                                || old.mode != d.mode
                                || old.uid != d.uid =>
                        {
                            "modified"
                        }
                        Some(_) => continue,
                    };
                    let sev = severity_for(cat);
                    evs.push(
                        Event::new(
                            now_ms,
                            "persistence",
                            EventData::PersistenceChange {
                                path: p.clone(),
                                category: cat.clone(),
                                change: change.into(),
                                before: prev.get(p).map(|(_, o)| o.clone()),
                                after: Some(d.clone()),
                            },
                        )
                        .with_signals(vec![Signal::new(
                            "persist.changed",
                            sev,
                            format!("{cat} location {change}: {p}"),
                        )]),
                    );
                }
                for (p, (cat, old)) in prev {
                    if !now_map.contains_key(p) {
                        evs.push(
                            Event::new(
                                now_ms,
                                "persistence",
                                EventData::PersistenceChange {
                                    path: p.clone(),
                                    category: cat.clone(),
                                    change: "removed".into(),
                                    before: Some(old.clone()),
                                    after: None,
                                },
                            )
                            .with_signals(vec![Signal::new(
                                "persist.changed",
                                severity_for(cat),
                                format!("{cat} location removed: {p}"),
                            )]),
                        );
                    }
                }
            }
        }
        let n = now_map.len();
        self.known = Some(now_map);
        cap_events("persistence", now_ms, evs, MAX_EVENTS_PER_POLL, out);
        self.health = if n == 0 {
            coverage(
                "persistence",
                CoverageStatus::Failed,
                "no persistence locations readable",
            )
        } else if capped {
            coverage(
                "persistence",
                CoverageStatus::Partial,
                format!("{n} locations watched; directory walk hit a cap or unreadable directory"),
            )
        } else {
            coverage(
                "persistence",
                CoverageStatus::Completed,
                format!("{n} locations watched"),
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
    use std::sync::Arc;

    fn w(root: &Path, p: &str, s: &str) {
        let full = root.join(p.trim_start_matches('/'));
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, s).unwrap();
    }

    fn src(root: &Path) -> PersistenceSource {
        PersistenceSource::new(
            Ctx {
                root: root.to_path_buf(),
                ind: Arc::new(nocve_proto::Indicators::builtin().unwrap()),
            },
            SourceToggle::default(),
        )
    }

    #[test]
    fn baseline_then_changes_hash_only() {
        let d = tempfile::tempdir().unwrap();
        w(
            d.path(),
            "/etc/shadow",
            "root:$6$supersecrethash:19000:0:99999:7:::\n",
        );
        w(
            d.path(),
            "/root/.ssh/authorized_keys",
            "ssh-ed25519 AAAA ryan\n",
        );
        w(d.path(), "/etc/cron.d/e2scrub", "30 3 * * 0 root true\n");
        let mut s = src(d.path());
        let mut out = Vec::new();
        s.poll(0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind(), "persistence.baseline");
        let json = serde_json::to_string(&out).unwrap();
        assert!(
            !json.contains("supersecrethash") && !json.contains("AAAA"),
            "contents never shipped"
        );
        s.poll(30_000, &mut out);
        assert_eq!(out.len(), 1, "no change, no event");
        w(
            d.path(),
            "/root/.ssh/authorized_keys",
            "ssh-ed25519 AAAA ryan\nssh-rsa BBBB attacker\n",
        );
        w(
            d.path(),
            "/etc/cron.d/miner",
            "* * * * * root /opt/.cache/x\n",
        );
        std::fs::remove_file(d.path().join("etc/cron.d/e2scrub")).unwrap();
        s.poll(60_000, &mut out);
        let changes: Vec<(String, String, Severity)> = out[1..]
            .iter()
            .map(|e| match &e.data {
                EventData::PersistenceChange { path, change, .. } => {
                    (path.clone(), change.clone(), e.max_severity().unwrap())
                }
                _ => panic!(),
            })
            .collect();
        assert!(
            changes.contains(&(
                "/root/.ssh/authorized_keys".into(),
                "modified".into(),
                Severity::High
            )),
            "{changes:?}"
        );
        assert!(changes.contains(&("/etc/cron.d/miner".into(), "added".into(), Severity::Medium)));
        assert!(changes.contains(&(
            "/etc/cron.d/e2scrub".into(),
            "removed".into(),
            Severity::Medium
        )));
    }

    #[test]
    fn history_to_dev_null_flagged_once() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("root")).unwrap();
        std::fs::create_dir_all(d.path().join("home/ryan")).unwrap();
        std::fs::write(d.path().join("home/ryan/.bash_history"), "ls\n").unwrap();
        let mut s = src(d.path());
        let mut out = Vec::new();
        s.poll(0, &mut out);
        assert!(out.iter().all(|e| e.kind() != "history.devnull"));
        std::os::unix::fs::symlink("/dev/null", d.path().join("root/.bash_history")).unwrap();
        s.poll(30_000, &mut out);
        s.poll(60_000, &mut out);
        let dn: Vec<&Event> = out
            .iter()
            .filter(|e| e.kind() == "history.devnull")
            .collect();
        assert_eq!(dn.len(), 1);
        assert_eq!(dn[0].max_severity(), Some(Severity::High));
    }

    #[test]
    fn ld_preload_present_at_baseline() {
        let d = tempfile::tempdir().unwrap();
        w(d.path(), "/etc/ld.so.preload", "/usr/lib/libhide.so\n");
        let mut s = src(d.path());
        let mut out = Vec::new();
        s.poll(0, &mut out);
        assert_eq!(out[0].signals[0].rule, "persist.ld_preload_present");
    }

    #[test]
    fn added_policy_paths_are_hashed_and_removal_keeps_category_severity() {
        let d = tempfile::tempdir().unwrap();
        w(d.path(), "/etc/ld.so.preload", "/usr/lib/libhide.so\n");
        w(d.path(), "/etc/ld.so.conf.d/libc.conf", "libc6\n");
        w(
            d.path(),
            "/etc/polkit-1/rules.d/49-evil.rules",
            "polkit.addRule(function(){return polkit.Result.YES;});\n",
        );
        w(d.path(), "/var/spool/at/a0000100", "echo staged\n");
        w(
            d.path(),
            "/etc/dbus-1/system.d/evil.conf",
            "<busconfig></busconfig>\n",
        );
        w(
            d.path(),
            "/home/ryan/.config/systemd/user/stay.service",
            "[Service]\n",
        );
        let mut s = src(d.path());
        let mut out = Vec::new();
        s.poll(0, &mut out);
        let json = serde_json::to_string(&out).unwrap();
        assert!(!json.contains("polkit.addRule") && !json.contains("echo staged"));
        assert!(json.contains("/etc/ld.so.conf.d/libc.conf"));
        assert!(json.contains("/var/spool/at/a0000100"));
        assert!(json.contains("/home/ryan/.config/systemd/user/stay.service"));
        std::fs::remove_file(d.path().join("etc/ld.so.preload")).unwrap();
        w(
            d.path(),
            "/etc/udev/rules.d/99-evil.rules",
            "ACTION==\"add\", RUN+=\"/tmp/x\"\n",
        );
        s.poll(30_000, &mut out);
        let changes: Vec<(String, String, Severity)> = out
            .iter()
            .filter_map(|e| match &e.data {
                EventData::PersistenceChange { path, change, .. } => {
                    Some((path.clone(), change.clone(), e.max_severity().unwrap()))
                }
                _ => None,
            })
            .collect();
        assert!(changes.contains(&(
            "/etc/ld.so.preload".into(),
            "removed".into(),
            Severity::High
        )));
        assert!(changes.contains(&(
            "/etc/udev/rules.d/99-evil.rules".into(),
            "added".into(),
            Severity::High
        )));
        assert_eq!(s.health().status, CoverageStatus::Completed);
    }

    #[test]
    fn nested_directory_over_1024_is_partial() {
        let d = tempfile::tempdir().unwrap();
        let nested = d.path().join("etc/systemd/system/foo.service.d");
        std::fs::create_dir_all(&nested).unwrap();
        for i in 0..1025 {
            std::fs::write(nested.join(format!("drop-{i:04}.conf")), "x\n").unwrap();
        }
        let mut s = src(d.path());
        let mut out = Vec::new();
        s.poll(0, &mut out);
        assert_eq!(s.health().status, CoverageStatus::Partial);
        let EventData::PersistenceBaseline { entries, .. } = &out[0].data else {
            panic!("baseline");
        };
        let watched = s.known.as_ref().unwrap().len();
        let nested_files = s
            .known
            .as_ref()
            .unwrap()
            .keys()
            .filter(|p| p.contains("foo.service.d/drop-"))
            .count();
        assert_eq!(
            nested_files,
            1024,
            "watched {watched}, baseline {}",
            entries.len()
        );
    }
}
