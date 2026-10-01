//! Optional read-only feed of chained envelopes for a local consumer
//! (cveguard's `afterguard`, which runs as its own unprivileged user and cannot
//! read the 0700 spool). Off by default.
//!
//! Every envelope line appended to `spool.jsonl` is also appended, unchanged,
//! to `<dir>/events.jsonl`. The directory is 0750 and the file 0640, both with
//! the configured group, so the group can read and nobody but nocved can
//! write. The file is bounded: when the next line would exceed `max_bytes` it
//! is renamed to `events.jsonl.1` (replacing the older `.1`) and a fresh file
//! (a new inode) takes its place, which is how readers that track
//! `(dev, ino)` notice the rotation. Exactly one old generation is kept.
//!
//! Rotation contract (DESIGN.md section 21): `.1` is never truncated and is
//! never replaced sooner than `ROTATE_HOLD` after it was created, so a reader
//! that drains `.1` within that window loses nothing even when a burst fills
//! the live file twice. During the hold the live file may grow to
//! `2 * max_bytes`; past that, lines are skipped and counted (`skipped_burst`)
//! rather than silently rotating an undrained generation away.
//!
//! Compact stand-ins (DESIGN.md section 21): the consumer rejects lines over
//! 8192 bytes, and a `persistence.baseline` envelope is often 12-13 KB. So an
//! envelope line that does not fit is written to the FEED ONLY as a compact
//! stand-in: the same `v`/`host`/`epoch`/`seq`/`prev`/`mac`, with `payload`
//! replaced by a bounded summary carrying `"feed_compact":true`, the original
//! payload's length and SHA-256, and (for `persistence.baseline`) per-location
//! counts and digests. One feed line per seq, so the reader sees no gap. The
//! spool, the chain and the MAC are untouched; the stand-in's `mac` is the
//! original's and does NOT verify over the stand-in payload. Only a line that
//! cannot be compacted (not an envelope) is skipped and counted.
//!
//! Threats: envelopes carry the per-event MAC, never the MAC key or the host
//! token; anything readable here is already shipped off-host. The feed is
//! best effort: a feed write error never affects the chain or the spool.
//! It does NOT authenticate the reader, and a reader cannot verify envelopes
//! without the key (DESIGN.md section 21): feed lines, compact or not, are
//! unverified hints to the reader, never evidence.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const FEED_FILE: &str = "events.jsonl";
pub const MAX_FEED_LINE: usize = 8192;
/// Minimum age of `.1` before a rotation may replace it.
pub const ROTATE_HOLD: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FeedConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "d_dir")]
    pub dir: PathBuf,
    /// Group that may read the feed: a name from `/etc/group` or a numeric
    /// gid. nocved must be a member (systemd `SupplementaryGroups=`), since
    /// it holds no CAP_CHOWN. `None`: the directory's existing group.
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default = "d_max")]
    pub max_bytes: u64,
}

fn d_dir() -> PathBuf {
    PathBuf::from("/var/lib/nocved/cveguard-feed")
}
fn d_max() -> u64 {
    4 * 1024 * 1024
}

impl Default for FeedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: d_dir(),
            group: None,
            max_bytes: d_max(),
        }
    }
}

impl FeedConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if !self.dir.is_absolute() {
            return Err("feed.dir must be absolute".into());
        }
        if !(64 * 1024..=256 * 1024 * 1024).contains(&self.max_bytes) {
            return Err("feed.max_bytes must be 64 KiB..256 MiB".into());
        }
        if let Some(g) = &self.group
            && (g.is_empty()
                || g.len() > 32
                || !g
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')))
        {
            return Err("feed.group must be a group name or gid".into());
        }
        Ok(())
    }
}

/// Resolves a group name (from `<root>/etc/group`) or numeric gid.
pub fn resolve_gid(root: &Path, group: &str) -> Result<u32, String> {
    if group.bytes().all(|b| b.is_ascii_digit()) {
        return group.parse().map_err(|_| format!("bad gid {group}"));
    }
    let text = crate::fsutil::read_bounded(&root.join("etc/group"), 1024 * 1024)
        .map_err(|e| format!("/etc/group: {e}"))?;
    String::from_utf8_lossy(&text)
        .lines()
        .find_map(|l| {
            let mut f = l.split(':');
            (f.next() == Some(group))
                .then(|| f.nth(1).and_then(|g| g.parse().ok()))
                .flatten()
        })
        .ok_or_else(|| format!("group {group} not found in /etc/group"))
}

pub struct Feed {
    dir: PathBuf,
    gid: Option<u32>,
    max_bytes: u64,
    file: File,
    ino: u64,
    size: u64,
    /// When `.1` was last (re)created; `None` if this process has not seen one.
    rotated_at: Option<Instant>,
    hold: Duration,
    /// Lines over `MAX_FEED_LINE` that could not be compacted, skipped.
    pub skipped_long: u64,
    /// Lines over `MAX_FEED_LINE` written as a compact stand-in.
    pub compacted: u64,
    /// Lines skipped because the live file hit `2 * max_bytes` while `.1`
    /// was still inside its hold window.
    pub skipped_burst: u64,
}

impl Feed {
    /// Creates (or adopts) the feed directory and file with the required
    /// modes and group.
    pub fn open(cfg: &FeedConfig, gid: Option<u32>) -> Result<Self, String> {
        let dir = cfg.dir.clone();
        let shown = dir.display().to_string();
        match std::fs::symlink_metadata(&dir) {
            Ok(m) if !m.is_dir() => return Err(format!("{shown}: not a directory")),
            Ok(_) => {}
            Err(_) => std::fs::create_dir_all(&dir).map_err(|e| format!("{shown}: {e}"))?,
        }
        if let Some(g) = gid {
            std::os::unix::fs::chown(&dir, None, Some(g))
                .map_err(|e| format!("{shown}: chgrp: {e}"))?;
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750))
            .map_err(|e| format!("{shown}: {e}"))?;
        let (file, ino, size) = open_file(&dir.join(FEED_FILE), gid, false)?;
        // A `.1` left by a previous run may be seconds old and still being
        // drained: treat it as just rotated.
        let rotated_at = std::fs::symlink_metadata(dir.join(format!("{FEED_FILE}.1")))
            .is_ok()
            .then(Instant::now);
        Ok(Self {
            dir,
            gid,
            max_bytes: cfg.max_bytes,
            file,
            ino,
            size,
            rotated_at,
            hold: ROTATE_HOLD,
            skipped_long: 0,
            compacted: 0,
            skipped_burst: 0,
        })
    }

    /// Lines skipped so far: `(over 8192 bytes, during a rotation hold)`.
    #[must_use]
    pub fn skipped(&self) -> (u64, u64) {
        (self.skipped_long, self.skipped_burst)
    }

    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.dir.join(FEED_FILE)
    }

    /// Appends one envelope line (no trailing newline in `line`). A line
    /// over `MAX_FEED_LINE` is replaced by its compact stand-in.
    pub fn append(&mut self, line: &str) -> Result<(), String> {
        let compact;
        let line = if line.len() < MAX_FEED_LINE {
            line
        } else if let Some(c) = compact_line(line) {
            self.compacted += 1;
            compact = c;
            compact.as_str()
        } else {
            self.skipped_long += 1;
            return Ok(());
        };
        let path = self.path();
        // Replaced or removed under us: start a fresh file.
        let same =
            std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file() && m.ino() == self.ino);
        let need = line.len() as u64 + 1;
        if !same {
            self.rotate(false)?;
        } else if self.size + need > self.max_bytes {
            let held = self.rotated_at.is_some_and(|t| t.elapsed() < self.hold);
            if !held {
                self.rotate(true)?;
            } else if self.size + need > self.max_bytes.saturating_mul(2) {
                self.skipped_burst += 1;
                return Ok(());
            }
        }
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        self.file
            .write_all(&buf)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        self.size += buf.len() as u64;
        Ok(())
    }

    /// Moves the current file to `events.jsonl.1` (if it is ours) and puts a
    /// fresh, empty file in place by rename: a new inode.
    fn rotate(&mut self, keep_old: bool) -> Result<(), String> {
        let path = self.path();
        if keep_old {
            std::fs::rename(&path, self.dir.join(format!("{FEED_FILE}.1")))
                .map_err(|e| format!("{}: {e}", path.display()))?;
            self.rotated_at = Some(Instant::now());
        }
        let (file, ino, size) = open_file(&path, self.gid, true)?;
        self.file = file;
        self.ino = ino;
        self.size = size;
        Ok(())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The feed-only stand-in for an envelope line too long for the feed, or
/// `None` if `line` is not an envelope. The result plus its newline always
/// fits `MAX_FEED_LINE`: what does not fit is folded into digests and counts.
#[must_use]
pub fn compact_line(line: &str) -> Option<String> {
    let env: nocve_proto::Envelope = serde_json::from_str(line).ok()?;
    let orig: Value = serde_json::from_str(&env.payload).ok()?;
    let orig = orig.as_object()?;
    let kind = orig.get("kind").and_then(Value::as_str).unwrap_or("");
    let signals: Vec<Value> = orig
        .get("signals")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|s| json!({ "rule": s.get("rule"), "severity": s.get("severity") }))
                .collect()
        })
        .unwrap_or_default();
    let mut head = serde_json::Map::new();
    head.insert(
        "observed_at_ms".into(),
        orig.get("observed_at_ms").cloned().unwrap_or(Value::Null),
    );
    head.insert(
        "source".into(),
        orig.get("source").cloned().unwrap_or(Value::Null),
    );
    head.insert("feed_compact".into(), Value::Bool(true));
    head.insert("orig_bytes".into(), env.payload.len().into());
    head.insert(
        "orig_sha256".into(),
        sha256_hex(env.payload.as_bytes()).into(),
    );
    head.insert("signals_count".into(), signals.len().into());
    // Groups of baseline entries by (parent directory, category), in order.
    let mut groups: Vec<(String, String, Vec<nocve_proto::PersistEntry>)> = Vec::new();
    if kind == "persistence.baseline" {
        head.insert("kind".into(), kind.into());
        head.insert(
            "truncated".into(),
            orig.get("truncated").cloned().unwrap_or(Value::Null),
        );
        let entries: Vec<nocve_proto::PersistEntry> =
            serde_json::from_value(orig.get("entries")?.clone()).ok()?;
        head.insert("count".into(), entries.len().into());
        let mut by: std::collections::BTreeMap<(String, String), Vec<nocve_proto::PersistEntry>> =
            std::collections::BTreeMap::new();
        for e in entries {
            let dir = Path::new(&e.path)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            by.entry((dir, e.category.clone())).or_default().push(e);
        }
        groups = by.into_iter().map(|((d, c), v)| (d, c, v)).collect();
    } else {
        // Not a kind the reader parses from a stand-in: a reader that knew
        // the original kind must not mistake the summary for the event.
        head.insert("kind".into(), "feed.compact".into());
        head.insert("orig_kind".into(), kind.into());
    }
    // SHA-256 of the JSON array of `entries`, byte for byte as the original
    // payload would encode that subset.
    let digest = |entries: &mut dyn Iterator<Item = &nocve_proto::PersistEntry>| {
        let mut h = Sha256::new();
        h.update(b"[");
        for (i, e) in entries.enumerate() {
            if i > 0 {
                h.update(b",");
            }
            h.update(serde_json::to_vec(e).ok()?);
        }
        h.update(b"]");
        Some(hex::encode(h.finalize()))
    };
    let mut locations = Vec::with_capacity(groups.len());
    for (dir, cat, entries) in &groups {
        locations.push(json!({
            "path": dir,
            "category": cat,
            "count": entries.len(),
            "sha256": digest(&mut entries.iter())?,
        }));
    }
    // The stand-in line with the first `kept` locations listed and the rest
    // folded into one digest + count, or `None` if it does not fit.
    let build = |kept: usize, with_signals: bool| -> Option<String> {
        let mut p = head.clone();
        if !groups.is_empty() {
            p.insert("locations".into(), Value::Array(locations[..kept].to_vec()));
            if kept < groups.len() {
                let rest = &groups[kept..];
                p.insert(
                    "rest".into(),
                    json!({
                        "locations": rest.len(),
                        "count": rest.iter().map(|g| g.2.len()).sum::<usize>(),
                        "sha256": digest(&mut rest.iter().flat_map(|g| &g.2))?,
                    }),
                );
            }
        }
        if with_signals {
            p.insert("signals".into(), Value::Array(signals.clone()));
        }
        let mut env = env.clone();
        env.payload = serde_json::to_string(&p).ok()?;
        serde_json::to_string(&env)
            .ok()
            .filter(|l| l.len() < MAX_FEED_LINE)
    };
    // Listing fewer locations makes the line shorter (but for the one-off
    // `rest` object), so binary-search the most that fit in O(log n) builds;
    // only a line that fits is ever returned. Drop the signal list last.
    for with_signals in [true, false] {
        if let Some(l) = build(groups.len(), with_signals) {
            return Some(l);
        }
        let Some(mut best) = build(0, with_signals) else {
            continue;
        };
        let (mut lo, mut hi) = (0, groups.len());
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            match build(mid, with_signals) {
                Some(l) => {
                    best = l;
                    lo = mid;
                }
                None => hi = mid,
            }
        }
        return Some(best);
    }
    None
}

/// Opens `path` for append (creating it 0640), or with `fresh` creates a new
/// file beside it and renames it over `path`. Checks type/mode on the fd.
fn open_file(path: &Path, gid: Option<u32>, fresh: bool) -> Result<(File, u64, u64), String> {
    let shown = path.display().to_string();
    let target = if fresh {
        let mut rnd = [0u8; 6];
        nocve_proto::random_bytes(&mut rnd).map_err(|e| e.to_string())?;
        path.with_file_name(format!(".{FEED_FILE}.new-{}", hex::encode(rnd)))
    } else {
        path.to_path_buf()
    };
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o640)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&target)
        .map_err(|e| format!("{shown}: {e}"))?;
    let md = file.metadata().map_err(|e| format!("{shown}: {e}"))?;
    if !md.is_file() {
        return Err(format!("{shown}: not a regular file"));
    }
    if let Some(g) = gid {
        std::os::unix::fs::fchown(&file, None, Some(g))
            .map_err(|e| format!("{shown}: chgrp: {e}"))?;
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o640))
        .map_err(|e| format!("{shown}: {e}"))?;
    if fresh {
        std::fs::rename(&target, path).map_err(|e| format!("{shown}: {e}"))?;
    }
    let md = file.metadata().map_err(|e| format!("{shown}: {e}"))?;
    Ok((file, md.ino(), md.len()))
}

/// Never fails the caller: logs the first error and every 1000th after.
pub fn append_logged(feed: &mut Feed, line: &str, errors: &mut u64) {
    if let Err(e) = feed.append(line) {
        if (*errors).is_multiple_of(1000) {
            eprintln!("nocved: feed: {e}");
        }
        *errors += 1;
    }
}

/// When the feed directory sits inside the 0700 state directory, the feed
/// group must be able to traverse (not list) the state directory: 0710 with
/// the feed group. Spool and state files stay 0600, so nothing else becomes
/// readable. Without a group the state directory stays 0700.
pub fn allow_traverse(state_dir: &Path, gid: Option<u32>) -> Result<(), String> {
    let Some(g) = gid else {
        return Err(
            "feed.dir is inside state_dir: set feed.group so the reader can traverse it".into(),
        );
    };
    let shown = state_dir.display();
    std::os::unix::fs::chown(state_dir, None, Some(g))
        .map_err(|e| format!("{shown}: chgrp: {e}"))?;
    std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o710))
        .map_err(|e| format!("{shown}: {e}"))
}

/// Current gid of `path` (for tests and `check`).
pub fn gid_of(path: &Path) -> io::Result<u32> {
    Ok(std::fs::metadata(path)?.gid())
}

/// A `persistence.baseline` event like a real host's: `n` entries spread
/// over the watched directories, each with a content digest.
#[cfg(test)]
pub(crate) fn baseline_event(n: usize, path_pad: usize) -> nocve_proto::Event {
    let dirs = [
        ("/etc/systemd/system", "systemd"),
        ("/etc/cron.d", "cron"),
        ("/etc/pam.d", "pam"),
        ("/etc/profile.d", "shell_init"),
        ("/etc/sudoers.d", "sudo"),
        ("/etc/udev/rules.d", "udev"),
        ("/etc/modprobe.d", "modprobe"),
        ("/etc/ssh/sshd_config.d", "sshd"),
    ];
    let entries = (0..n)
        .map(|i| {
            let (dir, cat) = dirs[i % dirs.len()];
            nocve_proto::PersistEntry {
                path: format!("{dir}/unit-{i}{}.conf", "p".repeat(path_pad)),
                category: cat.to_owned(),
                digest: nocve_proto::FileDigest {
                    kind: "file".into(),
                    size: 1000 + i as u64,
                    mode: 0o100_644,
                    uid: 0,
                    mtime: 1_790_000_000 + i as i64,
                    ctime: 1_790_000_000 + i as i64,
                    inode: 400_000 + i as u64,
                    sha256: Some(sha256_hex(format!("content {i}").as_bytes())),
                    link_target: None,
                },
            }
        })
        .collect();
    nocve_proto::Event::new(
        1_790_000_000_123,
        "persistence",
        nocve_proto::EventData::PersistenceBaseline {
            entries,
            truncated: false,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed(ev: &nocve_proto::Event) -> (nocve_proto::Envelope, String) {
        let mut ch = nocve_proto::Chainer::new_epoch(
            "web-01.example",
            nocve_proto::MacKey::from_bytes([7; 32]),
        )
        .unwrap();
        let _first = ch.seal("{\"kind\":\"sensor.start\",\"observed_at_ms\":1}".into());
        let env = ch.seal(serde_json::to_string(ev).unwrap());
        let line = serde_json::to_string(&env).unwrap();
        (env, line)
    }

    fn fed_lines(feed: &Feed) -> Vec<String> {
        std::fs::read_to_string(feed.path())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// A real-sized baseline (over 12 KB) becomes one compact feed line with
    /// the same envelope identity; nothing is skipped.
    #[test]
    fn large_baseline_is_compacted_not_skipped() {
        let (env, line) = sealed(&baseline_event(60, 0));
        assert!(line.len() > 12 * 1024, "{}", line.len());
        let d = tempfile::tempdir().unwrap();
        let mut feed = Feed::open(&cfg(d.path(), 1 << 20), None).unwrap();
        feed.append(&line).unwrap();
        assert_eq!((feed.skipped_long, feed.compacted), (0, 1));
        let fed = fed_lines(&feed);
        assert_eq!(fed.len(), 1);
        assert!(fed[0].len() < MAX_FEED_LINE, "{}", fed[0].len());
        let c: nocve_proto::Envelope = serde_json::from_str(&fed[0]).unwrap();
        assert_eq!(
            (c.v, &c.host, &c.epoch, c.seq, &c.prev, &c.mac),
            (env.v, &env.host, &env.epoch, env.seq, &env.prev, &env.mac)
        );
        assert_eq!(c.seq, 1);
        let p: Value = serde_json::from_str(&c.payload).unwrap();
        assert_eq!(p["kind"], "persistence.baseline");
        assert_eq!(p["feed_compact"], true);
        assert_eq!(p["observed_at_ms"], 1_790_000_000_123_i64);
        assert_eq!(p["count"], 60);
        assert_eq!(p["orig_bytes"], env.payload.len());
        assert_eq!(p["orig_sha256"], sha256_hex(env.payload.as_bytes()));
        let locs = p["locations"].as_array().unwrap();
        assert_eq!(locs.len(), 8, "every location listed");
        assert!(p.get("rest").is_none());
        let sum: u64 = locs.iter().map(|l| l["count"].as_u64().unwrap()).sum();
        assert_eq!(sum, 60);
        // A location digest is over exactly that location's entries as the
        // original payload encodes them.
        let nocve_proto::EventData::PersistenceBaseline { entries, .. } =
            baseline_event(60, 0).data
        else {
            unreachable!()
        };
        let cron: Vec<&nocve_proto::PersistEntry> =
            entries.iter().filter(|e| e.category == "cron").collect();
        let l = locs.iter().find(|l| l["path"] == "/etc/cron.d").unwrap();
        assert_eq!(l["sha256"], sha256_hex(&serde_json::to_vec(&cron).unwrap()));
        assert!(
            !c.payload.contains("\"payload\""),
            "the reader rejects a nested payload key"
        );
        // The mac does not verify over the stand-in: it is not evidence.
        assert!(c.verify(&nocve_proto::MacKey::from_bytes([7; 32])).is_err());
        // A short line is still mirrored unchanged.
        feed.append("{\"v\":1}").unwrap();
        assert_eq!(fed_lines(&feed)[1], "{\"v\":1}");
    }

    /// Pathological: hundreds of entries in distinct long directories and
    /// many signals still give one line under the cap, the tail folded.
    #[test]
    fn pathological_baseline_still_fits() {
        let mut ev = baseline_event(512, 0);
        if let nocve_proto::EventData::PersistenceBaseline { entries, .. } = &mut ev.data {
            for (i, e) in entries.iter_mut().enumerate() {
                e.path = format!("/{}/d{i}/f", "x".repeat(100));
            }
        }
        ev.signals = (0..32)
            .map(|i| {
                nocve_proto::Signal::new(
                    &format!("persist.ld_preload_present{i}{}", "z".repeat(90)),
                    nocve_proto::Severity::High,
                    "s".repeat(4000),
                )
            })
            .collect();
        let (env, line) = sealed(&ev);
        assert!(line.len() > 60 * 1024 / 2, "{}", line.len());
        let c = compact_line(&line).unwrap();
        assert!(c.len() < MAX_FEED_LINE, "{}", c.len());
        let c: nocve_proto::Envelope = serde_json::from_str(&c).unwrap();
        assert_eq!((c.seq, &c.epoch, &c.prev), (env.seq, &env.epoch, &env.prev));
        let p: Value = serde_json::from_str(&c.payload).unwrap();
        let listed: u64 = p["locations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["count"].as_u64().unwrap())
            .sum();
        assert_eq!(listed + p["rest"]["count"].as_u64().unwrap(), 512);
        assert_eq!(p["count"], 512);
        assert_eq!(p["signals_count"], 32);

        // Any other kind too big for the feed gets a kind the reader ignores.
        let big = nocve_proto::Event::new(
            5,
            "authlog",
            nocve_proto::EventData::LogSkipped {
                path: "/var/log/auth.log".into(),
                bytes: 1,
                reason: "r".repeat(9000),
            },
        );
        let (_, line) = sealed(&big);
        let c: nocve_proto::Envelope = serde_json::from_str(&compact_line(&line).unwrap()).unwrap();
        let p: Value = serde_json::from_str(&c.payload).unwrap();
        assert_eq!(
            (p["kind"].as_str(), p["orig_kind"].as_str()),
            (Some("feed.compact"), Some("log.skipped"))
        );
        // Not an envelope: skipped and counted, never written.
        assert!(compact_line(&"y".repeat(MAX_FEED_LINE)).is_none());
    }

    fn my_gid(d: &Path) -> u32 {
        let p = d.join("probe");
        std::fs::write(&p, b"").unwrap();
        gid_of(&p).unwrap()
    }

    fn cfg(dir: &Path, max: u64) -> FeedConfig {
        FeedConfig {
            enabled: true,
            dir: dir.join("feed"),
            group: None,
            max_bytes: max,
        }
    }

    #[test]
    fn modes_and_group_are_enforced() {
        let d = tempfile::tempdir().unwrap();
        let gid = my_gid(d.path());
        let c = cfg(d.path(), 64 * 1024);
        std::fs::create_dir_all(&c.dir).unwrap();
        std::fs::set_permissions(&c.dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        // A pre-existing, too-open feed file is tightened on open.
        let f = c.dir.join(FEED_FILE);
        std::fs::write(&f, b"").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        let mut feed = Feed::open(&c, Some(gid)).unwrap();
        feed.append("{\"v\":1}").unwrap();
        let dm = std::fs::metadata(&c.dir).unwrap();
        let fm = std::fs::metadata(&f).unwrap();
        assert_eq!(dm.permissions().mode() & 0o777, 0o750);
        assert_eq!(fm.permissions().mode() & 0o777, 0o640);
        assert_eq!((dm.gid(), fm.gid()), (gid, gid));
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "{\"v\":1}\n");
    }

    #[test]
    fn symlinked_feed_file_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let c = cfg(d.path(), 64 * 1024);
        std::fs::create_dir_all(&c.dir).unwrap();
        std::os::unix::fs::symlink(d.path().join("elsewhere"), c.dir.join(FEED_FILE)).unwrap();
        assert!(Feed::open(&c, None).is_err());
        assert!(!d.path().join("elsewhere").exists());
    }

    #[test]
    fn rotation_is_a_rename_to_a_new_inode_and_bounded() {
        let d = tempfile::tempdir().unwrap();
        let c = cfg(d.path(), 64 * 1024);
        let mut feed = Feed::open(&c, None).unwrap();
        let path = feed.path();
        let ino0 = std::fs::metadata(&path).unwrap().ino();
        let line = format!("{{\"seq\":0,\"pad\":\"{}\"}}", "x".repeat(1000));
        for _ in 0..70 {
            feed.append(&line).unwrap();
        }
        let m = std::fs::metadata(&path).unwrap();
        assert_ne!(m.ino(), ino0, "rotated by rename: new inode");
        assert!(m.len() <= c.max_bytes);
        assert_eq!(m.permissions().mode() & 0o777, 0o640);
        let old = std::fs::metadata(c.dir.join(format!("{FEED_FILE}.1"))).unwrap();
        assert_eq!(old.ino(), ino0, "the previous file is kept as .1");
        assert!(old.len() <= c.max_bytes);
        let names: Vec<String> = std::fs::read_dir(&c.dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2, "no temp files left: {names:?}");
    }

    /// Burst: a second rotation inside the hold window would replace a `.1`
    /// the reader may not have drained. It must not happen; the live file
    /// grows to 2x and then lines are skipped and counted.
    #[test]
    fn burst_never_replaces_undrained_generation() {
        let d = tempfile::tempdir().unwrap();
        let c = cfg(d.path(), 64 * 1024);
        let mut feed = Feed::open(&c, None).unwrap();
        let line = format!("{{\"pad\":\"{}\"}}", "x".repeat(1000));
        // ~1 MiB: without the hold this rotates ~15 times.
        for _ in 0..1000 {
            feed.append(&line).unwrap();
        }
        let old = c.dir.join(format!("{FEED_FILE}.1"));
        let first_gen = std::fs::metadata(&old).unwrap().ino();
        for _ in 0..1000 {
            feed.append(&line).unwrap();
        }
        assert_eq!(
            std::fs::metadata(&old).unwrap().ino(),
            first_gen,
            ".1 replaced inside the hold window"
        );
        let live = std::fs::metadata(feed.path()).unwrap().len();
        assert!(live <= 2 * c.max_bytes, "live file bounded at 2x: {live}");
        assert!(feed.skipped_burst > 0, "overflow is counted, not silent");
        assert_eq!(feed.skipped(), (0, feed.skipped_burst));
        // Once the hold has passed, rotation resumes.
        feed.hold = Duration::ZERO;
        feed.append(&line).unwrap();
        assert_ne!(std::fs::metadata(&old).unwrap().ino(), first_gen);
    }

    /// A `.1` left by a previous process is assumed fresh (held).
    #[test]
    fn existing_generation_is_held_after_restart() {
        let d = tempfile::tempdir().unwrap();
        let c = cfg(d.path(), 64 * 1024);
        std::fs::create_dir_all(&c.dir).unwrap();
        let old = c.dir.join(format!("{FEED_FILE}.1"));
        std::fs::write(&old, b"{\"undrained\":1}\n").unwrap();
        let ino = std::fs::metadata(&old).unwrap().ino();
        let mut feed = Feed::open(&c, None).unwrap();
        let line = format!("{{\"pad\":\"{}\"}}", "x".repeat(1000));
        for _ in 0..100 {
            feed.append(&line).unwrap();
        }
        assert_eq!(std::fs::metadata(&old).unwrap().ino(), ino);
    }

    #[test]
    fn long_lines_skipped_and_removed_file_recreated() {
        let d = tempfile::tempdir().unwrap();
        let c = cfg(d.path(), 64 * 1024);
        let mut feed = Feed::open(&c, None).unwrap();
        feed.append(&"y".repeat(MAX_FEED_LINE)).unwrap();
        assert_eq!(feed.skipped_long, 1);
        std::fs::remove_file(feed.path()).unwrap();
        feed.append("{\"a\":1}").unwrap();
        assert_eq!(std::fs::read_to_string(feed.path()).unwrap(), "{\"a\":1}\n");
    }

    #[test]
    fn state_dir_becomes_group_traversable_only() {
        let d = tempfile::tempdir().unwrap();
        let gid = my_gid(d.path());
        let state = d.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(allow_traverse(&state, None).is_err(), "needs a group");
        allow_traverse(&state, Some(gid)).unwrap();
        let m = std::fs::metadata(&state).unwrap();
        assert_eq!(
            m.permissions().mode() & 0o777,
            0o710,
            "traverse, never list or write"
        );
        assert_eq!(m.gid(), gid);
    }

    #[test]
    fn group_resolution() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("etc")).unwrap();
        std::fs::write(d.path().join("etc/group"), "root:x:0:\ncveguard:x:998:\n").unwrap();
        assert_eq!(resolve_gid(d.path(), "cveguard").unwrap(), 998);
        assert_eq!(resolve_gid(d.path(), "1234").unwrap(), 1234);
        assert!(resolve_gid(d.path(), "nope").is_err());
        let bad = FeedConfig {
            enabled: true,
            group: Some("a:b".into()),
            ..FeedConfig::default()
        };
        assert!(bad.validate().is_err());
        assert!(FeedConfig::default().validate().is_ok(), "off by default");
        assert!(!FeedConfig::default().enabled);
    }
}
