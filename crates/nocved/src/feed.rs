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
//! Threats: envelopes carry the per-event MAC, never the MAC key or the host
//! token; anything readable here is already shipped off-host. The feed is
//! best effort: a feed write error never affects the chain or the spool.
//! It does NOT authenticate the reader, and a reader cannot verify envelopes
//! without the key (DESIGN.md section 21). Lines over 8192 bytes are skipped
//! (the consumer rejects them) and counted.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

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
    /// Lines over `MAX_FEED_LINE`, skipped.
    pub skipped_long: u64,
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

    /// Appends one envelope line (no trailing newline in `line`).
    pub fn append(&mut self, line: &str) -> Result<(), String> {
        if line.len() + 1 > MAX_FEED_LINE {
            self.skipped_long += 1;
            return Ok(());
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
