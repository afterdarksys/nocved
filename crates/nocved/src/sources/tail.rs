//! Robust log tailing: rotation, truncation, NUL bytes, in-place replacement
//! (`sed -i`), in-place rewrite of already-read bytes, and deletion. Keeps
//! reading an unlinked-but-still-written inode (rsyslog writes into it until
//! its next HUP), so lines the attacker removed from the visible file still
//! arrive, and keeps draining a rotated inode to EOF across polls.
//!
//! Threats: a path swapped for a FIFO/device is refused on the open fd
//! (`O_NONBLOCK`, `fstat`, regular files only), so it cannot block the poll
//! loop. Bytes that become unreadable before they were drained are reported
//! (`skipped`), never dropped silently. Does NOT detect an edit that keeps
//! the last 4 KiB before the read offset intact.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::fsutil::open_regular_nofollow;

pub const MAX_LINE: usize = 16 * 1024;
pub const MAX_READ_PER_POLL: u64 = 1024 * 1024;
const ORPHAN_IDLE_POLLS: u32 = 1800;
/// A rotated inode is kept this many idle polls after reaching EOF (late
/// writes before the writer reopens).
const ROTATED_IDLE_POLLS: u32 = 30;
/// Bytes before the read offset whose digest is re-checked every poll.
pub const REWRITE_WINDOW: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anomaly {
    /// Same inode, size shrank below our offset.
    Truncated { from: u64, to: u64 },
    /// Path now names a different inode and the old one was not rotated to a
    /// sibling name (deleted or renamed away): in-place edit / replacement.
    Replaced {
        old_inode: u64,
        new_inode: u64,
        old_unlinked: bool,
    },
    /// Same inode and size did not shrink, but the bytes just before our read
    /// offset changed: already-read lines were edited in place.
    Rewritten { offset: u64 },
    /// The file disappeared.
    Deleted,
    /// The path is a symlink (not followed).
    Symlink,
}

/// Bytes that were lost before the tailer could read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub bytes: u64,
    pub reason: &'static str,
}

struct Handle {
    file: File,
    ino: u64,
    dev: u64,
    offset: u64,
    partial: Vec<u8>,
    idle_polls: u32,
    /// SHA-256 of `[offset - REWRITE_WINDOW, offset)` as last read.
    window: Option<(u64, [u8; 32])>,
}

impl Handle {
    fn unread(&self) -> u64 {
        self.file
            .metadata()
            .map_or(0, |m| m.len().saturating_sub(self.offset))
    }

    fn window_digest(&self, end: u64) -> Option<[u8; 32]> {
        let start = end.saturating_sub(REWRITE_WINDOW);
        let len = usize::try_from(end - start).ok()?;
        let mut buf = vec![0u8; len];
        self.file.read_exact_at(&mut buf, start).ok()?;
        Some(Sha256::digest(&buf).into())
    }

    fn remember_window(&mut self) {
        self.window = if self.offset == 0 {
            None
        } else {
            self.window_digest(self.offset).map(|d| (self.offset, d))
        };
    }
}

pub struct Tailer {
    path: PathBuf,
    cur: Option<Handle>,
    /// Old unlinked inode still being written to.
    orphan: Option<Handle>,
    /// Old inode renamed to a sibling (logrotate) or away; drained to EOF.
    rotated: Option<Handle>,
    start_at_end: bool,
    missing_reported: bool,
    symlink_reported: bool,
    pub lines_total: u64,
}

pub struct TailOutput {
    pub lines: Vec<String>,
    pub anomalies: Vec<Anomaly>,
    /// Lines that came from an unlinked (hidden) inode. They are the first
    /// `orphan_lines` entries of `lines`.
    pub orphan_lines: usize,
    pub skipped: Vec<Skipped>,
    /// Bytes written but not read yet (all inodes still followed).
    pub lag_bytes: u64,
}

/// Puts `h` into `slot`; an occupant with unread bytes is reported as lost.
fn park(slot: &mut Option<Handle>, h: Handle, skipped: &mut Vec<Skipped>, reason: &'static str) {
    if let Some(old) = slot.replace(h) {
        let bytes = old.unread();
        if bytes > 0 {
            skipped.push(Skipped { bytes, reason });
        }
    }
}

impl Tailer {
    /// `start_at_end`: skip existing content on the first open (daemon start).
    /// Files that appear later (after rotation) are always read from 0.
    #[must_use]
    pub fn new(path: PathBuf, start_at_end: bool) -> Self {
        Self {
            path,
            cur: None,
            orphan: None,
            rotated: None,
            start_at_end,
            missing_reported: false,
            symlink_reported: false,
            lines_total: 0,
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn is_open(&self) -> bool {
        self.cur.is_some()
    }

    fn open(&self, at_end: bool) -> Option<Handle> {
        let (file, md) = open_regular_nofollow(&self.path).ok()?;
        let offset = if at_end { md.len() } else { 0 };
        let mut h = Handle {
            file,
            ino: md.ino(),
            dev: md.dev(),
            offset,
            partial: Vec::new(),
            idle_polls: 0,
            window: None,
        };
        h.remember_window();
        Some(h)
    }

    fn rotated_to_sibling(path: &Path, ino: u64, dev: u64) -> bool {
        let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
            return false;
        };
        let name = name.to_string_lossy();
        let Ok(rd) = std::fs::read_dir(dir) else {
            return false;
        };
        rd.filter_map(Result::ok).take(4096).any(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n != name
                && n.starts_with(name.as_ref())
                && std::fs::symlink_metadata(e.path())
                    .is_ok_and(|m| m.ino() == ino && m.dev() == dev)
        })
    }

    pub fn poll(&mut self) -> TailOutput {
        let mut out = TailOutput {
            lines: Vec::new(),
            anomalies: Vec::new(),
            orphan_lines: 0,
            skipped: Vec::new(),
            lag_bytes: 0,
        };
        if let Some(o) = self.orphan.as_mut() {
            let before = out.lines.len();
            let grew = drain(o, &mut out.lines);
            out.orphan_lines += out.lines.len() - before;
            if grew {
                o.idle_polls = 0;
            } else {
                o.idle_polls += 1;
                if o.idle_polls > ORPHAN_IDLE_POLLS {
                    self.orphan = None;
                }
            }
        }
        if let Some(r) = self.rotated.as_mut() {
            if drain(r, &mut out.lines) {
                r.idle_polls = 0;
            } else if r.unread() == 0 {
                r.idle_polls += 1;
                if r.idle_polls > ROTATED_IDLE_POLLS {
                    self.rotated = None;
                }
            }
        }
        match std::fs::symlink_metadata(&self.path) {
            Ok(m) if m.file_type().is_symlink() => {
                if !self.symlink_reported {
                    out.anomalies.push(Anomaly::Symlink);
                    self.symlink_reported = true;
                }
            }
            Ok(m) => {
                self.missing_reported = false;
                self.symlink_reported = false;
                match self.cur.as_mut() {
                    None => {
                        let at_end = self.start_at_end;
                        self.start_at_end = false;
                        self.cur = self.open(at_end);
                    }
                    Some(h) if h.ino != m.ino() || h.dev != m.dev() => {
                        // Finish what we can of the old inode now; the rest is
                        // drained on later polls.
                        drain(h, &mut out.lines);
                        let old_ino = h.ino;
                        let unlinked = h.file.metadata().is_ok_and(|md| md.nlink() == 0);
                        let rotated =
                            !unlinked && Self::rotated_to_sibling(&self.path, h.ino, h.dev);
                        if !rotated {
                            out.anomalies.push(Anomaly::Replaced {
                                old_inode: old_ino,
                                new_inode: m.ino(),
                                old_unlinked: unlinked,
                            });
                        }
                        if let Some(old) = self.cur.take() {
                            if unlinked {
                                park(&mut self.orphan, old, &mut out.skipped, "replaced_again");
                            } else {
                                park(&mut self.rotated, old, &mut out.skipped, "rotated_again");
                            }
                        }
                        self.cur = self.open(false);
                    }
                    Some(_) => {}
                }
            }
            Err(_) => {
                if self.cur.is_some() && !self.missing_reported {
                    out.anomalies.push(Anomaly::Deleted);
                    self.missing_reported = true;
                    if let Some(mut h) = self.cur.take() {
                        drain(&mut h, &mut out.lines);
                        park(&mut self.orphan, h, &mut out.skipped, "replaced_again");
                    }
                }
                self.start_at_end = false;
            }
        }
        if let Some(h) = self.cur.as_mut() {
            match h.file.metadata() {
                Ok(md) if md.len() < h.offset => {
                    out.anomalies.push(Anomaly::Truncated {
                        from: h.offset,
                        to: md.len(),
                    });
                    h.offset = 0;
                    h.partial.clear();
                    h.window = None;
                }
                Ok(_) => {
                    if let Some((at, want)) = h.window
                        && at == h.offset
                        && h.window_digest(at).is_some_and(|got| got != want)
                    {
                        out.anomalies.push(Anomaly::Rewritten { offset: at });
                        // Re-baseline on the edited bytes: reported once.
                        h.window = None;
                    }
                }
                Err(_) => {}
            }
            let before = h.offset;
            drain(h, &mut out.lines);
            if h.offset != before || h.window.is_none_or(|(at, _)| at != h.offset) {
                h.remember_window();
            }
        }
        out.lag_bytes = [&self.cur, &self.rotated, &self.orphan]
            .iter()
            .filter_map(|h| h.as_ref())
            .map(Handle::unread)
            .sum();
        self.lines_total += out.lines.len() as u64;
        out
    }
}

/// Reads new bytes (bounded) and splits complete lines. Returns true if any
/// bytes were read.
fn drain(h: &mut Handle, lines: &mut Vec<String>) -> bool {
    if h.file.seek(SeekFrom::Start(h.offset)).is_err() {
        return false;
    }
    let mut buf = Vec::new();
    let Ok(n) = (&mut h.file).take(MAX_READ_PER_POLL).read_to_end(&mut buf) else {
        return false;
    };
    h.offset += n as u64;
    for &b in &buf {
        if b == b'\n' {
            push_line(&mut h.partial, lines);
        } else if b != 0 && h.partial.len() < MAX_LINE {
            // NUL runs (unclean shutdown artifacts) are dropped, never fatal.
            h.partial.push(b);
        }
    }
    n > 0
}

fn push_line(partial: &mut Vec<u8>, lines: &mut Vec<String>) {
    if !partial.is_empty() {
        lines.push(String::from_utf8_lossy(partial).into_owned());
    }
    partial.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    fn append(p: &Path, s: &[u8]) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .unwrap();
        f.write_all(s).unwrap();
    }

    #[test]
    fn start_at_end_then_follow_and_partial_lines() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("auth.log");
        append(&p, b"old line\n");
        let mut t = Tailer::new(p.clone(), true);
        assert!(t.poll().lines.is_empty());
        append(&p, b"a\nb");
        assert_eq!(t.poll().lines, vec!["a"]);
        append(&p, b"c\n");
        assert_eq!(t.poll().lines, vec!["bc"]);
    }

    #[test]
    fn nul_bytes_are_stripped_not_fatal() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("auth.log");
        append(&p, b"");
        let mut t = Tailer::new(p.clone(), true);
        t.poll();
        let mut data = vec![0u8; 5000];
        data.extend_from_slice(
            b"Sep 29 05:10:01 gdns1 systemd-logind[400]: New seat seat0.\n\0\0\0x\0y\n",
        );
        append(&p, &data);
        let o = t.poll();
        assert_eq!(
            o.lines,
            vec![
                "Sep 29 05:10:01 gdns1 systemd-logind[400]: New seat seat0.",
                "xy"
            ]
        );
        assert!(o.anomalies.is_empty());
    }

    #[test]
    fn logrotate_rename_is_not_an_anomaly() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("auth.log");
        append(&p, b"");
        let mut t = Tailer::new(p.clone(), true);
        t.poll();
        append(&p, b"before\n");
        std::fs::rename(&p, d.path().join("auth.log.1")).unwrap();
        append(&d.path().join("auth.log.1"), b"late write to old\n");
        append(&p, b"after\n");
        let o = t.poll();
        assert_eq!(o.lines, vec!["before", "late write to old", "after"]);
        assert!(o.anomalies.is_empty(), "{:?}", o.anomalies);
    }

    #[test]
    fn truncation_is_detected_and_reread() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("auth.log");
        append(&p, b"");
        let mut t = Tailer::new(p.clone(), true);
        t.poll();
        append(&p, b"one\ntwo\n");
        t.poll();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .unwrap()
            .set_len(0)
            .unwrap();
        append(&p, b"x\n");
        let o = t.poll();
        assert!(
            matches!(o.anomalies[..], [Anomaly::Truncated { from: 8, to: 2 }]),
            "{:?}",
            o.anomalies
        );
        assert_eq!(o.lines, vec!["x"]);
    }

    #[test]
    fn sed_i_replacement_detected_and_hidden_lines_still_read() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("auth.log");
        append(&p, b"");
        let mut t = Tailer::new(p.clone(), true);
        t.poll();
        // rsyslog holds its own fd on the original inode.
        let mut rsyslog = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        rsyslog
            .write_all(b"Accepted password for root from 185.121.108.3 port 1 ssh2\n")
            .unwrap();
        // sed -i: write a filtered copy and rename it over the original.
        let tmp = d.path().join("sedXYZ");
        std::fs::write(&tmp, b"").unwrap();
        std::fs::rename(&tmp, &p).unwrap();
        let o = t.poll();
        assert!(
            matches!(
                o.anomalies[..],
                [Anomaly::Replaced {
                    old_unlinked: true,
                    ..
                }]
            ),
            "{:?}",
            o.anomalies
        );
        assert_eq!(
            o.lines,
            vec!["Accepted password for root from 185.121.108.3 port 1 ssh2"]
        );
        // rsyslog keeps writing into the unlinked inode until HUP; we still see it.
        rsyslog.write_all(b"hidden line\n").unwrap();
        let o = t.poll();
        assert_eq!(o.lines, vec!["hidden line"]);
        assert_eq!(o.orphan_lines, 1);
    }

    #[test]
    fn deletion_and_symlink_reported_once() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("auth.log");
        append(&p, b"");
        let mut t = Tailer::new(p.clone(), true);
        t.poll();
        std::fs::remove_file(&p).unwrap();
        assert_eq!(t.poll().anomalies, vec![Anomaly::Deleted]);
        assert!(t.poll().anomalies.is_empty());
        std::os::unix::fs::symlink("/dev/null", &p).unwrap();
        assert_eq!(t.poll().anomalies, vec![Anomaly::Symlink]);
    }

    /// H1: auth.log swapped for a FIFO used to block `poll` forever in open().
    #[test]
    fn fifo_at_tailed_path_never_blocks() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("auth.log");
        append(&p, b"x\n");
        let (tx, rx) = std::sync::mpsc::channel();
        let pp = p.clone();
        std::thread::spawn(move || {
            let mut t = Tailer::new(pp.clone(), true);
            t.poll();
            std::fs::remove_file(&pp).unwrap();
            crate::testutil::mkfifo(&pp).unwrap();
            let o = t.poll();
            let o2 = t.poll();
            tx.send((o.anomalies, t.is_open(), o2.lines.len())).unwrap();
        });
        let got = rx.recv_timeout(std::time::Duration::from_secs(3));
        let _unblock = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&p);
        let (anomalies, open, lines) = got.expect("Tailer::poll blocked on a FIFO");
        assert!(
            matches!(anomalies[..], [Anomaly::Replaced { .. }]),
            "{anomalies:?}"
        );
        assert!(!open, "a FIFO is never opened for tailing");
        assert_eq!(lines, 0);
    }

    /// M5: more than one poll's worth of data in a rotated file used to be
    /// dropped after one bounded read.
    #[test]
    fn rotated_inode_is_drained_to_eof_across_polls() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("auth.log");
        append(&p, b"");
        let mut t = Tailer::new(p.clone(), true);
        t.poll();
        let line = vec![b'a'; 1023];
        let mut big = Vec::new();
        for _ in 0..1500 {
            big.extend_from_slice(&line);
            big.push(b'\n');
        }
        append(&p, &big);
        std::fs::rename(&p, d.path().join("auth.log.1")).unwrap();
        append(&p, b"after\n");
        let first = t.poll();
        assert!(
            first.lag_bytes > 0,
            "lag reported while the rotated inode is behind"
        );
        let mut n = first.lines.len();
        let mut saw_after = first.lines.iter().any(|l| l == "after");
        for _ in 0..3 {
            let o = t.poll();
            n += o.lines.len();
            saw_after |= o.lines.iter().any(|l| l == "after");
            assert!(o.skipped.is_empty());
        }
        assert_eq!(n, 1501, "every rotated line plus the new file's line");
        assert!(saw_after);
        assert_eq!(t.poll().lag_bytes, 0);
    }

    /// M5: a rotated inode replaced again before it was drained is a reported loss.
    #[test]
    fn rotating_again_before_drain_reports_skipped() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("auth.log");
        append(&p, b"");
        let mut t = Tailer::new(p.clone(), true);
        t.poll();
        let big = vec![b'b'; 3 * MAX_READ_PER_POLL as usize];
        append(&p, &big);
        std::fs::rename(&p, d.path().join("auth.log.1")).unwrap();
        append(&p, &big);
        t.poll();
        std::fs::rename(&p, d.path().join("auth.log.2")).unwrap();
        append(&p, b"x\n");
        let o = t.poll();
        let lost: u64 = o.skipped.iter().map(|s| s.bytes).sum();
        assert!(lost > 0, "{:?}", o.skipped);
        assert_eq!(o.skipped[0].reason, "rotated_again");
    }

    /// M5: rewriting already-read bytes without shrinking the file.
    #[test]
    fn in_place_rewrite_of_read_bytes_is_detected() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("auth.log");
        append(&p, b"");
        let mut t = Tailer::new(p.clone(), true);
        t.poll();
        append(&p, b"Accepted password for root from 185.121.108.3\n");
        assert_eq!(t.poll().lines.len(), 1);
        assert!(t.poll().anomalies.is_empty(), "unchanged bytes are quiet");
        let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.write_all_at(b"Accepted password for ryan", 0).unwrap();
        let o = t.poll();
        assert!(
            matches!(o.anomalies[..], [Anomaly::Rewritten { offset: 46 }]),
            "{:?}",
            o.anomalies
        );
        assert!(t.poll().anomalies.is_empty(), "reported once");
    }

    #[test]
    fn overlong_line_is_bounded() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("auth.log");
        append(&p, b"");
        let mut t = Tailer::new(p.clone(), true);
        t.poll();
        let mut long = vec![b'a'; MAX_LINE * 3];
        long.push(b'\n');
        append(&p, &long);
        let o = t.poll();
        assert_eq!(o.lines.len(), 1);
        assert_eq!(o.lines[0].len(), MAX_LINE);
    }
}
