//! Robust log tailing: rotation, truncation, NUL bytes, in-place replacement
//! (`sed -i`) and deletion. Keeps reading an unlinked-but-still-written inode
//! (rsyslog writes into it until its next HUP), so lines the attacker removed
//! from the visible file still arrive.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::fsutil::open_nofollow;

pub const MAX_LINE: usize = 8 * 1024;
pub const MAX_READ_PER_POLL: u64 = 1024 * 1024;
const ORPHAN_IDLE_POLLS: u32 = 1800;

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
    /// The file disappeared.
    Deleted,
    /// The path is a symlink (not followed).
    Symlink,
}

struct Handle {
    file: File,
    ino: u64,
    dev: u64,
    offset: u64,
    partial: Vec<u8>,
    idle_polls: u32,
}

pub struct Tailer {
    path: PathBuf,
    cur: Option<Handle>,
    /// Old unlinked inode still being written to.
    orphan: Option<Handle>,
    start_at_end: bool,
    missing_reported: bool,
    symlink_reported: bool,
    pub lines_total: u64,
}

pub struct TailOutput {
    pub lines: Vec<String>,
    pub anomalies: Vec<Anomaly>,
    /// Lines that came from an unlinked (hidden) inode.
    pub orphan_lines: usize,
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
        let file = open_nofollow(&self.path).ok()?;
        let md = file.metadata().ok()?;
        if !md.is_file() {
            return None;
        }
        let offset = if at_end { md.len() } else { 0 };
        Some(Handle {
            file,
            ino: md.ino(),
            dev: md.dev(),
            offset,
            partial: Vec::new(),
            idle_polls: 0,
        })
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
                        // Finish the old inode first (rotation keeps writing briefly).
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
                        let old = self.cur.take();
                        if unlinked {
                            self.orphan = old;
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
                        self.orphan = Some(h);
                    }
                }
                self.start_at_end = false;
            }
        }
        if let Some(h) = self.cur.as_mut() {
            if let Ok(md) = h.file.metadata()
                && md.len() < h.offset
            {
                out.anomalies.push(Anomaly::Truncated {
                    from: h.offset,
                    to: md.len(),
                });
                h.offset = 0;
                h.partial.clear();
            }
            drain(h, &mut out.lines);
        }
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
