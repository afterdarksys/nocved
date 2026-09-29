//! Defensive file helpers (host-inventory patterns): O_NOFOLLOW opens,
//! fd-based permission checks, bounded reads, atomic 0600 writes.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Opens read-only without following a final symlink.
pub fn open_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// Reads at most `max` bytes. Returns an error if the file is larger (fail closed).
pub fn read_bounded(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    let f = File::open(path)?;
    read_fd_bounded(f, max)
}

/// Like `read_bounded` but truncates silently (for /proc files where only a
/// prefix matters, e.g. cmdline).
pub fn read_prefix(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    let f = File::open(path)?;
    let mut buf = Vec::with_capacity(max.min(4096));
    f.take(max as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

fn read_fd_bounded(f: File, max: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds size limit",
        ));
    }
    Ok(buf)
}

/// Permission policy for a secret-bearing file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secrecy {
    /// Config: no group/other write.
    Config,
    /// Key: no group/other access at all.
    Key,
}

/// Opens with O_NOFOLLOW, then checks type/owner/mode on the *open fd* (no
/// TOCTOU between check and read). Owner must be root or the current user.
pub fn read_secure(path: &Path, max: usize, secrecy: Secrecy) -> Result<Vec<u8>, String> {
    let shown = path.display();
    let f = open_nofollow(path).map_err(|e| format!("{shown}: {e}"))?;
    let md = f.metadata().map_err(|e| format!("{shown}: {e}"))?;
    if !md.file_type().is_file() {
        return Err(format!("{shown}: not a regular file"));
    }
    let me = current_uid();
    if md.uid() != 0 && Some(md.uid()) != me {
        return Err(format!("{shown}: owned by uid {}, want root", md.uid()));
    }
    let mode = md.permissions().mode() & 0o777;
    let bad = match secrecy {
        Secrecy::Config => mode & 0o022,
        Secrecy::Key => mode & 0o077,
    };
    if bad != 0 {
        return Err(format!(
            "{shown}: mode {mode:04o} too open (want {})",
            if secrecy == Secrecy::Key {
                "0600"
            } else {
                "no group/other write"
            }
        ));
    }
    read_fd_bounded(f, max).map_err(|e| format!("{shown}: {e}"))
}

/// The effective uid, read from /proc/self/status or the owner of a fresh
/// temp file; `None` if unknown (then only root-owned files are accepted).
fn current_uid() -> Option<u32> {
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                return rest.split_whitespace().nth(1).and_then(|v| v.parse().ok());
            }
        }
    }
    std::env::var_os("HOME")
        .and_then(|h| std::fs::metadata(h).ok())
        .map(|m| m.uid())
}

/// Writes `bytes` to `path` atomically with mode 0600: temp file in the same
/// directory, fsync, rename, fsync dir.
pub fn write_atomic_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut rnd = [0u8; 6];
    nocve_proto::random_bytes(&mut rnd).map_err(|e| io::Error::other(e.to_string()))?;
    let tmp = dir.join(format!(".{name}.new-{}", hex::encode(rnd)));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        if let Ok(d) = File::open(dir) {
            d.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ignored_cleanup = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_read_rejects_open_modes_and_symlinks() -> Result<(), Box<dyn std::error::Error>> {
        let d = tempfile::tempdir()?;
        let key = d.path().join("key");
        write_atomic_0600(&key, b"k\n")?;
        assert_eq!(read_secure(&key, 100, Secrecy::Key)?, b"k\n");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640))?;
        assert!(read_secure(&key, 100, Secrecy::Key).is_err());
        assert!(read_secure(&key, 100, Secrecy::Config).is_ok());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o622))?;
        assert!(read_secure(&key, 100, Secrecy::Config).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&key, &link)?;
        assert!(read_secure(&link, 100, Secrecy::Key).is_err());
        assert!(read_secure(&key, 1, Secrecy::Key).is_err());
        assert!(read_secure(d.path(), 100, Secrecy::Config).is_err());
        Ok(())
    }

    #[test]
    fn atomic_write_is_0600() -> Result<(), Box<dyn std::error::Error>> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("state.json");
        write_atomic_0600(&p, b"{}")?;
        write_atomic_0600(&p, b"{\"a\":1}")?;
        assert_eq!(std::fs::metadata(&p)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&p)?, b"{\"a\":1}");
        assert_eq!(std::fs::read_dir(d.path())?.count(), 1);
        Ok(())
    }
}
