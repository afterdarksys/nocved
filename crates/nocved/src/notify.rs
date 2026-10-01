//! Minimal `sd_notify(3)`: one datagram to `$NOTIFY_SOCKET`, no dependency.
//! `READY=1` once started, `WATCHDOG=1` from the main poll loop so systemd
//! (`WatchdogSec=`) restarts a sensor whose polling froze even while its
//! shipper thread keeps heartbeating.
//!
//! Threats: the socket path comes from systemd's environment; nothing is read
//! back from it. Without `NOTIFY_SOCKET` (tests, `nocved check`) this is a no-op.

use std::io;
use std::os::unix::net::UnixDatagram;

pub struct Notifier {
    sock: UnixDatagram,
    target: String,
}

impl Notifier {
    /// `None` when not started by systemd with `Type=notify`.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let target = std::env::var("NOTIFY_SOCKET").ok()?;
        if target.is_empty() || target.len() > 107 {
            return None;
        }
        Some(Self {
            sock: UnixDatagram::unbound().ok()?,
            target,
        })
    }

    pub fn notify(&self, msg: &str) -> io::Result<()> {
        if let Some(name) = self.target.strip_prefix('@') {
            return send_abstract(&self.sock, name, msg);
        }
        self.sock.send_to(msg.as_bytes(), &self.target).map(|_| ())
    }
}

#[cfg(target_os = "linux")]
fn send_abstract(sock: &UnixDatagram, name: &str, msg: &str) -> io::Result<()> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    sock.send_to_addr(msg.as_bytes(), &addr).map(|_| ())
}

#[cfg(not(target_os = "linux"))]
fn send_abstract(_sock: &UnixDatagram, _name: &str, _msg: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "abstract sockets are Linux-only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sends_to_a_path_socket() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("notify");
        let rx = UnixDatagram::bind(&p).unwrap();
        let n = Notifier {
            sock: UnixDatagram::unbound().unwrap(),
            target: p.to_string_lossy().into_owned(),
        };
        n.notify("WATCHDOG=1").unwrap();
        let mut buf = [0u8; 64];
        let got = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..got], b"WATCHDOG=1");
    }
}
