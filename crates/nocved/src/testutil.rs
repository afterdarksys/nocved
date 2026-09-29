//! Fixture builders for a fake `/proc` tree. Used by unit tests here and by the
//! store's incident-replay integration test. Writes only under the given root.
#![allow(clippy::missing_panics_doc)]

use std::fs;
use std::path::{Path, PathBuf};

pub struct FakeProc {
    root: PathBuf,
}

fn w(p: &Path, s: &[u8]) {
    if let Some(d) = p.parent() {
        let _ok = fs::create_dir_all(d);
    }
    if let Err(e) = fs::write(p, s) {
        panic!("fixture write {}: {e}", p.display());
    }
}

fn link(target: &str, p: &Path) {
    if let Some(d) = p.parent() {
        let _ok = fs::create_dir_all(d);
    }
    let _ok = fs::remove_file(p);
    if let Err(e) = std::os::unix::fs::symlink(target, p) {
        panic!("fixture symlink {}: {e}", p.display());
    }
}

impl FakeProc {
    #[must_use]
    pub fn new(root: &Path) -> Self {
        let root = root.to_path_buf();
        w(&root.join("proc/stat"), b"cpu  1 2 3 4\nbtime 1758300000\n");
        w(
            &root.join("proc/sys/kernel/random/boot_id"),
            b"6f1c7c1e-0000-4000-8000-000000000001\n",
        );
        Self { root }
    }

    fn pid_dir(&self, pid: u32) -> PathBuf {
        self.root.join("proc").join(pid.to_string())
    }

    fn stat_line(pid: u32, comm: &str, ppid: u32, flags: u64, start: u64, cpu: u64) -> String {
        format!(
            "{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 {flags} 0 0 0 0 {cpu} 0 0 0 20 0 1 0 {start} 1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &self,
        pid: u32,
        ppid: u32,
        uid: u32,
        comm: &str,
        exe: &str,
        argv: &[&str],
        start: u64,
        cpu: u64,
    ) {
        let d = self.pid_dir(pid);
        let _ok = fs::remove_dir_all(&d);
        w(
            &d.join("stat"),
            Self::stat_line(pid, comm, ppid, 0x40_0100, start, cpu).as_bytes(),
        );
        w(
            &d.join("status"),
            format!("Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n").as_bytes(),
        );
        let mut cl = argv.join("\0");
        cl.push('\0');
        w(&d.join("cmdline"), cl.as_bytes());
        w(&d.join("cgroup"), b"0::/system.slice/ssh.service\n");
        link(exe, &d.join("exe"));
        link("/root", &d.join("cwd"));
        link("net:[4026531840]", &d.join("ns/net"));
    }

    pub fn add_kthread(&self, pid: u32, comm: &str) {
        let d = self.pid_dir(pid);
        w(
            &d.join("stat"),
            Self::stat_line(pid, comm, 2, 0x20_8040, 1, 0).as_bytes(),
        );
    }

    pub fn set_cpu(&self, pid: u32, start: u64, cpu: u64) {
        let d = self.pid_dir(pid);
        let old = fs::read_to_string(d.join("stat")).unwrap_or_default();
        let comm = old
            .find('(')
            .and_then(|a| old.rfind(')').map(|b| old[a + 1..b].to_owned()))
            .unwrap_or_default();
        w(
            &d.join("stat"),
            Self::stat_line(pid, &comm, 1, 0x40_0100, start, cpu).as_bytes(),
        );
    }

    pub fn remove(&self, pid: u32) {
        let _ok = fs::remove_dir_all(self.pid_dir(pid));
    }

    pub fn add_socket(&self, pid: u32, fd: u32, inode: u64) {
        link(
            &format!("socket:[{inode}]"),
            &self.pid_dir(pid).join("fd").join(fd.to_string()),
        );
    }

    /// Writes /proc/<pid>/net/<proto> (the per-namespace view).
    pub fn set_net(&self, pid: u32, proto: &str, rows: &[String]) {
        let mut s = String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        );
        for r in rows {
            s.push_str(r);
            s.push('\n');
        }
        w(&self.pid_dir(pid).join("net").join(proto), s.as_bytes());
    }

    #[must_use]
    pub fn tcp_row(
        local: [u8; 4],
        lport: u16,
        remote: [u8; 4],
        rport: u16,
        state: u8,
        inode: u64,
    ) -> String {
        let h = |ip: [u8; 4]| format!("{:08X}", u32::from_le_bytes(ip));
        format!(
            "   0: {}:{lport:04X} {}:{rport:04X} {state:02X} 00000000:00000000 00:00000000 00000000     0        0 {inode} 1 0000000000000000 20 4 30 10 -1",
            h(local),
            h(remote)
        )
    }
}
