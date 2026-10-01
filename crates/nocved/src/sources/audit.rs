//! Auditd `execve` tail. Reads `/var/log/audit/audit.log` and emits one
//! `audit.exec` per complete `EXECVE` record, plus `log.tamper` when that file
//! is truncated, replaced, deleted, or turned into a symlink.
//!
//! Threats: short-lived exec evidence leaves the host before the process
//! exits. Secrets in argv are masked. Raw audit lines and `PROCTITLE` are
//! never shipped. Bad, oversized, and incomplete records are dropped and
//! never chained. At most 32 audit ids are assembled at once, and only the
//! newest incomplete id is held across polls.
//! This does NOT prove the exec happened if root forges the log or holds the
//! MAC key. It does NOT see execs that never reach `audit.log`. It does NOT
//! follow symlinks (the tailer opens with `O_NOFOLLOW`).

use std::path::Path;
use std::time::Duration;

use nocve_proto::mask::mask_argv;
use nocve_proto::{
    AuditExecInfo, Coverage, CoverageStatus, Event, EventData, ProcessInfo, Severity, Signal,
};

use super::process::process_signals;
use super::tail::{Anomaly, Tailer};
use super::{Ctx, MAX_EVENTS_PER_POLL, Source, cap_events, coverage};
use crate::config::SourceToggle;

const AUDIT_LOG: &str = "/var/log/audit/audit.log";
const DEFAULT_INTERVAL_SECS: u64 = 2;
const MAX_OPEN: usize = 32;
const MAX_ARGC: usize = 128;
const MAX_DECODED: usize = 4096;
const MAX_FIELDS: usize = 256;
const MAX_TIME_LEN: usize = 32;
const MAX_NUM_LEN: usize = 20;
const MAX_EXE_CHARS: usize = 512;
const MAX_COMM_CHARS: usize = 64;

const F_SYSCALL: u8 = 1 << 0;
const F_EXEC: u8 = 1 << 1;
const F_EOE: u8 = 1 << 2;
const F_BAD: u8 = 1 << 3;

struct Group {
    serial: u64,
    audit_time: String,
    time_us: u128,
    pid: Option<u32>,
    ppid: Option<u32>,
    uid: Option<u32>,
    success: Option<bool>,
    exe: Option<String>,
    comm: Option<String>,
    argc: Option<usize>,
    args: Vec<Option<String>>,
    flags: u8,
}

impl Group {
    fn new(serial: u64, audit_time: &str, time_us: u128) -> Self {
        Self {
            serial,
            audit_time: audit_time.to_owned(),
            time_us,
            pid: None,
            ppid: None,
            uid: None,
            success: None,
            exe: None,
            comm: None,
            argc: None,
            args: Vec::new(),
            flags: 0,
        }
    }

    fn has(&self, bit: u8) -> bool {
        self.flags & bit != 0
    }

    fn mark(&mut self, bit: u8) {
        self.flags |= bit;
    }
}

struct Record<'a> {
    kind: &'a str,
    time: &'a str,
    serial: u64,
    time_us: u128,
    body: &'a str,
}

pub struct AuditSource {
    ctx: Ctx,
    cfg: SourceToggle,
    tailer: Tailer,
    open: Vec<Group>,
    health: Coverage,
    loud_drops: u64,
    capped: bool,
    /// Highest audit serial seen this poll, including ids already closed.
    /// Rebuilt from the open set at the start of each poll so a restart can
    /// reuse low serials. An incomplete exec is held only when it is this serial.
    seen_max: Option<u64>,
}

impl AuditSource {
    #[must_use]
    pub fn new(ctx: Ctx, cfg: SourceToggle) -> Self {
        let tailer = Tailer::new(ctx.path(AUDIT_LOG), true);
        Self {
            ctx,
            cfg,
            tailer,
            open: Vec::new(),
            health: coverage("auditd", CoverageStatus::Skipped, "not polled yet"),
            loud_drops: 0,
            capped: false,
            seen_max: None,
        }
    }

    fn note_serial(&mut self, serial: u64) {
        self.seen_max = Some(self.seen_max.map_or(serial, |m| m.max(serial)));
    }

    fn note_loud(&mut self) {
        self.loud_drops = self.loud_drops.saturating_add(1);
    }

    fn settle(
        &mut self,
        g: Group,
        now_ms: i64,
        evs: &mut Vec<Event>,
        holdable: bool,
    ) -> Option<Group> {
        if exec_complete(&g) {
            match self.event_for(&g, now_ms) {
                Some(ev) => evs.push(ev),
                None => self.note_loud(),
            }
            return None;
        }
        if holdable && !g.has(F_BAD) && !g.has(F_EOE) {
            return Some(g);
        }
        if g.has(F_EXEC) {
            self.note_loud();
        }
        None
    }

    /// `holdable` is false. A group that comes back would have been held; count
    /// it as a loud drop so it is not lost quietly.
    fn settle_now(&mut self, g: Group, now_ms: i64, evs: &mut Vec<Event>) {
        if self.settle(g, now_ms, evs, false).is_some() {
            self.note_loud();
        }
    }

    fn event_for(&self, g: &Group, now_ms: i64) -> Option<Event> {
        let raw = raw_argv(g)?;
        let view = view_process(g);
        let signals = process_signals(&self.ctx.ind, &view, &raw);
        let argc = u32::try_from(raw.len()).ok()?;
        let info = AuditExecInfo {
            serial: g.serial,
            audit_time: g.audit_time.clone(),
            pid: g.pid,
            ppid: g.ppid,
            uid: g.uid,
            success: g.success,
            exe: g.exe.as_deref().map(|s| clip_chars(s, MAX_EXE_CHARS)),
            comm: g.comm.as_deref().map(|s| clip_chars(s, MAX_COMM_CHARS)),
            argc,
            argv: mask_argv(&raw),
        };
        Some(Event::new(now_ms, "auditd", EventData::AuditExec(info)).with_signals(signals))
    }

    fn older_than_all(&self, serial: u64) -> bool {
        !self.open.is_empty() && self.open.iter().all(|g| serial < g.serial)
    }

    fn dispose_open(&mut self, now_ms: i64, evs: &mut Vec<Event>) {
        let old = std::mem::take(&mut self.open);
        for g in old {
            self.settle_now(g, now_ms, evs);
        }
    }

    fn close_older_complete(&mut self, serial: u64, now_ms: i64, evs: &mut Vec<Event>) {
        let mut i = 0;
        while i < self.open.len() {
            if self.open[i].serial < serial && exec_complete(&self.open[i]) {
                let g = self.open.remove(i);
                self.settle_now(g, now_ms, evs);
            } else {
                i += 1;
            }
        }
    }

    fn evict_one(&mut self, now_ms: i64, evs: &mut Vec<Event>) -> bool {
        let Some(i) = lowest_index(&self.open) else {
            return false;
        };
        let g = self.open.remove(i);
        self.capped = true;
        self.settle_now(g, now_ms, evs);
        true
    }

    fn make_room(&mut self, now_ms: i64, evs: &mut Vec<Event>) {
        while self.open.len() >= MAX_OPEN {
            if !self.evict_one(now_ms, evs) {
                break;
            }
        }
    }

    fn ensure_group(
        &mut self,
        serial: u64,
        time: &str,
        time_us: u128,
        now_ms: i64,
        evs: &mut Vec<Event>,
    ) -> Option<usize> {
        if let Some(i) = self.open.iter().position(|g| g.serial == serial) {
            self.note_serial(serial);
            return Some(i);
        }
        if self.older_than_all(serial) {
            if self.open.iter().all(|g| time_us > g.time_us) {
                self.dispose_open(now_ms, evs);
                self.seen_max = None;
            } else {
                return None;
            }
        }
        self.note_serial(serial);
        self.close_older_complete(serial, now_ms, evs);
        self.make_room(now_ms, evs);
        self.open.push(Group::new(serial, time, time_us));
        self.open.len().checked_sub(1)
    }

    fn close_at(&mut self, idx: usize, now_ms: i64, evs: &mut Vec<Event>) {
        if idx >= self.open.len() {
            return;
        }
        let g = self.open.remove(idx);
        self.settle_now(g, now_ms, evs);
    }

    fn ingest_line(&mut self, line: &str, now_ms: i64, evs: &mut Vec<Event>) {
        let Some(rec) = parse_record(line) else {
            return;
        };
        let Some(idx) = self.ensure_group(rec.serial, rec.time, rec.time_us, now_ms, evs) else {
            return;
        };
        match rec.kind {
            "EOE" => {
                if let Some(g) = self.open.get_mut(idx) {
                    g.mark(F_EOE);
                }
                self.close_at(idx, now_ms, evs);
            }
            "SYSCALL" => {
                if let Some(g) = self.open.get_mut(idx) {
                    apply_syscall(g, rec.body);
                }
            }
            "EXECVE" => {
                if let Some(g) = self.open.get_mut(idx) {
                    apply_execve(g, rec.body);
                }
                if self.open.get(idx).is_some_and(|g| g.has(F_BAD)) {
                    self.close_at(idx, now_ms, evs);
                }
            }
            _ => {}
        }
    }

    fn end_poll(&mut self, now_ms: i64, evs: &mut Vec<Event>) {
        let groups = std::mem::take(&mut self.open);
        let newest = self.seen_max;
        for g in groups {
            let hold = newest == Some(g.serial);
            if let Some(kept) = self.settle(g, now_ms, evs, hold) {
                self.open.push(kept);
            }
        }
    }

    fn drain_tail(&mut self, now_ms: i64, evs: &mut Vec<Event>) {
        let shown = shown_path(&self.ctx.root, self.tailer.path());
        let output = self.tailer.poll();
        for anomaly in &output.anomalies {
            evs.push(tamper(now_ms, &shown, anomaly));
        }
        for line in &output.lines {
            self.ingest_line(line, now_ms, evs);
        }
    }

    fn coverage_for(&self, shown: &str) -> Coverage {
        if !self.tailer.is_open() {
            return coverage(
                "auditd",
                CoverageStatus::Unsupported,
                "no /var/log/audit/audit.log",
            );
        }
        if !self.capped && self.loud_drops == 0 {
            return coverage(
                "auditd",
                CoverageStatus::Completed,
                format!("tailing {shown}"),
            );
        }
        let mut detail = format!("tailing {shown}");
        if self.capped {
            detail.push_str("; audit id table full");
        }
        if self.loud_drops > 0 {
            let n = self.loud_drops;
            detail.push_str(&format!("; dropped {n} incomplete exec records"));
        }
        coverage("auditd", CoverageStatus::Partial, detail)
    }
}

impl Source for AuditSource {
    fn id(&self) -> &'static str {
        "auditd"
    }

    fn interval(&self) -> Duration {
        let secs = if self.cfg.interval_secs == 0 {
            DEFAULT_INTERVAL_SECS
        } else {
            self.cfg.interval_secs
        };
        Duration::from_secs(secs)
    }

    fn poll(&mut self, now_ms: i64, out: &mut Vec<Event>) {
        self.loud_drops = 0;
        self.capped = false;
        self.seen_max = self.open.iter().map(|g| g.serial).max();
        let mut evs = Vec::new();
        self.drain_tail(now_ms, &mut evs);
        self.end_poll(now_ms, &mut evs);
        cap_events("auditd", now_ms, evs, MAX_EVENTS_PER_POLL, out);
        let shown = shown_path(&self.ctx.root, self.tailer.path());
        self.health = self.coverage_for(&shown);
    }

    fn health(&self) -> Coverage {
        self.health.clone()
    }
}

fn shown_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).map_or_else(
        |_| path.display().to_string(),
        |p| format!("/{}", p.display()),
    )
}

fn tamper(now_ms: i64, path: &str, anomaly: &Anomaly) -> Event {
    let (rule, reason, detail) = match anomaly {
        Anomaly::Truncated { from, to } => (
            "auditlog.truncated",
            "truncated",
            format!("{path} shrank from {from} to {to} bytes"),
        ),
        Anomaly::Replaced {
            old_inode,
            new_inode,
            old_unlinked,
        } => (
            "auditlog.replaced",
            "replaced",
            format!(
                "{path} replaced in place (inode {old_inode} -> {new_inode}, old unlinked: {old_unlinked}); typical of sed -i"
            ),
        ),
        Anomaly::Deleted => ("auditlog.deleted", "deleted", format!("{path} was deleted")),
        Anomaly::Symlink => (
            "auditlog.symlink",
            "symlink",
            format!("{path} is now a symlink (not followed)"),
        ),
    };
    Event::new(
        now_ms,
        "auditd",
        EventData::LogTamper {
            path: path.to_owned(),
            reason: reason.to_owned(),
            detail: detail.clone(),
        },
    )
    .with_signals(vec![Signal::new(rule, Severity::High, detail)])
}

fn exec_complete(g: &Group) -> bool {
    if g.has(F_BAD) {
        return false;
    }
    let Some(n) = g.argc else {
        return false;
    };
    n <= MAX_ARGC && g.args.len() == n && g.args.iter().all(Option::is_some)
}

fn raw_argv(g: &Group) -> Option<Vec<String>> {
    let n = g.argc?;
    if g.args.len() < n {
        return None;
    }
    let mut raw = Vec::with_capacity(n);
    for slot in g.args.iter().take(n) {
        raw.push(slot.clone()?);
    }
    Some(raw)
}

fn view_process(g: &Group) -> ProcessInfo {
    ProcessInfo {
        pid: g.pid.unwrap_or(0),
        ppid: g.ppid.unwrap_or(0),
        uid: g.uid.unwrap_or(u32::MAX),
        name: g.comm.clone().unwrap_or_default(),
        exe: g.exe.clone(),
        exe_deleted: false,
        cmdline: Vec::new(),
        cwd: None,
        start_ticks: 0,
        started_at_ms: None,
        container_id: None,
    }
}

fn clip_chars(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or("").to_owned()
}

fn lowest_index(open: &[Group]) -> Option<usize> {
    open.iter()
        .enumerate()
        .min_by_key(|(_, g)| g.serial)
        .map(|(i, _)| i)
}

fn apply_syscall(g: &mut Group, body: &str) {
    if g.has(F_SYSCALL) {
        return;
    }
    let Ok(fields) = scan_fields(body.trim_start()) else {
        return;
    };
    g.mark(F_SYSCALL);
    for (k, v) in fields {
        match k {
            "pid" => g.pid = parse_u32_digits(v),
            "ppid" => g.ppid = parse_u32_digits(v),
            "uid" => g.uid = parse_u32_digits(v),
            "success" => {
                g.success = match v {
                    "yes" => Some(true),
                    "no" => Some(false),
                    _ => None,
                }
            }
            "exe" => fill_text(&mut g.exe, v),
            "comm" => fill_text(&mut g.comm, v),
            _ => {}
        }
    }
}

fn fill_text(slot: &mut Option<String>, raw: &str) {
    if slot.is_some() {
        return;
    }
    if let Ok(v) = decode_encoded(raw) {
        *slot = v;
    }
}

fn apply_execve(g: &mut Group, body: &str) {
    g.mark(F_EXEC);
    if g.has(F_BAD) {
        return;
    }
    let Ok(fields) = scan_fields(body.trim_start()) else {
        g.mark(F_BAD);
        return;
    };
    for (k, v) in fields {
        if k == "argc" {
            note_argc(g, v);
        } else if let Some(idx) = arg_index(k) {
            note_arg(g, idx, v);
        }
    }
    if g.argc.is_some_and(|n| g.args.len() > n) {
        g.mark(F_BAD);
    }
}

fn note_argc(g: &mut Group, raw: &str) {
    match parse_usize_digits(raw) {
        Some(n) if n <= MAX_ARGC => match g.argc {
            Some(prev) if prev != n => g.mark(F_BAD),
            Some(_) => {}
            None => g.argc = Some(n),
        },
        _ => g.mark(F_BAD),
    }
}

fn note_arg(g: &mut Group, idx: usize, raw: &str) {
    if idx >= MAX_ARGC || g.argc.is_some_and(|n| idx >= n) {
        g.mark(F_BAD);
        return;
    }
    let Ok(Some(val)) = decode_encoded(raw) else {
        g.mark(F_BAD);
        return;
    };
    if g.args.len() <= idx {
        g.args.resize(idx + 1, None);
    }
    let Some(slot) = g.args.get_mut(idx) else {
        g.mark(F_BAD);
        return;
    };
    if slot.is_some() {
        g.mark(F_BAD);
        return;
    }
    *slot = Some(val);
}

/// `a` plus 1–3 digits (`a0`, `a10`, `a100`). `a0000` is four digits and is
/// not an index. `auid`, `arch`, and `argc` are not indexes.
fn arg_index(key: &str) -> Option<usize> {
    let rest = key.strip_prefix('a')?;
    if rest.is_empty() || rest.len() > 3 || !rest.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

fn parse_record(line: &str) -> Option<Record<'_>> {
    let s = skip_node(line.trim_start())?;
    let s = s.strip_prefix("type=")?;
    let (kind, rest) = split_token(s)?;
    if kind.is_empty() {
        return None;
    }
    let rest = rest.trim_start().strip_prefix("msg=audit(")?;
    let (stamp, body) = rest.split_once("):")?;
    let (time, serial_s) = stamp.split_once(':')?;
    if time.len() > MAX_TIME_LEN || serial_s.is_empty() || serial_s.len() > MAX_NUM_LEN {
        return None;
    }
    if !serial_s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let serial = serial_s.parse().ok()?;
    let time_us = parse_time_us(time)?;
    Some(Record {
        kind,
        time,
        serial,
        time_us,
        body,
    })
}

fn skip_node(s: &str) -> Option<&str> {
    let Some(rest) = s.strip_prefix("node=") else {
        return Some(s);
    };
    Some(skip_node_value(rest)?.trim_start())
}

fn skip_node_value(s: &str) -> Option<&str> {
    let b = s.as_bytes();
    if b.is_empty() {
        return None;
    }
    if b[0] == b'"' {
        let end = scan_quoted_end(b, 0).ok()?;
        return s.get(end..);
    }
    let (_, rest) = split_token(s)?;
    Some(rest)
}

fn split_token(s: &str) -> Option<(&str, &str)> {
    let end = s
        .as_bytes()
        .iter()
        .position(|c| c.is_ascii_whitespace())
        .unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    Some((s.get(..end)?, s.get(end..)?))
}

fn parse_time_us(time: &str) -> Option<u128> {
    if time.len() > MAX_TIME_LEN {
        return None;
    }
    let (sec_s, frac_s) = time.split_once('.')?;
    if sec_s.is_empty() || sec_s.len() > MAX_NUM_LEN || !digits(sec_s) {
        return None;
    }
    if !(1..=6).contains(&frac_s.len()) || !digits(frac_s) {
        return None;
    }
    let sec: u128 = sec_s.parse().ok()?;
    let frac: u128 = frac_s.parse().ok()?;
    let exp = u32::try_from(6 - frac_s.len()).ok()?;
    let pow = 10u128.checked_pow(exp)?;
    let frac_us = frac.checked_mul(pow)?;
    sec.checked_mul(1_000_000)?.checked_add(frac_us)
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

fn parse_u32_digits(s: &str) -> Option<u32> {
    if s.len() > MAX_NUM_LEN || !digits(s) {
        return None;
    }
    s.parse().ok()
}

fn parse_usize_digits(s: &str) -> Option<usize> {
    if s.len() > MAX_NUM_LEN || !digits(s) {
        return None;
    }
    s.parse().ok()
}

fn scan_fields(body: &str) -> Result<Vec<(&str, &str)>, ()> {
    let b = body.as_bytes();
    let mut i = 0usize;
    let mut fields = Vec::new();
    while i < b.len() {
        i = skip_ws(b, i);
        if i >= b.len() {
            break;
        }
        if fields.len() == MAX_FIELDS {
            return Err(());
        }
        let (key, next) = take_key(body, i)?;
        let (val, next) = take_val(body, next)?;
        fields.push((key, val));
        i = next;
    }
    Ok(fields)
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn is_key_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_key_cont(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn take_key(body: &str, start: usize) -> Result<(&str, usize), ()> {
    let b = body.as_bytes();
    if start >= b.len() || !is_key_start(b[start]) {
        return Err(());
    }
    let mut i = start + 1;
    while i < b.len() && is_key_cont(b[i]) {
        i += 1;
    }
    if i >= b.len() || b[i] != b'=' {
        return Err(());
    }
    let key = body.get(start..i).ok_or(())?;
    Ok((key, i + 1))
}

fn take_val(body: &str, start: usize) -> Result<(&str, usize), ()> {
    let b = body.as_bytes();
    if start >= b.len() {
        return Ok(("", start));
    }
    if b[start] == b'"' {
        let end = scan_quoted_end(b, start)?;
        let val = body.get(start..end).ok_or(())?;
        return Ok((val, end));
    }
    let mut i = start;
    while i < b.len() && !b[i].is_ascii_whitespace() {
        i += 1;
    }
    let val = body.get(start..i).ok_or(())?;
    Ok((val, i))
}

fn scan_quoted_end(b: &[u8], start: usize) -> Result<usize, ()> {
    let mut i = start + 1;
    while i < b.len() {
        if b[i] == b'\\' {
            if i + 1 >= b.len() {
                return Err(());
            }
            i += 2;
            continue;
        }
        if b[i] == b'"' {
            let next = i + 1;
            if next < b.len() && !b[next].is_ascii_whitespace() {
                return Err(());
            }
            return Ok(next);
        }
        i += 1;
    }
    Err(())
}

fn decode_encoded(raw: &str) -> Result<Option<String>, ()> {
    if raw == "(null)" {
        return Ok(None);
    }
    if raw.starts_with('"') {
        return decode_quoted(raw).map(Some);
    }
    decode_hex(raw).map(Some)
}

fn decode_quoted(raw: &str) -> Result<String, ()> {
    let b = raw.as_bytes();
    if b.first() != Some(&b'"') {
        return Err(());
    }
    let mut out = Vec::new();
    let mut i = 1usize;
    while i < b.len() {
        if b[i] == b'"' {
            if i + 1 != b.len() {
                return Err(());
            }
            return lossy_capped(&out);
        }
        if b[i] == b'\\' {
            i = push_escape(&mut out, b, i)?;
        } else {
            out.push(b[i]);
            i += 1;
        }
        if out.len() > MAX_DECODED {
            return Err(());
        }
    }
    Err(())
}

fn push_escape(out: &mut Vec<u8>, b: &[u8], i: usize) -> Result<usize, ()> {
    let n = i + 1;
    if n >= b.len() {
        return Err(());
    }
    match b[n] {
        b'"' => {
            out.push(b'"');
            Ok(n + 1)
        }
        b'\\' => {
            out.push(b'\\');
            Ok(n + 1)
        }
        b'0'..=b'7' => push_octal(out, b, n),
        _ => Err(()),
    }
}

fn push_octal(out: &mut Vec<u8>, b: &[u8], start: usize) -> Result<usize, ()> {
    if start + 2 >= b.len() {
        return Err(());
    }
    let d0 = oct_digit(b[start])?;
    let d1 = oct_digit(b[start + 1])?;
    let d2 = oct_digit(b[start + 2])?;
    let val = d0 * 64 + d1 * 8 + d2;
    if val > 255 {
        return Err(());
    }
    out.push(u8::try_from(val).map_err(|_| ())?);
    Ok(start + 3)
}

fn oct_digit(c: u8) -> Result<u16, ()> {
    if (b'0'..=b'7').contains(&c) {
        Ok(u16::from(c - b'0'))
    } else {
        Err(())
    }
}

fn decode_hex(raw: &str) -> Result<String, ()> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) || raw.len() / 2 > MAX_DECODED {
        return Err(());
    }
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(raw.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = hex_val(b[i])?;
        let lo = hex_val(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    lossy_capped(&out)
}

fn lossy_capped(out: &[u8]) -> Result<String, ()> {
    if out.len() > MAX_DECODED {
        return Err(());
    }
    Ok(String::from_utf8_lossy(out).into_owned())
}

fn hex_val(c: u8) -> Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Arc;

    const NOW: i64 = 1_700_000_000_000;

    fn src(root: &std::path::Path) -> AuditSource {
        let ctx = Ctx {
            root: root.to_path_buf(),
            ind: Arc::new(nocve_proto::Indicators::builtin().unwrap()),
        };
        AuditSource::new(ctx, SourceToggle::default())
    }

    fn audit_path(root: &std::path::Path) -> PathBuf {
        root.join("var/log/audit/audit.log")
    }

    fn append(p: &std::path::Path, s: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .unwrap()
            .write_all(s.as_bytes())
            .unwrap();
    }

    fn live(root: &std::path::Path) -> AuditSource {
        let p = audit_path(root);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::File::create(&p).unwrap();
        let mut s = src(root);
        let mut evs = Vec::new();
        s.poll(NOW, &mut evs);
        assert!(evs.is_empty());
        s
    }

    fn feed(s: &mut AuditSource, root: &std::path::Path, text: &str) -> Vec<Event> {
        append(&audit_path(root), text);
        let mut evs = Vec::new();
        s.poll(NOW, &mut evs);
        evs
    }

    fn rec(ty: &str, time: &str, serial: u64, body: &str) -> String {
        format!("type={ty} msg=audit({time}:{serial}): {body}\n")
    }

    fn dumped(evs: &[Event]) -> String {
        serde_json::to_string(evs).unwrap()
    }

    fn execs(evs: &[Event]) -> Vec<&AuditExecInfo> {
        evs.iter()
            .filter_map(|e| match &e.data {
                EventData::AuditExec(info) => Some(info),
                _ => None,
            })
            .collect()
    }

    fn hex_encode(s: &str) -> String {
        s.bytes().fold(String::new(), |mut out, b| {
            out.push_str(&format!("{b:02X}"));
            out
        })
    }

    #[test]
    fn id_and_default_interval() {
        let dir = tempfile::tempdir().unwrap();
        let s = src(dir.path());
        assert_eq!(s.id(), "auditd");
        assert_eq!(s.interval(), Duration::from_secs(2));
        assert_eq!(s.health().status, CoverageStatus::Skipped);
        let custom = AuditSource::new(
            Ctx {
                root: dir.path().to_path_buf(),
                ind: Arc::new(nocve_proto::Indicators::builtin().unwrap()),
            },
            SourceToggle {
                enabled: true,
                interval_secs: 9,
            },
        );
        assert_eq!(custom.interval(), Duration::from_secs(9));
    }

    #[test]
    fn complete_exec_masks_argv_and_ignores_syscall_registers() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let time = "1700000001.123456";
        let mut text = format!(
            "node=testhost type=SYSCALL msg=audit({time}:100): arch=c000003e syscall=59 \
             success=yes exit=0 a0=7ffd1234 a1=0 a2=7ffd5678 a3=0 items=1 ppid=10 pid=20 \
             auid=0 uid=1000 comm=\"curl\" exe=\"/usr/bin/curl\" key=(null)\n"
        );
        text.push_str(&rec(
            "EXECVE",
            time,
            100,
            r#"argc=3 a0="curl" a1="https://example" a2="--password=hunter2" a0_len=4"#,
        ));
        text.push_str(&rec("CWD", time, 100, r#"cwd="/tmp""#));
        text.push_str(&rec("PROCTITLE", time, 100, "proctitle=6375726C"));
        text.push_str(&rec("EOE", time, 100, ""));
        let evs = feed(&mut s, root, &text);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].source, "auditd");
        assert_eq!(evs[0].kind(), "audit.exec");
        assert!(evs[0].signals.is_empty());
        assert_eq!(evs[0].observed_at_ms, NOW);
        let info = execs(&evs)[0];
        assert_eq!(info.serial, 100);
        assert_eq!(info.audit_time, time);
        assert_eq!(info.pid, Some(20));
        assert_eq!(info.ppid, Some(10));
        assert_eq!(info.uid, Some(1000));
        assert_eq!(info.success, Some(true));
        assert_eq!(info.exe.as_deref(), Some("/usr/bin/curl"));
        assert_eq!(info.comm.as_deref(), Some("curl"));
        assert_eq!(info.argc, 3);
        assert_eq!(
            info.argv,
            vec![
                "curl".to_owned(),
                "https://example".to_owned(),
                "--password=<masked>".to_owned()
            ]
        );
        let js = dumped(&evs);
        assert!(!js.contains("hunter2"));
        assert!(js.contains("<masked>"));
        assert!(!js.contains("msg=audit"));
        assert!(!js.contains("PROCTITLE"));
        assert!(!js.contains("6375726C"));
        assert!(!js.contains("7ffd1234"));
        assert_eq!(s.health().status, CoverageStatus::Completed);
    }

    #[test]
    fn short_lived_miner_is_critical_on_audit_exec() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let time = "1700000002.000001";
        let text = format!(
            "{}{}{}",
            rec(
                "SYSCALL",
                time,
                7,
                r#"success=yes pid=9 ppid=1 uid=0 comm="xmrig" exe="/opt/.cache/xmrig""#
            ),
            rec(
                "EXECVE",
                time,
                7,
                r#"argc=2 a0="xmrig" a1="--donate-level=1""#
            ),
            rec("EOE", time, 7, "")
        );
        let evs = feed(&mut s, root, &text);
        let ev = evs.iter().find(|e| e.kind() == "audit.exec").unwrap();
        assert!(
            ev.signals.iter().any(|sig| {
                sig.rule == "proc.miner_cmdline" && sig.severity == Severity::Critical
            })
        );
        assert_eq!(ev.max_severity(), Some(Severity::Critical));
    }

    #[test]
    fn non_exec_records_stay_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let text = format!(
            "{}{}{}{}",
            rec(
                "USER_AUTH",
                "1700000010.000001",
                10,
                r#"pid=1 uid=0 auid=0 ses=1 msg='op=login acct="root" exe="/usr/sbin/sshd" hostname=? addr=1.2.3.4 terminal=ssh res=success'"#
            ),
            rec("EOE", "1700000010.000001", 10, ""),
            rec(
                "SYSCALL",
                "1700000010.000002",
                11,
                r#"arch=c000003e syscall=1 success=yes exit=0 a0=7ffd1234 a1=0 a2=0 a3=0 items=0 ppid=1 pid=2 uid=0 comm="cat" exe="/bin/cat""#
            ),
            rec("EOE", "1700000010.000002", 11, "")
        );
        let evs = feed(&mut s, root, &text);
        assert!(evs.is_empty());
        assert!(s.open.is_empty());
        assert_eq!(s.health().status, CoverageStatus::Completed);
        assert_eq!(s.health().detail, "tailing /var/log/audit/audit.log");
    }

    #[test]
    fn incomplete_exec_is_a_loud_drop() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let text = format!(
            "{}{}",
            rec(
                "EXECVE",
                "1700000011.000001",
                10,
                r#"argc=3 a0="partial-secret" a1="only-two""#
            ),
            rec("EXECVE", "1700000011.000002", 11, r#"argc=1 a0="kept-ok""#)
        );
        text_push_eoe(&mut s, root, &text);
    }

    fn text_push_eoe(s: &mut AuditSource, root: &std::path::Path, text: &str) {
        let mut full = text.to_owned();
        full.push_str(&rec("EOE", "1700000011.000002", 11, ""));
        let evs = feed(s, root, &full);
        let got = execs(&evs);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].argv, vec!["kept-ok".to_owned()]);
        let js = dumped(&evs);
        assert!(!js.contains("partial-secret"));
        assert_eq!(s.health().status, CoverageStatus::Partial);
        assert!(s.health().detail.contains("dropped"));
    }

    #[test]
    fn syscall_then_execve_across_polls_and_same_poll_merge() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let time = "1700000012.000001";
        let evs = feed(
            &mut s,
            root,
            &rec(
                "SYSCALL",
                time,
                4,
                r#"success=yes pid=42 ppid=7 uid=1000 comm="curl" exe="/usr/bin/curl""#,
            ),
        );
        assert!(evs.is_empty());
        assert_eq!(s.open.len(), 1);
        assert_eq!(s.health().status, CoverageStatus::Completed);
        let evs = feed(
            &mut s,
            root,
            &format!(
                "{}{}",
                rec("EXECVE", time, 4, r#"argc=1 a0="curl""#),
                rec("EOE", time, 4, "")
            ),
        );
        let got = execs(&evs);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].pid, Some(42));
        assert_eq!(got[0].exe.as_deref(), Some("/usr/bin/curl"));
        assert_eq!(got[0].argv, vec!["curl".to_owned()]);

        let merged = feed(
            &mut s,
            root,
            &format!(
                "{}{}{}",
                rec("EXECVE", "1700000012.000002", 5, r#"argc=2 a0="curl""#),
                rec("EXECVE", "1700000012.000002", 5, r#"a1="https://example""#),
                rec("EOE", "1700000012.000002", 5, "")
            ),
        );
        let got = execs(&merged);
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].argv,
            vec!["curl".to_owned(), "https://example".to_owned()]
        );
    }

    #[test]
    fn bad_records_drop_and_partial_is_not_sticky() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let time = "1700000013.000001";
        let text = format!(
            "{}{}{}{}",
            rec("EXECVE", time, 1, r#"argc=1 a0="unterminated-secret"#),
            rec("EXECVE", time, 2, "argc=1 a0=ABC"),
            rec("EXECVE", time, 3, "argc=1 a0=(null)"),
            rec("EXECVE", time, 4, r#"argc=1 a0="good-arg""#)
        ) + &rec("EOE", time, 4, "");
        let evs = feed(&mut s, root, &text);
        let got = execs(&evs);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].argv, vec!["good-arg".to_owned()]);
        assert!(!dumped(&evs).contains("unterminated-secret"));
        assert_eq!(s.health().status, CoverageStatus::Partial);
        let evs = feed(&mut s, root, "");
        assert!(evs.is_empty());
        assert_eq!(s.health().status, CoverageStatus::Completed);
    }

    #[test]
    fn hex_argv_decodes_then_masks() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let secret = "--password=hunter2";
        let hex = hex_encode(secret);
        let time = "1700000014.000001";
        let body = format!(r#"argc=2 a0="curl" a1={hex}"#);
        let evs = feed(
            &mut s,
            root,
            &format!(
                "{}{}",
                rec("EXECVE", time, 8, &body),
                rec("EOE", time, 8, "")
            ),
        );
        let got = execs(&evs);
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].argv,
            vec!["curl".to_owned(), "--password=<masked>".to_owned()]
        );
        let js = dumped(&evs);
        assert!(!js.contains("hunter2"));
        assert!(!js.contains(&hex));
        assert!(js.contains("<masked>"));
    }

    #[test]
    fn decode_quoted_octal_hex_and_failures() {
        assert_eq!(
            decode_encoded(r#""foo\040bar""#).unwrap().as_deref(),
            Some("foo bar")
        );
        assert_eq!(decode_encoded("2F746D70").unwrap().as_deref(), Some("/tmp"));
        assert_eq!(decode_encoded("2f746d70").unwrap().as_deref(), Some("/tmp"));
        assert_eq!(decode_encoded(r#""""#).unwrap().as_deref(), Some(""));
        assert_eq!(
            decode_encoded(r#""hello world""#).unwrap().as_deref(),
            Some("hello world")
        );
        assert!(decode_encoded("(null)").unwrap().is_none());
        assert!(decode_encoded("ABC").is_err());
        assert!(decode_encoded(r#""unterminated"#).is_err());
        assert!(decode_encoded(r"bad\x41").is_err());
        assert!(decode_encoded(r#""\400""#).is_err());
        assert!(decode_encoded("").is_err());
        let lossy = decode_encoded("FF").unwrap().unwrap();
        assert!(lossy.contains('\u{FFFD}'));
        assert_eq!(
            parse_time_us("1700000001.123").unwrap(),
            parse_time_us("1700000001.123000").unwrap()
        );
        assert!(parse_time_us("1700000001").is_none());
        assert!(arg_index("a0000").is_none());
        assert_eq!(arg_index("a0"), Some(0));
        assert_eq!(arg_index("a10"), Some(10));
        assert!(arg_index("auid").is_none());
        assert!(arg_index("argc").is_none());
        assert!(arg_index("a0_len").is_none());
    }

    #[test]
    fn binary_arg_still_emits() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let evs = feed(
            &mut s,
            root,
            &format!(
                "{}{}",
                rec("EXECVE", "1700000015.000001", 1, "argc=1 a0=FF"),
                rec("EOE", "1700000015.000001", 1, "")
            ),
        );
        let got = execs(&evs);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].argc, 1);
        assert!(got[0].argv[0].contains('\u{FFFD}'));
    }

    #[test]
    fn missing_log_is_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = src(dir.path());
        let mut evs = Vec::new();
        s.poll(NOW, &mut evs);
        assert!(evs.is_empty());
        assert_eq!(s.health().status, CoverageStatus::Unsupported);
        assert_eq!(s.health().detail, "no /var/log/audit/audit.log");
    }

    #[test]
    fn symlink_is_tamper_and_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let real = root.join("real.log");
        std::fs::write(
            &real,
            rec(
                "EXECVE",
                "1700000016.000001",
                1,
                r#"argc=1 a0="symlink-secret""#,
            ) + &rec("EOE", "1700000016.000001", 1, ""),
        )
        .unwrap();
        let path = audit_path(root);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        let mut s = src(root);
        let mut evs = Vec::new();
        s.poll(NOW, &mut evs);
        assert!(execs(&evs).is_empty());
        assert!(!dumped(&evs).contains("symlink-secret"));
        assert!(evs.iter().any(|e| matches!(
            &e.data,
            EventData::LogTamper { reason, .. } if reason == "symlink"
        )));
        assert!(evs.iter().any(|e| {
            e.signals
                .iter()
                .any(|sig| sig.rule == "auditlog.symlink" && sig.severity == Severity::High)
        }));
        assert_eq!(s.health().status, CoverageStatus::Unsupported);
    }

    #[test]
    fn replaced_and_deleted_logs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let path = audit_path(root);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(
            &path,
            format!(
                "{}{}",
                rec(
                    "EXECVE",
                    "1700000017.000001",
                    3,
                    r#"argc=1 a0="after-replace""#
                ),
                rec("EOE", "1700000017.000001", 3, "")
            ),
        )
        .unwrap();
        let mut evs = Vec::new();
        s.poll(NOW, &mut evs);
        assert_eq!(execs(&evs)[0].argv, vec!["after-replace".to_owned()]);
        assert!(evs.iter().any(|e| matches!(
            &e.data,
            EventData::LogTamper { reason, .. } if reason == "replaced"
        )));
        assert!(!evs.iter().any(|e| matches!(
            &e.data,
            EventData::LogTamper { reason, .. } if reason == "deleted"
        )));

        let dir2 = tempfile::tempdir().unwrap();
        let root2 = dir2.path();
        let mut s2 = live(root2);
        std::fs::remove_file(audit_path(root2)).unwrap();
        let mut evs = Vec::new();
        s2.poll(NOW, &mut evs);
        assert!(execs(&evs).is_empty());
        assert!(
            evs.iter()
                .any(|e| e.signals.iter().any(|sig| sig.rule == "auditlog.deleted"))
        );
        assert_eq!(s2.health().status, CoverageStatus::Unsupported);
        let mut again = Vec::new();
        s2.poll(NOW, &mut again);
        assert!(again.is_empty());
    }

    #[test]
    fn open_id_cap_holds_newest_and_ignores_straggler() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let time = "1700000002.000001";
        let mut text = String::new();
        for serial in 1..=33 {
            let arg = if serial == 33 {
                "kept-exec"
            } else {
                "should-not-emit"
            };
            text.push_str(&rec(
                "EXECVE",
                time,
                serial,
                &format!(r#"argc=2 a0="{arg}""#),
            ));
        }
        let evs = feed(&mut s, root, &text);
        assert!(execs(&evs).is_empty());
        assert!(!dumped(&evs).contains("should-not-emit"));
        assert_eq!(s.health().status, CoverageStatus::Partial);
        assert!(s.health().detail.contains("audit id table full"));
        assert!(s.health().detail.contains("dropped"));
        assert_eq!(s.open.len(), 1);
        assert_eq!(s.open[0].serial, 33);
        assert_eq!(s.loud_drops, 32);

        let evs = feed(
            &mut s,
            root,
            &format!(
                "{}{}",
                rec("EXECVE", time, 1, r#"argc=1 a0="straggler-secret""#),
                rec("EXECVE", time, 33, r#"a1="done-arg""#)
            ),
        );
        let got = execs(&evs);
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].argv,
            vec!["kept-exec".to_owned(), "done-arg".to_owned()]
        );
        let js = dumped(&evs);
        assert!(!js.contains("should-not-emit"));
        assert!(!js.contains("straggler-secret"));
        assert_eq!(s.health().status, CoverageStatus::Completed);
        assert_eq!(s.loud_drops, 0);
    }

    #[test]
    fn failed_exec_still_emits() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let evs = feed(
            &mut s,
            root,
            &format!(
                "{}{}{}",
                rec(
                    "SYSCALL",
                    "1700000018.000001",
                    9,
                    r#"success=no pid=3 uid=1 comm="false" exe="/bin/false""#
                ),
                rec("EXECVE", "1700000018.000001", 9, r#"argc=1 a0="false""#),
                rec("EOE", "1700000018.000001", 9, "")
            ),
        );
        let got = execs(&evs);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].success, Some(false));
        assert_eq!(got[0].argv, vec!["false".to_owned()]);
    }

    #[test]
    fn start_at_end_skips_history() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let path = audit_path(root);
        append(
            &path,
            &format!(
                "{}{}",
                rec(
                    "EXECVE",
                    "1700000019.000001",
                    1,
                    r#"argc=1 a0="hist-secret""#
                ),
                rec("EOE", "1700000019.000001", 1, "")
            ),
        );
        let mut s = src(root);
        let mut evs = Vec::new();
        s.poll(NOW, &mut evs);
        assert!(evs.is_empty());
        assert!(!dumped(&evs).contains("hist-secret"));
        let evs = feed(
            &mut s,
            root,
            &format!(
                "{}{}",
                rec("EXECVE", "1700000019.000002", 2, r#"argc=1 a0="live-arg""#),
                rec("EOE", "1700000019.000002", 2, "")
            ),
        );
        assert_eq!(execs(&evs)[0].argv, vec!["live-arg".to_owned()]);
        assert!(!dumped(&evs).contains("hist-secret"));
    }

    #[test]
    fn auditd_restart_accepts_lower_serial_with_newer_time() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let evs = feed(
            &mut s,
            root,
            &rec(
                "EXECVE",
                "1700000030.000001",
                50,
                r#"argc=2 a0="restart-secret""#,
            ),
        );
        assert!(evs.is_empty());
        assert_eq!(s.open.len(), 1);
        assert_eq!(s.health().status, CoverageStatus::Completed);
        let evs = feed(
            &mut s,
            root,
            &format!(
                "{}{}{}",
                rec(
                    "SYSCALL",
                    "1700000031.000001",
                    1,
                    r#"success=yes pid=4 exe="/bin/true""#
                ),
                rec(
                    "EXECVE",
                    "1700000031.000001",
                    1,
                    r#"argc=1 a0="after-restart""#
                ),
                rec("EOE", "1700000031.000001", 1, "")
            ),
        );
        assert_eq!(execs(&evs)[0].argv, vec!["after-restart".to_owned()]);
        assert!(!dumped(&evs).contains("restart-secret"));
        assert_eq!(s.health().status, CoverageStatus::Partial);
    }

    #[test]
    fn equal_time_lower_serial_is_a_straggler() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let time = "1700000032.000001";
        let evs = feed(
            &mut s,
            root,
            &rec("EXECVE", time, 50, r#"argc=2 a0="held-secret""#),
        );
        assert!(evs.is_empty());
        let evs = feed(
            &mut s,
            root,
            &format!(
                "{}{}",
                rec("EXECVE", time, 1, r#"argc=1 a0="same-time-secret""#),
                rec("EOE", time, 1, "")
            ),
        );
        assert!(execs(&evs).is_empty());
        assert!(!dumped(&evs).contains("same-time-secret"));
        assert_eq!(s.open.len(), 1);
        assert_eq!(s.open[0].serial, 50);
        assert_eq!(s.health().status, CoverageStatus::Completed);
        let evs = feed(&mut s, root, &rec("EXECVE", time, 50, r#"a1="done""#));
        assert_eq!(
            execs(&evs)[0].argv,
            vec!["held-secret".to_owned(), "done".to_owned()]
        );
    }

    #[test]
    fn duplicate_arg_drops_without_emitting_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let time = "1700000020.000001";
        let evs = feed(
            &mut s,
            root,
            &format!(
                "{}{}{}{}",
                rec("EXECVE", time, 7, r#"argc=1 a0="dup-secret""#),
                rec("EXECVE", time, 7, r#"a0="second""#),
                rec("EXECVE", time, 8, r#"argc=1 a0="ok-arg""#),
                rec("EOE", time, 8, "")
            ),
        );
        assert_eq!(execs(&evs).len(), 1);
        assert_eq!(execs(&evs)[0].argv, vec!["ok-arg".to_owned()]);
        assert!(!dumped(&evs).contains("dup-secret"));
        assert_eq!(s.health().status, CoverageStatus::Partial);
    }

    #[test]
    fn malformed_fields_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let time = "1700000021.000001";
        let evs = feed(
            &mut s,
            root,
            &format!(
                "{}{}{}{}{}{}{}{}",
                rec("EXECVE", time, 1, r#"argc=1 a0="conflict-secret""#),
                rec("EXECVE", time, 1, "argc=2"),
                rec("EXECVE", time, 2, r#"argc=1 a0[0]="bracket-secret""#),
                rec("EXECVE", time, 3, r#"argc=129 a0="big-secret""#),
                rec(
                    "EXECVE",
                    time,
                    4,
                    r#"argc=1 a0="slot-ok" a1="overflow-secret""#
                ),
                rec("EXECVE", time, 5, r#"argc=1 a0="trail"x"#),
                rec("EXECVE", time, 6, r#"argc=1 a0="survivor""#),
                rec("EOE", time, 6, "")
            ),
        );
        assert_eq!(execs(&evs).len(), 1);
        assert_eq!(execs(&evs)[0].argv, vec!["survivor".to_owned()]);
        let js = dumped(&evs);
        for secret in [
            "conflict-secret",
            "bracket-secret",
            "big-secret",
            "overflow-secret",
            "slot-ok",
        ] {
            assert!(!js.contains(secret), "{secret} leaked");
        }
        assert_eq!(s.health().status, CoverageStatus::Partial);
    }

    #[test]
    fn logrotate_to_sibling_is_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let path = audit_path(root);
        let evs = feed(
            &mut s,
            root,
            &format!(
                "{}{}",
                rec(
                    "EXECVE",
                    "1700000022.000001",
                    1,
                    r#"argc=1 a0="rotate-old""#
                ),
                rec("EOE", "1700000022.000001", 1, "")
            ),
        );
        assert_eq!(execs(&evs)[0].argv, vec!["rotate-old".to_owned()]);
        std::fs::rename(&path, path.with_file_name("audit.log.1")).unwrap();
        std::fs::write(
            &path,
            format!(
                "{}{}",
                rec(
                    "EXECVE",
                    "1700000022.000002",
                    2,
                    r#"argc=1 a0="rotate-new""#
                ),
                rec("EOE", "1700000022.000002", 2, "")
            ),
        )
        .unwrap();
        let mut evs = Vec::new();
        s.poll(NOW, &mut evs);
        assert_eq!(execs(&evs)[0].argv, vec!["rotate-new".to_owned()]);
        assert!(evs.iter().all(|e| e.kind() != "log.tamper"));
    }

    #[test]
    fn truncated_log_is_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut s = live(root);
        let path = audit_path(root);
        let _ = feed(&mut s, root, &rec("EOE", "1700000023.000001", 1, ""));
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let mut evs = Vec::new();
        s.poll(NOW, &mut evs);
        assert!(evs.iter().any(|e| {
            e.signals
                .iter()
                .any(|sig| sig.rule == "auditlog.truncated" && sig.severity == Severity::High)
        }));
    }
}
