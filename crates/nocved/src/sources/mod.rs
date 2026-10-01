//! Pluggable, bounded event sources. The auditd source tails `execve` records
//! on 4.19 and 6.1. An eBPF source (6.1 hosts) implements the same trait later
//! (DESIGN.md section 11).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use nocve_proto::{Coverage, CoverageStatus, Event, EventData, Indicators};

pub mod audit;
pub mod authlog;
pub mod docker;
pub mod net;
pub mod packages;
pub mod persistence;
pub mod process;
pub mod tail;

/// Upper bound on events one poll of one source may emit; the rest is
/// summarised as `source.truncated`.
pub const MAX_EVENTS_PER_POLL: usize = 1000;

pub trait Source: Send {
    fn id(&self) -> &'static str;
    fn interval(&self) -> Duration;
    fn poll(&mut self, now_ms: i64, out: &mut Vec<Event>);
    fn health(&self) -> Coverage;
}

/// Shared read context: filesystem root and indicator lists.
#[derive(Debug, Clone)]
pub struct Ctx {
    pub root: PathBuf,
    pub ind: Arc<Indicators>,
}

impl Ctx {
    #[must_use]
    pub fn path(&self, abs: &str) -> PathBuf {
        self.root.join(abs.trim_start_matches('/'))
    }

    /// True when there is no procfs under the root (e.g. macOS).
    #[must_use]
    pub fn no_procfs(&self) -> bool {
        !self.path("/proc/stat").exists()
    }
}

#[must_use]
pub fn coverage(source: &str, status: CoverageStatus, detail: impl Into<String>) -> Coverage {
    Coverage {
        source: source.to_owned(),
        status,
        detail: detail.into(),
    }
}

/// Enforces the per-poll cap, appending a `source.truncated` summary.
pub fn cap_events(
    source: &'static str,
    now_ms: i64,
    mut evs: Vec<Event>,
    cap: usize,
    out: &mut Vec<Event>,
) {
    if evs.len() > cap {
        // Keep the most severe events when trimming.
        evs.sort_by_key(|e| std::cmp::Reverse(e.max_severity()));
        let dropped = (evs.len() - cap) as u64;
        evs.truncate(cap);
        evs.sort_by_key(|e| e.observed_at_ms);
        out.extend(evs);
        out.push(Event::new(
            now_ms,
            source,
            EventData::SourceTruncated {
                source_id: source.to_owned(),
                dropped,
            },
        ));
    } else {
        out.extend(evs);
    }
}

/// `log.tamper` events (rule `{prefix}.truncated|replaced|rewritten|deleted|symlink`)
/// and `log.skipped` events for one tailer poll. Shared by every log source.
pub fn tail_events(
    source: &'static str,
    prefix: &str,
    now_ms: i64,
    path: &str,
    o: &tail::TailOutput,
    evs: &mut Vec<Event>,
) {
    use nocve_proto::{Severity, Signal};
    use tail::Anomaly;
    for anomaly in &o.anomalies {
        let (reason, detail) = match anomaly {
            Anomaly::Truncated { from, to } => (
                "truncated",
                format!("{path} shrank from {from} to {to} bytes"),
            ),
            Anomaly::Replaced {
                old_inode,
                new_inode,
                old_unlinked,
            } => (
                "replaced",
                format!(
                    "{path} replaced in place (inode {old_inode} -> {new_inode}, old unlinked: {old_unlinked}); typical of sed -i"
                ),
            ),
            Anomaly::Rewritten { offset } => (
                "rewritten",
                format!(
                    "{path}: bytes before offset {offset} changed in place (already-read lines edited)"
                ),
            ),
            Anomaly::Deleted => ("deleted", format!("{path} was deleted")),
            Anomaly::Symlink => ("symlink", format!("{path} is now a symlink (not followed)")),
        };
        evs.push(
            Event::new(
                now_ms,
                source,
                EventData::LogTamper {
                    path: path.to_owned(),
                    reason: reason.to_owned(),
                    detail: detail.clone(),
                },
            )
            .with_signals(vec![Signal::new(
                &format!("{prefix}.{reason}"),
                Severity::High,
                detail,
            )]),
        );
    }
    for s in &o.skipped {
        let detail = format!(
            "{path}: {} bytes were lost before they could be read ({})",
            s.bytes, s.reason
        );
        evs.push(
            Event::new(
                now_ms,
                source,
                EventData::LogSkipped {
                    path: path.to_owned(),
                    bytes: s.bytes,
                    reason: s.reason.to_owned(),
                },
            )
            .with_signals(vec![Signal::new("log.skipped", Severity::High, detail)]),
        );
    }
}

/// Coverage detail suffix for tail lag; lag over this many bytes is partial coverage.
pub const LAG_PARTIAL_BYTES: u64 = 8 * 1024 * 1024;
