//! Pluggable, bounded event sources. An eBPF source (6.1 hosts) or an auditd
//! source (4.19 hosts) implements the same trait later (DESIGN.md section 11).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use nocve_proto::{Coverage, CoverageStatus, Event, EventData, Indicators};

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
