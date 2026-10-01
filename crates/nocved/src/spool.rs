//! Bounded on-disk spool of chained envelopes plus chain state.
//!
//! Events are chained only when they enter the spool; a full spool drops
//! events *before* chaining and later reports the count in a chained
//! `sensor.events_dropped` event, so the sensor never creates a chain gap.
//! Local state is untrusted (root can rewrite it); tampering shows up at the
//! store as a gap, rewrite, rollback or epoch reset.

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fsutil::write_atomic_0600;
use nocve_proto::chain::{EPOCH_BYTES, decode_hex};
use nocve_proto::{Chainer, Envelope, Event, EventData, MacKey, Severity};

const REJECTED_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct State {
    host: String,
    epoch: String,
    next_seq: u64,
    head: String,
    hb_counter: u64,
    acked_through: Option<u64>,
    /// Fingerprint of the MAC key the chain was sealed with. A different key
    /// (rekey) starts a new epoch: envelopes MACed with the old key can never
    /// verify at the store.
    #[serde(default)]
    key_fp: Option<String>,
}

/// Non-secret fingerprint of a MAC key (state file only).
fn key_fp(key: &MacKey) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"nocve-spool-keyfp-v1");
    h.update(key.to_bytes());
    hex::encode(&h.finalize()[..8])
}

pub struct Spool {
    dir: PathBuf,
    chainer: Chainer,
    queue: VecDeque<(u64, String)>,
    queue_bytes: u64,
    file_bytes: u64,
    max_bytes: u64,
    hb_counter: u64,
    acked_through: Option<u64>,
    dropped_pending: u64,
    dropped_since_ms: i64,
    pub dropped_total: u64,
    pub new_epoch: bool,
    feed: Option<crate::feed::Feed>,
    feed_errors: u64,
}

impl Spool {
    /// Opens (or creates) the spool in `dir` (created 0700).
    pub fn open(dir: &Path, host: &str, key: MacKey, max_bytes: u64) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        let state: Option<State> = std::fs::read(dir.join("state.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .filter(|s: &State| s.host == host);
        let fp = key_fp(&key);
        let rekeyed = state
            .as_ref()
            .is_some_and(|s| s.key_fp.as_deref().is_some_and(|k| k != fp));
        if rekeyed {
            // Keep the old-key envelopes for aftercve; they are never resent.
            let old = dir.join("spool.jsonl");
            if old.exists() {
                std::fs::rename(&old, dir.join("spool.rekeyed.jsonl"))
                    .map_err(|e| format!("{}: {e}", old.display()))?;
            }
            eprintln!("nocved: host key changed; starting a new chain epoch");
        }
        let state = state.filter(|_| !rekeyed);
        let resumed = state.as_ref().and_then(|s| {
            let epoch = decode_hex::<EPOCH_BYTES>(&s.epoch, "epoch").ok()?;
            let head = decode_hex::<32>(&s.head, "head").ok()?;
            Some((epoch, head, s))
        });
        let (mut chainer, hb, acked, new_epoch) = match resumed {
            Some((epoch, head, s)) => (
                Chainer::resume(host, key.clone(), epoch, s.next_seq, head),
                s.hb_counter,
                s.acked_through,
                false,
            ),
            None => (
                Chainer::new_epoch(host, key.clone()).map_err(|e| format!("CSPRNG: {e}"))?,
                0,
                None,
                true,
            ),
        };
        let mut queue = VecDeque::new();
        let mut queue_bytes = 0;
        if !new_epoch && let Ok(text) = std::fs::read_to_string(dir.join("spool.jsonl")) {
            let epoch_hex = chainer.epoch_hex();
            for line in text.lines() {
                let Ok(env) = serde_json::from_str::<Envelope>(line) else {
                    continue;
                };
                if env.epoch != epoch_hex || acked.is_some_and(|a| env.seq <= a) {
                    continue;
                }
                // Crash between spool append and state write: advance the
                // chain to the last spooled envelope (verified with our key).
                if env.seq >= chainer.next_seq() {
                    if let Ok(v) = env.verify(&key) {
                        chainer = Chainer::resume(host, key.clone(), v.epoch, env.seq + 1, v.link);
                    } else {
                        continue;
                    }
                }
                queue_bytes += line.len() as u64 + 1;
                queue.push_back((env.seq, line.to_owned()));
            }
        }
        let mut s = Self {
            dir: dir.to_path_buf(),
            chainer,
            queue,
            queue_bytes,
            file_bytes: 0,
            max_bytes,
            hb_counter: hb,
            acked_through: acked,
            dropped_pending: 0,
            dropped_since_ms: 0,
            dropped_total: 0,
            new_epoch,
            feed: None,
            feed_errors: 0,
        };
        s.compact().map_err(|e| format!("spool compact: {e}"))?;
        s.save_state().map_err(|e| format!("state: {e}"))?;
        Ok(s)
    }

    fn save_state(&self) -> std::io::Result<()> {
        let st = State {
            host: self.chainer.host().to_owned(),
            epoch: self.chainer.epoch_hex(),
            next_seq: self.chainer.next_seq(),
            head: hex::encode(self.chainer.head()),
            hb_counter: self.hb_counter,
            acked_through: self.acked_through,
            key_fp: Some(key_fp(self.chainer.key())),
        };
        let b = serde_json::to_vec(&st).map_err(std::io::Error::other)?;
        write_atomic_0600(&self.dir.join("state.json"), &b)
    }

    fn compact(&mut self) -> std::io::Result<()> {
        let mut buf = String::with_capacity(usize::try_from(self.queue_bytes).unwrap_or(0));
        for (_, l) in &self.queue {
            buf.push_str(l);
            buf.push('\n');
        }
        write_atomic_0600(&self.dir.join("spool.jsonl"), buf.as_bytes())?;
        self.file_bytes = buf.len() as u64;
        Ok(())
    }

    fn append(&mut self, line: &str) -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.dir.join("spool.jsonl"))?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        self.file_bytes += line.len() as u64 + 1;
        Ok(())
    }

    fn seal_and_append(&mut self, ev: &Event) -> Result<(), String> {
        let payload = serde_json::to_string(ev).map_err(|e| e.to_string())?;
        if payload.len() > nocve_proto::MAX_PAYLOAD_BYTES {
            return Err("event payload too large".into());
        }
        // Seal on a copy and commit the chain state only after the append
        // succeeded: a failed write must not advance seq/head (that would be a
        // gap the sensor made itself).
        let mut next = self.chainer.clone();
        let env = next.seal(payload);
        let line = serde_json::to_string(&env).map_err(|e| e.to_string())?;
        self.append(&line)
            .map_err(|e| format!("spool append: {e}"))?;
        self.chainer = next;
        if let Some(f) = self.feed.as_mut() {
            crate::feed::append_logged(f, &line, &mut self.feed_errors);
        }
        self.queue_bytes += line.len() as u64 + 1;
        self.queue.push_back((env.seq, line));
        Ok(())
    }

    /// Adds an event. Returns false if it was dropped (spool full or too large).
    pub fn push(&mut self, ev: &Event) -> bool {
        let high = ev.max_severity().is_some_and(|s| s >= Severity::High);
        let limit = if high {
            self.max_bytes + self.max_bytes / 4
        } else {
            self.max_bytes
        };
        if self.queue_bytes >= limit {
            if self.dropped_pending == 0 {
                self.dropped_since_ms = ev.observed_at_ms;
            }
            self.dropped_pending += 1;
            self.dropped_total += 1;
            return false;
        }
        if self.dropped_pending > 0 {
            let d = Event::new(
                ev.observed_at_ms,
                "sensor",
                EventData::EventsDropped {
                    count: self.dropped_pending,
                    since_ms: self.dropped_since_ms,
                },
            )
            .with_signals(vec![nocve_proto::Signal::new(
                "sensor.events_dropped",
                Severity::High,
                format!(
                    "{} events dropped while the spool was full",
                    self.dropped_pending
                ),
            )]);
            if self.seal_and_append(&d).is_ok() {
                self.dropped_pending = 0;
            }
        }
        match self.seal_and_append(ev) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("nocved: spool: {e}");
                self.dropped_pending += 1;
                self.dropped_total += 1;
                false
            }
        }
    }

    /// Persists chain state (call once per loop iteration).
    pub fn flush(&mut self) -> Result<(), String> {
        if let Ok(f) = OpenOptions::new()
            .append(true)
            .open(self.dir.join("spool.jsonl"))
        {
            f.sync_data().map_err(|e| e.to_string())?;
        }
        self.save_state().map_err(|e| e.to_string())
    }

    /// Up to `max_events` / `max_bytes` envelopes from the front.
    #[must_use]
    pub fn peek(&self, max_events: usize, max_bytes: usize) -> Vec<(u64, String)> {
        let mut out = Vec::new();
        let mut bytes = 2;
        for (seq, l) in self.queue.iter().take(max_events) {
            if bytes + l.len() + 1 > max_bytes && !out.is_empty() {
                break;
            }
            bytes += l.len() + 1;
            out.push((*seq, l.clone()));
        }
        out
    }

    /// Drops everything with seq <= `through` (acknowledged by the store).
    pub fn ack(&mut self, through: u64) -> Result<(), String> {
        while self.queue.front().is_some_and(|(s, _)| *s <= through) {
            if let Some((_, l)) = self.queue.pop_front() {
                self.queue_bytes = self.queue_bytes.saturating_sub(l.len() as u64 + 1);
            }
        }
        self.acked_through = Some(through);
        if self.file_bytes > 2 * self.queue_bytes + 64 * 1024 || self.queue.is_empty() {
            self.compact().map_err(|e| e.to_string())?;
        }
        self.save_state().map_err(|e| e.to_string())
    }

    /// Moves a rejected batch aside (bounded) and acks it so shipping continues.
    pub fn reject(&mut self, batch: &[(u64, String)], reason: &str) -> Result<(), String> {
        let p = self.dir.join("rejected.jsonl");
        let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        if size < REJECTED_MAX_BYTES {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&p)
                .map_err(|e| e.to_string())?;
            for (_, l) in batch {
                writeln!(
                    f,
                    "{{\"reason\":{},\"envelope\":{l}}}",
                    serde_json::Value::String(reason.to_owned())
                )
                .map_err(|e| e.to_string())?;
            }
        }
        match batch.last() {
            Some((seq, _)) => self.ack(*seq),
            None => Ok(()),
        }
    }

    /// Mirrors every newly spooled envelope line into a read-only feed.
    pub fn set_feed(&mut self, feed: crate::feed::Feed) {
        self.feed = Some(feed);
    }

    /// Feed lines skipped `(too long, burst)`, or `None` without a feed.
    #[must_use]
    pub fn feed_skipped(&self) -> Option<(u64, u64)> {
        self.feed.as_ref().map(crate::feed::Feed::skipped)
    }

    pub fn next_heartbeat_counter(&mut self) -> Result<u64, String> {
        self.hb_counter += 1;
        self.save_state().map_err(|e| e.to_string())?;
        Ok(self.hb_counter)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.queue_bytes
    }
    #[must_use]
    pub fn chainer(&self) -> &Chainer {
        &self.chainer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nocve_proto::Signal;

    fn key() -> MacKey {
        MacKey::derive(&[7; 32])
    }

    fn ev(i: i64, sev: Option<Severity>) -> Event {
        let e = Event::new(
            i,
            "t",
            EventData::EventsDropped {
                count: 0,
                since_ms: i,
            },
        );
        match sev {
            Some(s) => e.with_signals(vec![Signal::new("x", s, "y")]),
            None => e,
        }
    }

    #[test]
    fn persists_and_resumes_chain() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(d.path(), "h", key(), 1 << 20).unwrap();
        assert!(s.new_epoch);
        for i in 0..3 {
            assert!(s.push(&ev(i, None)));
        }
        s.flush().unwrap();
        s.ack(0).unwrap();
        let epoch = s.chainer().epoch_hex();
        drop(s);
        let s2 = Spool::open(d.path(), "h", key(), 1 << 20).unwrap();
        assert!(!s2.new_epoch);
        assert_eq!(s2.chainer().epoch_hex(), epoch);
        assert_eq!(s2.len(), 2);
        assert_eq!(s2.chainer().next_seq(), 3);
    }

    #[test]
    fn crash_before_state_write_recovers_from_spool() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(d.path(), "h", key(), 1 << 20).unwrap();
        s.push(&ev(1, None));
        s.flush().unwrap();
        s.push(&ev(2, None)); // appended, state not saved
        drop(s);
        let s2 = Spool::open(d.path(), "h", key(), 1 << 20).unwrap();
        assert_eq!(s2.chainer().next_seq(), 2);
        assert_eq!(s2.len(), 2);
    }

    #[test]
    fn full_spool_drops_before_chaining_then_reports() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(d.path(), "h", key(), 64 * 1024).unwrap();
        let mut dropped = 0;
        for i in 0..2000 {
            if !s.push(&ev(i, None)) {
                dropped += 1;
            }
        }
        assert!(dropped > 0);
        let before = s.chainer().next_seq();
        let all = s.peek(10_000, usize::MAX);
        s.ack(all[all.len() / 2].0).unwrap();
        assert!(s.push(&ev(10_000, None)));
        assert_eq!(
            s.chainer().next_seq(),
            before + 2,
            "dropped-count event + the new event"
        );
        let last = s.peek(10_000, usize::MAX);
        let env: Envelope = serde_json::from_str(&last[last.len() - 2].1).unwrap();
        assert!(env.payload.contains("sensor.events_dropped"));
        let seqs: Vec<u64> = last.iter().map(|x| x.0).collect();
        assert!(
            seqs.windows(2).all(|w| w[1] == w[0] + 1),
            "chain contiguous"
        );
        let mut i = 20_000;
        while s.push(&ev(i, None)) {
            i += 1;
        }
        assert!(
            s.push(&ev(i, Some(Severity::Critical))),
            "high severity uses the reserve"
        );
    }

    /// LOW-1: a failed append used to advance the chain anyway (self-made gap).
    #[test]
    fn failed_append_does_not_advance_the_chain() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(d.path(), "h", key(), 1 << 20).unwrap();
        assert!(s.push(&ev(1, None)));
        let before = s.chainer().next_seq();
        let head = s.chainer().head();
        let spool = d.path().join("spool.jsonl");
        std::fs::remove_file(&spool).unwrap();
        std::fs::create_dir(&spool).unwrap();
        assert!(!s.push(&ev(2, None)), "append into a directory fails");
        assert_eq!(s.chainer().next_seq(), before);
        assert_eq!(s.chainer().head(), head);
        std::fs::remove_dir(&spool).unwrap();
        assert!(s.push(&ev(3, None)));
        let seqs: Vec<u64> = s.peek(100, usize::MAX).iter().map(|x| x.0).collect();
        assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1), "{seqs:?}");
    }

    /// LOW-2: a new host key starts a new epoch instead of resending
    /// envelopes MACed with the old key.
    #[test]
    fn rekey_starts_new_epoch_and_keeps_old_spool_aside() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(d.path(), "h", key(), 1 << 20).unwrap();
        s.push(&ev(1, None));
        s.flush().unwrap();
        let e1 = s.chainer().epoch_hex();
        drop(s);
        let same = Spool::open(d.path(), "h", key(), 1 << 20).unwrap();
        assert!(!same.new_epoch);
        drop(same);
        let s2 = Spool::open(d.path(), "h", MacKey::derive(&[9; 32]), 1 << 20).unwrap();
        assert!(s2.new_epoch);
        assert_ne!(s2.chainer().epoch_hex(), e1);
        assert!(s2.is_empty());
        assert!(d.path().join("spool.rekeyed.jsonl").exists());
    }

    /// cveguard feed: every spooled envelope line is mirrored unchanged.
    #[test]
    fn feed_mirrors_spooled_envelopes() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(&d.path().join("state"), "h", key(), 1 << 20).unwrap();
        let cfg = crate::feed::FeedConfig {
            enabled: true,
            dir: d.path().join("feed"),
            group: None,
            max_bytes: 1 << 20,
        };
        s.set_feed(crate::feed::Feed::open(&cfg, None).unwrap());
        for i in 0..3 {
            assert!(s.push(&ev(i, None)));
        }
        let spooled: Vec<String> = s.peek(10, usize::MAX).into_iter().map(|x| x.1).collect();
        let fed = std::fs::read_to_string(cfg.dir.join(crate::feed::FEED_FILE)).unwrap();
        assert_eq!(fed.lines().collect::<Vec<_>>(), spooled);
        assert!(
            !fed.contains(&hex::encode(key().to_bytes())),
            "never the MAC key"
        );
    }

    #[test]
    fn state_for_other_host_starts_new_epoch() {
        let d = tempfile::tempdir().unwrap();
        let s = Spool::open(d.path(), "a", key(), 1 << 20).unwrap();
        let e = s.chainer().epoch_hex();
        drop(s);
        let s2 = Spool::open(d.path(), "b", key(), 1 << 20).unwrap();
        assert!(s2.new_epoch);
        assert_ne!(s2.chainer().epoch_hex(), e);
    }
}
