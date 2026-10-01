//! Main loop: poll due sources, spool chained events; a shipper thread pushes
//! batches and heartbeats so a slow store never blocks polling.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nocve_proto::{Coverage, CoverageStatus, Event, EventData, Token};

use crate::config::Config;
use crate::notify::Notifier;
use crate::ship::{ShipOutcome, Shipper};
use crate::sources::{self, Ctx, Source, coverage};
use crate::spool::Spool;

#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Builds the enabled sources for a config.
pub fn build_sources(cfg: &Config) -> Result<Vec<Box<dyn Source>>, String> {
    let ctx = Ctx {
        root: cfg.root.clone(),
        ind: Arc::new(cfg.indicators()?),
    };
    let s = &cfg.sources;
    let mut v: Vec<Box<dyn Source>> = Vec::new();
    if s.process.enabled {
        v.push(Box::new(sources::process::ProcessSource::new(
            ctx.clone(),
            s.process.clone(),
        )));
    }
    if s.net.enabled {
        v.push(Box::new(sources::net::NetSource::new(
            ctx.clone(),
            s.net.clone(),
        )));
    }
    if s.authlog.enabled {
        v.push(Box::new(sources::authlog::AuthlogSource::new(
            ctx.clone(),
            s.authlog.clone(),
        )));
    }
    if s.docker.enabled {
        v.push(Box::new(sources::docker::DockerSource::new(
            ctx.clone(),
            s.docker.clone(),
        )));
    }
    if s.packages.enabled {
        v.push(Box::new(sources::packages::PackagesSource::new(
            ctx.clone(),
            s.packages.clone(),
        )));
    }
    if s.persistence.enabled {
        v.push(Box::new(sources::persistence::PersistenceSource::new(
            ctx.clone(),
            s.persistence.clone(),
        )));
    }
    if s.auditd.enabled {
        v.push(Box::new(sources::audit::AuditSource::new(
            ctx,
            s.auditd.clone(),
        )));
    }
    Ok(v)
}

pub struct Sensor {
    sources: Vec<(Box<dyn Source>, i64)>,
    disabled: Vec<Coverage>,
    pub spool: Arc<Mutex<Spool>>,
    pub host: String,
    pub boot_id: Option<String>,
}

impl Sensor {
    pub fn new(cfg: &Config, key: &Token) -> Result<Self, String> {
        let host = cfg.host_name()?;
        let mut spool = Spool::open(&cfg.state_dir, &host, key.mac_key(), cfg.spool_max_bytes)?;
        let mut disabled = Vec::new();
        if cfg.feed.enabled {
            // A feed problem must never stop the sensor: report it in coverage.
            let opened = cfg
                .feed
                .group
                .as_deref()
                .map(|g| crate::feed::resolve_gid(&cfg.root, g))
                .transpose()
                .and_then(|gid| {
                    if cfg.feed.dir.starts_with(&cfg.state_dir) {
                        crate::feed::allow_traverse(&cfg.state_dir, gid)?;
                    }
                    crate::feed::Feed::open(&cfg.feed, gid)
                });
            match opened {
                Ok(f) => spool.set_feed(f),
                Err(e) => {
                    eprintln!("nocved: feed disabled: {e}");
                    disabled.push(coverage("feed", CoverageStatus::Failed, e));
                }
            }
        }
        let s = &cfg.sources;
        for (name, on) in [
            ("process", s.process.enabled),
            ("net", s.net.enabled),
            ("authlog", s.authlog.enabled),
            ("docker", s.docker.enabled),
            ("packages", s.packages.enabled),
            ("persistence", s.persistence.enabled),
            ("auditd", s.auditd.enabled),
        ] {
            if !on {
                disabled.push(coverage(
                    name,
                    CoverageStatus::Skipped,
                    "disabled in config",
                ));
            }
        }
        let boot_id = std::fs::read_to_string(cfg.root.join("proc/sys/kernel/random/boot_id"))
            .ok()
            .map(|s| s.trim().to_owned());
        Ok(Self {
            sources: build_sources(cfg)?
                .into_iter()
                .map(|s| (s, i64::MIN))
                .collect(),
            disabled,
            spool: Arc::new(Mutex::new(spool)),
            host,
            boot_id,
        })
    }

    /// Spools the `sensor.start` event (call once, before the first tick).
    pub fn start(&mut self, now_ms: i64) -> Result<(), String> {
        let coverage = self.coverage();
        let mut sp = self.spool.lock().map_err(|_| "spool lock poisoned")?;
        let ev = Event::new(
            now_ms,
            "sensor",
            EventData::SensorStart {
                version: env!("CARGO_PKG_VERSION").to_owned(),
                boot_id: self.boot_id.clone(),
                new_epoch: sp.new_epoch,
                coverage,
            },
        );
        sp.push(&ev);
        sp.flush()
    }

    /// Polls every due source once and spools the events. Returns the number spooled.
    pub fn tick(&mut self, now_ms: i64) -> Result<usize, String> {
        let mut evs = Vec::new();
        for (src, due) in &mut self.sources {
            if now_ms >= *due {
                src.poll(now_ms, &mut evs);
                *due = now_ms + i64::try_from(src.interval().as_millis()).unwrap_or(i64::MAX / 2);
            }
        }
        let mut sp = self.spool.lock().map_err(|_| "spool lock poisoned")?;
        let mut n = 0;
        for e in &evs {
            if sp.push(e) {
                n += 1;
            }
        }
        // fsync only when something was spooled: idle ticks cost no disk I/O.
        if !evs.is_empty() {
            sp.flush()?;
        }
        Ok(n)
    }

    /// Polls all sources now (ignoring intervals).
    pub fn tick_all(&mut self, now_ms: i64) -> Result<usize, String> {
        for (_, due) in &mut self.sources {
            *due = i64::MIN;
        }
        self.tick(now_ms)
    }

    /// Source health, disabled sources, and the feed when one is open.
    /// Takes the spool lock: never call it while holding that lock.
    #[must_use]
    pub fn coverage(&self) -> Vec<Coverage> {
        let mut v: Vec<Coverage> = self.sources.iter().map(|(s, _)| s.health()).collect();
        v.extend(self.disabled.iter().cloned());
        if let Some((long, burst)) = self.spool.lock().ok().and_then(|s| s.feed_skipped()) {
            v.push(feed_coverage(long, burst));
        }
        v
    }

    fn next_due(&self) -> i64 {
        self.sources
            .iter()
            .map(|(_, d)| *d)
            .min()
            .unwrap_or(i64::MAX)
    }
}

/// `feed: degraded` once any line was skipped, so the store and operators
/// see that cveguard's view is incomplete.
fn feed_coverage(long: u64, burst: u64) -> Coverage {
    if long == 0 && burst == 0 {
        return coverage("feed", CoverageStatus::Completed, "");
    }
    coverage(
        "feed",
        CoverageStatus::Degraded,
        format!(
            "skipped {long} line(s) over {} bytes, {burst} during a rotation hold",
            crate::feed::MAX_FEED_LINE
        ),
    )
}

fn jitter_ms(max: u64) -> u64 {
    let mut b = [0u8; 8];
    if nocve_proto::random_bytes(&mut b).is_err() || max == 0 {
        return 0;
    }
    u64::from_le_bytes(b) % max
}

/// Runs until `stop` is set.
pub fn run(cfg: &Config, key: &Token, stop: &AtomicBool) -> Result<(), String> {
    let mut sensor = Sensor::new(cfg, key)?;
    let shipper = Shipper::new(&cfg.store_url, key, &sensor.host);
    eprintln!(
        "nocved: starting host={} store={} key_fp={} sources={}",
        sensor.host,
        cfg.store_url,
        shipper.fingerprint,
        sensor
            .sources
            .iter()
            .map(|(s, _)| s.id())
            .collect::<Vec<_>>()
            .join(",")
    );
    sensor.start(now_ms())?;
    let cov = Arc::new(Mutex::new(sensor.coverage()));
    let spool = Arc::clone(&sensor.spool);
    let hb_ms = i64::try_from(cfg.heartbeat_secs).unwrap_or(30) * 1000;
    let boot_id = sensor.boot_id.clone();
    let cov2 = Arc::clone(&cov);
    // Main-loop liveness for the heartbeat (0 = no tick yet). The heartbeat is
    // sent by the shipper thread, so without this a frozen poll loop would look
    // healthy at the store.
    let last_tick = AtomicI64::new(0);
    let notifier = Notifier::from_env();
    if let Some(n) = &notifier
        && let Err(e) = n.notify("READY=1")
    {
        eprintln!("nocved: sd_notify: {e}");
    }
    let mut last_watchdog = i64::MIN;
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut next_hb = 0i64;
            let mut backoff = Duration::from_secs(1);
            while !stop.load(Ordering::Relaxed) {
                let now = now_ms();
                if now >= next_hb {
                    let c = cov2.lock().map(|c| c.clone()).unwrap_or_default();
                    let tick = Some(last_tick.load(Ordering::Relaxed)).filter(|t| *t > 0);
                    match shipper.heartbeat(&spool, c, now, boot_id.clone(), tick) {
                        Ok(200) => {}
                        Ok(st) => eprintln!("nocved: heartbeat status {st}"),
                        Err(e) => eprintln!("nocved: heartbeat: {e}"),
                    }
                    next_hb = now + hb_ms;
                }
                match shipper.ship_batch(&spool) {
                    ShipOutcome::Sent { .. } => {
                        backoff = Duration::from_secs(1);
                        continue;
                    }
                    ShipOutcome::Idle => std::thread::sleep(Duration::from_millis(500)),
                    ShipOutcome::Split { status, keep } => {
                        eprintln!(
                            "nocved: store rejected a batch ({status}); resending in parts of {keep}"
                        );
                    }
                    ShipOutcome::Rejected { status, body } => {
                        eprintln!(
                            "nocved: store rejected batch ({status}): {}",
                            body.chars().take(300).collect::<String>()
                        );
                    }
                    ShipOutcome::Retry { after, why } => {
                        eprintln!("nocved: ship failed, retrying: {why}");
                        let wait = after.max(backoff) + Duration::from_millis(jitter_ms(1000));
                        std::thread::sleep(wait.min(Duration::from_secs(60)));
                        backoff = (backoff * 2).min(Duration::from_secs(60));
                    }
                }
            }
        });
        while !stop.load(Ordering::Relaxed) {
            let now = now_ms();
            if let Err(e) = sensor.tick(now) {
                eprintln!("nocved: tick: {e}");
            }
            if let Ok(mut c) = cov.lock() {
                *c = sensor.coverage();
            }
            let done = now_ms();
            last_tick.store(done, Ordering::Relaxed);
            if let Some(n) = &notifier
                && done.saturating_sub(last_watchdog) >= 5_000
            {
                last_watchdog = done;
                if let Err(e) = n.notify("WATCHDOG=1") {
                    eprintln!("nocved: sd_notify: {e}");
                }
            }
            let wait = (sensor.next_due() - now_ms()).clamp(100, 1000);
            std::thread::sleep(Duration::from_millis(u64::try_from(wait).unwrap_or(1000)));
        }
    });
    Ok(())
}
