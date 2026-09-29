//! HTTPS push to nocve-store: POST /v1/events (batches) and /v1/heartbeat.
//! https only (loopback http for tests), system CA store, no redirects, no
//! proxy, 10 s timeout, response bodies capped. The key travels only in the
//! Authorization header and is never logged.

use std::sync::Mutex;
use std::time::Duration;

use nocve_proto::{Coverage, Heartbeat, HeartbeatEnvelope, MacKey, Token};

use crate::spool::Spool;

const MAX_RESPONSE: u64 = 64 * 1024;

pub struct Shipper {
    agent: ureq::Agent,
    base: String,
    auth: String,
    key: MacKey,
    host: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShipOutcome {
    Idle,
    Sent {
        events: usize,
        through: u64,
    },
    /// The store refused the batch permanently (400/409/413/422); moved aside.
    Rejected {
        status: u16,
        body: String,
    },
    /// Try again later (transport error, 401/403, 429, 5xx).
    Retry {
        after: Duration,
        why: String,
    },
}

fn is_loopback_http(url: &str) -> bool {
    url.starts_with("http://")
}

impl Shipper {
    #[must_use]
    pub fn new(base_url: &str, token: &Token, host: &str) -> Self {
        let tls = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(10)))
            .max_redirects(0)
            .proxy(None)
            .http_status_as_error(false)
            .https_only(!is_loopback_http(base_url))
            .tls_config(tls)
            .user_agent(concat!("nocved/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self {
            agent,
            base: base_url.trim_end_matches('/').to_owned(),
            auth: format!("Bearer {}", token.expose()),
            key: token.mac_key(),
            host: host.to_owned(),
            fingerprint: token.fingerprint(),
        }
    }

    fn post(&self, path: &str, body: &[u8]) -> Result<(u16, String, Option<u64>), String> {
        let url = format!("{}{path}", self.base);
        let mut resp = self
            .agent
            .post(&url)
            .header("Authorization", &self.auth)
            .header("Content-Type", "application/json")
            .send(body)
            .map_err(|e| format!("POST {path}: {e}"))?;
        let status = resp.status().as_u16();
        let retry = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok());
        let text = resp
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE)
            .read_to_string()
            .unwrap_or_default();
        Ok((status, text, retry))
    }

    /// Sends the oldest batch from the spool. The spool lock is not held
    /// during the network call.
    pub fn ship_batch(&self, spool: &Mutex<Spool>) -> ShipOutcome {
        let batch = match spool.lock() {
            Ok(s) => s.peek(
                nocve_proto::MAX_BATCH_EVENTS,
                nocve_proto::MAX_BODY_BYTES - 64,
            ),
            Err(_) => {
                return ShipOutcome::Retry {
                    after: Duration::from_secs(1),
                    why: "spool lock poisoned".into(),
                };
            }
        };
        let Some(&(through, _)) = batch.last() else {
            return ShipOutcome::Idle;
        };
        let mut body = String::from("{\"events\":[");
        for (i, (_, l)) in batch.iter().enumerate() {
            if i > 0 {
                body.push(',');
            }
            body.push_str(l);
        }
        body.push_str("]}");
        match self.post("/v1/events", body.as_bytes()) {
            Ok((200, _, _)) => {
                if let Ok(mut s) = spool.lock()
                    && let Err(e) = s.ack(through)
                {
                    return ShipOutcome::Retry {
                        after: Duration::from_secs(1),
                        why: format!("ack: {e}"),
                    };
                }
                ShipOutcome::Sent {
                    events: batch.len(),
                    through,
                }
            }
            Ok((st @ (400 | 409 | 413 | 422), text, _)) => {
                if let Ok(mut s) = spool.lock()
                    && let Err(e) = s.reject(&batch, &text)
                {
                    return ShipOutcome::Retry {
                        after: Duration::from_secs(5),
                        why: format!("reject: {e}"),
                    };
                }
                ShipOutcome::Rejected {
                    status: st,
                    body: text,
                }
            }
            Ok((429, _, retry)) => ShipOutcome::Retry {
                after: Duration::from_secs(retry.unwrap_or(5).clamp(1, 60)),
                why: "rate limited".into(),
            },
            Ok((st, text, _)) => ShipOutcome::Retry {
                after: Duration::from_secs(5),
                why: format!(
                    "status {st}: {}",
                    text.chars().take(200).collect::<String>()
                ),
            },
            Err(e) => ShipOutcome::Retry {
                after: Duration::from_secs(5),
                why: e,
            },
        }
    }

    /// Sends one heartbeat. Returns the HTTP status.
    pub fn heartbeat(
        &self,
        spool: &Mutex<Spool>,
        coverage: Vec<Coverage>,
        now_ms: i64,
        boot_id: Option<String>,
    ) -> Result<u16, String> {
        let hb = {
            let mut s = spool.lock().map_err(|_| "spool lock poisoned")?;
            let counter = s.next_heartbeat_counter()?;
            Heartbeat {
                host: self.host.clone(),
                epoch: s.chainer().epoch_hex(),
                counter,
                sent_at_ms: now_ms,
                next_seq: s.chainer().next_seq(),
                head: hex::encode(s.chainer().head()),
                spool_events: s.len() as u64,
                spool_bytes: s.bytes(),
                dropped_total: s.dropped_total,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                boot_id,
                coverage,
            }
        };
        let payload = serde_json::to_string(&hb).map_err(|e| e.to_string())?;
        let env = HeartbeatEnvelope::seal(&self.key, &self.host, payload);
        let body = serde_json::to_vec(&env).map_err(|e| e.to_string())?;
        self.post("/v1/heartbeat", &body).map(|(st, _, _)| st)
    }

    /// Drains the whole spool (tests and `--once`). Returns events sent.
    pub fn drain(&self, spool: &Mutex<Spool>) -> Result<usize, String> {
        let mut n = 0;
        loop {
            match self.ship_batch(spool) {
                ShipOutcome::Idle => return Ok(n),
                ShipOutcome::Sent { events, .. } => n += events,
                ShipOutcome::Rejected { status, body } => {
                    return Err(format!("rejected {status}: {body}"));
                }
                ShipOutcome::Retry { why, .. } => return Err(why),
            }
        }
    }
}
