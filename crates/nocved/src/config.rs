//! nocved configuration (`/etc/nocved/config.json`, root-owned, no group/other
//! write) and the key file (`/etc/nocved/key`, 0600). Same rules as host-inventory.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::fsutil::{Secrecy, read_secure};
use nocve_proto::{Indicators, Token, TokenKind};

pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

fn t() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceToggle {
    #[serde(default = "t")]
    pub enabled: bool,
    /// 0 = the source's default interval.
    #[serde(default)]
    pub interval_secs: u64,
}

impl Default for SourceToggle {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessConfig {
    #[serde(default = "t")]
    pub enabled: bool,
    #[serde(default)]
    pub interval_secs: u64,
    #[serde(default = "t")]
    pub emit_exits: bool,
    #[serde(default = "d_cpu_pct")]
    pub cpu_threshold_pct: u32,
    #[serde(default = "d_cpu_window")]
    pub cpu_window_secs: u32,
}
fn d_cpu_pct() -> u32 {
    80
}
fn d_cpu_window() -> u32 {
    60
}
impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 0,
            emit_exits: true,
            cpu_threshold_pct: d_cpu_pct(),
            cpu_window_secs: d_cpu_window(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetConfig {
    #[serde(default = "t")]
    pub enabled: bool,
    #[serde(default)]
    pub interval_secs: u64,
    /// Also report connections to private/loopback/link-local addresses.
    #[serde(default)]
    pub include_private: bool,
}
impl Default for NetConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 0,
            include_private: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthlogConfig {
    #[serde(default = "t")]
    pub enabled: bool,
    #[serde(default)]
    pub interval_secs: u64,
    #[serde(default = "d_auth_paths")]
    pub paths: Vec<String>,
    #[serde(default = "d_silence")]
    pub silence_secs: u64,
}
fn d_auth_paths() -> Vec<String> {
    vec!["/var/log/auth.log".into(), "/var/log/secure".into()]
}
fn d_silence() -> u64 {
    1800
}
impl Default for AuthlogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 0,
            paths: d_auth_paths(),
            silence_secs: d_silence(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DockerConfig {
    #[serde(default = "t")]
    pub enabled: bool,
    #[serde(default)]
    pub interval_secs: u64,
    #[serde(default = "d_socket")]
    pub socket: String,
}
fn d_socket() -> String {
    "/var/run/docker.sock".into()
}
impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 0,
            socket: d_socket(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Sources {
    #[serde(default)]
    pub process: ProcessConfig,
    #[serde(default)]
    pub net: NetConfig,
    #[serde(default)]
    pub authlog: AuthlogConfig,
    #[serde(default)]
    pub docker: DockerConfig,
    #[serde(default)]
    pub packages: SourceToggle,
    #[serde(default)]
    pub persistence: SourceToggle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub store_url: String,
    #[serde(default = "d_key_file")]
    pub key_file: PathBuf,
    /// Host name reported to the store; default: the kernel hostname.
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default = "d_state_dir")]
    pub state_dir: PathBuf,
    /// Filesystem root all sources read under (tests use a fixture tree).
    #[serde(default = "d_root")]
    pub root: PathBuf,
    #[serde(default = "d_hb")]
    pub heartbeat_secs: u64,
    #[serde(default = "d_spool")]
    pub spool_max_bytes: u64,
    #[serde(default)]
    pub indicators_file: Option<PathBuf>,
    #[serde(default)]
    pub sources: Sources,
}
fn d_key_file() -> PathBuf {
    PathBuf::from("/etc/nocved/key")
}
fn d_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/nocved")
}
fn d_root() -> PathBuf {
    PathBuf::from("/")
}
fn d_hb() -> u64 {
    30
}
fn d_spool() -> u64 {
    8 * 1024 * 1024
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = read_secure(path, MAX_CONFIG_BYTES, Secrecy::Config)?;
        let cfg: Self =
            serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_url(&self.store_url)?;
        if !(5..=3600).contains(&self.heartbeat_secs) {
            return Err("heartbeat_secs must be 5..3600".into());
        }
        if !(64 * 1024..=512 * 1024 * 1024).contains(&self.spool_max_bytes) {
            return Err("spool_max_bytes must be 64 KiB..512 MiB".into());
        }
        if let Some(h) = &self.host {
            validate_host(h)?;
        }
        if !self.state_dir.is_absolute() || !self.root.is_absolute() {
            return Err("state_dir and root must be absolute".into());
        }
        Ok(())
    }

    pub fn load_key(&self) -> Result<Token, String> {
        let bytes = read_secure(&self.key_file, 256, Secrecy::Key)?;
        let s = String::from_utf8(bytes).map_err(|_| "key file is not UTF-8".to_owned())?;
        // Never echo the key or parse details: just say what is wrong.
        Token::parse(&s, TokenKind::Host).map_err(|e| format!("{}: {e}", self.key_file.display()))
    }

    pub fn indicators(&self) -> Result<Indicators, String> {
        match &self.indicators_file {
            None => Indicators::builtin().map_err(|e| format!("builtin indicators: {e}")),
            Some(p) => {
                let b = read_secure(p, 1024 * 1024, Secrecy::Config)?;
                let s = String::from_utf8(b).map_err(|_| "indicators not UTF-8".to_owned())?;
                Indicators::from_json(&s).map_err(|e| format!("{}: {e}", p.display()))
            }
        }
    }

    pub fn host_name(&self) -> Result<String, String> {
        if let Some(h) = &self.host {
            return Ok(h.clone());
        }
        for p in ["proc/sys/kernel/hostname", "etc/hostname"] {
            if let Ok(s) = std::fs::read_to_string(self.root.join(p)) {
                let h = s.trim().to_owned();
                if validate_host(&h).is_ok() {
                    return Ok(h);
                }
            }
        }
        Err("cannot determine host name; set \"host\" in the config".into())
    }
}

pub fn validate_host(h: &str) -> Result<(), String> {
    if h.is_empty()
        || h.len() > 253
        || !h
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        return Err("host must be 1-253 chars of [A-Za-z0-9._-]".into());
    }
    Ok(())
}

/// https only, except plain http to loopback (tests / local store). No
/// userinfo, query or fragment.
pub fn validate_url(url: &str) -> Result<(), String> {
    let rest = if let Some(r) = url.strip_prefix("https://") {
        r
    } else if let Some(r) = url.strip_prefix("http://") {
        let hostport = r.split('/').next().unwrap_or("");
        let host = if hostport.starts_with('[') {
            hostport
                .split(']')
                .next()
                .map(|h| format!("{h}]"))
                .unwrap_or_default()
        } else {
            hostport.split(':').next().unwrap_or("").to_owned()
        };
        if !matches!(host.as_str(), "127.0.0.1" | "[::1]" | "localhost") {
            return Err("store_url must be https:// (plain http only to loopback)".into());
        }
        r
    } else {
        return Err("store_url must start with https://".into());
    };
    if rest.is_empty() || rest.contains(['@', '?', '#']) || rest.contains(char::is_whitespace) {
        return Err("store_url must not contain credentials, a query, a fragment or spaces".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_rules() {
        assert!(validate_url("https://nocve.afterdarksys.com").is_ok());
        assert!(validate_url("http://127.0.0.1:8750").is_ok());
        assert!(validate_url("http://[::1]:8750").is_ok());
        assert!(validate_url("http://nocve.afterdarksys.com").is_err());
        assert!(validate_url("http://127.0.0.1.evil.com").is_err());
        assert!(validate_url("https://u:p@x.com").is_err());
        assert!(validate_url("https://x.com/?a=1").is_err());
        assert!(validate_url("ftp://x").is_err());
        assert!(validate_url("https://").is_err());
    }

    #[test]
    fn config_defaults_and_unknown_fields() -> Result<(), serde_json::Error> {
        let c: Config = serde_json::from_str(r#"{"store_url":"https://x.example"}"#)?;
        assert!(c.validate().is_ok());
        assert_eq!(c.heartbeat_secs, 30);
        assert!(c.sources.docker.enabled);
        assert_eq!(c.sources.process.cpu_threshold_pct, 80);
        assert!(serde_json::from_str::<Config>(r#"{"store_url":"https://x","bogus":1}"#).is_err());
        let c: Config = serde_json::from_str(
            r#"{"store_url":"https://x.example","sources":{"docker":{"enabled":false}}}"#,
        )?;
        assert!(!c.sources.docker.enabled);
        Ok(())
    }
}
