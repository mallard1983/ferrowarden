use serde::Deserialize;
use std::path::PathBuf;

use crate::error::{FerroError, FerroResult};

/// How the vault master password is supplied at startup.
/// The operator chooses one mode; both result in the same unlocked runtime state.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UnlockMode {
    /// Read the master password from a file once at startup, then zero it.
    /// The file should be a Docker secret or a chmod 400 bind mount.
    File,
    /// Start locked. The operator POSTs the master password to POST /v1/unlock
    /// once after boot. The password is zeroed immediately after unlock.
    Manual,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Address the ferrowarden HTTP server binds to.
    /// Default: 127.0.0.1:3000 — change to 0.0.0.0:3000 when running in Docker.
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// URL of the bw serve process.
    /// Must be localhost-only — bw serve should never be exposed externally.
    #[serde(default = "default_bw_serve_url")]
    pub bw_serve_url: String,

    /// Unlock mode. Required — the operator must make an explicit choice.
    pub unlock_mode: UnlockMode,

    /// Path to the master password file. Required when unlock_mode = file.
    /// Ignored when unlock_mode = manual.
    pub unlock_file: Option<PathBuf>,

    /// Admin API key for managing agent keys and viewing audit logs.
    /// Must be set via environment variable FERROWARDEN_ADMIN_KEY.
    /// Never set this in a config file checked into version control.
    #[serde(skip)]
    pub admin_key: String,

    /// Path to the agent key store file.
    /// When set, agent keys survive container restarts. The file stores only
    /// SHA-256 hashes — plaintext tokens are never written to disk.
    /// Omit to use in-memory-only storage (keys lost on restart).
    pub keys_file: Option<PathBuf>,

    /// Whether to enable TLS. Defaults to true.
    /// Set to false ONLY when ferrowarden runs on the same host as the agent
    /// (e.g. both in the same Docker network on the same machine). Any other
    /// plaintext deployment exposes credentials to network interception.
    #[serde(default = "default_tls_enabled")]
    pub tls_enabled: bool,

    /// Path to the TLS certificate file (PEM format).
    /// Required when tls_enabled = true.
    pub tls_cert_file: Option<PathBuf>,

    /// Path to the TLS private key file (PEM format).
    /// Required when tls_enabled = true.
    pub tls_key_file: Option<PathBuf>,

    /// Allow forwarding to private, loopback, link-local and other
    /// non-public addresses. Default: false. Prefer `allowed_targets` to open
    /// only the specific internal hosts or ranges an agent needs. The bw serve
    /// endpoint is always blocked regardless of this setting.
    #[serde(default)]
    pub allow_private_targets: bool,

    /// Comma-separated list of internal targets the agent may reach even
    /// though they resolve to non-public addresses. Each entry is a CIDR
    /// (`192.168.1.0/24`), a single IP (`10.0.0.5`) or a hostname
    /// (`proxmox.lan`). Example: `"192.168.1.0/24,nas.lan"`.
    #[serde(default)]
    pub allowed_targets: String,

    /// Require every credential to be bound to the hosts listed in its vault
    /// item's URIs. A credential is only substituted into a request whose
    /// target host (and port/scheme, when the URI specifies them) matches one
    /// of those URIs. Default: true. Disabling this lets any agent send any
    /// credential to any host it can reach — including one that echoes it back.
    #[serde(default = "default_true")]
    pub enforce_credential_hosts: bool,

    /// How often (seconds) to sync bw serve with Vaultwarden, refresh the
    /// credential cache and re-check the lock state. 0 disables the refresh.
    #[serde(default = "default_refresh_interval_secs")]
    pub refresh_interval_secs: u64,

    /// Maximum size of a forwarded response body, in bytes. Larger responses
    /// are rejected with 502 rather than buffered. Default: 10 MiB.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,

    /// Timeout for forwarded requests, in seconds. Default: 30.
    #[serde(default = "default_forward_timeout_secs")]
    pub forward_timeout_secs: u64,

    /// Comma-separated CIDRs/IPs of reverse proxies in front of ferrowarden.
    /// When a request arrives from one of these, the client IP used for rate
    /// limiting is taken from `X-Forwarded-For`. Leave empty when clients
    /// connect directly — otherwise clients could spoof the header.
    #[serde(default)]
    pub trusted_proxies: String,

    /// Optional path prefix for every API route except `/health`, e.g.
    /// `/k7f3q9` serves the API at `/k7f3q9/v1/forward`. Empty (default)
    /// serves it at `/v1/...`. Use a hard-to-guess value to keep generic
    /// scanners off the API and to give a reverse proxy (e.g. an SSO bypass
    /// rule) a non-obvious path to match. This is obscurity, not
    /// authentication: the agent and admin keys remain the real controls.
    #[serde(default)]
    pub api_prefix: String,

    /// Sustained request rate allowed per client IP on the agent endpoints
    /// (`/v1/forward`, `/v1/credentials`), in requests per minute. Default 120.
    #[serde(default = "default_agent_rate_limit_per_minute")]
    pub agent_rate_limit_per_minute: u32,

    /// Burst size for the agent endpoints: how many requests a client may
    /// make back-to-back before the sustained rate applies. Default 20.
    #[serde(default = "default_agent_rate_limit_burst")]
    pub agent_rate_limit_burst: u32,

    /// Sustained request rate per client IP on the admin endpoints
    /// (`/v1/admin/*`, `/v1/unlock`), in requests per minute. Default 30 —
    /// deliberately low, to slow down admin key guessing.
    #[serde(default = "default_admin_rate_limit_per_minute")]
    pub admin_rate_limit_per_minute: u32,

    /// Burst size for the admin endpoints. Default 5.
    #[serde(default = "default_admin_rate_limit_burst")]
    pub admin_rate_limit_burst: u32,

    /// Security event stream: sinks, queue and in-memory buffer. `[events]`
    /// in the TOML file, `FERROWARDEN_EVENTS__*` in the environment.
    #[serde(default)]
    pub events: EventsConfig,

    /// Admin web UI: its own listener, Vaultwarden sign-in. `[ui]` in the
    /// TOML file, `FERROWARDEN_UI__*` in the environment. Disabled unless
    /// `ui.bind` is set (see docs/admin-ui.md).
    #[serde(default)]
    pub ui: UiConfig,
}

/// Settings of the admin web UI.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct UiConfig {
    /// Address of the UI listener, e.g. `0.0.0.0:3001`. Empty (default)
    /// disables the UI. It is a separate server: the agent and admin API
    /// router is never reachable on this port, and the UI is not reachable on
    /// the API port.
    pub bind: String,
    /// Vaultwarden base URL used to verify the master password at sign-in.
    /// Must be `https://` (plain `http://` is accepted for loopback hosts
    /// only, for tests).
    pub vaultwarden_url: String,
    /// PEM file with an extra CA certificate to trust for `vaultwarden_url`,
    /// on top of the public roots. Never replaces certificate verification.
    pub vaultwarden_ca_file: String,
    /// Serve the sign-in form over plain HTTP too. Off by default: without
    /// TLS (here or at a trusted reverse proxy) the master password would
    /// cross the network in clear text.
    pub insecure_http: bool,
    /// A session ends after this many minutes without a request. Default 15.
    pub session_idle_minutes: u64,
    /// A session ends this many hours after sign-in, whatever its activity.
    /// Default 8.
    pub session_max_hours: u64,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            bind: String::new(),
            vaultwarden_url: "https://vaultwarden".to_string(),
            vaultwarden_ca_file: String::new(),
            insecure_http: false,
            session_idle_minutes: 15,
            session_max_hours: 8,
        }
    }
}

impl UiConfig {
    pub fn enabled(&self) -> bool {
        !self.bind.trim().is_empty()
    }

    fn validate(&self) -> FerroResult<()> {
        if !self.enabled() {
            return Ok(());
        }
        self.bind
            .trim()
            .parse::<std::net::SocketAddr>()
            .map_err(|e| {
                FerroError::Config(format!(
                    "ui.bind {:?} is not an address:port ({e})",
                    self.bind
                ))
            })?;
        if self.session_idle_minutes == 0 || self.session_max_hours == 0 {
            return Err(FerroError::Config(
                "ui.session_idle_minutes and ui.session_max_hours must be greater than 0"
                    .to_string(),
            ));
        }
        // Bounded so the arithmetic on them cannot overflow.
        if self.session_idle_minutes > 7 * 24 * 60 || self.session_max_hours > 30 * 24 {
            return Err(FerroError::Config(
                "ui.session_idle_minutes (max 10080) or ui.session_max_hours (max 720) is too large"
                    .to_string(),
            ));
        }
        let url = reqwest::Url::parse(&self.vaultwarden_url).map_err(|e| {
            FerroError::Config(format!(
                "ui.vaultwarden_url {:?} is not a URL ({e})",
                self.vaultwarden_url
            ))
        })?;
        let loopback = url.host_str().is_some_and(|h| {
            h == "localhost"
                || h.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        match url.scheme() {
            "https" => {}
            "http" if loopback => {}
            _ => {
                return Err(FerroError::Config(
                    "ui.vaultwarden_url must be an https:// URL (http:// only for localhost)"
                        .to_string(),
                ))
            }
        }
        if url.host_str().is_none() || url.query().is_some() || url.fragment().is_some() {
            return Err(FerroError::Config(
                "ui.vaultwarden_url must be a plain base URL (no query or fragment)".to_string(),
            ));
        }
        Ok(())
    }
}

/// Settings of the security event stream (see docs/events.md).
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct EventsConfig {
    /// Write events as JSON lines to stdout (alongside the application logs;
    /// events carry `event.dataset = "ferrowarden.security"`). Default: true.
    pub stdout: bool,
    /// Events kept in memory for `GET /v1/admin/audit`. Default 1000.
    pub buffer_size: usize,
    /// Events that may wait for the sink writer. When full, new events are
    /// dropped (and reported) instead of blocking requests. Default 10000.
    pub queue_size: usize,
    /// Path of a JSON-lines event file. Empty (default) disables it.
    pub file: String,
    /// Rotate the event file when it would exceed this many bytes. Default 50 MiB.
    pub file_max_bytes: u64,
    /// Rotated files to keep (`events.jsonl.1` ... `.N`). Default 10.
    pub file_keep: u32,
    /// Syslog destination: `udp://host:port`, `tcp://host:port` or
    /// `tls://host:port`. Empty (default) disables it.
    pub syslog: String,
    /// Syslog facility name or number. Default `auth`.
    pub syslog_facility: String,
    /// Extra CA bundle (PEM) trusted for `tls://` syslog, besides the public
    /// roots. Empty (default) means public roots only.
    pub syslog_ca_file: String,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            stdout: true,
            buffer_size: 1000,
            queue_size: 10_000,
            file: String::new(),
            file_max_bytes: 50 * 1024 * 1024,
            file_keep: 10,
            syslog: String::new(),
            syslog_facility: "auth".to_string(),
            syslog_ca_file: String::new(),
        }
    }
}

impl EventsConfig {
    /// Names of the enabled sinks, for the startup event.
    pub fn enabled_sinks(&self) -> Vec<&'static str> {
        let mut sinks = Vec::new();
        if self.stdout {
            sinks.push("stdout");
        }
        if !self.file.is_empty() {
            sinks.push("file");
        }
        if !self.syslog.is_empty() {
            sinks.push("syslog");
        }
        sinks
    }

    fn validate(&self) -> FerroResult<()> {
        if self.buffer_size == 0 || self.queue_size == 0 {
            return Err(FerroError::Config(
                "events.buffer_size and events.queue_size must be greater than 0".to_string(),
            ));
        }
        if !self.file.is_empty() && (self.file_max_bytes == 0 || self.file_keep == 0) {
            return Err(FerroError::Config(
                "events.file_max_bytes and events.file_keep must be greater than 0".to_string(),
            ));
        }
        if !self.syslog.is_empty() {
            crate::events::sinks::parse_syslog_url(&self.syslog).map_err(FerroError::Config)?;
            crate::events::sinks::parse_facility(&self.syslog_facility)
                .map_err(FerroError::Config)?;
        }
        if !self.syslog_ca_file.is_empty() && !self.syslog.starts_with("tls://") {
            return Err(FerroError::Config(
                "events.syslog_ca_file is only used with a tls:// syslog URL".to_string(),
            ));
        }
        Ok(())
    }
}

fn default_bind_addr() -> String {
    "0.0.0.0:3000".to_string()
}

fn default_bw_serve_url() -> String {
    "http://127.0.0.1:8087".to_string()
}

fn default_tls_enabled() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_refresh_interval_secs() -> u64 {
    300
}

fn default_max_response_bytes() -> usize {
    10 * 1024 * 1024
}

fn default_agent_rate_limit_per_minute() -> u32 {
    120
}

fn default_agent_rate_limit_burst() -> u32 {
    20
}

fn default_admin_rate_limit_per_minute() -> u32 {
    30
}

fn default_admin_rate_limit_burst() -> u32 {
    5
}

fn default_forward_timeout_secs() -> u64 {
    30
}

/// Normalize and validate an API prefix. Returns "" for no prefix, otherwise
/// a string like "/a/b": leading slash, no trailing slash, segments of
/// letters, digits, '-' and '_' only.
pub fn normalize_api_prefix(raw: &str) -> FerroResult<String> {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    for segment in trimmed.split('/') {
        let valid = !segment.is_empty()
            && segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !valid {
            return Err(FerroError::Config(format!(
                "api_prefix {raw:?} is invalid: use path segments of letters, digits, '-' and '_' (e.g. \"/k7f3q9\")"
            )));
        }
    }
    if trimmed == "health" {
        return Err(FerroError::Config(
            "api_prefix may not be \"/health\"".to_string(),
        ));
    }
    Ok(format!("/{trimmed}"))
}

/// Split a comma-separated config value into trimmed, non-empty entries.
pub fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

impl Config {
    pub fn load() -> FerroResult<Self> {
        let settings = config::Config::builder()
            // Base config from file — ferrowarden.toml in the working directory.
            // The full file name matters: with_name("ferrowarden") also matches
            // a file named exactly "ferrowarden" (config >= 0.15), which in the
            // Docker image is the binary itself in /app.
            .add_source(
                config::File::new("ferrowarden.toml", config::FileFormat::Toml).required(false),
            )
            // Environment variables override file values.
            // FERROWARDEN_BIND_ADDR, FERROWARDEN_UNLOCK_MODE, etc.
            .add_source(
                config::Environment::with_prefix("FERROWARDEN")
                    .prefix_separator("_") // single _ between prefix and key (FERROWARDEN_FIELD)
                    .separator("__") // double __ for nested keys (FERROWARDEN_SECTION__KEY)
                    .ignore_empty(true),
            )
            .build()
            .map_err(|e| FerroError::Config(e.to_string()))?;

        let mut cfg: Config = settings
            .try_deserialize()
            .map_err(|e| FerroError::Config(e.to_string()))?;

        // Admin key must come from the environment — never a config file.
        cfg.admin_key = std::env::var("FERROWARDEN_ADMIN_KEY")
            .map_err(|_| FerroError::Config("FERROWARDEN_ADMIN_KEY must be set".to_string()))?;

        cfg.api_prefix = normalize_api_prefix(&cfg.api_prefix)?;

        cfg.validate()?;

        Ok(cfg)
    }

    fn validate(&self) -> FerroResult<()> {
        if self.unlock_mode == UnlockMode::File && self.unlock_file.is_none() {
            return Err(FerroError::Config(
                "unlock_mode = file requires unlock_file to be set".to_string(),
            ));
        }

        if self.admin_key.len() < 32 {
            return Err(FerroError::Config(
                "FERROWARDEN_ADMIN_KEY must be at least 32 characters".to_string(),
            ));
        }

        if self.max_response_bytes == 0 {
            return Err(FerroError::Config(
                "max_response_bytes must be greater than 0".to_string(),
            ));
        }

        if self.agent_rate_limit_per_minute == 0
            || self.agent_rate_limit_burst == 0
            || self.admin_rate_limit_per_minute == 0
            || self.admin_rate_limit_burst == 0
        {
            return Err(FerroError::Config(
                "agent_rate_limit_* and admin_rate_limit_* settings must be greater than 0"
                    .to_string(),
            ));
        }

        if self.forward_timeout_secs == 0 {
            return Err(FerroError::Config(
                "forward_timeout_secs must be greater than 0".to_string(),
            ));
        }

        for entry in split_list(&self.trusted_proxies) {
            if crate::net::Cidr::parse(&entry).is_none() {
                return Err(FerroError::Config(format!(
                    "trusted_proxies entry {entry:?} is not a valid IP or CIDR"
                )));
            }
        }

        self.events.validate()?;
        self.ui.validate()?;

        if self.tls_enabled {
            if self.tls_cert_file.is_none() {
                return Err(FerroError::Config(
                    "tls_enabled = true requires tls_cert_file to be set".to_string(),
                ));
            }
            if self.tls_key_file.is_none() {
                return Err(FerroError::Config(
                    "tls_enabled = true requires tls_key_file to be set".to_string(),
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config(mode: UnlockMode) -> Config {
        Config {
            bind_addr: "127.0.0.1:3000".to_string(),
            bw_serve_url: "http://127.0.0.1:8087".to_string(),
            unlock_mode: mode,
            unlock_file: None,
            admin_key: "a".repeat(32),
            keys_file: None,
            tls_enabled: false,
            tls_cert_file: None,
            tls_key_file: None,
            allow_private_targets: false,
            allowed_targets: String::new(),
            enforce_credential_hosts: true,
            refresh_interval_secs: 300,
            max_response_bytes: 1024,
            forward_timeout_secs: 30,
            trusted_proxies: String::new(),
            api_prefix: String::new(),
            agent_rate_limit_per_minute: 120,
            agent_rate_limit_burst: 20,
            admin_rate_limit_per_minute: 30,
            admin_rate_limit_burst: 5,
            events: Default::default(),
            ui: Default::default(),
        }
    }

    #[test]
    fn events_defaults_match_the_documentation() {
        let e = EventsConfig::default();
        assert!(e.stdout);
        assert_eq!(e.buffer_size, 1000);
        assert_eq!(e.queue_size, 10_000);
        assert!(e.file.is_empty() && e.syslog.is_empty() && e.syslog_ca_file.is_empty());
        assert_eq!(e.file_max_bytes, 52_428_800);
        assert_eq!(e.file_keep, 10);
        assert_eq!(e.syslog_facility, "auth");
        assert_eq!(e.enabled_sinks(), vec!["stdout"]);
        assert!(base_config(UnlockMode::Manual).validate().is_ok());
    }

    #[test]
    fn events_section_deserializes_partially() {
        let cfg: Config = config::Config::builder()
            .add_source(config::File::from_str(
                "unlock_mode = \"manual\"
[events]
file = \"/tmp/e.jsonl\"
file_keep = 3
",
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(cfg.events.file, "/tmp/e.jsonl");
        assert_eq!(cfg.events.file_keep, 3);
        assert!(cfg.events.stdout, "unspecified keys keep their defaults");
        assert_eq!(cfg.events.buffer_size, 1000);
    }

    #[test]
    fn invalid_events_settings_fail_validation() {
        type Tweak = Box<dyn Fn(&mut EventsConfig)>;
        let bad: Vec<Tweak> = vec![
            Box::new(|e| e.buffer_size = 0),
            Box::new(|e| e.queue_size = 0),
            Box::new(|e| {
                e.file = "/tmp/e.jsonl".into();
                e.file_keep = 0;
            }),
            Box::new(|e| {
                e.file = "/tmp/e.jsonl".into();
                e.file_max_bytes = 0;
            }),
            Box::new(|e| e.syslog = "http://siem:514".into()),
            Box::new(|e| e.syslog = "udp://siem".into()),
            Box::new(|e| {
                e.syslog = "udp://siem:514".into();
                e.syslog_facility = "nope".into();
            }),
            Box::new(|e| {
                e.syslog = "tcp://siem:514".into();
                e.syslog_ca_file = "/ca.pem".into();
            }),
        ];
        for (i, tweak) in bad.iter().enumerate() {
            let mut cfg = base_config(UnlockMode::Manual);
            tweak(&mut cfg.events);
            assert!(cfg.validate().is_err(), "case {i} should fail");
        }
        let mut ok = base_config(UnlockMode::Manual);
        ok.events.syslog = "tls://siem.example:6514".into();
        ok.events.syslog_ca_file = "/ca.pem".into();
        ok.events.file = "/tmp/e.jsonl".into();
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn zero_rate_limit_fails() {
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.agent_rate_limit_burst = 0;
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("rate_limit"));
    }

    #[test]
    fn api_prefix_normalization() {
        assert_eq!(normalize_api_prefix("").unwrap(), "");
        assert_eq!(normalize_api_prefix("/").unwrap(), "");
        assert_eq!(normalize_api_prefix("k7f3q9").unwrap(), "/k7f3q9");
        assert_eq!(normalize_api_prefix("/a-b/c_d/").unwrap(), "/a-b/c_d");
        for bad in ["/a//b", "/a b", "/a?b", "/../x", "/health", "/a.b"] {
            assert!(normalize_api_prefix(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn invalid_trusted_proxy_fails() {
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.trusted_proxies = "10.0.0.0/8, not-an-ip".to_string();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("trusted_proxies"));
    }

    #[test]
    fn split_list_trims_and_drops_empty() {
        assert_eq!(
            split_list(" a, ,b ,"),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn valid_manual_mode_passes() {
        assert!(base_config(UnlockMode::Manual).validate().is_ok());
    }

    #[test]
    fn valid_file_mode_passes() {
        let mut cfg = base_config(UnlockMode::File);
        cfg.unlock_file = Some(PathBuf::from("/run/secrets/bw_password"));
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn file_mode_without_unlock_file_fails() {
        let cfg = base_config(UnlockMode::File);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("unlock_file"));
    }

    #[test]
    fn short_admin_key_fails() {
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.admin_key = "short".to_string();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("32 characters"));
    }

    #[test]
    fn exactly_32_char_admin_key_passes() {
        let cfg = base_config(UnlockMode::Manual);
        assert_eq!(cfg.admin_key.len(), 32);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn tls_enabled_without_cert_fails() {
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.tls_enabled = true;
        cfg.tls_key_file = Some(PathBuf::from("/certs/server.key"));
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("tls_cert_file"));
    }

    #[test]
    fn tls_enabled_without_key_fails() {
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.tls_enabled = true;
        cfg.tls_cert_file = Some(PathBuf::from("/certs/server.crt"));
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("tls_key_file"));
    }

    #[test]
    fn tls_enabled_with_both_files_passes() {
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.tls_enabled = true;
        cfg.tls_cert_file = Some(PathBuf::from("/certs/server.crt"));
        cfg.tls_key_file = Some(PathBuf::from("/certs/server.key"));
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn tls_disabled_no_files_passes() {
        let cfg = base_config(UnlockMode::Manual);
        assert!(!cfg.tls_enabled);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn ui_is_disabled_by_default_with_the_documented_defaults() {
        let ui = UiConfig::default();
        assert!(!ui.enabled());
        assert_eq!(ui.bind, "");
        assert_eq!(ui.vaultwarden_url, "https://vaultwarden");
        assert_eq!(ui.vaultwarden_ca_file, "");
        assert!(!ui.insecure_http);
        assert_eq!(ui.session_idle_minutes, 15);
        assert_eq!(ui.session_max_hours, 8);
        assert!(base_config(UnlockMode::Manual).validate().is_ok());
    }

    #[test]
    fn ui_section_deserializes_partially() {
        let ui: UiConfig = serde_json::from_str(r#"{"bind":"0.0.0.0:3001"}"#).unwrap();
        assert!(ui.enabled());
        assert_eq!(ui.session_idle_minutes, 15);
    }

    #[test]
    fn invalid_ui_settings_fail_validation() {
        let with = |f: &dyn Fn(&mut UiConfig)| {
            let mut cfg = base_config(UnlockMode::Manual);
            cfg.ui.bind = "0.0.0.0:3001".to_string();
            f(&mut cfg.ui);
            cfg.validate()
        };
        assert!(with(&|_| {}).is_ok());
        assert!(with(&|u| u.bind = "not an address".into()).is_err());
        assert!(with(&|u| u.session_idle_minutes = 0).is_err());
        assert!(with(&|u| u.session_max_hours = 0).is_err());
        assert!(with(&|u| u.session_idle_minutes = u64::MAX).is_err());
        assert!(with(&|u| u.session_max_hours = u64::MAX).is_err());
        // HTTPS only, except loopback (tests).
        assert!(with(&|u| u.vaultwarden_url = "http://vaultwarden".into()).is_err());
        assert!(with(&|u| u.vaultwarden_url = "http://10.0.0.5".into()).is_err());
        assert!(with(&|u| u.vaultwarden_url = "http://127.0.0.1:8080".into()).is_ok());
        assert!(with(&|u| u.vaultwarden_url = "http://localhost:8080".into()).is_ok());
        assert!(with(&|u| u.vaultwarden_url = "https://vault.example.com".into()).is_ok());
        assert!(with(&|u| u.vaultwarden_url = "ftp://vault".into()).is_err());
        assert!(with(&|u| u.vaultwarden_url = "https://vault/?x=1".into()).is_err());
        assert!(with(&|u| u.vaultwarden_url = "not a url".into()).is_err());
    }

    #[test]
    fn a_disabled_ui_ignores_the_rest_of_its_section() {
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.ui.vaultwarden_url = "garbage".into();
        cfg.ui.session_idle_minutes = 0;
        assert!(cfg.validate().is_ok());
    }
}
