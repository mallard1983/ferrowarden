use serde::Deserialize;
use std::fmt;
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::error::{FerroError, FerroResult};

pub mod secrets;
use secrets::Both;

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
    /// Comes from FERROWARDEN_ADMIN_KEY or, in a container, from the file
    /// named by FERROWARDEN_ADMIN_KEY_FILE (read here, never exported into
    /// the process environment). Never a config file.
    #[serde(skip)]
    pub admin_key: Zeroizing<String>,

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

    /// Push notifications for security events: Gotify, ntfy and a generic
    /// webhook. `[notify]` in the TOML file, `FERROWARDEN_NOTIFY__*` in the
    /// environment; the tokens only ever come from `FERROWARDEN_NOTIFY_*_TOKEN`
    /// (or `_FILE`). Disabled unless a sender URL is set (docs/notifications.md).
    #[serde(default)]
    pub notify: NotifyConfig,

    /// Which vault backend Ferrowarden reads credentials from, and how it
    /// reaches Vaultwarden. `[vault]` in the TOML file, `FERROWARDEN_VAULT__*`
    /// in the environment (docs/native-vault.md).
    #[serde(default)]
    pub vault: VaultConfig,
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
        validate_vaultwarden_url("ui.vaultwarden_url", &self.vaultwarden_url)?;
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

// ── Vault backend ─────────────────────────────────────────────────────────────

/// The vault backend, chosen once at startup.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum VaultBackend {
    /// The Bitwarden CLI's `bw serve` REST API (`bw_serve_url`). The default.
    #[default]
    BwServe,
    /// The Bitwarden client protocol implemented in Rust directly against
    /// Vaultwarden: no `bw`, no Node. Needs `vault.url` and an API key.
    Native,
}

impl VaultBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            VaultBackend::BwServe => "bw-serve",
            VaultBackend::Native => "native",
        }
    }
}

/// Environment variables the native backend's API key is read from. Each also
/// has a `_FILE` variant that names a file holding the value.
pub const ENV_VAULT_CLIENT_ID: &str = "FERROWARDEN_VAULT_CLIENT_ID";
pub const ENV_VAULT_CLIENT_SECRET: &str = "FERROWARDEN_VAULT_CLIENT_SECRET";

/// The Vaultwarden API key (personal API key: `client_id` and
/// `client_secret`). Never from a config file, wiped when dropped, and
/// `[redacted]` in `Debug` output.
#[derive(Clone, Default)]
pub struct VaultCredentials {
    pub client_id: Option<Zeroizing<String>>,
    pub client_secret: Option<Zeroizing<String>>,
}

impl fmt::Debug for VaultCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let show = |t: &Option<Zeroizing<String>>| if t.is_some() { "[redacted]" } else { "none" };
        f.debug_struct("VaultCredentials")
            .field("client_id", &show(&self.client_id))
            .field("client_secret", &show(&self.client_secret))
            .finish()
    }
}

impl VaultCredentials {
    /// Read the API key from the environment and the files it names (a
    /// direct variable wins over its `_FILE`, like the admin key).
    pub fn from_env() -> FerroResult<Self> {
        Self::load(
            |name| std::env::var(name).ok().filter(|v| !v.is_empty()),
            |path| std::fs::read(path),
        )
    }

    pub fn load(
        get: impl Fn(&str) -> Option<String>,
        read: impl Fn(&std::path::Path) -> std::io::Result<Vec<u8>>,
    ) -> FerroResult<Self> {
        Ok(Self {
            client_id: secrets::load_secret(ENV_VAULT_CLIENT_ID, Both::DirectWins, &get, &read)?,
            client_secret: secrets::load_secret(
                ENV_VAULT_CLIENT_SECRET,
                Both::DirectWins,
                &get,
                &read,
            )?,
        })
    }
}

/// Settings of the vault backend. `[vault]` in the TOML file.
#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct VaultConfig {
    /// `bw-serve` (default) or `native`.
    pub backend: VaultBackend,
    /// Vaultwarden base URL: how Ferrowarden reaches the server. Used by the
    /// native backend and, with the admin UI, to verify the master password at
    /// sign-in. Must be `https://` (plain `http://` only for loopback hosts).
    /// Replaces `ui.vaultwarden_url`, which still works as an alias.
    pub url: String,
    /// PEM file with an extra CA certificate to trust for `url`, on top of the
    /// public roots. Never replaces certificate verification. Replaces
    /// `ui.vaultwarden_ca_file`, which still works as an alias.
    pub ca_file: String,
    /// The native backend's API key (`FERROWARDEN_VAULT_CLIENT_ID[_FILE]`,
    /// `FERROWARDEN_VAULT_CLIENT_SECRET[_FILE]`).
    #[serde(skip)]
    pub credentials: VaultCredentials,
}

pub const DEFAULT_VAULT_URL: &str = "https://vaultwarden";

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            backend: VaultBackend::default(),
            url: DEFAULT_VAULT_URL.to_string(),
            ca_file: String::new(),
            credentials: VaultCredentials::default(),
        }
    }
}

/// Check a Vaultwarden base URL: https, or http for loopback hosts only; no
/// query or fragment. `name` is the setting's name for the message.
fn validate_vaultwarden_url(name: &str, value: &str) -> FerroResult<()> {
    let url = reqwest::Url::parse(value)
        .map_err(|e| FerroError::Config(format!("{name} {value:?} is not a URL ({e})")))?;
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
            return Err(FerroError::Config(format!(
                "{name} must be an https:// URL (http:// only for localhost)"
            )))
        }
    }
    if url.host_str().is_none() || url.query().is_some() || url.fragment().is_some() {
        return Err(FerroError::Config(format!(
            "{name} must be a plain base URL (no query or fragment)"
        )));
    }
    Ok(())
}

impl VaultConfig {
    /// Settle `vault.url` / `vault.ca_file` against their deprecated aliases
    /// `ui.vaultwarden_url` / `ui.vaultwarden_ca_file`, and write the result
    /// back to both places so every user of Vaultwarden sees one value.
    /// Returns the deprecation notices to log.
    pub(crate) fn resolve_aliases(&mut self, ui: &mut UiConfig) -> Vec<String> {
        let mut notes = Vec::new();
        if ui.vaultwarden_url != DEFAULT_VAULT_URL {
            if self.url == DEFAULT_VAULT_URL {
                self.url = ui.vaultwarden_url.clone();
                notes.push(
                    "ui.vaultwarden_url is deprecated: use vault.url (FERROWARDEN_VAULT__URL)"
                        .to_string(),
                );
            } else if self.url != ui.vaultwarden_url {
                notes.push(
                    "both vault.url and the deprecated ui.vaultwarden_url are set and differ: \
                     vault.url is used"
                        .to_string(),
                );
            }
        }
        if !ui.vaultwarden_ca_file.is_empty() {
            if self.ca_file.is_empty() {
                self.ca_file = ui.vaultwarden_ca_file.clone();
                notes.push(
                    "ui.vaultwarden_ca_file is deprecated: use vault.ca_file \
                     (FERROWARDEN_VAULT__CA_FILE)"
                        .to_string(),
                );
            } else if self.ca_file != ui.vaultwarden_ca_file {
                notes.push(
                    "both vault.ca_file and the deprecated ui.vaultwarden_ca_file are set and \
                     differ: vault.ca_file is used"
                        .to_string(),
                );
            }
        }
        ui.vaultwarden_url = self.url.clone();
        ui.vaultwarden_ca_file = self.ca_file.clone();
        notes
    }

    /// Native settings are required in native mode and meaningless otherwise.
    /// Returns warnings for settings that are set but ignored.
    pub(crate) fn validate(
        &self,
        bw_serve_url_set: bool,
        native_vars_set: bool,
    ) -> FerroResult<Vec<String>> {
        let mut warnings = Vec::new();
        match self.backend {
            VaultBackend::Native => {
                validate_vaultwarden_url("vault.url", &self.url)?;
                if self.credentials.client_id.is_none() || self.credentials.client_secret.is_none()
                {
                    return Err(FerroError::Config(format!(
                        "vault.backend = native requires the Vaultwarden API key: set \
                         {ENV_VAULT_CLIENT_ID} (or {ENV_VAULT_CLIENT_ID}_FILE) and \
                         {ENV_VAULT_CLIENT_SECRET} (or {ENV_VAULT_CLIENT_SECRET}_FILE)"
                    )));
                }
                if bw_serve_url_set {
                    warnings.push("vault.backend = native: bw_serve_url is ignored".to_string());
                }
            }
            VaultBackend::BwServe => {
                if native_vars_set {
                    warnings.push(format!(
                        "vault.backend = bw-serve: {ENV_VAULT_CLIENT_ID} and \
                         {ENV_VAULT_CLIENT_SECRET} are ignored (they belong to the native backend)"
                    ));
                }
            }
        }
        Ok(warnings)
    }
}

// ── Notifications ─────────────────────────────────────────────────────────────

/// Environment variables the notifier tokens are read from. Each also has a
/// `_FILE` variant that names a file holding the token.
pub const ENV_GOTIFY_TOKEN: &str = "FERROWARDEN_NOTIFY_GOTIFY_TOKEN";
pub const ENV_NTFY_TOKEN: &str = "FERROWARDEN_NOTIFY_NTFY_TOKEN";
pub const ENV_WEBHOOK_TOKEN: &str = "FERROWARDEN_NOTIFY_WEBHOOK_TOKEN";

/// Notifier tokens. They never come from the config file (the field is
/// skipped by serde), are wiped from memory when dropped, and print as
/// `[redacted]` in `Debug` output.
#[derive(Clone, Default)]
pub struct NotifyTokens {
    pub gotify: Option<Zeroizing<String>>,
    pub ntfy: Option<Zeroizing<String>>,
    pub webhook: Option<Zeroizing<String>>,
}

impl fmt::Debug for NotifyTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let show = |t: &Option<Zeroizing<String>>| if t.is_some() { "[redacted]" } else { "none" };
        f.debug_struct("NotifyTokens")
            .field("gotify", &show(&self.gotify))
            .field("ntfy", &show(&self.ntfy))
            .field("webhook", &show(&self.webhook))
            .finish()
    }
}

impl NotifyTokens {
    /// Read the tokens from the process environment and the files it names.
    pub fn from_env() -> FerroResult<Self> {
        Self::load(
            |name| std::env::var(name).ok().filter(|v| !v.is_empty()),
            |path| std::fs::read(path),
        )
    }

    /// [`from_env`](Self::from_env) with the lookups injected (tests). Setting
    /// both `NAME` and `NAME_FILE` is an error; so is an empty token file or a
    /// token that is not a valid header value. Error messages carry names and
    /// error kinds, never a value.
    pub fn load(
        get: impl Fn(&str) -> Option<String>,
        read: impl Fn(&std::path::Path) -> std::io::Result<Vec<u8>>,
    ) -> FerroResult<Self> {
        let one = |name: &'static str| -> FerroResult<Option<Zeroizing<String>>> {
            let Some(raw) = secrets::load_secret(name, Both::Error, &get, &read)? else {
                return Ok(None);
            };
            let token = Zeroizing::new(raw.trim().to_string());
            if token.is_empty() {
                return Err(FerroError::Config(format!(
                    "the token from {name} (or {name}_FILE) is empty"
                )));
            }
            // Becomes a header value: visible ASCII only.
            if !token.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(FerroError::Config(format!(
                    "the token from {name} (or {name}_FILE) must be printable ASCII without spaces"
                )));
            }
            Ok(Some(token))
        };
        Ok(Self {
            gotify: one(ENV_GOTIFY_TOKEN)?,
            ntfy: one(ENV_NTFY_TOKEN)?,
            webhook: one(ENV_WEBHOOK_TOKEN)?,
        })
    }
}

/// Settings of the notifier (see docs/notifications.md).
#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct NotifyConfig {
    /// Gotify base URL, e.g. `https://gotify.example.com`. Needs
    /// `FERROWARDEN_NOTIFY_GOTIFY_TOKEN`. Empty (default) disables it.
    pub gotify_url: String,
    /// ntfy topic URL, e.g. `https://ntfy.example.com/ferrowarden`. A token
    /// (`FERROWARDEN_NOTIFY_NTFY_TOKEN`) is optional. Empty disables it.
    pub ntfy_url: String,
    /// Generic webhook URL (JSON POST). A token
    /// (`FERROWARDEN_NOTIFY_WEBHOOK_TOKEN`) is optional. Empty disables it.
    pub webhook_url: String,
    /// Categories to notify about: `blocked`, `auth_failure`, `vault`,
    /// `admin`, `system`. A TOML list, or a comma-separated string in the
    /// environment. Default: all but `admin`.
    #[serde(deserialize_with = "string_or_list")]
    pub events: Vec<String>,
    /// At most one notification per category and subject in this many
    /// seconds; the rest are counted and summarised. Default 60.
    pub min_interval_secs: u64,
    /// At most this many notifications per hour in total. Default 60.
    pub max_per_hour: u32,
    /// Failed authentications from one IP address that make a notification.
    /// Default 5.
    pub auth_failure_threshold: u32,
    /// The window those failures are counted in, in seconds. Default 300.
    pub auth_failure_window_secs: u64,
    /// Allow `http://` notifier URLs for hosts other than loopback. Off by
    /// default: a notification crossing the network in clear text can be read
    /// and altered.
    pub allow_http: bool,
    /// PEM file with an extra CA certificate to trust for the notifier URLs,
    /// on top of the public roots.
    pub ca_file: String,
    /// The tokens, from the environment. Never read from the config file.
    #[serde(skip)]
    pub tokens: NotifyTokens,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            gotify_url: String::new(),
            ntfy_url: String::new(),
            webhook_url: String::new(),
            events: crate::notify::Category::DEFAULT
                .iter()
                .map(|c| c.as_str().to_string())
                .collect(),
            min_interval_secs: 60,
            max_per_hour: 60,
            auth_failure_threshold: 5,
            auth_failure_window_secs: 300,
            allow_http: false,
            ca_file: String::new(),
            tokens: NotifyTokens::default(),
        }
    }
}

/// Accept a list, or one comma-separated string (what an environment
/// variable can carry).
fn string_or_list<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Either::deserialize(d)? {
        Either::One(s) => split_list(&s),
        Either::Many(v) => v.into_iter().map(|s| s.trim().to_string()).collect(),
    })
}

/// A host that is this machine: `localhost` or a loopback address.
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

impl NotifyConfig {
    /// The configured sender URLs as `(name, url)`, for the senders that are
    /// enabled.
    pub fn urls(&self) -> Vec<(&'static str, &str)> {
        [
            ("gotify", self.gotify_url.trim()),
            ("ntfy", self.ntfy_url.trim()),
            ("webhook", self.webhook_url.trim()),
        ]
        .into_iter()
        .filter(|(_, u)| !u.is_empty())
        .collect()
    }

    /// At least one sender is configured.
    pub fn enabled(&self) -> bool {
        !self.urls().is_empty()
    }

    /// The enabled categories (valid after validation).
    pub fn categories(&self) -> crate::notify::CategorySet {
        crate::notify::CategorySet::from_names(&self.events).unwrap_or_default()
    }

    /// `(host, port)` of every configured notifier URL, lower-cased, for the
    /// outbound target policy's deny list.
    pub fn endpoints(&self) -> Vec<(String, u16)> {
        self.urls()
            .into_iter()
            .filter_map(|(_, raw)| {
                let url = reqwest::Url::parse(raw).ok()?;
                let host = url
                    .host_str()?
                    .trim_matches(['[', ']'])
                    .to_ascii_lowercase();
                Some((host, url.port_or_known_default()?))
            })
            .collect()
    }

    fn validate(&self) -> FerroResult<()> {
        let err = |m: String| Err(FerroError::Config(m));
        if crate::notify::CategorySet::from_names(&self.events).is_err() {
            let bad: Vec<&str> = self
                .events
                .iter()
                .map(String::as_str)
                .filter(|n| crate::notify::Category::parse(n).is_none())
                .collect();
            return err(format!(
                "notify.events has unknown categories {bad:?}; valid: blocked, auth_failure, vault, admin, system"
            ));
        }
        if self.max_per_hour == 0 || self.auth_failure_threshold == 0 {
            return err(
                "notify.max_per_hour and notify.auth_failure_threshold must be greater than 0"
                    .to_string(),
            );
        }
        if self.auth_failure_window_secs == 0 || self.auth_failure_window_secs > 86_400 {
            return err("notify.auth_failure_window_secs must be between 1 and 86400".to_string());
        }
        if self.min_interval_secs > 86_400 {
            return err("notify.min_interval_secs must be at most 86400".to_string());
        }
        for (name, raw) in self.urls() {
            let key = format!("notify.{name}_url");
            let Ok(url) = reqwest::Url::parse(raw) else {
                return err(format!("{key} is not a valid URL"));
            };
            let Some(host) = url.host_str() else {
                return err(format!("{key} has no host"));
            };
            // Secrets belong in the token variables, not in a URL that ends
            // up in the config file and in logs.
            if !url.username().is_empty() || url.password().is_some() {
                return err(format!(
                    "{key} must not contain a user name or password; use the *_TOKEN variable"
                ));
            }
            if url.query().is_some() || url.fragment().is_some() {
                return err(format!(
                    "{key} must not have a query or fragment; use the *_TOKEN variable for secrets"
                ));
            }
            match url.scheme() {
                "https" => {}
                "http" if is_loopback_host(host) || self.allow_http => {}
                "http" => {
                    return err(format!(
                        "{key} must be https:// (http:// only for localhost, or with notify.allow_http = true)"
                    ))
                }
                _ => return err(format!("{key} must be an https:// URL")),
            }
        }
        if !self.gotify_url.trim().is_empty() && self.tokens.gotify.is_none() {
            return err(format!(
                "notify.gotify_url needs a token: set {ENV_GOTIFY_TOKEN} or {ENV_GOTIFY_TOKEN}_FILE"
            ));
        }
        if self.enabled() && self.events.is_empty() {
            return err("notify.events must list at least one category".to_string());
        }
        if !self.ca_file.trim().is_empty() {
            if !self.enabled() {
                return err("notify.ca_file is set but no notifier URL is".to_string());
            }
            crate::notify::senders::load_ca(self.ca_file.trim()).map_err(FerroError::Config)?;
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
    /// The settings from `ferrowarden.toml` and `FERROWARDEN_*` variables,
    /// without secrets and without validation.
    fn load_settings() -> FerroResult<Self> {
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
        cfg.api_prefix = normalize_api_prefix(&cfg.api_prefix)?;
        Ok(cfg)
    }

    pub fn load() -> FerroResult<Self> {
        let mut cfg = Self::load_settings()?;

        // The admin key never comes from a config file: from the environment,
        // or from the file FERROWARDEN_ADMIN_KEY_FILE names. A direct variable
        // wins. Either way the value stays in this struct (zeroed on drop) and
        // is not exported into the process environment.
        cfg.admin_key = secrets::load_secret_from_env("FERROWARDEN_ADMIN_KEY", Both::DirectWins)?
            .ok_or_else(|| {
            FerroError::Config(
                "FERROWARDEN_ADMIN_KEY must be set (directly or via FERROWARDEN_ADMIN_KEY_FILE)"
                    .to_string(),
            )
        })?;

        cfg.notify.tokens = NotifyTokens::from_env()?;

        let notes = cfg.vault.resolve_aliases(&mut cfg.ui);
        for note in &notes {
            tracing::warn!("{note}");
        }
        // The API key matters to the native backend only. In bw-serve mode
        // the variables are not read (a stale `_FILE` must not stop startup).
        if cfg.vault.backend == VaultBackend::Native {
            cfg.vault.credentials = VaultCredentials::from_env()?;
        }

        cfg.validate()?;

        Ok(cfg)
    }

    /// The settings `ferrowarden healthcheck` needs (bind address, TLS
    /// certificate): no secrets are read and nothing is validated, so the
    /// check works with the same environment as the server and no more.
    pub fn load_for_healthcheck() -> FerroResult<Self> {
        Self::load_settings()
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
        self.notify.validate()?;
        let native_vars_set = [ENV_VAULT_CLIENT_ID, ENV_VAULT_CLIENT_SECRET]
            .iter()
            .any(|n| {
                std::env::var_os(n).is_some() || std::env::var_os(format!("{n}_FILE")).is_some()
            });
        for warning in self
            .vault
            .validate(self.bw_serve_url != default_bw_serve_url(), native_vars_set)?
        {
            tracing::warn!("{warning}");
        }

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
            admin_key: "a".repeat(32).into(),
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
            notify: Default::default(),
            vault: Default::default(),
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
        cfg.admin_key = "short".to_string().into();
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("32 characters"));
    }

    #[test]
    fn the_admin_key_file_is_read_without_touching_the_environment() {
        // Config::load reads the real environment; this is the only test that
        // sets FERROWARDEN_* variables, and it removes them again.
        let key = "k".repeat(40);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin_key");
        std::fs::write(
            &path,
            format!(
                "{key}
"
            ),
        )
        .unwrap();
        std::env::remove_var("FERROWARDEN_ADMIN_KEY");
        std::env::set_var("FERROWARDEN_ADMIN_KEY_FILE", &path);
        std::env::set_var("FERROWARDEN_TLS_ENABLED", "false");
        std::env::set_var("FERROWARDEN_UNLOCK_MODE", "manual");
        let loaded = Config::load();
        // The key stays out of the process environment.
        let leaked = std::env::var("FERROWARDEN_ADMIN_KEY");
        let in_env_values = std::env::vars().any(|(_, v)| v == key);

        // A missing file is an error, not a silent empty key.
        std::env::set_var("FERROWARDEN_ADMIN_KEY_FILE", dir.path().join("nope"));
        let missing = Config::load().unwrap_err().to_string();
        // A direct variable takes precedence over the file.
        let direct = "d".repeat(40);
        std::env::set_var("FERROWARDEN_ADMIN_KEY", &direct);
        let preferred = Config::load();
        for name in [
            "FERROWARDEN_ADMIN_KEY",
            "FERROWARDEN_ADMIN_KEY_FILE",
            "FERROWARDEN_TLS_ENABLED",
            "FERROWARDEN_UNLOCK_MODE",
        ] {
            std::env::remove_var(name);
        }

        assert_eq!(loaded.unwrap().admin_key.as_str(), key);
        assert!(leaked.is_err(), "the key must not be exported");
        assert!(!in_env_values);
        assert!(missing.contains("does not exist"), "{missing}");
        assert_eq!(preferred.unwrap().admin_key.as_str(), direct);
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

    // ── [notify] ──────────────────────────────────────────────────────────────

    fn tokens_from(env: &[(&str, &str)], files: &[(&str, &[u8])]) -> FerroResult<NotifyTokens> {
        let env: std::collections::HashMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let files: std::collections::HashMap<String, Vec<u8>> = files
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_vec()))
            .collect();
        NotifyTokens::load(
            |name| env.get(name).cloned(),
            |path| {
                files
                    .get(path.to_str().unwrap())
                    .cloned()
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
            },
        )
    }

    #[test]
    fn notify_defaults_match_the_documentation() {
        let n = NotifyConfig::default();
        assert!(!n.enabled());
        assert_eq!(n.events, ["blocked", "auth_failure", "vault", "system"]);
        assert_eq!(n.min_interval_secs, 60);
        assert_eq!(n.max_per_hour, 60);
        assert_eq!(n.auth_failure_threshold, 5);
        assert_eq!(n.auth_failure_window_secs, 300);
        assert!(!n.allow_http);
        assert!(n.ca_file.is_empty());
        assert!(base_config(UnlockMode::Manual).validate().is_ok());
    }

    #[test]
    fn notify_section_deserializes_from_a_list_or_a_comma_separated_string() {
        let from = |text: &str| -> Config {
            config::Config::builder()
                .add_source(config::File::from_str(text, config::FileFormat::Toml))
                .build()
                .unwrap()
                .try_deserialize()
                .unwrap()
        };
        let cfg = from(
            "unlock_mode = \"manual\"\n[notify]\nwebhook_url = \"https://hooks.example.com/x\"\nevents = [\"blocked\", \"admin\"]\nmax_per_hour = 5\n",
        );
        assert_eq!(cfg.notify.events, ["blocked", "admin"]);
        assert_eq!(cfg.notify.max_per_hour, 5);
        assert_eq!(
            cfg.notify.min_interval_secs, 60,
            "unspecified keys keep their defaults"
        );
        let cfg = from("unlock_mode = \"manual\"\n[notify]\nevents = \"blocked, vault\"\n");
        assert_eq!(cfg.notify.events, ["blocked", "vault"]);
    }

    #[test]
    fn notify_settings_come_from_the_environment_too() {
        // The same builder the real loader uses, with a fake environment.
        let mut env = std::collections::HashMap::new();
        env.insert("FERROWARDEN_UNLOCK_MODE".to_string(), "manual".to_string());
        env.insert(
            "FERROWARDEN_NOTIFY__WEBHOOK_URL".to_string(),
            "https://hooks.example.com/x".to_string(),
        );
        env.insert(
            "FERROWARDEN_NOTIFY__EVENTS".to_string(),
            "blocked,auth_failure".to_string(),
        );
        env.insert(
            "FERROWARDEN_NOTIFY__MIN_INTERVAL_SECS".to_string(),
            "5".to_string(),
        );
        env.insert(
            "FERROWARDEN_NOTIFY__ALLOW_HTTP".to_string(),
            "true".to_string(),
        );
        // Token variables share the prefix: they must be ignored here.
        env.insert(
            "FERROWARDEN_NOTIFY_GOTIFY_TOKEN".to_string(),
            "not-a-setting".to_string(),
        );
        let cfg: Config = config::Config::builder()
            .add_source(
                config::Environment::with_prefix("FERROWARDEN")
                    .prefix_separator("_")
                    .separator("__")
                    .ignore_empty(true)
                    .source(Some(env)),
            )
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(cfg.notify.webhook_url, "https://hooks.example.com/x");
        assert_eq!(cfg.notify.events, ["blocked", "auth_failure"]);
        assert_eq!(cfg.notify.min_interval_secs, 5);
        assert!(cfg.notify.allow_http);
        assert!(cfg.notify.tokens.gotify.is_none());
    }

    #[test]
    fn notifier_tokens_come_from_the_environment_or_a_file_never_both() {
        assert!(tokens_from(&[], &[]).unwrap().gotify.is_none());
        let t = tokens_from(&[(ENV_GOTIFY_TOKEN, "  direct-token-1 \n")], &[]).unwrap();
        assert_eq!(
            t.gotify.as_deref().map(String::as_str),
            Some("direct-token-1")
        );
        let t = tokens_from(
            &[("FERROWARDEN_NOTIFY_NTFY_TOKEN_FILE", "/run/secrets/ntfy")],
            &[("/run/secrets/ntfy", b"file-token-2\r\n")],
        )
        .unwrap();
        assert_eq!(t.ntfy.as_deref().map(String::as_str), Some("file-token-2"));
        assert!(t.gotify.is_none() && t.webhook.is_none());

        let both = tokens_from(
            &[
                (ENV_WEBHOOK_TOKEN, "tok-one-secret-value"),
                ("FERROWARDEN_NOTIFY_WEBHOOK_TOKEN_FILE", "/f"),
            ],
            &[("/f", b"tok-two-secret-value")],
        )
        .unwrap_err()
        .to_string();
        assert!(both.contains("only one of"), "{both}");
        assert!(!both.contains("secret-value"), "{both}");
    }

    #[test]
    fn bad_token_sources_are_errors_that_never_echo_the_value() {
        let spaced = "s3cr3t token with spaces";
        type Case<'a> = (Vec<(&'a str, &'a str)>, Vec<(&'a str, &'a [u8])>);
        let cases: Vec<Case> = vec![
            // A missing file.
            (
                vec![("FERROWARDEN_NOTIFY_GOTIFY_TOKEN_FILE", "/nope")],
                vec![],
            ),
            // An empty file, a whitespace-only value.
            (
                vec![("FERROWARDEN_NOTIFY_GOTIFY_TOKEN_FILE", "/e")],
                vec![("/e", b"\n")],
            ),
            (vec![(ENV_GOTIFY_TOKEN, "   ")], vec![]),
            // Not valid UTF-8.
            (
                vec![("FERROWARDEN_NOTIFY_GOTIFY_TOKEN_FILE", "/b")],
                vec![("/b", &[0xff, 0xfe, 0x41])],
            ),
            // Not a valid header value: spaces inside, control characters.
            (vec![(ENV_GOTIFY_TOKEN, spaced)], vec![]),
            (vec![(ENV_GOTIFY_TOKEN, "ab\u{1}cd")], vec![]),
            (vec![(ENV_GOTIFY_TOKEN, "tok\u{e9}n")], vec![]),
        ];
        for (env, files) in cases {
            let err = tokens_from(&env, &files).unwrap_err().to_string();
            assert!(err.contains("FERROWARDEN_NOTIFY_GOTIFY_TOKEN"), "{err}");
            for (_, v) in &env {
                if v.len() > 6 && !v.starts_with('/') {
                    assert!(!err.contains(v), "{err}");
                }
            }
        }
    }

    #[test]
    fn tokens_are_redacted_in_debug_output_and_not_read_from_the_config_file() {
        let t = tokens_from(&[(ENV_GOTIFY_TOKEN, "gotify-secret-123456")], &[]).unwrap();
        let shown = format!("{t:?}");
        assert!(!shown.contains("gotify-secret"), "{shown}");
        assert!(shown.contains("[redacted]"));
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.notify.tokens = t;
        assert!(!format!("{cfg:?}").contains("gotify-secret"));

        // A `tokens` key in the file is ignored (serde skip), not read.
        let cfg: Config = config::Config::builder()
            .add_source(config::File::from_str(
                "unlock_mode = \"manual\"\n[notify.tokens]\ngotify = \"from-the-file-12345\"\n",
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert!(cfg.notify.tokens.gotify.is_none());
    }

    fn notify_cfg(f: impl Fn(&mut NotifyConfig)) -> FerroResult<()> {
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.notify.webhook_url = "https://hooks.example.com/ferrowarden".into();
        f(&mut cfg.notify);
        cfg.validate()
    }

    #[test]
    fn notify_validation_covers_urls_categories_limits_and_tokens() {
        assert!(notify_cfg(|_| {}).is_ok());
        type Tweak = Box<dyn Fn(&mut NotifyConfig)>;
        let bad: Vec<(&str, Tweak)> = vec![
            (
                "not a url",
                Box::new(|n| n.webhook_url = "not a url".into()),
            ),
            ("no host", Box::new(|n| n.webhook_url = "https://".into())),
            (
                "ftp",
                Box::new(|n| n.webhook_url = "ftp://hooks.example.com/x".into()),
            ),
            (
                "http",
                Box::new(|n| n.webhook_url = "http://hooks.example.com/x".into()),
            ),
            (
                "userinfo",
                Box::new(|n| n.webhook_url = "https://u:p@hooks.example.com/x".into()),
            ),
            (
                "query",
                Box::new(|n| n.webhook_url = "https://hooks.example.com/x?token=abc".into()),
            ),
            (
                "fragment",
                Box::new(|n| n.webhook_url = "https://hooks.example.com/x#f".into()),
            ),
            (
                "bad ntfy",
                Box::new(|n| n.ntfy_url = "ntfy.example.com/topic".into()),
            ),
            (
                "gotify without token",
                Box::new(|n| n.gotify_url = "https://gotify.example.com".into()),
            ),
            (
                "unknown category",
                Box::new(|n| n.events = vec!["blocked".into(), "everything".into()]),
            ),
            ("no categories", Box::new(|n| n.events = vec![])),
            ("zero cap", Box::new(|n| n.max_per_hour = 0)),
            ("zero threshold", Box::new(|n| n.auth_failure_threshold = 0)),
            ("zero window", Box::new(|n| n.auth_failure_window_secs = 0)),
            (
                "huge window",
                Box::new(|n| n.auth_failure_window_secs = 100_000),
            ),
            ("huge interval", Box::new(|n| n.min_interval_secs = 100_000)),
            (
                "missing ca file",
                Box::new(|n| n.ca_file = "/no/such/ca.pem".into()),
            ),
        ];
        for (name, tweak) in &bad {
            assert!(notify_cfg(tweak).is_err(), "{name} should fail");
        }
        // http is fine for this machine, and anywhere with allow_http.
        for url in [
            "http://localhost:8080/x",
            "http://127.0.0.1/x",
            "http://[::1]:9/x",
        ] {
            assert!(notify_cfg(|n| n.webhook_url = url.into()).is_ok(), "{url}");
        }
        assert!(notify_cfg(|n| {
            n.webhook_url = "http://hooks.example.com/x".into();
            n.allow_http = true;
        })
        .is_ok());
        // Gotify with its token.
        assert!(notify_cfg(|n| {
            n.gotify_url = "https://gotify.example.com".into();
            n.tokens.gotify = Some(Zeroizing::new("tok".into()));
        })
        .is_ok());
        // Unknown categories are an error even with no sender.
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.notify.events = vec!["nope".into()];
        assert!(cfg.validate().unwrap_err().to_string().contains("nope"));
        // A disabled notifier with a stray CA file is a mistake worth saying.
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.notify.ca_file = "/x.pem".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn notify_endpoints_list_each_notifier_host_and_port() {
        let n = NotifyConfig {
            gotify_url: "https://Gotify.Example.com/".into(),
            ntfy_url: "https://ntfy.example.com:8443/topic".into(),
            webhook_url: "http://[::1]:7777/n".into(),
            ..NotifyConfig::default()
        };
        assert_eq!(
            n.endpoints(),
            [
                ("gotify.example.com".to_string(), 443),
                ("ntfy.example.com".to_string(), 8443),
                ("::1".to_string(), 7777)
            ]
        );
        assert!(NotifyConfig::default().endpoints().is_empty());
    }

    #[test]
    fn a_disabled_ui_ignores_the_rest_of_its_section() {
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.ui.vaultwarden_url = "garbage".into();
        cfg.ui.session_idle_minutes = 0;
        assert!(cfg.validate().is_ok());
    }

    // ── [vault] ───────────────────────────────────────────────────────────────

    fn vault_creds(id: Option<&str>, secret: Option<&str>) -> VaultCredentials {
        VaultCredentials {
            client_id: id.map(|v| Zeroizing::new(v.to_string())),
            client_secret: secret.map(|v| Zeroizing::new(v.to_string())),
        }
    }

    #[test]
    fn vault_defaults_to_bw_serve_and_the_documented_url() {
        let v = VaultConfig::default();
        assert_eq!(v.backend, VaultBackend::BwServe);
        assert_eq!(v.url, "https://vaultwarden");
        assert_eq!(v.ca_file, "");
        assert_eq!(VaultBackend::Native.as_str(), "native");
        assert_eq!(VaultBackend::BwServe.as_str(), "bw-serve");
        assert!(base_config(UnlockMode::Manual).validate().is_ok());
    }

    #[test]
    fn vault_backend_comes_from_the_file_or_the_environment() {
        let v: VaultConfig =
            serde_json::from_str(r#"{"backend":"native","url":"https://vw.example"}"#).unwrap();
        assert_eq!(v.backend, VaultBackend::Native);
        assert_eq!(v.url, "https://vw.example");
        assert!(serde_json::from_str::<VaultConfig>(r#"{"backend":"nope"}"#).is_err());

        let mut env = std::collections::HashMap::new();
        env.insert("FERROWARDEN_UNLOCK_MODE".to_string(), "manual".to_string());
        env.insert(
            "FERROWARDEN_VAULT__BACKEND".to_string(),
            "native".to_string(),
        );
        env.insert(
            "FERROWARDEN_VAULT__CA_FILE".to_string(),
            "/ca/ca.crt".to_string(),
        );
        // The API key variables share the prefix: they must be ignored here.
        env.insert(
            "FERROWARDEN_VAULT_CLIENT_SECRET".to_string(),
            "not-a-setting".to_string(),
        );
        let cfg: Config = config::Config::builder()
            .add_source(
                config::Environment::with_prefix("FERROWARDEN")
                    .prefix_separator("_")
                    .separator("__")
                    .ignore_empty(true)
                    .source(Some(env)),
            )
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(cfg.vault.backend, VaultBackend::Native);
        assert_eq!(cfg.vault.ca_file, "/ca/ca.crt");
        assert!(cfg.vault.credentials.client_secret.is_none());
    }

    #[test]
    fn native_mode_needs_a_valid_url_and_the_api_key() {
        let native = |url: &str, id: Option<&str>, secret: Option<&str>| {
            let mut cfg = base_config(UnlockMode::Manual);
            cfg.vault.backend = VaultBackend::Native;
            cfg.vault.url = url.to_string();
            cfg.vault.credentials = vault_creds(id, secret);
            cfg.validate()
        };
        assert!(native("https://vaultwarden", Some("i"), Some("s")).is_ok());
        assert!(native("http://localhost:8000", Some("i"), Some("s")).is_ok());
        for bad in [
            "http://vaultwarden",
            "ftp://x",
            "not a url",
            "https://vw/?a=b",
            "https://vw/#f",
        ] {
            let err = native(bad, Some("i"), Some("s")).unwrap_err().to_string();
            assert!(err.contains("vault.url"), "{bad}: {err}");
        }
        for (id, secret) in [(None, Some("s")), (Some("i"), None), (None, None)] {
            let err = native("https://vaultwarden", id, secret)
                .unwrap_err()
                .to_string();
            assert!(err.contains(ENV_VAULT_CLIENT_ID), "{err}");
            assert!(err.contains(ENV_VAULT_CLIENT_SECRET), "{err}");
        }
    }

    #[test]
    fn bw_serve_mode_does_not_need_or_check_the_native_settings() {
        let mut cfg = base_config(UnlockMode::Manual);
        cfg.vault.url = "http://not-https-and-never-used".to_string();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn ignored_settings_produce_warnings_in_either_mode() {
        let mut v = VaultConfig::default();
        assert!(v.validate(false, false).unwrap().is_empty());
        let w = v.validate(false, true).unwrap();
        assert!(w[0].contains("ignored"), "{w:?}");
        v.backend = VaultBackend::Native;
        v.credentials = vault_creds(Some("i"), Some("s"));
        assert!(v.validate(false, true).unwrap().is_empty());
        let w = v.validate(true, true).unwrap();
        assert!(w[0].contains("bw_serve_url is ignored"), "{w:?}");
    }

    #[test]
    fn the_api_key_comes_from_the_environment_or_a_file_and_is_redacted() {
        let load = |vars: &[(&str, &str)], files: &[(&str, &str)]| {
            let vars: std::collections::HashMap<String, String> = vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let files: std::collections::HashMap<String, String> = files
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            VaultCredentials::load(
                |n| vars.get(n).cloned(),
                |p| {
                    files
                        .get(p.to_str().unwrap())
                        .map(|v| v.clone().into_bytes())
                        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
                },
            )
        };
        let c = load(
            &[
                ("FERROWARDEN_VAULT_CLIENT_ID_FILE", "/run/secrets/id"),
                ("FERROWARDEN_VAULT_CLIENT_SECRET", "direct-secret-value"),
            ],
            &[("/run/secrets/id", "user.abc\n")],
        )
        .unwrap();
        assert_eq!(c.client_id.as_ref().unwrap().as_str(), "user.abc");
        assert_eq!(
            c.client_secret.as_ref().unwrap().as_str(),
            "direct-secret-value"
        );
        // Never in Debug output.
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("direct-secret-value") && !dbg.contains("user.abc"));
        assert!(dbg.contains("[redacted]"));
        // A missing file is an error that names the variable, not the value.
        let err = load(&[("FERROWARDEN_VAULT_CLIENT_ID_FILE", "/nope")], &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("FERROWARDEN_VAULT_CLIENT_ID_FILE"), "{err}");
        // Nothing set: both absent.
        let none = load(&[], &[]).unwrap();
        assert!(none.client_id.is_none() && none.client_secret.is_none());
    }

    #[test]
    fn deprecated_ui_settings_are_aliases_for_the_vault_settings() {
        // Only the old names set: they are adopted, with a deprecation note.
        let mut vault = VaultConfig::default();
        let mut ui = UiConfig {
            vaultwarden_url: "https://old.example".to_string(),
            vaultwarden_ca_file: "/ca/old.crt".to_string(),
            ..UiConfig::default()
        };
        let notes = vault.resolve_aliases(&mut ui);
        assert_eq!(vault.url, "https://old.example");
        assert_eq!(vault.ca_file, "/ca/old.crt");
        assert_eq!(notes.len(), 2);
        assert!(notes.iter().all(|n| n.contains("deprecated")));

        // New names win when both are set and differ.
        let mut vault = VaultConfig {
            url: "https://new.example".to_string(),
            ca_file: "/ca/new.crt".to_string(),
            ..VaultConfig::default()
        };
        let mut ui = UiConfig {
            vaultwarden_url: "https://old.example".to_string(),
            vaultwarden_ca_file: "/ca/old.crt".to_string(),
            ..UiConfig::default()
        };
        let notes = vault.resolve_aliases(&mut ui);
        assert_eq!(vault.url, "https://new.example");
        assert_eq!(ui.vaultwarden_url, "https://new.example", "written back");
        assert_eq!(ui.vaultwarden_ca_file, "/ca/new.crt");
        assert_eq!(notes.len(), 2);

        // Only the new names, or nothing: no notes.
        let mut vault = VaultConfig {
            ca_file: "/ca/new.crt".to_string(),
            ..VaultConfig::default()
        };
        let mut ui = UiConfig::default();
        assert!(vault.resolve_aliases(&mut ui).is_empty());
        assert_eq!(ui.vaultwarden_ca_file, "/ca/new.crt");
    }
}
