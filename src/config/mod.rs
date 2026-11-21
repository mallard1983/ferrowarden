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

fn default_forward_timeout_secs() -> u64 {
    30
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
            // Base config from file — ferrowarden.toml in the working directory
            .add_source(
                config::File::with_name("ferrowarden")
                    .format(config::FileFormat::Toml)
                    .required(false),
            )
            // Environment variables override file values.
            // FERROWARDEN_BIND_ADDR, FERROWARDEN_UNLOCK_MODE, etc.
            .add_source(
                config::Environment::with_prefix("FERROWARDEN")
                    .prefix_separator("_")  // single _ between prefix and key (FERROWARDEN_FIELD)
                    .separator("__")        // double __ for nested keys (FERROWARDEN_SECTION__KEY)
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
        assert_eq!(split_list(" a, ,b ,"), vec!["a".to_string(), "b".to_string()]);
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
}
