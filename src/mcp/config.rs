//! Configuration of `ferrowarden-mcp`, read from the environment.
//!
//! Every problem is reported without echoing a secret: the agent key is never
//! formatted, and the base URL is described by its host only because its path
//! may be the operator's secret `api_prefix`.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use reqwest::Url;
use zeroize::Zeroizing;

pub const ENV_URL: &str = "FERROWARDEN_URL";
pub const ENV_KEY: &str = "FERROWARDEN_AGENT_KEY";
pub const ENV_KEY_FILE: &str = "FERROWARDEN_AGENT_KEY_FILE";
pub const ENV_CA_FILE: &str = "FERROWARDEN_CA_FILE";
pub const ENV_TIMEOUT: &str = "FERROWARDEN_MCP_TIMEOUT_SECS";
pub const ENV_ALLOW_HTTP: &str = "FERROWARDEN_MCP_ALLOW_HTTP";

pub const DEFAULT_TIMEOUT_SECS: u64 = 60;
pub const MIN_TIMEOUT_SECS: u64 = 1;
pub const MAX_TIMEOUT_SECS: u64 = 600;

/// A configuration problem. The message is safe to print: it names the
/// variable and the rule, never a value.
#[derive(Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn err<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(message.into()))
}

/// Validated settings.
pub struct Config {
    /// The base URL with any `api_prefix`, no trailing slash, no query or
    /// fragment. Its path may be a secret.
    pub base_url: Url,
    pub agent_key: Zeroizing<String>,
    /// Extra root certificates, added to the built-in webpki roots.
    pub extra_roots: Vec<reqwest::Certificate>,
    pub timeout: Duration,
    /// `http://` to a non-loopback host was explicitly allowed.
    pub insecure_http_allowed: bool,
}

// `Zeroizing<String>` prints its contents under `{:?}`, and the base URL path
// may be secret, so the derived `Debug` is not used.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("host", &self.host_for_log())
            .field("agent_key", &"<redacted>")
            .field("extra_roots", &self.extra_roots.len())
            .field("timeout", &self.timeout)
            .field("insecure_http_allowed", &self.insecure_http_allowed)
            .finish()
    }
}

impl Config {
    /// The host (and port) only, for logs. Never the path.
    pub fn host_for_log(&self) -> String {
        match (self.base_url.host_str(), self.base_url.port()) {
            (Some(host), Some(port)) => format!("{host}:{port}"),
            (Some(host), None) => host.to_string(),
            _ => "<unknown>".to_string(),
        }
    }

    /// Whether the base URL is plain `http://` to a host that is not loopback.
    pub fn uses_insecure_http(&self) -> bool {
        self.base_url.scheme() == "http" && !is_loopback_host(&self.base_url)
    }

    /// Read the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(()),
        })
    }

    /// Read settings through `lookup`. `Ok(None)` is "not set"; `Err(())` is
    /// "set to something that is not valid text". Used by tests with a map.
    pub fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Result<Option<String>, ()>,
    {
        let get = |name: &str| -> Result<Option<String>, ConfigError> {
            lookup(name)
                .map_err(|()| ConfigError(format!("{name} is not valid UTF-8 text")))
                .map(|v| v.filter(|s| !s.trim().is_empty()))
        };

        let allow_http = match get(ENV_ALLOW_HTTP)?.as_deref().map(str::trim) {
            None | Some("0") => false,
            Some("1") => true,
            Some(_) => return err(format!("{ENV_ALLOW_HTTP} must be 1 or 0 when it is set")),
        };

        let raw_url = match get(ENV_URL)? {
            Some(v) => v,
            None => {
                return err(format!(
                    "{ENV_URL} is required: the base URL of Ferrowarden, including any api_prefix"
                ))
            }
        };
        let base_url = parse_base_url(raw_url.trim(), allow_http)?;

        let agent_key = read_agent_key(&get)?;

        let extra_roots = match get(ENV_CA_FILE)? {
            Some(path) => read_ca_file(PathBuf::from(path.trim()))?,
            None => Vec::new(),
        };

        let timeout = match get(ENV_TIMEOUT)? {
            None => Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            Some(raw) => match raw.trim().parse::<u64>() {
                Ok(n) if (MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&n) => {
                    Duration::from_secs(n)
                }
                _ => {
                    return err(format!(
                        "{ENV_TIMEOUT} must be a whole number of seconds from \
                         {MIN_TIMEOUT_SECS} to {MAX_TIMEOUT_SECS}"
                    ))
                }
            },
        };

        Ok(Config {
            base_url,
            agent_key,
            extra_roots,
            timeout,
            insecure_http_allowed: allow_http,
        })
    }
}

fn is_loopback_host(url: &Url) -> bool {
    // `host_str` is lower-case and writes an IPv6 literal in brackets.
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

fn parse_base_url(raw: &str, allow_http: bool) -> Result<Url, ConfigError> {
    // The parse error is not printed: it can quote part of the URL.
    let mut url = match Url::parse(raw) {
        Ok(u) => u,
        Err(_) => {
            return err(format!(
                "{ENV_URL} is not a valid URL (expected https://host[:port][/api_prefix])"
            ))
        }
    };
    if url.cannot_be_a_base() || url.host_str().is_none() {
        return err(format!(
            "{ENV_URL} must be an absolute http(s) URL with a host"
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return err(format!(
            "{ENV_URL} must not contain a user name or password"
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return err(format!("{ENV_URL} must not contain a query or fragment"));
    }
    match url.scheme() {
        "https" => {}
        "http" => {
            if !is_loopback_host(&url) && !allow_http {
                return err(format!(
                    "{ENV_URL} must use https:// (http:// is accepted only for localhost, \
                     127.0.0.1 and [::1]; set {ENV_ALLOW_HTTP}=1 for a trusted internal network)"
                ));
            }
        }
        _ => return err(format!("{ENV_URL} must use https://")),
    }
    // Normalise: no trailing slash, so endpoints are base + "/v1/...".
    let trimmed = url.path().trim_end_matches('/').to_string();
    url.set_path(&trimmed);
    Ok(url)
}

fn read_agent_key<F>(get: &F) -> Result<Zeroizing<String>, ConfigError>
where
    F: Fn(&str) -> Result<Option<String>, ConfigError>,
{
    let direct = get(ENV_KEY)?.map(Zeroizing::new);
    let file = get(ENV_KEY_FILE)?;
    let key = match (direct, file) {
        (Some(_), Some(_)) => {
            return err(format!(
                "set only one of {ENV_KEY} and {ENV_KEY_FILE}, not both"
            ))
        }
        (None, None) => {
            return err(format!(
                "{ENV_KEY} (or {ENV_KEY_FILE}) is required: the agent key for this client"
            ))
        }
        (Some(k), None) => Zeroizing::new(k.trim().to_string()),
        (None, Some(path)) => {
            let raw = match std::fs::read_to_string(path.trim()) {
                Ok(s) => Zeroizing::new(s),
                Err(e) => {
                    // The io error text can contain the path; say only the kind.
                    return err(format!("could not read {ENV_KEY_FILE} ({:?})", e.kind()));
                }
            };
            Zeroizing::new(raw.trim().to_string())
        }
    };
    if key.is_empty() {
        return err(format!(
            "the agent key (from {ENV_KEY} or {ENV_KEY_FILE}) is empty"
        ));
    }
    // It becomes an HTTP header value: no control characters or whitespace.
    if key
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || !c.is_ascii())
    {
        return err(
            "the agent key contains whitespace, control or non-ASCII characters; \
             it must be a single token on one line",
        );
    }
    Ok(key)
}

fn read_ca_file(path: PathBuf) -> Result<Vec<reqwest::Certificate>, ConfigError> {
    let pem = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            return err(format!("could not read {ENV_CA_FILE} ({:?})", e.kind()));
        }
    };
    match reqwest::Certificate::from_pem_bundle(&pem) {
        Ok(certs) if !certs.is_empty() => Ok(certs),
        Ok(_) => err(format!("{ENV_CA_FILE} contains no certificates")),
        Err(_) => err(format!(
            "{ENV_CA_FILE} is not a valid PEM certificate bundle"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    pub const FAKE_KEY: &str = "fw_agent_FAKEKEY0123456789";
    pub const FAKE_PREFIX: &str = "s3cr3tpr3fix";

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Result<Option<String>, ()> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| Ok(map.get(name).cloned())
    }

    fn load(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        Config::from_lookup(lookup(pairs))
    }

    fn msg(r: Result<Config, ConfigError>) -> String {
        r.expect_err("expected a configuration error").0
    }

    #[test]
    fn minimal_https_config_defaults() {
        let c = load(&[(ENV_URL, "https://ferro.example.com"), (ENV_KEY, FAKE_KEY)]).unwrap();
        assert_eq!(c.timeout, Duration::from_secs(60));
        assert_eq!(c.agent_key.as_str(), FAKE_KEY);
        assert!(!c.insecure_http_allowed);
        assert!(!c.uses_insecure_http());
        assert!(c.extra_roots.is_empty());
    }

    #[test]
    fn url_and_key_are_required() {
        assert!(msg(load(&[(ENV_KEY, FAKE_KEY)])).contains(ENV_URL));
        assert!(msg(load(&[(ENV_URL, "https://f.example.com")])).contains(ENV_KEY));
        // Blank counts as unset.
        assert!(msg(load(&[(ENV_URL, "  "), (ENV_KEY, FAKE_KEY)])).contains(ENV_URL));
    }

    #[test]
    fn prefix_is_kept_and_trailing_slash_removed() {
        let url = format!("https://ferro.example.com/{FAKE_PREFIX}/");
        let c = load(&[(ENV_URL, &url), (ENV_KEY, FAKE_KEY)]).unwrap();
        assert_eq!(c.base_url.path(), format!("/{FAKE_PREFIX}"));
        let bare = load(&[(ENV_URL, "https://ferro.example.com/"), (ENV_KEY, FAKE_KEY)]).unwrap();
        assert_eq!(bare.base_url.path(), "/");
    }

    #[test]
    fn plain_http_only_for_loopback_or_when_allowed() {
        for ok in [
            "http://localhost:3000",
            "http://127.0.0.1:3000/p",
            "http://[::1]:3000",
        ] {
            let c = load(&[(ENV_URL, ok), (ENV_KEY, FAKE_KEY)]).unwrap();
            assert!(!c.uses_insecure_http(), "{ok}");
        }
        let url = format!("http://ferro.lan:3000/{FAKE_PREFIX}");
        let refused = msg(load(&[(ENV_URL, &url), (ENV_KEY, FAKE_KEY)]));
        assert!(refused.contains("https://"));
        assert!(!refused.contains(FAKE_PREFIX), "error echoed the URL path");
        let c = load(&[(ENV_URL, &url), (ENV_KEY, FAKE_KEY), (ENV_ALLOW_HTTP, "1")]).unwrap();
        assert!(c.uses_insecure_http());
        assert_eq!(c.host_for_log(), "ferro.lan:3000");
        assert!(msg(load(&[
            (ENV_URL, &url),
            (ENV_KEY, FAKE_KEY),
            (ENV_ALLOW_HTTP, "yes"),
        ]))
        .contains(ENV_ALLOW_HTTP));
        // 0 is the same as unset.
        assert!(load(&[(ENV_URL, &url), (ENV_KEY, FAKE_KEY), (ENV_ALLOW_HTTP, "0")]).is_err());
    }

    #[test]
    fn rejects_bad_urls_without_echoing_them() {
        for bad in [
            "ftp://ferro.example.com/x",
            "not a url",
            "https://user:pw@ferro.example.com/x",
            "https://ferro.example.com/x?a=1",
            "https://ferro.example.com/x#frag",
            "mailto:someone@example.com",
        ] {
            let m = msg(load(&[(ENV_URL, bad), (ENV_KEY, FAKE_KEY)]));
            assert!(
                !m.contains("pw@") && !m.contains("ferro.example.com"),
                "{m}"
            );
        }
    }

    #[test]
    fn key_file_is_trimmed_and_conflicts_with_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent-key");
        std::fs::write(&path, format!("  {FAKE_KEY}\r\n")).unwrap();
        let p = path.to_str().unwrap();
        let c = load(&[(ENV_URL, "https://f.example.com"), (ENV_KEY_FILE, p)]).unwrap();
        assert_eq!(c.agent_key.as_str(), FAKE_KEY);

        let both = msg(load(&[
            (ENV_URL, "https://f.example.com"),
            (ENV_KEY, FAKE_KEY),
            (ENV_KEY_FILE, p),
        ]));
        assert!(both.contains("only one"));
        assert!(!both.contains(FAKE_KEY));

        std::fs::write(&path, "  \n").unwrap();
        assert!(msg(load(&[
            (ENV_URL, "https://f.example.com"),
            (ENV_KEY_FILE, p)
        ]))
        .contains("empty"));

        let missing = dir.path().join("nope");
        let m = msg(load(&[
            (ENV_URL, "https://f.example.com"),
            (ENV_KEY_FILE, missing.to_str().unwrap()),
        ]));
        assert!(m.contains(ENV_KEY_FILE));
        assert!(!m.contains("nope"), "error echoed the file path");
    }

    #[test]
    fn key_with_whitespace_inside_is_refused() {
        let m = msg(load(&[
            (ENV_URL, "https://f.example.com"),
            (ENV_KEY, "two words"),
        ]));
        assert!(!m.contains("two words"));
        assert!(m.contains("single token"));
    }

    #[test]
    fn timeout_bounds() {
        let base = [(ENV_URL, "https://f.example.com"), (ENV_KEY, FAKE_KEY)];
        let with = |t: &str| {
            let mut v = base.to_vec();
            v.push((ENV_TIMEOUT, t));
            load(&v)
        };
        assert_eq!(with("1").unwrap().timeout, Duration::from_secs(1));
        assert_eq!(with("600").unwrap().timeout, Duration::from_secs(600));
        for bad in ["0", "601", "-5", "abc", "1.5"] {
            assert!(msg(with(bad)).contains(ENV_TIMEOUT), "{bad}");
        }
    }

    #[test]
    fn ca_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let base = |ca: &str| {
            load(&[
                (ENV_URL, "https://f.example.com"),
                (ENV_KEY, FAKE_KEY),
                (ENV_CA_FILE, ca),
            ])
        };
        let missing = dir.path().join("missing.pem");
        assert!(msg(base(missing.to_str().unwrap())).contains(ENV_CA_FILE));

        let junk = dir.path().join("junk.pem");
        std::fs::write(&junk, "this is not a certificate").unwrap();
        assert!(msg(base(junk.to_str().unwrap())).contains(ENV_CA_FILE));

        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, include_str!("testdata/test-ca.pem")).unwrap();
        let c = base(ca.to_str().unwrap()).unwrap();
        assert_eq!(c.extra_roots.len(), 1);
    }

    #[test]
    fn debug_output_hides_key_and_path() {
        let url = format!("https://ferro.example.com/{FAKE_PREFIX}");
        let c = load(&[(ENV_URL, &url), (ENV_KEY, FAKE_KEY)]).unwrap();
        let shown = format!("{c:?}");
        assert!(!shown.contains(FAKE_KEY));
        assert!(!shown.contains(FAKE_PREFIX));
        assert!(shown.contains("ferro.example.com"));
    }

    #[test]
    fn non_unicode_value_is_an_error() {
        let r = Config::from_lookup(|name| if name == ENV_URL { Err(()) } else { Ok(None) });
        assert!(msg(r).contains("UTF-8"));
    }
}
