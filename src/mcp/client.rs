//! The HTTP side: a small client of a running Ferrowarden.
//!
//! Two things matter here. The agent key goes into one sensitive header and
//! nowhere else. And nothing from `reqwest::Error` is ever formatted, because
//! its `Display` includes the request URL, whose path may be the operator's
//! secret `api_prefix`.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT};
use reqwest::{redirect, Method, Url};
use serde_json::Value;
use zeroize::Zeroizing;

use super::config::Config;

/// The largest Ferrowarden answer this client will read. Ferrowarden caps
/// target responses itself (10 MiB by default); this bounds a misbehaving
/// server and the base64 and JSON expansion on top of that cap.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// What Ferrowarden said, before it is interpreted.
#[derive(Debug)]
pub struct Raw {
    pub status: u16,
    pub request_id: Option<String>,
    pub retry_after_secs: Option<u64>,
    pub body: Vec<u8>,
}

/// Why no answer came back. Carries no URL and no error text from the HTTP
/// stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreachable {
    Timeout,
    Connect,
    Tls,
    TooLarge,
    Other,
}

impl Unreachable {
    pub fn describe(self) -> &'static str {
        match self {
            Unreachable::Timeout => "the request timed out",
            Unreachable::Connect => "the connection failed",
            Unreachable::Tls => "the TLS handshake or certificate check failed",
            Unreachable::TooLarge => "the answer was larger than this client accepts",
            Unreachable::Other => "the request could not be completed",
        }
    }
}

/// Strips the agent key, and optionally the secret base path, out of text
/// that is about to be shown to the agent or written to a log.
pub struct Redactor {
    key: Zeroizing<String>,
    /// The base URL path without slashes, if there is one.
    path: Option<String>,
}

impl Redactor {
    pub fn new(key: &str, base_url: &Url) -> Self {
        let path = base_url.path().trim_matches('/');
        Redactor {
            key: Zeroizing::new(key.to_string()),
            path: (!path.is_empty()).then(|| path.to_string()),
        }
    }

    /// Replace the agent key and the base path. For text that came from
    /// Ferrowarden's own error answers.
    pub fn scrub_error_text(&self, text: &str) -> String {
        let mut out = self.scrub_key(text);
        if let Some(path) = &self.path {
            out = out.replace(path.as_str(), "[api prefix]");
        }
        out
    }

    /// Replace the agent key only. Used on successful output, where the base
    /// path is ordinary text if a target happens to contain it.
    pub fn scrub_key(&self, text: &str) -> String {
        if self.key.is_empty() {
            return text.to_string();
        }
        text.replace(self.key.as_str(), "[agent key]")
    }

    pub fn scrub_value(&self, value: &mut Value) {
        match value {
            Value::String(s) => {
                if s.contains(self.key.as_str()) {
                    *s = self.scrub_key(s);
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|v| self.scrub_value(v)),
            Value::Object(map) => {
                let needs_rekey = map.keys().any(|k| k.contains(self.key.as_str()));
                if needs_rekey {
                    let old = std::mem::take(map);
                    for (k, v) in old {
                        map.insert(self.scrub_key(&k), v);
                    }
                }
                map.values_mut().for_each(|v| self.scrub_value(v));
            }
            _ => {}
        }
    }
}

pub struct FerroClient {
    http: reqwest::Client,
    base: Url,
    pub redactor: Redactor,
    host: String,
}

impl FerroClient {
    pub fn new(config: &Config) -> Result<Self, String> {
        let mut key_header = HeaderValue::from_str(config.agent_key.as_str())
            .map_err(|_| "the agent key is not usable as an HTTP header value".to_string())?;
        // Keeps the value out of any debug output of the HTTP stack.
        key_header.set_sensitive(true);

        let mut headers = HeaderMap::new();
        headers.insert(HeaderName::from_static("x-agent-key"), key_header);
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let mut builder = reqwest::Client::builder()
            .default_headers(headers)
            .user_agent(concat!("ferrowarden-mcp/", env!("CARGO_PKG_VERSION")))
            .timeout(config.timeout)
            .connect_timeout(Duration::from_secs(10).min(config.timeout))
            // A redirect would carry the key header to wherever it points.
            .redirect(redirect::Policy::none());
        for cert in &config.extra_roots {
            builder = builder.add_root_certificate(cert.clone());
        }
        let http = builder
            .build()
            .map_err(|_| "could not set up the HTTP client".to_string())?;

        Ok(FerroClient {
            http,
            base: config.base_url.clone(),
            redactor: Redactor::new(config.agent_key.as_str(), &config.base_url),
            host: config.host_for_log(),
        })
    }

    /// The host (and port) for logs. Never the path.
    pub fn host(&self) -> &str {
        &self.host
    }

    fn endpoint(&self, tail: &str, query: Option<&str>) -> Url {
        let mut url = self.base.clone();
        // The root path is "/", so slashes are trimmed before the tail is added.
        url.set_path(&format!(
            "{}{}",
            self.base.path().trim_end_matches('/'),
            tail
        ));
        url.set_query(query);
        url
    }

    pub async fn list_credentials(&self) -> Result<Raw, Unreachable> {
        let url = self.endpoint("/v1/credentials", Some("detail=true"));
        self.send(self.http.request(Method::GET, url)).await
    }

    pub async fn forward(&self, payload: &Value) -> Result<Raw, Unreachable> {
        let url = self.endpoint("/v1/forward", None);
        self.send(self.http.request(Method::POST, url).json(payload))
            .await
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<Raw, Unreachable> {
        let mut response = request.send().await.map_err(classify)?;
        let status = response.status().as_u16();
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .and_then(sanitize_request_id);
        let retry_after_secs = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());

        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(classify)? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(Unreachable::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Raw {
            status,
            request_id,
            retry_after_secs,
            body,
        })
    }
}

/// Map a `reqwest` error to a kind, without formatting it (it contains the URL).
fn classify(error: reqwest::Error) -> Unreachable {
    if error.is_timeout() {
        Unreachable::Timeout
    } else if error.is_connect() {
        // A failed TLS handshake surfaces as a connect error; the source chain
        // distinguishes it, but only the kind is used here.
        let mut source = std::error::Error::source(&error);
        while let Some(s) = source {
            let text = s.to_string().to_ascii_lowercase();
            if text.contains("certificate") || text.contains("tls") || text.contains("handshake") {
                return Unreachable::Tls;
            }
            source = s.source();
        }
        Unreachable::Connect
    } else {
        Unreachable::Other
    }
}

/// Request ids are UUIDs. Accept only a short run of safe characters so that
/// nothing odd can be echoed into tool output.
pub fn sanitize_request_id(raw: &str) -> Option<String> {
    let raw = raw.trim();
    (!raw.is_empty()
        && raw.len() <= 64
        && raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
    .then(|| raw.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_must_be_plain() {
        assert_eq!(
            sanitize_request_id("0191a2b3-c4d5-7e6f-8a9b-0c1d2e3f4a5b").as_deref(),
            Some("0191a2b3-c4d5-7e6f-8a9b-0c1d2e3f4a5b")
        );
        assert_eq!(sanitize_request_id("a b"), None);
        assert_eq!(sanitize_request_id("<script>"), None);
        assert_eq!(sanitize_request_id(&"a".repeat(65)), None);
        assert_eq!(sanitize_request_id(""), None);
    }

    #[test]
    fn redactor_replaces_key_and_prefix() {
        let base = Url::parse("https://f.example.com/pfx123abc").unwrap();
        let r = Redactor::new("KEY0123456789", &base);
        let s = r.scrub_error_text("bad KEY0123456789 at /pfx123abc/v1/forward");
        assert!(!s.contains("KEY0123456789") && !s.contains("pfx123abc"));
        // Success output only loses the key.
        let t = r.scrub_key("KEY0123456789 /pfx123abc");
        assert!(!t.contains("KEY0123456789") && t.contains("pfx123abc"));
        let mut v = serde_json::json!({"a": ["x KEY0123456789"], "KEY0123456789": 1});
        r.scrub_value(&mut v);
        assert!(!v.to_string().contains("KEY0123456789"));
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;

    fn client_for(url: &str) -> FerroClient {
        let config = Config::from_lookup(|name| {
            Ok(match name {
                "FERROWARDEN_URL" => Some(url.to_string()),
                "FERROWARDEN_AGENT_KEY" => Some("KEY0123456789".to_string()),
                _ => None,
            })
        })
        .unwrap();
        FerroClient::new(&config).unwrap()
    }

    #[test]
    fn endpoints_have_no_double_slash_with_or_without_a_prefix() {
        let bare = client_for("https://f.example.com/");
        assert_eq!(
            bare.endpoint("/v1/credentials", Some("detail=true"))
                .as_str(),
            "https://f.example.com/v1/credentials?detail=true"
        );
        let prefixed = client_for("https://f.example.com/pfx/");
        assert_eq!(
            prefixed.endpoint("/v1/forward", None).as_str(),
            "https://f.example.com/pfx/v1/forward"
        );
    }
}
