use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use reqwest::{Client, Method, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

use crate::error::{FerroError, FerroResult};
use crate::net::{BlockedTarget, TargetPolicy};
use crate::proxy::scrub::{scrub_bytes, scrub_response};

/// A header map whose values are zeroed on drop.
/// Zeroizing<HashMap<_,_>> is not possible because HashMap doesn't implement
/// Zeroize — instead we hold values as individual Zeroizing<String> entries.
pub type ZeroizingHeaders = HashMap<String, Zeroizing<String>>;

/// The inner request the agent wants forwarded, with placeholders in place of
/// real credential values. Ferrowarden substitutes credentials before sending.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// A JSON string is sent as-is (raw text body). Any other JSON value is
    /// serialized and sent as JSON.
    pub body: Option<Value>,
}

impl ProxyRequest {
    /// The method, upper-cased. Only meaningful after [`validate`](Self::validate).
    pub fn normalized_method(&self) -> String {
        self.method.to_ascii_uppercase()
    }

    /// Reject requests that are ambiguous even though they parsed: header names
    /// that differ only by case are distinct JSON keys but the same HTTP header,
    /// so the agent could be stacking values the target resolves differently.
    pub fn validate(&self) -> FerroResult<()> {
        // Only the standard methods are forwarded, whatever the key's policy.
        crate::policy::normalize_method(&self.method)?;
        let mut seen = std::collections::HashSet::new();
        for name in self.headers.keys() {
            if !seen.insert(name.to_ascii_lowercase()) {
                return Err(FerroError::InvalidRequest(format!(
                    "header {:?} appears more than once (header names are case-insensitive)",
                    name.chars().take(64).collect::<String>()
                )));
            }
        }
        Ok(())
    }
}

/// The response returned to the agent after scrubbing.
#[derive(Debug, Serialize)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    /// "utf8" when `body` is the text of the response, "base64" when the
    /// response was not valid UTF-8 and `body` is its base64 encoding.
    pub body_encoding: &'static str,
}

/// Limits applied to one forwarded request.
pub struct ForwardLimits {
    pub timeout: Duration,
    pub max_response_bytes: usize,
}

/// Forward a fully-substituted request to its target and return a scrubbed response.
///
/// `target` is the parsed URL with credentials already substituted; it has
/// been checked against the target policy for scheme and IP-literal hosts.
/// Name-based hosts are checked at DNS resolution time by the policy resolver.
///
/// `secrets` are the credential values substituted into this request; every
/// encoding of them is scrubbed from the response headers, body and any error.
pub async fn forward_request(
    method: &str,
    target: &Url,
    substituted_headers: ZeroizingHeaders,
    substituted_body: Option<Zeroizing<String>>,
    secrets: &[&str],
    policy: &Arc<TargetPolicy>,
    limits: &ForwardLimits,
) -> FerroResult<ProxyResponse> {
    let method = Method::from_bytes(method.to_uppercase().as_bytes())
        .map_err(|_| FerroError::InvalidTargetUrl(format!("Invalid HTTP method: {}", method)))?;

    let port = target
        .port_or_known_default()
        .ok_or_else(|| FerroError::InvalidTargetUrl("Target URL has no port".to_string()))?;

    let client = Client::builder()
        .timeout(limits.timeout)
        // Do not follow redirects — the agent should see the real response,
        // and a redirect must not carry credentials to another host.
        .redirect(reqwest::redirect::Policy::none())
        // Ignore HTTP(S)_PROXY: a proxy would resolve the target itself and
        // bypass the policy resolver.
        .no_proxy()
        .dns_resolver(policy.resolver(port))
        .build()
        .map_err(|_| FerroError::Internal("failed to build HTTP client".to_string()))?;

    let mut req = client.request(method, target.clone());

    // Apply substituted headers. The Ferrowarden agent key header is never
    // forwarded — it only exists on the outer ferrowarden request.
    for (key, value) in &substituted_headers {
        let lower = key.to_lowercase();
        // Drop ferrowarden-internal headers (x-fw-*) — forward everything else
        // including Authorization which now contains the real credential value
        if !lower.starts_with("x-fw-") {
            req = req.header(key.as_str(), value.as_str());
        }
    }

    if let Some(ref body) = substituted_body {
        req = req.body(body.as_str().to_string());
    }

    let mut resp = req.send().await.map_err(|e| map_send_error(&e))?;

    let status = resp.status().as_u16();

    if let Some(len) = resp.content_length() {
        if len > limits.max_response_bytes as u64 {
            return Err(FerroError::ResponseTooLarge(limits.max_response_bytes));
        }
    }

    // Collect response headers — filter out transfer-encoding and similar
    // hop-by-hop headers that shouldn't be proxied — and scrub every value.
    let resp_headers: HashMap<String, String> = resp
        .headers()
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "transfer-encoding"
                    | "connection"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
                    | "upgrade"
                    | "content-length"
            )
        })
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.to_string(), scrub_response(v, secrets)))
        })
        .collect();

    // Read the body in chunks so an oversized response is rejected without
    // being buffered in full.
    let mut raw: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    while let Some(chunk) = resp.chunk().await.map_err(|e| map_send_error(&e))? {
        if raw.len() + chunk.len() > limits.max_response_bytes {
            return Err(FerroError::ResponseTooLarge(limits.max_response_bytes));
        }
        raw.extend_from_slice(&chunk);
    }

    let (body, body_encoding) = match std::str::from_utf8(&raw) {
        Ok(text) => (scrub_response(text, secrets), "utf8"),
        Err(_) => (STANDARD.encode(scrub_bytes(&raw, secrets)), "base64"),
    };

    Ok(ProxyResponse {
        status,
        headers: resp_headers,
        body,
        body_encoding,
    })
}

/// Map a reqwest error to a FerroError without ever including the URL: the
/// URL has credentials substituted into it, and reqwest's Display output
/// includes it ("error sending request for url (...)").
fn map_send_error(e: &reqwest::Error) -> FerroError {
    let mut source: Option<&(dyn StdError + 'static)> = e.source();
    while let Some(err) = source {
        if let Some(blocked) = err.downcast_ref::<BlockedTarget>() {
            return FerroError::TargetBlocked(blocked.0.clone());
        }
        source = err.source();
    }
    let msg = if e.is_timeout() {
        "request to target timed out"
    } else if e.is_connect() {
        "could not connect to target"
    } else if e.is_body() || e.is_decode() {
        "failed to read target response"
    } else if e.is_builder() {
        "invalid request (check header names and values)"
    } else {
        "request to target failed"
    };
    tracing::debug!(error = %e.without_url_ref(), "forward error");
    FerroError::ForwardFailed(msg.to_string())
}

/// reqwest's `without_url` consumes the error; this helper formats a
/// borrowed error without its URL for debug logging.
trait WithoutUrlRef {
    fn without_url_ref(&self) -> String;
}

impl WithoutUrlRef for reqwest::Error {
    fn without_url_ref(&self) -> String {
        let mut parts = Vec::new();
        let mut source: Option<&(dyn StdError + 'static)> = self.source();
        while let Some(err) = source {
            parts.push(err.to_string());
            source = err.source();
        }
        if parts.is_empty() {
            "unknown error".to_string()
        } else {
            parts.join(": ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, UnlockMode};

    fn policy(allowed: &str) -> Arc<TargetPolicy> {
        Arc::new(TargetPolicy::from_config(&Config {
            bind_addr: "127.0.0.1:3000".to_string(),
            bw_serve_url: "http://127.0.0.1:8087".to_string(),
            unlock_mode: UnlockMode::Manual,
            unlock_file: None,
            admin_key: "a".repeat(32),
            keys_file: None,
            tls_enabled: false,
            tls_cert_file: None,
            tls_key_file: None,
            allow_private_targets: false,
            allowed_targets: allowed.to_string(),
            enforce_credential_hosts: true,
            refresh_interval_secs: 0,
            max_response_bytes: 1024,
            forward_timeout_secs: 5,
            trusted_proxies: String::new(),
            api_prefix: String::new(),
            agent_rate_limit_per_minute: 120,
            agent_rate_limit_burst: 20,
            admin_rate_limit_per_minute: 30,
            admin_rate_limit_burst: 5,
            events: Default::default(),
            ui: Default::default(),
        }))
    }

    fn limits() -> ForwardLimits {
        ForwardLimits {
            timeout: Duration::from_secs(5),
            max_response_bytes: 1024,
        }
    }

    async fn fwd(method: &str, url: &str, allowed: &str) -> FerroResult<ProxyResponse> {
        forward_request(
            method,
            &Url::parse(url).unwrap(),
            HashMap::new(),
            None,
            &[],
            &policy(allowed),
            &limits(),
        )
        .await
    }

    #[tokio::test]
    async fn rejects_invalid_method() {
        let err = fwd("BAD METHOD", "http://localhost/", "localhost")
            .await
            .unwrap_err();
        assert!(matches!(err, FerroError::InvalidTargetUrl(_)));
    }

    #[tokio::test]
    async fn blocks_internal_name_at_resolution() {
        let err = fwd("GET", "http://localhost:1/", "").await.unwrap_err();
        assert!(matches!(err, FerroError::TargetBlocked(_)), "{err:?}");
    }

    #[tokio::test]
    async fn connection_error_never_contains_url_or_secret() {
        // Allowed internal target with nothing listening.
        let url = "http://localhost:1/path?key=SUPERSECRETVALUE";
        let err = fwd("GET", url, "localhost").await.unwrap_err();
        assert!(matches!(err, FerroError::ForwardFailed(_)), "{err:?}");
        let text = err.to_string();
        assert!(!text.contains("SUPERSECRETVALUE"), "{text}");
        assert!(!text.contains("localhost"), "{text}");
    }

    fn parse(json: &str) -> Result<ProxyRequest, String> {
        crate::api::strict_json::parse_strict(json.as_bytes())
    }

    #[test]
    fn validate_rejects_case_insensitive_duplicate_headers() {
        let r = parse(r#"{"method":"GET","url":"http://x","headers":{"Authorization":"a","authorization":"b"}}"#)
            .unwrap();
        let e = r.validate().unwrap_err().to_string();
        assert!(e.contains("more than once"), "{e}");

        let r =
            parse(r#"{"method":"GET","url":"http://x","headers":{"X-A":"1","x-a":"1","X-B":"2"}}"#)
                .unwrap();
        assert!(r.validate().is_err());
    }

    #[test]
    fn validate_accepts_distinct_headers() {
        let r = parse(
            r#"{"method":"GET","url":"http://x","headers":{"Authorization":"a","X-Other":"a"}}"#,
        )
        .unwrap();
        assert!(r.validate().is_ok());
        let r = parse(r#"{"method":"GET","url":"http://x"}"#).unwrap();
        assert!(r.validate().is_ok());
    }

    #[test]
    fn proxy_request_rejects_unknown_fields_and_duplicate_keys() {
        let e = parse(r#"{"method":"GET","url":"http://x","extra":1}"#).unwrap_err();
        assert!(e.contains("unknown field `extra`"), "{e}");
        assert!(parse(r#"{"method":"GET","method":"POST","url":"http://x"}"#).is_err());
        assert!(parse(r#"{"method":"GET","url":"http://x","headers":{"a":"1","a":"2"}}"#).is_err());
        assert!(parse(r#"{"method":"GET","url":"http://x","body":{"k":{"a":1,"a":2}}}"#).is_err());
    }
}
