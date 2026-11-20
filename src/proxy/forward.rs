use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use zeroize::Zeroizing;

use crate::error::{FerroError, FerroResult};
use crate::proxy::scrub::scrub_response;

/// A header map whose values are zeroed on drop.
/// Zeroizing<HashMap<_,_>> is not possible because HashMap doesn't implement
/// Zeroize — instead we hold values as individual Zeroizing<String> entries.
pub type ZeroizingHeaders = HashMap<String, Zeroizing<String>>;

/// The inner request the agent wants forwarded, with placeholders in place of
/// real credential values. Ferrowarden substitutes credentials before sending.
#[derive(Debug, Deserialize)]
pub struct ProxyRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub body: Option<Value>,
}

/// The response returned to the agent after scrubbing.
#[derive(Debug, Serialize)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// Forward a fully-substituted request to its target and return a scrubbed response.
///
/// substituted_headers and substituted_body contain real credential values —
/// header values are individually Zeroizing so they wipe from memory when
/// this function returns.
pub async fn forward_request(
    method: &str,
    url: &str,
    substituted_headers: ZeroizingHeaders,
    substituted_body: Option<Zeroizing<String>>,
) -> FerroResult<ProxyResponse> {
    // Reject non-http(s) schemes — no file://, data://, etc.
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(FerroError::InvalidTargetUrl(
            "Only http and https targets are allowed".to_string(),
        ));
    }

    let method = Method::from_bytes(method.to_uppercase().as_bytes())
        .map_err(|_| FerroError::InvalidTargetUrl(format!("Invalid HTTP method: {}", method)))?;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        // Do not follow redirects — the agent should see the real response
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| FerroError::Internal(e.to_string()))?;

    let mut req = client.request(method, url);

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

    let resp = req
        .send()
        .await
        .map_err(|e| FerroError::ForwardFailed(e.to_string()))?;

    let status = resp.status().as_u16();

    // Collect response headers — filter out transfer-encoding and similar
    // hop-by-hop headers that shouldn't be proxied
    let resp_headers: HashMap<String, String> = resp
        .headers()
        .iter()
        .filter(|(name, _)| {
            let n = name.as_str().to_lowercase();
            !matches!(
                n.as_str(),
                "transfer-encoding" | "connection" | "keep-alive" | "proxy-authenticate"
                    | "proxy-authorization" | "te" | "trailer" | "upgrade"
            )
        })
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|v| (name.to_string(), v.to_string()))
        })
        .collect();

    let body_text = resp
        .text()
        .await
        .map_err(|e| FerroError::ForwardFailed(e.to_string()))?;

    // Scrub the response body before returning to the agent
    let scrubbed_body = scrub_response(&body_text);

    Ok(ProxyResponse {
        status,
        headers: resp_headers,
        body: scrubbed_body,
    })
}
