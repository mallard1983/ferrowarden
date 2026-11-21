use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use regex::Regex;
use std::sync::OnceLock;
use zeroize::Zeroizing;

pub const REDACTED: &str = "[REDACTED]";

/// Credential values shorter than this are not exact-match scrubbed: a 1–3
/// character "secret" would shred ordinary response text. Such values offer
/// no real security anyway.
pub const MIN_SCRUB_LEN: usize = 4;

/// Patterns that match common credential shapes in response bodies.
/// These run against the raw response text before it is returned to the agent.
/// Conservative by design — false positives (redacting non-credentials) are
/// preferable to false negatives (leaking real credentials).
static SCRUB_PATTERNS: &[(&str, &str)] = &[
    // Generic Bearer tokens in JSON values or headers
    (
        r#"(?i)(bearer\s+)[A-Za-z0-9\-_\.~\+/]+=*"#,
        "${1}[REDACTED]",
    ),
    // Generic API key patterns in JSON (key/token/secret/password fields)
    (
        r#"(?i)("(?:api_?key|api_?token|secret|password|passwd|access_token|auth_token|private_key)"\s*:\s*")[^"]{8,}""#,
        r#"${1}[REDACTED]""#,
    ),
    // PVE API tokens (Proxmox)
    (r#"PVEAPIToken=[^\s"',]+"#, "PVEAPIToken=[REDACTED]"),
    // Basic auth in URLs
    (r#"(https?://)([^:@/\s]+:[^@/\s]+@)"#, "${1}[REDACTED]@"),
    // Private key blocks
    (
        r#"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"#,
        "[REDACTED PRIVATE KEY]",
    ),
];

fn compiled_patterns() -> &'static [(Regex, &'static str)] {
    static COMPILED: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        SCRUB_PATTERNS
            .iter()
            .map(|(p, r)| (Regex::new(p).expect("scrub pattern compiles"), *r))
            .collect()
    })
}

/// Every encoding of a secret that a target might plausibly echo back:
/// raw, JSON-escaped, URL-encoded, and the four common base64 forms.
/// Longest first so a longer variant is replaced before a shorter one
/// that it contains.
fn variants(secret: &str) -> Vec<Zeroizing<String>> {
    if secret.chars().count() < MIN_SCRUB_LEN {
        return Vec::new();
    }
    let json = serde_json::to_string(secret).unwrap_or_default();
    let json_inner = json
        .get(1..json.len().saturating_sub(1))
        .unwrap_or_default()
        .to_string();
    let mut out: Vec<Zeroizing<String>> = vec![
        Zeroizing::new(secret.to_string()),
        Zeroizing::new(json_inner),
        Zeroizing::new(urlencoding::encode(secret).into_owned()),
        Zeroizing::new(STANDARD.encode(secret)),
        Zeroizing::new(STANDARD_NO_PAD.encode(secret)),
        Zeroizing::new(URL_SAFE.encode(secret)),
        Zeroizing::new(URL_SAFE_NO_PAD.encode(secret)),
    ];
    out.sort_by_key(|v| std::cmp::Reverse(v.len()));
    out.dedup_by(|a, b| a.as_str() == b.as_str());
    out
}

/// Scrub a response string: first every encoding of the credential values
/// substituted into this request, then the generic credential patterns.
pub fn scrub_response(body: &str, secrets: &[&str]) -> String {
    let mut result = body.to_string();

    for secret in secrets {
        for v in variants(secret) {
            if result.contains(v.as_str()) {
                let replaced = result.replace(v.as_str(), REDACTED);
                // Wipe the previous copy, which still contains the secret.
                drop(Zeroizing::new(std::mem::replace(&mut result, replaced)));
            }
        }
    }

    for (re, replacement) in compiled_patterns() {
        if re.is_match(&result) {
            result = re.replace_all(&result, *replacement).into_owned();
        }
    }

    result
}

/// Scrub a non-UTF-8 (binary) body: exact-match replacement of every
/// encoding of each substituted value.
pub fn scrub_bytes(body: &[u8], secrets: &[&str]) -> Vec<u8> {
    let mut result = body.to_vec();
    for secret in secrets {
        for v in variants(secret) {
            result = replace_bytes(&result, v.as_bytes(), REDACTED.as_bytes());
        }
    }
    result
}

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_bearer() {
        let body = r#"{"token": "Bearer eyJhbGciOiJIUzI1NiJ9.test.sig"}"#;
        let scrubbed = scrub_response(body, &[]);
        assert!(!scrubbed.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(scrubbed.contains("[REDACTED]"));
    }

    #[test]
    fn test_scrub_api_key_field() {
        let body = r#"{"api_key": "sk-abcdef1234567890abcdef"}"#;
        let scrubbed = scrub_response(body, &[]);
        assert!(!scrubbed.contains("sk-abcdef1234567890abcdef"));
        assert!(scrubbed.contains("[REDACTED]"));
    }

    #[test]
    fn test_scrub_basic_auth_url() {
        let body = r#"connect to https://admin:supersecret@192.168.1.1/api"#;
        let scrubbed = scrub_response(body, &[]);
        assert!(!scrubbed.contains("supersecret"));
        assert!(scrubbed.contains("[REDACTED]@"));
    }

    #[test]
    fn test_no_false_positive_on_clean_body() {
        let body = r#"{"status": "ok", "nodes": ["sg1", "sg2"]}"#;
        assert_eq!(scrub_response(body, &[]), body);
    }

    #[test]
    fn exact_value_echo_is_scrubbed_in_any_field() {
        let secret = "zq-9f8e7d6c5b4a";
        let body =
            format!(r#"{{"headers": {{"X-Whatever": "{secret}"}}, "args": {{"q": "{secret}"}}}}"#);
        let scrubbed = scrub_response(&body, &[secret]);
        assert!(!scrubbed.contains(secret));
        assert_eq!(scrubbed.matches(REDACTED).count(), 2);
    }

    #[test]
    fn encoded_echoes_are_scrubbed() {
        let secret = "p@ss w/rd\"+ok";
        let json_escaped = r#"p@ss w/rd\"+ok"#;
        let body = format!(
            "json={json_escaped} url={} b64={} b64url={}",
            urlencoding::encode(secret),
            STANDARD.encode(secret),
            URL_SAFE_NO_PAD.encode(secret),
        );
        let scrubbed = scrub_response(&body, &[secret]);
        assert!(!scrubbed.contains(json_escaped));
        assert!(!scrubbed.contains(&*urlencoding::encode(secret)));
        assert!(!scrubbed.contains(&STANDARD_NO_PAD.encode(secret)));
        assert!(!scrubbed.contains(&URL_SAFE_NO_PAD.encode(secret)));
    }

    #[test]
    fn short_values_are_not_scrubbed() {
        assert_eq!(scrub_response("abc abc", &["abc"]), "abc abc");
    }

    #[test]
    fn binary_body_is_scrubbed() {
        let mut body = vec![0xff, 0xfe];
        body.extend_from_slice(b"SECRETVALUE");
        body.push(0x00);
        let out = scrub_bytes(&body, &["SECRETVALUE"]);
        assert!(!out.windows(11).any(|w| w == b"SECRETVALUE"));
        assert!(out
            .windows(REDACTED.len())
            .any(|w| w == REDACTED.as_bytes()));
    }
}
