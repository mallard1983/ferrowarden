use regex::Regex;

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
    (r#"(https?://)([^:@]+:[^@]+@)"#, "${1}[REDACTED]@"),
    // Private key blocks
    (
        r#"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"#,
        "[REDACTED PRIVATE KEY]",
    ),
];

/// Scrub known credential patterns from a response body string.
/// Returns the cleaned string. Any pattern that fails to compile is skipped
/// with a warning rather than crashing — availability over silent failure.
pub fn scrub_response(body: &str) -> String {
    let mut result = body.to_string();

    for (pattern, replacement) in SCRUB_PATTERNS {
        match Regex::new(pattern) {
            Ok(re) => {
                result = re.replace_all(&result, *replacement).into_owned();
            }
            Err(e) => {
                tracing::warn!("Scrub pattern failed to compile: {} — {}", pattern, e);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_bearer() {
        let body = r#"{"token": "Bearer eyJhbGciOiJIUzI1NiJ9.test.sig"}"#;
        let scrubbed = scrub_response(body);
        assert!(!scrubbed.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(scrubbed.contains("[REDACTED]"));
    }

    #[test]
    fn test_scrub_api_key_field() {
        let body = r#"{"api_key": "sk-abcdef1234567890abcdef"}"#;
        let scrubbed = scrub_response(body);
        assert!(!scrubbed.contains("sk-abcdef1234567890abcdef"));
        assert!(scrubbed.contains("[REDACTED]"));
    }

    #[test]
    fn test_scrub_basic_auth_url() {
        let body = r#"connect to https://admin:supersecret@192.168.1.1/api"#;
        let scrubbed = scrub_response(body);
        assert!(!scrubbed.contains("supersecret"));
        assert!(scrubbed.contains("[REDACTED]@"));
    }

    #[test]
    fn test_no_false_positive_on_clean_body() {
        let body = r#"{"status": "ok", "nodes": ["sg1", "sg2"]}"#;
        let scrubbed = scrub_response(body);
        assert_eq!(scrubbed, body);
    }
}
