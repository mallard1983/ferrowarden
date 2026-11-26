use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use regex::Regex;
use serde_json::Value;
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

/// `s` with the hex digits of every `%XX` escape in lower case (`%2F` ->
/// `%2f`): servers are not bound to the upper case `urlencoding` writes.
fn lower_percent_hex(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            out.push('%');
            out.push((b[i + 1] as char).to_ascii_lowercase());
            out.push((b[i + 2] as char).to_ascii_lowercase());
            i += 3;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// Every encoding of a secret that a target might plausibly echo back:
/// raw, JSON-escaped, URL-encoded (upper and lower case hex), and the four
/// common base64 forms.
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
        Zeroizing::new(lower_percent_hex(&urlencoding::encode(secret))),
        Zeroizing::new(STANDARD.encode(secret)),
        Zeroizing::new(STANDARD_NO_PAD.encode(secret)),
        Zeroizing::new(URL_SAFE.encode(secret)),
        Zeroizing::new(URL_SAFE_NO_PAD.encode(secret)),
    ];
    out.sort_by_key(|v| std::cmp::Reverse(v.len()));
    out.dedup_by(|a, b| a.as_str() == b.as_str());
    out
}

/// A value to remove from a response, and the text that takes its place.
/// Vault secrets are replaced with [`REDACTED`]; a captured session is
/// replaced with `[CAPTURED:name]` so the agent can tell what was there.
#[derive(Debug, Clone, Copy)]
pub struct Secret<'a> {
    pub value: &'a str,
    pub replacement: &'a str,
}

impl<'a> Secret<'a> {
    /// A secret that is replaced with [`REDACTED`].
    pub fn redacted(value: &'a str) -> Self {
        Self {
            value,
            replacement: REDACTED,
        }
    }
}

/// [`scrub_response_with`] for secrets that are all replaced with
/// [`REDACTED`] (the tests' shorthand).
#[cfg(test)]
pub fn scrub_response(body: &str, secrets: &[&str]) -> String {
    let secrets: Vec<Secret<'_>> = secrets.iter().map(|s| Secret::redacted(s)).collect();
    scrub_response_with(body, &secrets)
}

/// Every (variant, replacement) pair of every secret, longest variant first
/// across all secrets, so a shorter secret that sits inside a longer one
/// cannot break the longer match. The sort is stable: ties keep the order of
/// the secrets given.
fn replacements<'a>(secrets: &[Secret<'a>]) -> Vec<(Zeroizing<String>, &'a str)> {
    let mut pairs: Vec<(Zeroizing<String>, &'a str)> = secrets
        .iter()
        .flat_map(|s| {
            variants(s.value)
                .into_iter()
                .map(move |v| (v, s.replacement))
        })
        .collect();
    pairs.sort_by_key(|(v, _)| std::cmp::Reverse(v.len()));
    pairs
}

/// Scrub a response string: first every encoding of the credential values
/// substituted into this request (and of the captured sessions), then the
/// generic credential patterns.
pub fn scrub_response_with(body: &str, secrets: &[Secret<'_>]) -> String {
    let mut result = body.to_string();

    for (v, replacement) in replacements(secrets) {
        if result.contains(v.as_str()) {
            let replaced = result.replace(v.as_str(), replacement);
            // Wipe the previous copy, which still contains the secret.
            drop(Zeroizing::new(std::mem::replace(&mut result, replaced)));
        }
    }

    for (re, replacement) in compiled_patterns() {
        if re.is_match(&result) {
            result = re.replace_all(&result, *replacement).into_owned();
        }
    }

    result
}

fn json_mentions(value: &Value, needles: &[Zeroizing<String>]) -> bool {
    match value {
        Value::String(s) => needles.iter().any(|n| s.contains(n.as_str())),
        Value::Array(items) => items.iter().any(|v| json_mentions(v, needles)),
        Value::Object(map) => map.iter().any(|(k, v)| {
            needles.iter().any(|n| k.contains(n.as_str())) || json_mentions(v, needles)
        }),
        _ => false,
    }
}

/// Scrub every string (keys and values) of a JSON value in place.
fn scrub_json_strings(value: &mut Value, secrets: &[Secret<'_>]) {
    use zeroize::Zeroize;
    match value {
        Value::String(s) => {
            let scrubbed = scrub_response_with(s, secrets);
            s.zeroize();
            *s = scrubbed;
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|v| scrub_json_strings(v, secrets)),
        Value::Object(map) => {
            for (mut k, mut v) in std::mem::take(map) {
                scrub_json_strings(&mut v, secrets);
                let new_key = scrub_response_with(&k, secrets);
                k.zeroize();
                map.insert(new_key, v);
            }
        }
        _ => {}
    }
}

/// Scrub a UTF-8 response body. Exact-value scrubbing first; then, if the
/// body is JSON and a decoded string still holds a secret (the target wrote
/// it with escapes the text match does not know: `\/`, `\u0026`, `\u00XX`
/// for every character), fall back to scrubbing the decoded strings and
/// re-serializing. The body keeps its exact bytes unless that happens.
pub fn scrub_json_body(body: &str, secrets: &[Secret<'_>]) -> String {
    let first = scrub_response_with(body, secrets);
    let needles: Vec<Zeroizing<String>> = secrets.iter().flat_map(|s| variants(s.value)).collect();
    if needles.is_empty() {
        return first;
    }
    let Ok(mut decoded) = serde_json::from_str::<Value>(&first) else {
        return first;
    };
    let leaks = json_mentions(&decoded, &needles);
    crate::proxy::substitute::zeroize_json(&mut decoded);
    if !leaks {
        return first;
    }
    let Ok(mut original) = serde_json::from_str::<Value>(body) else {
        return first;
    };
    scrub_json_strings(&mut original, secrets);
    let out = serde_json::to_string(&original).unwrap_or(first);
    crate::proxy::substitute::zeroize_json(&mut original);
    out
}

/// [`scrub_bytes_with`] for secrets that are all replaced with [`REDACTED`]
/// (the tests' shorthand).
#[cfg(test)]
pub fn scrub_bytes(body: &[u8], secrets: &[&str]) -> Vec<u8> {
    let secrets: Vec<Secret<'_>> = secrets.iter().map(|s| Secret::redacted(s)).collect();
    scrub_bytes_with(body, &secrets)
}

/// Scrub a non-UTF-8 (binary) body: exact-match replacement of every
/// encoding of each substituted value.
pub fn scrub_bytes_with(body: &[u8], secrets: &[Secret<'_>]) -> Vec<u8> {
    let mut result = body.to_vec();
    for (v, replacement) in replacements(secrets) {
        result = replace_bytes(&result, v.as_bytes(), replacement.as_bytes());
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
mod tests;
