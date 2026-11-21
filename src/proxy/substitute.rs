use regex::Regex;
use reqwest::Url;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{FerroError, FerroResult};
use crate::vault::{CredentialMap, VaultClient};

// Placeholder pattern: {{vault:credential_name}}
// Name may contain alphanumerics, underscores, hyphens, and dots.
const PLACEHOLDER_PATTERN: &str = r"\{\{vault:([a-zA-Z0-9_\-\.]+)\}\}";

fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(PLACEHOLDER_PATTERN).expect("placeholder regex compiles"))
}

/// Resolved credential values for one request, keyed by name. Every value is
/// Zeroizing and wiped when the map is dropped.
pub type ResolvedValues = BTreeMap<String, Zeroizing<String>>;

/// Extract all unique credential names referenced by placeholders in a string.
pub fn extract_placeholder_names(input: &str) -> HashSet<String> {
    placeholder_re()
        .captures_iter(input)
        .filter_map(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Extract placeholder names from every string (keys and values) in a JSON value.
pub fn extract_json_placeholder_names(value: &Value, out: &mut HashSet<String>) {
    match value {
        Value::String(s) => out.extend(extract_placeholder_names(s)),
        Value::Array(items) => items.iter().for_each(|v| extract_json_placeholder_names(v, out)),
        Value::Object(map) => {
            for (k, v) in map {
                out.extend(extract_placeholder_names(k));
                extract_json_placeholder_names(v, out);
            }
        }
        _ => {}
    }
}

/// Check whether a credential bound to `uris` may be sent to `target`.
///
/// A URI matches when its host equals the target host (case-insensitive) and,
/// if the URI states them explicitly, the scheme and port also match. URIs
/// without a scheme (e.g. `api.example.com`) match either http or https.
pub fn credential_allows(uris: &[String], target: &Url) -> Result<(), String> {
    if uris.is_empty() {
        return Err("the vault item has no URIs; add the target's URL to the item to allow it".to_string());
    }
    let target_host = normalize_host(target.host_str().unwrap_or_default());
    let target_port = target.port_or_known_default();

    for raw in uris {
        let raw = raw.trim();
        let explicit_scheme = raw.contains("://");
        let parsed = if explicit_scheme {
            Url::parse(raw)
        } else {
            Url::parse(&format!("https://{raw}"))
        };
        let Ok(uri) = parsed else { continue };
        let Some(host) = uri.host_str() else { continue };
        if normalize_host(host) != target_host {
            continue;
        }
        if explicit_scheme && uri.scheme() != target.scheme() {
            continue;
        }
        if uri.port().is_some() || explicit_scheme {
            // An explicit port, or the scheme's default port when the scheme is explicit.
            if uri.port_or_known_default() != target_port {
                continue;
            }
        }
        return Ok(());
    }
    Err("the target does not match any URI on the vault item".to_string())
}

fn normalize_host(h: &str) -> String {
    h.trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Validate and fetch every named credential for a request to `target`.
///
/// Fails before fetching any value if a name is unknown, ambiguous, or (when
/// `enforce_hosts` is set) not bound to the target host.
pub async fn resolve_credentials(
    names: &HashSet<String>,
    credentials: &CredentialMap,
    target: &Url,
    enforce_hosts: bool,
    vault: &VaultClient,
) -> FerroResult<ResolvedValues> {
    let mut sorted: Vec<&String> = names.iter().collect();
    sorted.sort();

    let mut ids = Vec::with_capacity(sorted.len());
    for name in sorted {
        let entries = credentials
            .get(name)
            .ok_or_else(|| FerroError::UnknownPlaceholder(name.clone()))?;
        let entry = match entries.as_slice() {
            [one] => one,
            [] => return Err(FerroError::UnknownPlaceholder(name.clone())),
            _ => return Err(FerroError::AmbiguousCredential(name.clone())),
        };
        if enforce_hosts {
            credential_allows(&entry.uris, target).map_err(|reason| {
                FerroError::CredentialHostNotAllowed {
                    name: name.clone(),
                    host: target.host_str().unwrap_or_default().to_string(),
                    reason,
                }
            })?;
        }
        ids.push((name.clone(), entry.id.clone()));
    }

    let mut values = ResolvedValues::new();
    for (name, id) in ids {
        let value = vault.get_password(&id, &name).await?;
        values.insert(name, value);
    }
    Ok(values)
}

/// Replace every {{vault:name}} placeholder in `input` with its resolved
/// value. Names not in `values` are left untouched (callers resolve every
/// extracted name first, so this does not happen in practice).
pub fn substitute_str(input: &str, values: &ResolvedValues) -> Zeroizing<String> {
    let mut result = Zeroizing::new(String::with_capacity(input.len()));
    let mut last_end = 0;

    for cap in placeholder_re().captures_iter(input) {
        let full = cap.get(0).expect("group 0 always present");
        let name = cap.get(1).expect("group 1 always present").as_str();
        if let Some(value) = values.get(name) {
            result.push_str(&input[last_end..full.start()]);
            result.push_str(value.as_str());
            last_end = full.end();
        }
    }
    result.push_str(&input[last_end..]);
    result
}

/// Substitute placeholders inside every string (keys and values) of a JSON
/// value. Substituting into the parsed structure, rather than the serialized
/// text, means credential values containing `"` or `\` are escaped correctly
/// and cannot alter the JSON structure. The caller must pass the result to
/// [`zeroize_json`] once it is no longer needed.
pub fn substitute_json(value: &Value, values: &ResolvedValues) -> Value {
    match value {
        Value::String(s) => Value::String(substitute_str(s, values).to_string()),
        Value::Array(items) => Value::Array(items.iter().map(|v| substitute_json(v, values)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (substitute_str(k, values).to_string(), substitute_json(v, values)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Wipe every string in a JSON value (keys and values).
pub fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(zeroize_json),
        Value::Object(map) => {
            for (mut k, mut v) in std::mem::take(map) {
                k.zeroize();
                zeroize_json(&mut v);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::client::CredentialEntry;
    use serde_json::json;

    fn values(pairs: &[(&str, &str)]) -> ResolvedValues {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
            .collect()
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn test_extract_names() {
        let input =
            r#"{"Authorization": "Bearer {{vault:proxmox_token}}", "X-Key": "{{vault:nas_key}}"}"#;
        let names = extract_placeholder_names(input);
        assert!(names.contains("proxmox_token"));
        assert!(names.contains("nas_key"));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn test_extract_no_placeholders() {
        assert!(extract_placeholder_names(r#"{"Authorization": "Bearer real_token"}"#).is_empty());
    }

    #[test]
    fn test_extract_duplicate_placeholders() {
        let names = extract_placeholder_names("{{vault:token}} and {{vault:token}} again");
        assert_eq!(names.len(), 1);
        assert!(names.contains("token"));
    }

    #[test]
    fn extract_json_includes_keys() {
        let mut out = HashSet::new();
        extract_json_placeholder_names(&json!({"{{vault:k}}": ["{{vault:v}}", 1]}), &mut out);
        assert!(out.contains("k") && out.contains("v"));
    }

    #[test]
    fn substitute_str_replaces_all_occurrences() {
        let v = values(&[("t", "SECRET")]);
        let out = substitute_str("a {{vault:t}} b {{vault:t}}", &v);
        assert_eq!(out.as_str(), "a SECRET b SECRET");
    }

    #[test]
    fn substitute_json_escapes_special_characters() {
        let v = values(&[("pw", r#"pa"ss\word"#)]);
        let mut out = substitute_json(&json!({"password": "{{vault:pw}}", "n": 5}), &v);
        let text = serde_json::to_string(&out).unwrap();
        let reparsed: Value = serde_json::from_str(&text).expect("still valid JSON");
        assert_eq!(reparsed["password"], r#"pa"ss\word"#);
        assert_eq!(reparsed.as_object().unwrap().len(), 2, "no injected keys");
        zeroize_json(&mut out);
    }

    #[test]
    fn host_binding_matches_host_scheme_and_port() {
        let uris = vec!["https://api.example.com".to_string()];
        assert!(credential_allows(&uris, &url("https://API.example.com/v1")).is_ok());
        assert!(credential_allows(&uris, &url("http://api.example.com/v1")).is_err(), "scheme downgrade");
        assert!(credential_allows(&uris, &url("https://api.example.com:8443/")).is_err(), "other port");
        assert!(credential_allows(&uris, &url("https://evil.example.com/")).is_err());
        assert!(credential_allows(&uris, &url("https://api.example.com.evil.net/")).is_err());
    }

    #[test]
    fn host_binding_without_scheme_matches_any_scheme_and_port() {
        let uris = vec!["nas.lan".to_string()];
        assert!(credential_allows(&uris, &url("http://nas.lan:5000/x")).is_ok());
        assert!(credential_allows(&uris, &url("https://nas.lan/x")).is_ok());
    }

    #[test]
    fn host_binding_explicit_port() {
        let uris = vec!["http://mock-api:7777".to_string()];
        assert!(credential_allows(&uris, &url("http://mock-api:7777/a")).is_ok());
        assert!(credential_allows(&uris, &url("http://mock-api/a")).is_err());
    }

    #[test]
    fn host_binding_requires_uris() {
        assert!(credential_allows(&[], &url("https://a.example/")).is_err());
    }

    #[tokio::test]
    async fn resolve_rejects_unknown_ambiguous_and_unbound_before_fetching() {
        // Unreachable vault: any fetch attempt would return VaultUnavailable.
        let vault = VaultClient::new("http://127.0.0.1:1".to_string());
        let mut creds = CredentialMap::new();
        creds.insert("dup".into(), vec![
            CredentialEntry { id: "1".into(), uris: vec![] },
            CredentialEntry { id: "2".into(), uris: vec![] },
        ]);
        creds.insert("bound".into(), vec![CredentialEntry { id: "3".into(), uris: vec!["https://a.example".into()] }]);
        let target = url("https://b.example/");

        let names: HashSet<String> = ["missing".to_string()].into();
        let err = resolve_credentials(&names, &creds, &target, true, &vault).await.unwrap_err();
        assert!(matches!(err, FerroError::UnknownPlaceholder(_)));

        let names: HashSet<String> = ["dup".to_string()].into();
        let err = resolve_credentials(&names, &creds, &target, true, &vault).await.unwrap_err();
        assert!(matches!(err, FerroError::AmbiguousCredential(_)));

        let names: HashSet<String> = ["bound".to_string()].into();
        let err = resolve_credentials(&names, &creds, &target, true, &vault).await.unwrap_err();
        assert!(matches!(err, FerroError::CredentialHostNotAllowed { .. }));

        // With enforcement off the binding is skipped and the fetch is attempted.
        let err = resolve_credentials(&names, &creds, &target, false, &vault).await.unwrap_err();
        assert!(matches!(err, FerroError::VaultUnavailable));
    }

    #[test]
    fn substitute_no_placeholders_returns_input() {
        let out = substitute_str("no placeholders here", &ResolvedValues::new());
        assert_eq!(out.as_str(), "no placeholders here");
    }
}
