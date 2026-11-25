use reqwest::Url;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{FerroError, FerroResult};
use crate::proxy::placeholder::{scan, Placeholder, Selector};
use crate::vault::model::{CredentialEntry, FieldKind, FieldLookup, ItemKind};
use crate::vault::{Builtin, CredentialMap, Vault};

/// A resolved placeholder value. `scrub` says whether exact-value scrubbing
/// applies: false for usernames, TOTP codes and boolean fields, which are
/// low-entropy or not secret and would corrupt responses if redacted.
pub struct Resolved {
    pub value: Zeroizing<String>,
    pub scrub: bool,
}

/// Never prints the value.
impl std::fmt::Debug for Resolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolved")
            .field("value", &"<redacted>")
            .field("scrub", &self.scrub)
            .finish()
    }
}

/// Resolved values for one request, keyed by placeholder. Every value is
/// Zeroizing and wiped when the map is dropped.
pub type ResolvedValues = BTreeMap<Placeholder, Resolved>;

/// Check whether a credential bound to `uris` may be sent to `target`.
///
/// A URI matches when its host equals the target host (case-insensitive) and,
/// if the URI states them explicitly, the scheme and port also match. URIs
/// without a scheme (e.g. `api.example.com`) match either http or https.
pub fn credential_allows(uris: &[String], target: &Url) -> Result<(), String> {
    if uris.is_empty() {
        return Err(
            "the vault item has no URIs; add the target's URL to the item (or a ferrowarden_uris field) to allow it"
                .to_string(),
        );
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

/// What to fetch for a validated placeholder, and whether to scrub it.
#[derive(Debug)]
enum Fetch {
    Builtin(Builtin),
    Field(String),
}

/// Validate a placeholder against the cached item metadata (no vault call).
fn plan(p: &Placeholder, entry: &CredentialEntry) -> FerroResult<(Fetch, bool)> {
    let unknown = || FerroError::UnknownPlaceholder(p.label());
    let login = entry.kind == ItemKind::Login;
    match &p.selector {
        Selector::Password if login && entry.has_password => {
            Ok((Fetch::Builtin(Builtin::Password), true))
        }
        Selector::Username if login && entry.has_username => {
            Ok((Fetch::Builtin(Builtin::Username), false))
        }
        Selector::Totp if login && entry.has_totp => Ok((Fetch::Builtin(Builtin::Totp), false)),
        Selector::Notes if entry.has_notes => Ok((Fetch::Builtin(Builtin::Notes), true)),
        Selector::Field(name) => match entry.field(name) {
            FieldLookup::Missing => Err(unknown()),
            FieldLookup::Duplicate => Err(FerroError::AmbiguousField {
                item: p.item.clone(),
                field: name.clone(),
            }),
            FieldLookup::Unique(f) => {
                let scrub = match f.kind {
                    FieldKind::Text | FieldKind::Hidden | FieldKind::LinkedPassword => true,
                    FieldKind::Boolean | FieldKind::LinkedUsername => false,
                    FieldKind::LinkedOther => return Err(unknown()),
                };
                if matches!(
                    f.kind,
                    FieldKind::LinkedUsername | FieldKind::LinkedPassword
                ) && !login
                {
                    return Err(unknown());
                }
                Ok((Fetch::Field(name.clone()), scrub))
            }
        },
        _ => Err(unknown()),
    }
}

/// The outcome of the check phase: every placeholder validated, and what to
/// fetch for each. Holds no values.
#[derive(Debug)]
pub struct CredentialPlan {
    items: Vec<PlannedItem>,
}

#[derive(Debug)]
struct PlannedItem {
    placeholder: Placeholder,
    id: String,
    fetch: Fetch,
    scrub: bool,
}

/// Check phase: validate every placeholder for a request to `target` against
/// the cached item metadata. Pure: no vault access and no I/O, so `/v1/forward`
/// and the policy preview run exactly the same checks.
///
/// Fails if an item is unknown or ambiguous, has master password re-prompt
/// enabled, lacks the selected value or field, or (when `enforce_hosts` is
/// set) is not bound to the target host.
pub fn check_credentials(
    placeholders: &BTreeSet<Placeholder>,
    credentials: &CredentialMap,
    target: &Url,
    enforce_hosts: bool,
) -> FerroResult<CredentialPlan> {
    let mut items = Vec::with_capacity(placeholders.len());
    for p in placeholders {
        let entries = credentials
            .get(&p.item)
            .ok_or_else(|| FerroError::UnknownPlaceholder(p.label()))?;
        let entry = match entries.as_slice() {
            [one] => one,
            [] => return Err(FerroError::UnknownPlaceholder(p.label())),
            _ => return Err(FerroError::AmbiguousCredential(p.item.clone())),
        };
        if entry.reprompt {
            return Err(FerroError::RepromptRequired(p.item.clone()));
        }
        let (fetch, scrub) = plan(p, entry)?;
        if enforce_hosts {
            credential_allows(&entry.uris, target).map_err(|reason| {
                FerroError::CredentialHostNotAllowed {
                    name: p.label(),
                    host: target.host_str().unwrap_or_default().to_string(),
                    reason,
                }
            })?;
        }
        items.push(PlannedItem {
            placeholder: p.clone(),
            id: entry.id.clone(),
            fetch,
            scrub,
        });
    }
    Ok(CredentialPlan { items })
}

/// Fetch phase: get the values a validated plan calls for from the vault.
pub async fn fetch_credentials<V: Vault + ?Sized>(
    plan: &CredentialPlan,
    vault: &V,
) -> FerroResult<ResolvedValues> {
    let mut values = ResolvedValues::new();
    for item in &plan.items {
        let label = item.placeholder.label();
        let value = match &item.fetch {
            Fetch::Builtin(which) => vault.get_value(*which, &item.id, &label).await?,
            Fetch::Field(name) => vault.get_field(&item.id, name, &label).await?,
        };
        values.insert(
            item.placeholder.clone(),
            Resolved {
                value,
                scrub: item.scrub,
            },
        );
    }
    Ok(values)
}

/// Check then fetch. Fails before fetching any value if any check fails.
#[cfg(test)]
pub async fn resolve_credentials<V: Vault + ?Sized>(
    placeholders: &BTreeSet<Placeholder>,
    credentials: &CredentialMap,
    target: &Url,
    enforce_hosts: bool,
    vault: &V,
) -> FerroResult<ResolvedValues> {
    let plan = check_credentials(placeholders, credentials, target, enforce_hosts)?;
    fetch_credentials(&plan, vault).await
}

/// Replace every placeholder in `input` with its resolved value. Placeholders
/// not in `values` are left untouched (callers resolve every placeholder
/// first, and malformed ones are rejected before substitution).
pub fn substitute_str(input: &str, values: &ResolvedValues) -> Zeroizing<String> {
    let mut result = Zeroizing::new(String::with_capacity(input.len()));
    let mut last_end = 0;
    for occ in scan(input).unwrap_or_default() {
        if let Some(resolved) = values.get(&occ.placeholder) {
            result.push_str(&input[last_end..occ.start]);
            result.push_str(resolved.value.as_str());
            last_end = occ.end;
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
        Value::Array(items) => {
            Value::Array(items.iter().map(|v| substitute_json(v, values)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    (
                        substitute_str(k, values).to_string(),
                        substitute_json(v, values),
                    )
                })
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
    use crate::vault::model::FieldInfo;
    use serde_json::json;

    fn ph(item: &str, selector: Selector) -> Placeholder {
        Placeholder {
            item: item.to_string(),
            selector,
        }
    }

    fn values(pairs: &[(Placeholder, &str)]) -> ResolvedValues {
        pairs
            .iter()
            .map(|(p, v)| {
                (
                    p.clone(),
                    Resolved {
                        value: Zeroizing::new(v.to_string()),
                        scrub: true,
                    },
                )
            })
            .collect()
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn substitute_str_replaces_all_occurrences_and_selectors() {
        let v = values(&[
            (ph("t", Selector::Password), "SECRET"),
            (ph("a b", Selector::Username), "USER"),
        ]);
        let out = substitute_str(
            "a {{vault:t}} b {{vault:t:password}} u={{vault:'a b':username}}",
            &v,
        );
        assert_eq!(out.as_str(), "a SECRET b SECRET u=USER");
    }

    #[test]
    fn substitute_json_escapes_special_characters() {
        let v = values(&[(ph("pw", Selector::Password), r#"pa"ss\word"#)]);
        let mut out = substitute_json(&json!({"password": "{{vault:pw}}", "n": 5}), &v);
        let text = serde_json::to_string(&out).unwrap();
        let reparsed: Value = serde_json::from_str(&text).expect("still valid JSON");
        assert_eq!(reparsed["password"], r#"pa"ss\word"#);
        assert_eq!(reparsed.as_object().unwrap().len(), 2, "no injected keys");
        zeroize_json(&mut out);
    }

    #[test]
    fn substitute_no_placeholders_returns_input() {
        let out = substitute_str("no placeholders here", &ResolvedValues::new());
        assert_eq!(out.as_str(), "no placeholders here");
    }

    #[test]
    fn host_binding_matches_host_scheme_and_port() {
        let uris = vec!["https://api.example.com".to_string()];
        assert!(credential_allows(&uris, &url("https://API.example.com/v1")).is_ok());
        assert!(
            credential_allows(&uris, &url("http://api.example.com/v1")).is_err(),
            "scheme downgrade"
        );
        assert!(
            credential_allows(&uris, &url("https://api.example.com:8443/")).is_err(),
            "other port"
        );
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

    fn rich_login() -> CredentialEntry {
        let mut e = CredentialEntry::login("9", &["https://a.example"]);
        e.has_username = true;
        e.has_notes = true;
        e.fields = vec![
            FieldInfo {
                name: "api key".into(),
                kind: FieldKind::Hidden,
            },
            FieldInfo {
                name: "flag".into(),
                kind: FieldKind::Boolean,
            },
            FieldInfo {
                name: "lu".into(),
                kind: FieldKind::LinkedUsername,
            },
            FieldInfo {
                name: "card".into(),
                kind: FieldKind::LinkedOther,
            },
            FieldInfo {
                name: "dup".into(),
                kind: FieldKind::Text,
            },
            FieldInfo {
                name: "dup".into(),
                kind: FieldKind::Text,
            },
        ];
        e
    }

    #[test]
    fn plan_selectors_and_scrub_rules() {
        let e = rich_login();
        let scrub = |s: Selector| plan(&ph("x", s), &e).map(|(_, scrub)| scrub);
        assert!(scrub(Selector::Password).unwrap());
        assert!(!scrub(Selector::Username).unwrap());
        assert!(scrub(Selector::Notes).unwrap());
        assert!(scrub(Selector::Field("api key".into())).unwrap());
        assert!(!scrub(Selector::Field("flag".into())).unwrap());
        assert!(!scrub(Selector::Field("lu".into())).unwrap());
        assert!(
            matches!(
                scrub(Selector::Totp),
                Err(FerroError::UnknownPlaceholder(_))
            ),
            "no totp on item"
        );
        assert!(matches!(
            scrub(Selector::Field("card".into())),
            Err(FerroError::UnknownPlaceholder(_))
        ));
        assert!(matches!(
            scrub(Selector::Field("missing".into())),
            Err(FerroError::UnknownPlaceholder(_))
        ));
        assert!(matches!(
            scrub(Selector::Field("dup".into())),
            Err(FerroError::AmbiguousField { .. })
        ));
    }

    #[test]
    fn plan_secure_note_has_no_login_values() {
        let mut n = CredentialEntry::login("7", &["https://n.example"]);
        n.kind = ItemKind::SecureNote;
        n.has_password = false;
        n.has_notes = true;
        n.fields = vec![FieldInfo {
            name: "token".into(),
            kind: FieldKind::Hidden,
        }];
        assert!(plan(&ph("n", Selector::Notes), &n).is_ok());
        assert!(plan(&ph("n", Selector::Field("token".into())), &n).is_ok());
        assert!(matches!(
            plan(&ph("n", Selector::Password), &n),
            Err(FerroError::UnknownPlaceholder(_))
        ));
        assert!(matches!(
            plan(&ph("n", Selector::Username), &n),
            Err(FerroError::UnknownPlaceholder(_))
        ));
    }

    #[tokio::test]
    async fn resolve_rejects_before_fetching() {
        // Unreachable vault: any fetch attempt would return VaultUnavailable.
        let vault = crate::vault::BwServe::new("http://127.0.0.1:1".to_string());
        let mut creds = CredentialMap::new();
        creds.insert(
            "dup".into(),
            vec![
                CredentialEntry::login("1", &[]),
                CredentialEntry::login("2", &[]),
            ],
        );
        creds.insert(
            "bound".into(),
            vec![CredentialEntry::login("3", &["https://a.example"])],
        );
        let mut rp = CredentialEntry::login("4", &["https://b.example"]);
        rp.reprompt = true;
        creds.insert("guarded".into(), vec![rp]);
        let target = url("https://b.example/");
        let set = |p: Placeholder| BTreeSet::from([p]);

        let err = resolve_credentials(
            &set(ph("missing", Selector::Password)),
            &creds,
            &target,
            true,
            &vault,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, FerroError::UnknownPlaceholder(_)));

        let err = resolve_credentials(
            &set(ph("dup", Selector::Password)),
            &creds,
            &target,
            true,
            &vault,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, FerroError::AmbiguousCredential(_)));

        let err = resolve_credentials(
            &set(ph("guarded", Selector::Password)),
            &creds,
            &target,
            true,
            &vault,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, FerroError::RepromptRequired(_)));

        let err = resolve_credentials(
            &set(ph("bound", Selector::Password)),
            &creds,
            &target,
            true,
            &vault,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, FerroError::CredentialHostNotAllowed { .. }));

        // With enforcement off the binding is skipped and the fetch is attempted.
        let err = resolve_credentials(
            &set(ph("bound", Selector::Password)),
            &creds,
            &target,
            false,
            &vault,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, FerroError::VaultUnavailable));
    }

    #[test]
    fn check_phase_needs_no_vault_and_matches_resolve_errors() {
        let mut creds = CredentialMap::new();
        creds.insert(
            "ok".into(),
            vec![CredentialEntry::login("1", &["https://b.example"])],
        );
        creds.insert(
            "dup".into(),
            vec![
                CredentialEntry::login("2", &[]),
                CredentialEntry::login("3", &[]),
            ],
        );
        let mut rp = CredentialEntry::login("4", &["https://b.example"]);
        rp.reprompt = true;
        creds.insert("guarded".into(), vec![rp]);
        let target = url("https://b.example/");
        let check = |p: Placeholder| {
            check_credentials(&BTreeSet::from([p]), &creds, &target, true).map(|_| ())
        };

        assert!(check(ph("ok", Selector::Password)).is_ok());
        assert!(matches!(
            check(ph("missing", Selector::Password)),
            Err(FerroError::UnknownPlaceholder(_))
        ));
        assert!(matches!(
            check(ph("ok", Selector::Username)),
            Err(FerroError::UnknownPlaceholder(_))
        ));
        assert!(matches!(
            check(ph("dup", Selector::Password)),
            Err(FerroError::AmbiguousCredential(_))
        ));
        assert!(matches!(
            check(ph("guarded", Selector::Password)),
            Err(FerroError::RepromptRequired(_))
        ));
        let other = url("https://evil.example/");
        assert!(matches!(
            check_credentials(
                &BTreeSet::from([ph("ok", Selector::Password)]),
                &creds,
                &other,
                true
            ),
            Err(FerroError::CredentialHostNotAllowed { .. })
        ));
        // Binding enforcement off: the check passes.
        assert!(check_credentials(
            &BTreeSet::from([ph("ok", Selector::Password)]),
            &creds,
            &other,
            false
        )
        .is_ok());
    }
}
