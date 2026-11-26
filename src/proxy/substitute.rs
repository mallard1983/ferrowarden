use reqwest::Url;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{FerroError, FerroResult};
use crate::proxy::placeholder::{scan, Placeholder, Selector, Token};
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

impl CredentialPlan {
    /// Every item name the plan uses, and whether its vault item carries the
    /// reserved `ferrowarden_approval` field (the vault's half of "needs
    /// approval"; the key policy is the other half).
    pub fn approval_fields(&self) -> BTreeMap<String, bool> {
        let mut out = BTreeMap::new();
        for item in &self.items {
            let flag = out.entry(item.placeholder.item.clone()).or_insert(false);
            *flag |= item.approval_field;
        }
        out
    }
}

#[derive(Debug)]
struct PlannedItem {
    placeholder: Placeholder,
    id: String,
    fetch: Fetch,
    scrub: bool,
    /// The vault item has a `ferrowarden_approval` field.
    approval_field: bool,
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
            approval_field: entry.approval_required,
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

/// The values of the captured sessions a request uses, by session name. Every
/// value is Zeroizing and wiped when the map is dropped.
pub type SessionValues = BTreeMap<String, Zeroizing<String>>;

/// Replace every placeholder in `input` with its resolved value. Placeholders
/// not in `values` or `sessions` are left untouched (callers resolve every
/// placeholder first, and malformed ones are rejected before substitution).
pub fn substitute_str(
    input: &str,
    values: &ResolvedValues,
    sessions: &SessionValues,
) -> Zeroizing<String> {
    let mut result = Zeroizing::new(String::with_capacity(input.len()));
    let mut last_end = 0;
    for occ in scan(input).unwrap_or_default() {
        let value = match &occ.token {
            Token::Vault(p) => values.get(p).map(|r| r.value.as_str()),
            Token::Session(name) => sessions.get(name).map(|v| v.as_str()),
        };
        if let Some(value) = value {
            result.push_str(&input[last_end..occ.start]);
            result.push_str(value);
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
pub fn substitute_json(value: &Value, values: &ResolvedValues, sessions: &SessionValues) -> Value {
    match value {
        Value::String(s) => Value::String(substitute_str(s, values, sessions).to_string()),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| substitute_json(v, values, sessions))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    (
                        substitute_str(k, values, sessions).to_string(),
                        substitute_json(v, values, sessions),
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
mod tests;
