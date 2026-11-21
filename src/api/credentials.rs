use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::error::{FerroError, FerroResult};
use crate::proxy::placeholder::{Placeholder, Selector};
use crate::state::AppState;
use crate::vault::client::{CredentialEntry, FieldKind, FieldLookup, ItemKind};

/// One credential in the detailed listing: ready-made placeholders for every
/// available value, so agents copy strings instead of building quoting
/// themselves. Never contains a value.
#[derive(Debug, Serialize, PartialEq)]
pub struct CredentialDetail {
    pub name: String,
    /// "login" or "secure_note"; omitted when the name is ambiguous.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
    /// Placeholder for the password.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Custom field name → placeholder.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
    /// Custom field name → why it cannot be used.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub unavailable_fields: BTreeMap<String, String>,
    /// Hosts the credential may be sent to (its bindings).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bound_to: Vec<String>,
    /// Set when the whole credential cannot be used, with the reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<String>,
}

fn detail(name: &str, entries: &[CredentialEntry]) -> CredentialDetail {
    let mut d = CredentialDetail {
        name: name.to_string(),
        kind: None,
        placeholder: None,
        username: None,
        totp: None,
        notes: None,
        fields: BTreeMap::new(),
        unavailable_fields: BTreeMap::new(),
        bound_to: Vec::new(),
        unavailable: None,
    };
    let entry = match entries {
        [one] => one,
        _ => {
            d.unavailable = Some(format!(
                "ambiguous: {} vault items share this name; rename one of them",
                entries.len()
            ));
            return d;
        }
    };
    d.kind = Some(entry.kind.as_str());
    d.bound_to = entry.uris.clone();
    if entry.reprompt {
        d.unavailable = Some(
            "master password re-prompt is enabled on this item; agents cannot use it until approvals are supported"
                .to_string(),
        );
        return d;
    }

    let render = |selector: Selector| {
        Placeholder {
            item: name.to_string(),
            selector,
        }
        .render()
    };
    let login = entry.kind == ItemKind::Login;
    if login && entry.has_password {
        d.placeholder = Some(render(Selector::Password));
    }
    if login && entry.has_username {
        d.username = Some(render(Selector::Username));
    }
    if login && entry.has_totp {
        d.totp = Some(render(Selector::Totp));
    }
    if entry.has_notes {
        d.notes = Some(render(Selector::Notes));
    }
    for f in &entry.fields {
        if d.fields.contains_key(&f.name) || d.unavailable_fields.contains_key(&f.name) {
            continue;
        }
        let reason = match (entry.field(&f.name), f.kind) {
            (FieldLookup::Duplicate, _) => {
                Some("ambiguous: the item has more than one field with this name")
            }
            (_, FieldKind::LinkedOther) => Some("linked to a value that is not supported"),
            (_, FieldKind::LinkedUsername | FieldKind::LinkedPassword) if !login => {
                Some("linked field on a non-login item")
            }
            _ => None,
        };
        match reason {
            Some(r) => {
                d.unavailable_fields.insert(f.name.clone(), r.to_string());
            }
            None => {
                d.fields
                    .insert(f.name.clone(), render(Selector::Field(f.name.clone())));
            }
        }
    }
    d
}

/// GET /v1/credentials
///
/// Returns the credentials available in the vault — names only, never
/// values. With `?detail=true`, returns [`CredentialDetail`] objects with
/// ready-made placeholders for every usable value and field.
/// Requires a valid agent key in the X-Agent-Key header.
pub async fn list_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> FerroResult<Json<Value>> {
    authenticate_agent(&state, &headers).await?;

    // In file mode, try to unlock again right away (e.g. after a bw serve
    // restart) instead of failing until the next refresh.
    if state.is_locked().await && !crate::vault::refresh::reunlock_if_possible(&state).await {
        return Err(FerroError::VaultLocked);
    }

    let credentials = state.credentials.read().await;
    let detailed = params
        .get("detail")
        .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "" | "1" | "true" | "yes"));

    let body = if detailed {
        let list: Vec<CredentialDetail> = credentials
            .iter()
            .map(|(name, entries)| detail(name, entries))
            .collect();
        serde_json::to_value(list)
    } else {
        // BTreeMap keys: sorted, de-duplicated names.
        serde_json::to_value(credentials.keys().collect::<Vec<_>>())
    }
    .map_err(|e| FerroError::Internal(e.to_string()))?;

    Ok(Json(body))
}

/// Extract and validate the agent key from the X-Agent-Key header.
pub async fn authenticate_agent(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> FerroResult<crate::state::AgentKey> {
    let token = headers
        .get("x-agent-key")
        .and_then(|v| v.to_str().ok())
        .ok_or(FerroError::Unauthorized)?;

    state
        .authenticate(token)
        .await
        .ok_or(FerroError::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::placeholder::scan;
    use crate::vault::client::FieldInfo;

    fn field(name: &str, kind: FieldKind) -> FieldInfo {
        FieldInfo {
            name: name.into(),
            kind,
        }
    }

    #[test]
    fn detail_offers_ready_placeholders_that_parse_back() {
        let mut e = CredentialEntry::login("1", &["https://pve.lan:8006"]);
        e.has_username = true;
        e.has_totp = true;
        e.fields = vec![
            field("api secret", FieldKind::Hidden),
            field("flag", FieldKind::Boolean),
            field("dup", FieldKind::Text),
            field("dup", FieldKind::Text),
            field("card", FieldKind::LinkedOther),
        ];
        let d = detail("Proxmox (prod)", &[e]);
        assert_eq!(d.kind, Some("login"));
        assert_eq!(d.placeholder.as_deref(), Some("{{vault:'Proxmox (prod)'}}"));
        assert_eq!(
            d.username.as_deref(),
            Some("{{vault:'Proxmox (prod)':username}}")
        );
        assert_eq!(d.totp.as_deref(), Some("{{vault:'Proxmox (prod)':totp}}"));
        assert_eq!(d.notes, None);
        assert_eq!(
            d.fields["api secret"],
            "{{vault:'Proxmox (prod)':field:'api secret'}}"
        );
        assert!(d.fields.contains_key("flag"));
        assert!(d.unavailable_fields["dup"].starts_with("ambiguous"));
        assert!(d.unavailable_fields.contains_key("card"));
        assert_eq!(d.bound_to, vec!["https://pve.lan:8006"]);
        // Every offered placeholder parses back to this item.
        for p in [&d.placeholder, &d.username, &d.totp]
            .into_iter()
            .flatten()
            .chain(d.fields.values())
        {
            let occ = scan(p).unwrap();
            assert_eq!(occ.len(), 1);
            assert_eq!(occ[0].placeholder.item, "Proxmox (prod)");
        }
    }

    #[test]
    fn detail_marks_ambiguous_and_reprompt_items_unavailable() {
        let a = CredentialEntry::login("1", &[]);
        let d = detail("same", &[a.clone(), a]);
        assert!(d.unavailable.unwrap().starts_with("ambiguous: 2"));
        assert!(d.placeholder.is_none() && d.kind.is_none());

        let mut rp = CredentialEntry::login("2", &["https://x.example"]);
        rp.reprompt = true;
        let d = detail("guarded", &[rp]);
        assert!(d.unavailable.unwrap().contains("re-prompt"));
        assert!(d.placeholder.is_none());
    }

    #[test]
    fn detail_secure_note() {
        let mut n = CredentialEntry::login("3", &["https://n.example"]);
        n.kind = ItemKind::SecureNote;
        n.has_password = false;
        n.has_notes = true;
        n.fields = vec![field("token", FieldKind::Hidden)];
        let d = detail("note", &[n]);
        assert_eq!(d.kind, Some("secure_note"));
        assert!(d.placeholder.is_none());
        assert_eq!(d.notes.as_deref(), Some("{{vault:note:notes}}"));
        assert_eq!(d.fields["token"], "{{vault:note:field:token}}");
    }
}
