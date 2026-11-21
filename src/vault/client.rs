use reqwest::Client;
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{FerroError, FerroResult};
use crate::proxy::substitute::zeroize_json;

/// Name of the reserved custom field that lists a credential's host bindings
/// (comma- or newline-separated URIs). It provides bindings for secure notes
/// and overrides a login's URIs when present. Not offered as a selectable field.
pub const BINDINGS_FIELD: &str = "ferrowarden_uris";

/// Minimal response shapes from bw serve. We only deserialize what we need.
#[derive(Debug, Deserialize)]
struct BwResponse<T> {
    success: bool,
    message: Option<String>,
    data: Option<T>,
}

/// One item from `GET /list/object/items`. The response contains every
/// decrypted value; only names, ids, URIs and *presence* of values are read
/// out of it (`IgnoredAny` skips a value without copying it).
#[derive(Debug, Deserialize)]
struct BwItem {
    id: String,
    name: String,
    /// 1 = login, 2 = secure note (3 card, 4 identity, 5 SSH key: not yet supported).
    #[serde(rename = "type")]
    item_type: u8,
    #[serde(default)]
    reprompt: u8,
    #[serde(default)]
    notes: Option<IgnoredAny>,
    #[serde(default)]
    login: Option<BwLogin>,
    #[serde(default)]
    fields: Option<Vec<BwField>>,
}

#[derive(Debug, Deserialize)]
struct BwLogin {
    #[serde(default)]
    username: Option<IgnoredAny>,
    #[serde(default)]
    password: Option<IgnoredAny>,
    #[serde(default)]
    totp: Option<IgnoredAny>,
    #[serde(default)]
    uris: Option<Vec<BwUri>>,
}

#[derive(Debug, Deserialize)]
struct BwUri {
    #[serde(default)]
    uri: Option<String>,
    /// Bitwarden URI match type: null default, 0 domain, 1 host,
    /// 2 starts with, 3 exact, 4 regex, 5 never.
    #[serde(default, rename = "match")]
    match_type: Option<u8>,
}

#[derive(Debug, Deserialize)]
struct BwField {
    #[serde(default)]
    name: Option<String>,
    /// 0 text, 1 hidden, 2 boolean, 3 linked.
    #[serde(rename = "type", default)]
    field_type: u8,
    /// For linked fields: 100 = login username, 101 = login password.
    #[serde(rename = "linkedId", default)]
    linked_id: Option<u32>,
    /// Kept only for the reserved bindings field; wiped on drop.
    #[serde(default)]
    value: Option<Zeroizing<String>>,
}

#[derive(Debug, Deserialize)]
struct BwListData {
    data: Vec<BwItem>,
}

#[derive(Debug, Deserialize)]
struct BwStringData {
    data: String,
}

#[derive(Debug, Deserialize)]
struct BwStatusData {
    template: BwStatusTemplate,
}

#[derive(Debug, Deserialize)]
struct BwStatusTemplate {
    #[serde(default)]
    status: String,
    #[serde(default, rename = "userEmail")]
    user_email: Option<String>,
    #[serde(default, rename = "lastSync")]
    last_sync: Option<String>,
}

/// What `GET /status` of bw serve reports: no secrets, just the session.
#[derive(Debug, Clone, PartialEq)]
pub struct BwStatus {
    /// `unauthenticated`, `locked` or `unlocked`.
    pub status: String,
    /// Email of the logged-in account (absent when unauthenticated).
    pub user_email: Option<String>,
    /// Timestamp of the last sync with the server, as bw serve reports it.
    pub last_sync: Option<String>,
}

/// Kind of vault item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    Login,
    SecureNote,
}

impl ItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ItemKind::Login => "login",
            ItemKind::SecureNote => "secure_note",
        }
    }
}

/// Kind of custom field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Hidden,
    Boolean,
    /// Linked to the login's username.
    LinkedUsername,
    /// Linked to the login's password.
    LinkedPassword,
    /// Linked to something not supported (e.g. card/identity properties).
    LinkedOther,
}

/// A custom field's metadata — never its value.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldInfo {
    pub name: String,
    pub kind: FieldKind,
}

/// Result of looking a custom field up by name.
pub enum FieldLookup<'a> {
    Missing,
    Unique(&'a FieldInfo),
    Duplicate,
}

/// One vault item as seen by ferrowarden: never a value, only the id used to
/// fetch values, which values exist, and the URIs that bind it to hosts.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialEntry {
    pub id: String,
    pub kind: ItemKind,
    /// Host bindings: `ferrowarden_uris` if present, otherwise the login's
    /// URIs excluding those with match type "regex" or "never".
    pub uris: Vec<String>,
    pub has_username: bool,
    pub has_password: bool,
    pub has_totp: bool,
    pub has_notes: bool,
    /// Custom fields, excluding the reserved bindings field.
    pub fields: Vec<FieldInfo>,
    /// Master password re-prompt is enabled on the item.
    pub reprompt: bool,
}

impl CredentialEntry {
    /// A login item with just a password and URIs (used by tests).
    #[cfg(test)]
    pub fn login(id: &str, uris: &[&str]) -> Self {
        Self {
            id: id.to_string(),
            kind: ItemKind::Login,
            uris: uris.iter().map(|u| u.to_string()).collect(),
            has_username: false,
            has_password: true,
            has_totp: false,
            has_notes: false,
            fields: Vec::new(),
            reprompt: false,
        }
    }

    pub fn field(&self, name: &str) -> FieldLookup<'_> {
        let mut found = self.fields.iter().filter(|f| f.name == name);
        match (found.next(), found.next()) {
            (None, _) => FieldLookup::Missing,
            (Some(f), None) => FieldLookup::Unique(f),
            (Some(_), Some(_)) => FieldLookup::Duplicate,
        }
    }
}

/// Credential cache: item name -> all supported items with that name. More
/// than one entry means the name is ambiguous and cannot be used.
pub type CredentialMap = std::collections::BTreeMap<String, Vec<CredentialEntry>>;

fn split_uris(raw: &str) -> Vec<String> {
    raw.split([',', '\n', '\r'])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn entry_from_item(item: BwItem) -> Option<(String, CredentialEntry)> {
    let kind = match item.item_type {
        1 => ItemKind::Login,
        2 => ItemKind::SecureNote,
        _ => return None,
    };

    let mut bindings_override = None;
    let mut fields = Vec::new();
    for f in item.fields.unwrap_or_default() {
        let Some(name) = f.name else { continue };
        if name == BINDINGS_FIELD {
            if let Some(v) = &f.value {
                bindings_override = Some(split_uris(v));
            }
            continue;
        }
        let kind = match (f.field_type, f.linked_id) {
            (0, _) => FieldKind::Text,
            (1, _) => FieldKind::Hidden,
            (2, _) => FieldKind::Boolean,
            (3, Some(100)) => FieldKind::LinkedUsername,
            (3, Some(101)) => FieldKind::LinkedPassword,
            (3, _) => FieldKind::LinkedOther,
            _ => continue,
        };
        fields.push(FieldInfo { name, kind });
    }

    let login = item.login;
    let login_uris: Vec<String> = login
        .as_ref()
        .and_then(|l| l.uris.as_ref())
        .map(|uris| {
            uris.iter()
                // regex and "never" URIs are not host bindings
                .filter(|u| !matches!(u.match_type, Some(4) | Some(5)))
                .filter_map(|u| u.uri.clone())
                .filter(|u| !u.trim().is_empty())
                .collect()
        })
        .unwrap_or_default();

    let entry = CredentialEntry {
        id: item.id,
        kind,
        uris: bindings_override.unwrap_or(login_uris),
        has_username: login.as_ref().is_some_and(|l| l.username.is_some()),
        has_password: login.as_ref().is_some_and(|l| l.password.is_some()),
        has_totp: login.as_ref().is_some_and(|l| l.totp.is_some()),
        has_notes: item.notes.is_some(),
        fields,
        reprompt: item.reprompt != 0,
    };
    Some((item.name, entry))
}

/// Client for the bw serve local REST API.
/// All methods assume bw serve is running and unlocked — callers must check
/// lock state before calling. The bw_serve_url must be localhost-only.
pub struct VaultClient {
    client: Client,
    base_url: String,
}

impl VaultClient {
    pub fn new(base_url: String) -> Self {
        Self {
            // Short timeouts — bw serve is local, slow responses indicate a problem.
            // no_proxy: vault traffic must never be routed via an HTTP(S)_PROXY.
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .no_proxy()
                .build()
                .expect("Failed to build vault HTTP client"),
            base_url,
        }
    }

    /// `GET /status`: login state, account email and last sync of bw serve.
    /// Used by the admin UI to learn which account to sign in as. Bounded by
    /// a short timeout so a slow bw serve cannot hang a page.
    pub async fn status(&self) -> FerroResult<BwStatus> {
        let url = format!("{}/status", self.base_url);
        let resp = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|_| FerroError::VaultUnavailable)?;
        if !resp.status().is_success() {
            return Err(FerroError::VaultUnavailable);
        }
        let body: BwResponse<BwStatusData> = resp
            .json()
            .await
            .map_err(|_| FerroError::VaultUnavailable)?;
        let template = match (body.success, body.data) {
            (true, Some(data)) => data.template,
            _ => return Err(FerroError::VaultUnavailable),
        };
        Ok(BwStatus {
            status: template.status,
            user_email: template.user_email.filter(|e| !e.trim().is_empty()),
            last_sync: template.last_sync,
        })
    }

    /// Pull the latest vault contents from Vaultwarden into bw serve's local
    /// cache. Without this, items added after `bw login` never appear.
    pub async fn sync(&self) -> FerroResult<()> {
        let url = format!("{}/sync", self.base_url);
        let resp = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|_| FerroError::VaultUnavailable)?;
        if !resp.status().is_success() {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let msg = body
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("sync failed");
            if msg.to_lowercase().contains("locked") {
                return Err(FerroError::VaultLocked);
            }
            return Err(FerroError::Internal(msg.to_string()));
        }
        Ok(())
    }

    /// Return metadata for every supported item (logins and secure notes).
    /// Values are never kept. Called on unlock and periodically.
    pub async fn list_credentials(&self) -> FerroResult<CredentialMap> {
        let url = format!("{}/list/object/items", self.base_url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|_| FerroError::VaultUnavailable)?;

        if resp.status() == reqwest::StatusCode::BAD_REQUEST {
            return Err(FerroError::VaultLocked);
        }

        let body: BwResponse<BwListData> = resp
            .json()
            .await
            .map_err(|e| FerroError::Internal(e.to_string()))?;

        if !body.success {
            let msg = body
                .message
                .unwrap_or_else(|| "unknown vault error".to_string());
            // A "vault is locked" message from bw serve maps to VaultLocked
            if msg.to_lowercase().contains("locked") {
                return Err(FerroError::VaultLocked);
            }
            return Err(FerroError::Internal(msg));
        }

        let mut map = CredentialMap::new();
        for item in body.data.map(|d| d.data).unwrap_or_default() {
            if let Some((name, entry)) = entry_from_item(item) {
                map.entry(name).or_default().push(entry);
            }
        }
        Ok(map)
    }

    /// Fetch one built-in value of an item by id via bw serve's single-value
    /// getter: `object` is `password`, `username`, `totp` or `notes`.
    /// `label` (the placeholder text) is only used in error messages.
    pub async fn get_value(
        &self,
        object: &str,
        id: &str,
        label: &str,
    ) -> FerroResult<Zeroizing<String>> {
        let url = format!(
            "{}/object/{}/{}",
            self.base_url,
            object,
            urlencoding::encode(id)
        );

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|_| FerroError::VaultUnavailable)?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(FerroError::CredentialNotFound(label.to_string()));
        }

        let body: BwResponse<BwStringData> = resp
            .json()
            .await
            .map_err(|e| FerroError::Internal(e.to_string()))?;

        if !body.success {
            return Err(map_failure(body.message, label));
        }

        let value = body
            .data
            .map(|d| Zeroizing::new(d.data))
            .ok_or_else(|| FerroError::CredentialNotFound(label.to_string()))?;

        Ok(value)
    }

    /// Fetch a custom field's value. bw serve has no single-field getter, so
    /// the whole item is fetched, the field extracted, and every other value
    /// in the response wiped. Linked fields resolve to the login username
    /// or password they point at.
    pub async fn get_field(
        &self,
        id: &str,
        field: &str,
        label: &str,
    ) -> FerroResult<Zeroizing<String>> {
        let url = format!("{}/object/item/{}", self.base_url, urlencoding::encode(id));
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|_| FerroError::VaultUnavailable)?;
        let raw = Zeroizing::new(
            resp.bytes()
                .await
                .map_err(|_| FerroError::VaultUnavailable)?
                .to_vec(),
        );
        let mut doc: Value =
            serde_json::from_slice(&raw).map_err(|e| FerroError::Internal(e.to_string()))?;
        let result = extract_field(&doc, field, label);
        zeroize_json(&mut doc);
        result
    }
}

/// Map a bw serve failure message to an error.
fn map_failure(message: Option<String>, label: &str) -> FerroError {
    let msg = message
        .unwrap_or_else(|| "unknown vault error".to_string())
        .to_lowercase();
    if msg.contains("locked") {
        FerroError::VaultLocked
    } else if msg.contains("no item")
        || msg.contains("not found")
        || msg.contains("no username")
        || msg.contains("no password")
        || msg.contains("no totp")
        || msg.contains("no notes")
    {
        FerroError::CredentialNotFound(label.to_string())
    } else {
        FerroError::Internal("vault returned an error".to_string())
    }
}

/// Pick a custom field's value out of a `GET /object/item/{id}` response.
fn extract_field(doc: &Value, field: &str, label: &str) -> FerroResult<Zeroizing<String>> {
    if doc.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(map_failure(
            doc.get("message")
                .and_then(Value::as_str)
                .map(str::to_string),
            label,
        ));
    }
    let item = doc
        .get("data")
        .ok_or_else(|| FerroError::CredentialNotFound(label.to_string()))?;
    let mut matches = item
        .get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|f| f.get("name").and_then(Value::as_str) == Some(field));
    let found = match (matches.next(), matches.next()) {
        (Some(f), None) => f,
        (Some(_), Some(_)) => {
            return Err(FerroError::AmbiguousField {
                item: label.to_string(),
                field: field.to_string(),
            })
        }
        (None, _) => return Err(FerroError::CredentialNotFound(label.to_string())),
    };
    let value = match found.get("type").and_then(Value::as_u64) {
        Some(3) => {
            let key = match found.get("linkedId").and_then(Value::as_u64) {
                Some(100) => "username",
                Some(101) => "password",
                _ => return Err(FerroError::CredentialNotFound(label.to_string())),
            };
            item.get("login").and_then(|l| l.get(key))
        }
        _ => found.get("value"),
    };
    value
        .and_then(Value::as_str)
        .map(|s| Zeroizing::new(s.to_string()))
        .ok_or_else(|| FerroError::CredentialNotFound(label.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(items: &str) -> CredentialMap {
        let raw = format!(r#"{{"success":true,"data":{{"object":"list","data":[{items}]}}}}"#);
        let body: BwResponse<BwListData> = serde_json::from_str(&raw).unwrap();
        let mut map = CredentialMap::new();
        for item in body.data.unwrap().data {
            if let Some((name, entry)) = entry_from_item(item) {
                map.entry(name).or_default().push(entry);
            }
        }
        map
    }

    #[test]
    fn login_metadata_without_values() {
        let map = parse(
            r#"{"id":"1","name":"full","type":1,"reprompt":0,"notes":"N",
                "login":{"username":"u","password":"SECRET","totp":"JBSW",
                         "uris":[{"uri":"https://a.example"},{"uri":"^re$","match":4},
                                 {"uri":"https://never.example","match":5},{"uri":"b.example","match":0}]},
                "fields":[{"name":"api_key","value":"V","type":1},
                          {"name":"flag","value":"true","type":2},
                          {"name":"lu","type":3,"linkedId":100},
                          {"name":"lp","type":3,"linkedId":101},
                          {"name":"dup","value":"1","type":0},{"name":"dup","value":"2","type":0}]}"#,
        );
        let e = &map["full"][0];
        assert_eq!(e.kind, ItemKind::Login);
        assert!(e.has_username && e.has_password && e.has_totp && e.has_notes && !e.reprompt);
        assert_eq!(
            e.uris,
            vec!["https://a.example", "b.example"],
            "regex/never URIs dropped"
        );
        assert!(
            matches!(e.field("api_key"), FieldLookup::Unique(f) if f.kind == FieldKind::Hidden)
        );
        assert!(matches!(e.field("flag"), FieldLookup::Unique(f) if f.kind == FieldKind::Boolean));
        assert!(
            matches!(e.field("lu"), FieldLookup::Unique(f) if f.kind == FieldKind::LinkedUsername)
        );
        assert!(
            matches!(e.field("lp"), FieldLookup::Unique(f) if f.kind == FieldKind::LinkedPassword)
        );
        assert!(matches!(e.field("dup"), FieldLookup::Duplicate));
        assert!(matches!(e.field("nope"), FieldLookup::Missing));
        // The debug form must not contain any value.
        let dbg = format!("{e:?}");
        assert!(!dbg.contains("SECRET") && !dbg.contains("JBSW"));
    }

    #[test]
    fn secure_note_bindings_from_reserved_field_and_unsupported_types_skipped() {
        let map = parse(
            r#"{"id":"2","name":"note","type":2,"notes":"body","secureNote":{"type":0},
                "fields":[{"name":"ferrowarden_uris","value":"https://n.example, ssh://host\nhttps://m.example","type":0},
                          {"name":"token","value":"T","type":1}]},
               {"id":"3","name":"card","type":3,"card":{"number":"4111"}},
               {"id":"5","name":"key","type":5,"sshKey":{"privateKey":"K"}},
               {"id":"6","name":"rp","type":1,"reprompt":1,"login":{"password":"P"}}"#,
        );
        let n = &map["note"][0];
        assert_eq!(n.kind, ItemKind::SecureNote);
        assert_eq!(
            n.uris,
            vec!["https://n.example", "ssh://host", "https://m.example"]
        );
        assert!(!n.has_password && n.has_notes);
        assert!(
            matches!(n.field("ferrowarden_uris"), FieldLookup::Missing),
            "reserved field hidden"
        );
        assert!(!map.contains_key("card") && !map.contains_key("key"));
        assert!(map["rp"][0].reprompt);
    }

    #[test]
    fn bindings_field_overrides_login_uris() {
        let map = parse(
            r#"{"id":"1","name":"x","type":1,"login":{"password":"P","uris":[{"uri":"https://autofill.example"}]},
                "fields":[{"name":"ferrowarden_uris","value":"https://api.example","type":0}]}"#,
        );
        assert_eq!(map["x"][0].uris, vec!["https://api.example"]);
    }

    fn item_doc(fields: &str) -> Value {
        serde_json::from_str(&format!(
            r#"{{"success":true,"data":{{"login":{{"username":"USER","password":"PASS"}},"fields":[{fields}]}}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn extract_field_values_and_links() {
        let doc = item_doc(
            r#"{"name":"k","value":"V","type":1},{"name":"lu","type":3,"linkedId":100},
               {"name":"lp","type":3,"linkedId":101},{"name":"d","value":"1","type":0},{"name":"d","value":"2","type":0},
               {"name":"empty","value":null,"type":0}"#,
        );
        assert_eq!(extract_field(&doc, "k", "x").unwrap().as_str(), "V");
        assert_eq!(extract_field(&doc, "lu", "x").unwrap().as_str(), "USER");
        assert_eq!(extract_field(&doc, "lp", "x").unwrap().as_str(), "PASS");
        assert!(matches!(
            extract_field(&doc, "d", "x"),
            Err(FerroError::AmbiguousField { .. })
        ));
        assert!(matches!(
            extract_field(&doc, "missing", "x"),
            Err(FerroError::CredentialNotFound(_))
        ));
        assert!(matches!(
            extract_field(&doc, "empty", "x"),
            Err(FerroError::CredentialNotFound(_))
        ));
    }
}
