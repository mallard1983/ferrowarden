//! What the rest of Ferrowarden knows about a vault item, whichever backend
//! supplies it: names, ids, URIs and which values exist. Never a value.

/// Name of the reserved custom field that lists a credential's host bindings
/// (comma- or newline-separated URIs). It provides bindings for secure notes
/// and overrides a login's URIs when present. Not offered as a selectable field.
pub const BINDINGS_FIELD: &str = "ferrowarden_uris";

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

    /// Bitwarden's item type number: 1 login, 2 secure note. Cards (3),
    /// identities (4), SSH keys (5) and anything newer are not offered.
    pub fn from_type(item_type: u8) -> Option<Self> {
        match item_type {
            1 => Some(ItemKind::Login),
            2 => Some(ItemKind::SecureNote),
            _ => None,
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

impl FieldKind {
    /// Map Bitwarden's field type (0 text, 1 hidden, 2 boolean, 3 linked) and,
    /// for linked fields, the linked id (100 username, 101 password). Unknown
    /// field types are not offered (`None`).
    pub fn from_wire(field_type: u8, linked_id: Option<u32>) -> Option<Self> {
        match (field_type, linked_id) {
            (0, _) => Some(FieldKind::Text),
            (1, _) => Some(FieldKind::Hidden),
            (2, _) => Some(FieldKind::Boolean),
            (3, Some(100)) => Some(FieldKind::LinkedUsername),
            (3, Some(101)) => Some(FieldKind::LinkedPassword),
            (3, _) => Some(FieldKind::LinkedOther),
            _ => None,
        }
    }
}

/// Whether a login URI with this match type is a host binding. Bitwarden's
/// match types: null default, 0 domain, 1 host, 2 starts with, 3 exact,
/// 4 regular expression, 5 never. The last two are not host bindings.
pub fn match_type_is_binding(match_type: Option<u8>) -> bool {
    !matches!(match_type, Some(4) | Some(5))
}

/// A built-in value of an item that can be fetched on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builtin {
    Password,
    Username,
    /// The current one-time code, not the stored secret.
    Totp,
    Notes,
}

impl Builtin {
    /// The object name bw serve uses for this value.
    pub fn as_str(self) -> &'static str {
        match self {
            Builtin::Password => "password",
            Builtin::Username => "username",
            Builtin::Totp => "totp",
            Builtin::Notes => "notes",
        }
    }
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

/// Split a `ferrowarden_uris` value into URIs.
pub fn split_uris(raw: &str) -> Vec<String> {
    raw.split([',', '\n', '\r'])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Whether the vault is usable, and for which account.
#[derive(Debug, Clone, PartialEq)]
pub struct VaultStatus {
    /// `unauthenticated`, `locked` or `unlocked`.
    pub status: String,
    /// Email of the logged-in account (absent when unauthenticated).
    pub user_email: Option<String>,
    /// Timestamp of the last sync with the server (RFC 3339 for the native
    /// backend; as bw serve reports it otherwise).
    pub last_sync: Option<String>,
}

/// Which items a sync left out because they could not be read safely, by
/// reason (a fixed code). Item ids are Bitwarden's random UUIDs, not names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExclusionReport {
    /// Reason code -> number of items.
    pub counts: std::collections::BTreeMap<&'static str, usize>,
    /// Up to [`ExclusionReport::MAX_IDS`] ids of excluded items.
    pub ids: Vec<String>,
}

impl ExclusionReport {
    pub const MAX_IDS: usize = 20;

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    pub fn total(&self) -> usize {
        self.counts.values().sum()
    }

    pub fn add(&mut self, reason: &'static str, id: &str) {
        *self.counts.entry(reason).or_default() += 1;
        if self.ids.len() < Self::MAX_IDS {
            self.ids.push(id.to_string());
        }
    }
}

/// What listing the vault's credentials produced.
#[derive(Debug, Default)]
pub struct Listing {
    pub map: CredentialMap,
    /// Set (once) when the native backend rebuilt its metadata and excluded
    /// items while doing so.
    pub excluded: Option<ExclusionReport>,
}
