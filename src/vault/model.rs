//! What the rest of Ferrowarden knows about a vault item, whichever backend
//! supplies it: names, ids, URIs and which values exist. Never a value.

use zeroize::Zeroizing;

/// Name of the reserved custom field that lists a credential's host bindings
/// (comma- or newline-separated URIs). It provides bindings for secure notes
/// and overrides a login's URIs when present. Not offered as a selectable field.
pub const BINDINGS_FIELD: &str = "ferrowarden_uris";

/// Name of the reserved custom field that marks a credential as needing a
/// human's approval before it is used (docs/approvals.md). `required` says so;
/// any other value, an empty one included, also means required, so a typo can
/// only ever make a credential stricter. Not offered as a selectable field.
pub const APPROVAL_FIELD: &str = "ferrowarden_approval";

/// Is a custom field named `name` the approval field? Trimmed and in any
/// letter case, so a mistyped capital cannot silently drop the requirement.
pub fn is_approval_field_name(name: &str) -> bool {
    name.trim().eq_ignore_ascii_case(APPROVAL_FIELD)
}

/// What a `ferrowarden_approval` field says. Fail closed: only the value
/// `required` (trimmed, any letter case) is a clean spelling, and every
/// other value still means approval is required.
pub fn approval_field_valid(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("required")
}

/// Name of the reserved custom field that records which agent key created an
/// item (docs/managed-credentials.md). A plain text field, written when
/// Ferrowarden creates an item; shown like any other field.
pub const CREATED_BY_FIELD: &str = "ferrowarden_created_by";

/// Name of the reserved **hidden** custom field that holds the pending new
/// password of a rotation that has started and not yet been committed or
/// aborted (docs/managed-credentials.md). Written and removed only by
/// Ferrowarden's rotation; never offered as a `field:` placeholder (the
/// pending value is reached with `{{vault:NAME:next}}`) and never listed.
pub const NEXT_FIELD: &str = "ferrowarden_next";

/// Is `name` the reserved pending-rotation field? Compared trimmed and
/// case-insensitively, like [`APPROVAL_FIELD`], so a hand-typed variant is
/// still recognised (and not offered as an ordinary field).
pub fn is_next_field_name(name: &str) -> bool {
    name.trim().eq_ignore_ascii_case(NEXT_FIELD)
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
    /// The pending new password of a rotation (`{{vault:NAME:next}}`): the
    /// value of the reserved `ferrowarden_next` field.
    Next,
    Password,
    Username,
    /// The current one-time code, not the stored secret.
    Totp,
    Notes,
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
    /// Custom fields, excluding the reserved bindings and approval fields.
    pub fields: Vec<FieldInfo>,
    /// Master password re-prompt is enabled on the item.
    pub reprompt: bool,
    /// The item carries a `ferrowarden_approval` field: a human has to
    /// approve its use (whatever the field's value says: see
    /// [`APPROVAL_FIELD`]).
    pub approval_required: bool,
    /// The field's value is not `required`: it still means required, and the
    /// sync reports it as a warning so the operator can fix the spelling.
    pub approval_field_invalid: bool,
    /// A rotation has started and is waiting to be committed or aborted: the
    /// item has a `ferrowarden_next` field.
    pub has_next: bool,
    /// The collections the item is in (organisation items), as the sync lists
    /// them. A rotation is only ever done to an item in the managed one.
    pub collection_ids: Vec<String>,
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
            approval_required: false,
            approval_field_invalid: false,
            has_next: false,
            collection_ids: Vec::new(),
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
    /// backend).
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
    /// How many items the latest rebuild of the native backend's metadata
    /// left out. Unlike `excluded` it is reported on every
    /// listing, so a metric can fall back to 0 when the cause is fixed.
    pub excluded_count: usize,
}

/// What the refresher learned from the vault, for the metrics endpoint
/// (`ferrowarden_vault_last_sync_timestamp_seconds`,
/// `ferrowarden_vault_excluded_items`). Plain numbers, no names, no values.
#[derive(Debug, Default)]
pub struct SyncStats {
    /// Unix time of the last refresh whose sync and listing both succeeded;
    /// 0 until the first one.
    last_sync_unix: std::sync::atomic::AtomicI64,
    excluded: std::sync::atomic::AtomicU64,
    /// Items whose `ferrowarden_approval` value is not `required`, as of the
    /// last listing (to report a change once, not on every refresh).
    approval_invalid: std::sync::atomic::AtomicU64,
    /// The managed collection's problem code as of the last listing, to report
    /// a change once, not on every refresh.
    managed_problem: std::sync::Mutex<Option<&'static str>>,
}

impl SyncStats {
    pub fn record_success(&self, excluded: usize) {
        use std::sync::atomic::Ordering::Relaxed;
        self.excluded
            .store(u64::try_from(excluded).unwrap_or(u64::MAX), Relaxed);
        self.last_sync_unix
            .store(chrono::Utc::now().timestamp(), Relaxed);
    }

    pub fn last_sync_unix(&self) -> i64 {
        self.last_sync_unix
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record how many items carry a `ferrowarden_approval` field whose value
    /// is not `required`; returns the number before.
    pub fn swap_approval_invalid(&self, n: usize) -> u64 {
        self.approval_invalid.swap(
            u64::try_from(n).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        )
    }

    /// Record the managed collection's problem (`None`: usable or not
    /// configured); returns the one before.
    pub fn swap_managed_problem(&self, problem: Option<&'static str>) -> Option<&'static str> {
        std::mem::replace(
            &mut *self
                .managed_problem
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            problem,
        )
    }

    pub fn excluded(&self) -> u64 {
        self.excluded.load(std::sync::atomic::Ordering::Relaxed)
    }
}

// ── The managed collection (docs/managed-credentials.md) ──────────────────────

/// Why the managed collection cannot be written to right now. A fixed set:
/// the reason is shown to the operator and, as a code, to the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedProblem {
    /// No collection with that id or name in the account's sync.
    NotFound,
    /// The account has "View only" on the collection.
    ReadOnly,
    /// The account has "Hide passwords" on the collection.
    HidesPasswords,
    /// More than one collection has that name: use the id.
    Ambiguous,
    /// The collection's organisation key could not be unwrapped.
    NoOrganizationKey,
}

impl ManagedProblem {
    /// The fixed code.
    pub fn code(self) -> &'static str {
        match self {
            ManagedProblem::NotFound => "not_found",
            ManagedProblem::ReadOnly => "read_only",
            ManagedProblem::HidesPasswords => "hides_passwords",
            ManagedProblem::Ambiguous => "ambiguous_name",
            ManagedProblem::NoOrganizationKey => "no_organization_key",
        }
    }

    /// A sentence for the operator, the log and the agent.
    pub fn describe(self) -> &'static str {
        match self {
            ManagedProblem::NotFound => {
                "the managed collection was not found in the account's vault"
            }
            ManagedProblem::ReadOnly => {
                "the account has only view access to the managed collection (it needs Can edit)"
            }
            ManagedProblem::HidesPasswords => {
                "the managed collection hides passwords from the account (turn off Hide passwords)"
            }
            ManagedProblem::Ambiguous => {
                "more than one collection has the configured name; set the collection's id instead"
            }
            ManagedProblem::NoOrganizationKey => {
                "the managed collection's organisation key could not be read"
            }
        }
    }
}

/// The collection Ferrowarden may create items in: a collection the account
/// can edit and whose passwords it can see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedCollection {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    /// How many readable items of the vault are in it.
    pub items: usize,
}

/// Where `vault.managed.collection` stands, evaluated on every unlock and
/// sync.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ManagedState {
    /// Not configured: creating is off.
    #[default]
    Off,
    /// Configured and writable.
    Usable(ManagedCollection),
    /// Configured but not writable now. `setting` is what the operator wrote
    /// (an id or a name, not a secret).
    Unavailable {
        setting: String,
        problem: ManagedProblem,
    },
}

impl ManagedState {
    /// The status shown to the operator (admin API and UI): the collection's
    /// name and id and whether it is usable. No secrets.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            ManagedState::Off => serde_json::json!({ "configured": false, "usable": false }),
            ManagedState::Usable(c) => serde_json::json!({
                "configured": true,
                "usable": true,
                "id": c.id,
                "name": c.name,
                "items": c.items,
            }),
            ManagedState::Unavailable { setting, problem } => serde_json::json!({
                "configured": true,
                "usable": false,
                "setting": setting,
                "reason": problem.code(),
                "message": problem.describe(),
            }),
        }
    }
}

/// What the vault is asked to write as a new login item. The value is wiped
/// when dropped and never printed.
pub struct NewLogin {
    pub name: String,
    pub username: Option<String>,
    pub uris: Vec<String>,
    pub password: Zeroizing<String>,
    /// The agent key's name, recorded in the `ferrowarden_created_by` field.
    pub created_by: String,
    /// Add a `ferrowarden_approval = required` field.
    pub approval_required: bool,
}

impl std::fmt::Debug for NewLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewLogin")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}
