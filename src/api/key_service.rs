//! The one implementation of every agent-key operation.
//!
//! The JSON admin API (`api::admin`) and the admin web UI (`ui`) both call the
//! functions here, so validation, the key-file lock, persist-before-memory
//! ordering and the security events behave identically whichever door the
//! operator came through. The only difference an event carries is
//! `ferrowarden.details.via` (`"api"` or `"ui"`), so a SIEM can tell them apart.
//!
//! Nothing here reads a credential value, and no event or log line ever
//! contains a token: [`create_key`] hands the token back to the caller, which
//! must show it once and drop it.

use axum::http::StatusCode;
use chrono::Utc;
use rand::RngExt;
use serde::Serialize;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::api::credentials::{visible_details, CredentialDetail};
use crate::api::forward::check_only;
use crate::approvals::{self, ApprovalNeed, ClearCause, Reasons};
use crate::error::{FerroError, FerroResult};
use crate::events::{Action, Outcome, Reason, SecurityEvent};
use crate::keys::{hash_token, load, save, StoredKey};
use crate::middleware::request_context::RequestContext;
use crate::policy::{KeyPolicy, Patch};
use crate::proxy::forward::ProxyRequest;
use crate::state::{AgentKey, AppState};

/// Which front door an operation came through. Recorded on every event as
/// `ferrowarden.details.via`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Api,
    Ui,
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Api => "api",
            Via::Ui => "ui",
        }
    }
}

/// Who is asking: the request (for the request id and source IP on events)
/// and the front door.
#[derive(Clone, Copy)]
pub struct Caller<'a> {
    pub ctx: &'a RequestContext,
    pub via: Via,
}

impl Caller<'_> {
    /// A new event of `action` with the request context and `via` attached.
    pub(crate) fn event(&self, action: Action) -> SecurityEvent {
        SecurityEvent::new(action)
            .request(self.ctx)
            .detail("via", self.via.as_str())
    }
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct CreateKeyResponse {
    pub id: String,
    pub name: String,
    /// The token value — shown only once at creation, never stored in plaintext.
    pub token: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub credentials: Vec<String>,
    pub methods: Vec<String>,
    /// Credential patterns that need a human's approval for this key.
    pub approval: Vec<String>,
    pub policy_set: bool,
}

#[derive(Serialize)]
pub struct KeySummary {
    pub id: String,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Credential patterns the key may use (`["*"]` = all, `[]` = none).
    pub credentials: Vec<String>,
    /// Methods the key may use (`["*"]` = all, `[]` = none).
    pub methods: Vec<String>,
    /// Credential patterns that need a human's approval for this key
    /// (`["*"]` = every credential, `[]` = no extra requirement).
    pub approval: Vec<String>,
    /// False for a key created with 0.1.0 that has no policy yet: it is
    /// deny-all until one is set with PATCH.
    pub policy_set: bool,
}

impl KeySummary {
    fn new(k: &AgentKey) -> Self {
        Self {
            id: k.id.clone(),
            name: k.name.clone(),
            created_at: k.created_at,
            credentials: k.policy.credentials.clone(),
            methods: k.policy.methods.clone(),
            approval: k.policy.approval.clone(),
            policy_set: k.policy_set,
        }
    }
}

/// What a policy change did, for the response and the audit event.
pub struct PolicyChange {
    pub summary: KeySummary,
    pub name: String,
    pub before: KeyPolicy,
    pub after: KeyPolicy,
}

/// The answer of a policy preview.
pub struct Preview {
    pub key: KeySummary,
    pub saved: KeyPolicy,
    pub draft: KeyPolicy,
    /// What the draft reaches, with ready-made placeholders (never values).
    pub credentials: Vec<CredentialDetail>,
    pub gained: Vec<String>,
    pub lost: Vec<String>,
    /// The credentials the draft reaches that would need a human's approval,
    /// and why (the vault item's field, the draft's `approval` patterns, or
    /// both).
    pub approval_required: Vec<ApprovalNeed>,
    /// Present only if a request was supplied.
    pub request_check: Option<RequestCheck>,
}

/// The verdict on one request checked against a draft policy.
pub struct RequestCheck {
    pub allowed: bool,
    pub status: Option<u16>,
    pub reason: Option<Reason>,
    pub message: Option<String>,
    /// When allowed: the request's credentials that would need approval. A
    /// preview never asks for one.
    pub approval: Vec<ApprovalNeed>,
}

/// The one check a preview cannot run: it never resolves or connects.
pub const DNS_NOTE: &str = "The target host is checked against the outbound policy by name and IP literal only; private-address checks on resolved DNS names happen when a request is actually forwarded.";

impl Preview {
    /// The JSON body of `POST /v1/admin/keys/{id}/preview`.
    pub fn to_json(&self) -> Value {
        let mut body = json!({
            "key": { "id": self.key.id, "name": self.key.name, "policy_set": self.key.policy_set },
            "saved_policy": self.saved.to_json(),
            "draft_policy": self.draft.to_json(),
            "credentials": self.credentials,
            "gained": self.gained,
            "lost": self.lost,
            "approval_required": self
                .approval_required
                .iter()
                .map(ApprovalNeed::to_json)
                .collect::<Vec<_>>(),
        });
        if let Some(check) = &self.request_check {
            body["request_check"] = if check.allowed {
                json!({
                    "allowed": true,
                    "approval": check.approval.iter().map(ApprovalNeed::to_json).collect::<Vec<_>>(),
                    "note": DNS_NOTE,
                })
            } else {
                json!({
                    "allowed": false,
                    "status": check.status,
                    "reason": check.reason,
                    "message": check.message,
                    "note": DNS_NOTE,
                })
            };
        }
        body
    }

    /// Does saving the draft give the key more access than it has now? True
    /// if it reaches credentials the saved policy does not, allows more
    /// methods, or has a pattern the saved patterns do not cover (which could
    /// reach credentials added to the vault later).
    pub fn widens(&self) -> bool {
        !self.gained.is_empty() || self.saved.is_widened_by(&self.draft)
    }
}

// ── Create ────────────────────────────────────────────────────────────────────

/// Create a key. Emits `key_create`. The returned token is the only copy.
pub async fn create_key(
    state: &Arc<AppState>,
    caller: Caller<'_>,
    name: &str,
    credentials: Vec<String>,
    methods: Vec<String>,
    approval: Vec<String>,
) -> FerroResult<CreateKeyResponse> {
    match create_key_inner(state, name, credentials, methods, approval).await {
        Ok(created) => {
            // The token itself never leaves the response: only id + name.
            state.events.emit(
                caller
                    .event(Action::KeyCreate)
                    .status(StatusCode::CREATED.as_u16())
                    .detail("key_id", created.id.as_str())
                    .detail_str("key_name", &created.name)
                    .detail("credentials", created.credentials.clone())
                    .detail("methods", created.methods.clone())
                    .detail("approval", created.approval.clone()),
            );
            Ok(created)
        }
        Err(e) => {
            state.events.emit(
                caller
                    .event(Action::KeyCreate)
                    .failed_with(&e)
                    .status(e.status_code().as_u16()),
            );
            Err(e)
        }
    }
}

async fn create_key_inner(
    state: &Arc<AppState>,
    name: &str,
    credentials: Vec<String>,
    methods: Vec<String>,
    approval: Vec<String>,
) -> FerroResult<CreateKeyResponse> {
    let id = Uuid::new_v4().to_string();
    let token = generate_token();
    let token_hash = hash_token(&token);
    let now = Utc::now();

    let name = name.trim().to_string();
    if name.is_empty() || name.len() > 128 {
        return Err(FerroError::InvalidRequest(
            "name must be 1-128 characters".to_string(),
        ));
    }

    let policy = KeyPolicy::from_raw(credentials, methods, approval)?;

    // Serialize key-file updates: without this, two concurrent creates (or a
    // create and a revoke) can each read the old file and drop the other's change.
    let _guard = state.keys_file_lock.lock().await;

    // Persist first. If the write fails, the key is never activated, so the
    // caller is not left with an error response for a token that still works.
    if let Some(ref path) = state.config.keys_file {
        let mut stored = load(path)
            .map_err(|e| FerroError::Internal(format!("Failed to read key file: {e}")))?;
        stored.push(StoredKey::new(
            id.clone(),
            name.clone(),
            token_hash.clone(),
            now,
            &policy,
        ));
        save(path, &stored)
            .map_err(|e| FerroError::Internal(format!("Failed to write key file: {e}")))?;
    }

    // Insert into in-memory map keyed by hash — plaintext never stored
    state.agent_keys.write().await.insert(
        token_hash,
        AgentKey {
            id: id.clone(),
            name: name.clone(),
            created_at: now,
            policy: policy.clone(),
            policy_set: true,
        },
    );

    tracing::info!(agent_id = %id, agent_name = %name, "Agent key created");

    Ok(CreateKeyResponse {
        id,
        name,
        // Return the raw token once — the caller must store it
        token,
        created_at: now,
        credentials: policy.credentials,
        methods: policy.methods,
        approval: policy.approval,
        policy_set: true,
    })
}

// ── List and get ──────────────────────────────────────────────────────────────

/// Every key, unsorted. Emits `key_list`. Token values are never returned.
pub async fn list_keys(state: &Arc<AppState>, caller: Caller<'_>) -> Vec<KeySummary> {
    let keys = state.agent_keys.read().await;
    let summaries: Vec<KeySummary> = keys.values().map(KeySummary::new).collect();
    drop(keys);
    state.events.emit(
        caller
            .event(Action::KeyList)
            .status(200)
            .detail("count", summaries.len()),
    );
    summaries
}

/// One key by id (no event: reading it reveals nothing `list_keys` does not).
pub async fn get_key(state: &Arc<AppState>, id: &str) -> FerroResult<KeySummary> {
    state
        .agent_keys
        .read()
        .await
        .values()
        .find(|k| k.id == id)
        .map(KeySummary::new)
        .ok_or(FerroError::AgentKeyNotFound)
}

// ── Revoke ────────────────────────────────────────────────────────────────────

/// Revoke the key; returns its name. Emits `key_revoke`.
pub async fn revoke_key(
    state: &Arc<AppState>,
    caller: Caller<'_>,
    id: &str,
) -> FerroResult<String> {
    match revoke_key_inner(state, id).await {
        Ok(name) => {
            state.events.emit(
                caller
                    .event(Action::KeyRevoke)
                    .status(200)
                    .detail_str("key_id", id)
                    .detail_str("key_name", &name),
            );
            Ok(name)
        }
        Err(e) => {
            state.events.emit(
                caller
                    .event(Action::KeyRevoke)
                    // AgentKeyNotFound maps to reason `key_not_found`.
                    .failed_with(&e)
                    .status(e.status_code().as_u16())
                    .detail_str("key_id", id),
            );
            Err(e)
        }
    }
}

async fn revoke_key_inner(state: &Arc<AppState>, id: &str) -> FerroResult<String> {
    let _guard = state.keys_file_lock.lock().await;

    let name = state
        .agent_keys
        .read()
        .await
        .values()
        .find(|k| k.id == id)
        .map(|k| k.name.clone())
        .ok_or(FerroError::AgentKeyNotFound)?;

    // Rewrite the key file without the revoked entry first, so a failed write
    // is reported before the in-memory state diverges from disk.
    if let Some(ref path) = state.config.keys_file {
        let stored = load(path)
            .map_err(|e| FerroError::Internal(format!("Failed to read key file: {e}")))?;
        let remaining: Vec<_> = stored.into_iter().filter(|k| k.id != id).collect();
        save(path, &remaining)
            .map_err(|e| FerroError::Internal(format!("Failed to write key file: {e}")))?;
    }

    // Revoke in memory — takes effect for the very next request.
    state.agent_keys.write().await.retain(|_, k| k.id != id);
    // The key's captured sessions go with it, and so do its open approvals
    // and grants.
    crate::sessions::clear_key(state, id, crate::sessions::DeleteCause::KeyRevoke);
    approvals::clear_key(state, id, ClearCause::KeyRevoke);

    tracing::info!(agent_id = %id, "Agent key revoked");

    Ok(name)
}

// ── Patch ─────────────────────────────────────────────────────────────────────

/// Replace the policy fields that are present; fields left out are unchanged.
/// Emits `key_policy_change`.
pub async fn patch_key(
    state: &Arc<AppState>,
    caller: Caller<'_>,
    id: &str,
    credentials: Patch<Vec<String>>,
    methods: Patch<Vec<String>>,
    approval: Patch<Vec<String>>,
) -> FerroResult<PolicyChange> {
    match patch_key_inner(state, id, credentials, methods, approval).await {
        Ok(change) => {
            state.events.emit(
                caller
                    .event(Action::KeyPolicyChange)
                    .status(200)
                    .detail_str("key_id", id)
                    .detail_str("key_name", &change.name)
                    .detail("before", change.before.to_json())
                    .detail("after", change.after.to_json()),
            );
            Ok(change)
        }
        Err(e) => {
            state.events.emit(
                caller
                    .event(Action::KeyPolicyChange)
                    .failed_with(&e)
                    .status(e.status_code().as_u16())
                    .detail_str("key_id", id),
            );
            Err(e)
        }
    }
}

async fn patch_key_inner(
    state: &Arc<AppState>,
    id: &str,
    credentials: Patch<Vec<String>>,
    methods: Patch<Vec<String>>,
    approval: Patch<Vec<String>>,
) -> FerroResult<PolicyChange> {
    if credentials.is_absent() && methods.is_absent() && approval.is_absent() {
        return Err(FerroError::InvalidRequest(
            "nothing to change: send `credentials`, `methods` and/or `approval`".to_string(),
        ));
    }

    let _guard = state.keys_file_lock.lock().await;

    let (name, before) = state
        .agent_keys
        .read()
        .await
        .values()
        .find(|k| k.id == id)
        .map(|k| (k.name.clone(), k.policy.clone()))
        .ok_or(FerroError::AgentKeyNotFound)?;
    // Absent fields keep the current value; on a legacy key that is deny-all.
    let after = before.patched(credentials, methods, approval)?;

    // Persist first, so a failed write leaves memory and disk consistent. The
    // entry is saved with both fields explicit, which also marks a legacy key
    // as having a policy.
    if let Some(ref path) = state.config.keys_file {
        let mut stored = load(path)
            .map_err(|e| FerroError::Internal(format!("Failed to read key file: {e}")))?;
        let entry = stored
            .iter_mut()
            .find(|k| k.id == id)
            // The key is in memory but not on disk: the two have diverged
            // (e.g. the file was edited by hand). Fail loudly rather than
            // report "not found" for a key that is in use.
            .ok_or_else(|| {
                FerroError::Internal("Agent key is loaded but missing from the key file".into())
            })?;
        entry.set_policy(&after);
        save(path, &stored)
            .map_err(|e| FerroError::Internal(format!("Failed to write key file: {e}")))?;
    }

    let mut keys = state.agent_keys.write().await;
    let mut summary = None;
    for key in keys.values_mut().filter(|k| k.id == id) {
        key.policy = after.clone();
        key.policy_set = true;
        summary.get_or_insert_with(|| KeySummary::new(key));
    }
    drop(keys);
    // A policy change ends the key's captured sessions: what was captured
    // under the old policy is not carried into the new one.
    crate::sessions::clear_key(state, id, crate::sessions::DeleteCause::KeyPolicyChange);
    // So do the key's open approvals and grants: what a human allowed under
    // the old policy is asked again under the new one.
    approvals::clear_key(state, id, ClearCause::KeyPolicyChange);

    tracing::info!(agent_id = %id, "Agent key policy changed");

    Ok(PolicyChange {
        summary: summary.ok_or(FerroError::AgentKeyNotFound)?,
        name,
        before,
        after,
    })
}

// ── Preview ───────────────────────────────────────────────────────────────────

/// Show what a draft policy would allow, without saving anything, reading any
/// credential value or sending anything. Emits `policy_preview`.
pub async fn preview_key(
    state: &Arc<AppState>,
    caller: Caller<'_>,
    id: &str,
    credentials: Patch<Vec<String>>,
    methods: Patch<Vec<String>>,
    approval: Patch<Vec<String>>,
    request: Option<&ProxyRequest>,
) -> FerroResult<Preview> {
    match compute_preview(state, id, credentials, methods, approval, request).await {
        Ok(preview) => {
            state.events.emit(
                caller
                    .event(Action::PolicyPreview)
                    .status(200)
                    .detail_str("key_id", id)
                    .detail_str("key_name", &preview.key.name)
                    .detail("request_checked", request.is_some()),
            );
            Ok(preview)
        }
        Err(e) => {
            state.events.emit(
                caller
                    .event(Action::PolicyPreview)
                    .failed_with(&e)
                    .status(e.status_code().as_u16())
                    .detail_str("key_id", id),
            );
            Err(e)
        }
    }
}

/// [`preview_key`] without the event: for callers that need the diff as a
/// step of another operation (the UI's "confirm a widening save" page).
pub async fn compute_preview(
    state: &Arc<AppState>,
    id: &str,
    credentials: Patch<Vec<String>>,
    methods: Patch<Vec<String>>,
    approval: Patch<Vec<String>>,
    request: Option<&ProxyRequest>,
) -> FerroResult<Preview> {
    let key = state
        .agent_keys
        .read()
        .await
        .values()
        .find(|k| k.id == id)
        .cloned()
        .ok_or(FerroError::AgentKeyNotFound)?;
    let saved = key.policy.clone();
    // Absent fields fall back to the saved value.
    let draft = saved.patched(credentials, methods, approval)?;

    // Like GET /v1/credentials, but a locked vault is fine while a credential
    // cache exists: only names and metadata are used, never values.
    if state.is_locked().await
        && state.credentials.read().await.is_empty()
        && !crate::vault::refresh::reunlock_if_possible(state).await
    {
        return Err(FerroError::VaultLocked);
    }
    let credentials = state.credentials.read().await.clone();

    let details = visible_details(&credentials, &draft);
    let mut gained = Vec::new();
    let mut lost = Vec::new();
    for name in credentials.keys() {
        match (saved.allows_credential(name), draft.allows_credential(name)) {
            (false, true) => gained.push(name.clone()),
            (true, false) => lost.push(name.clone()),
            _ => {}
        }
    }

    // The credentials the draft reaches that would need approval: the vault
    // item's field, the draft's patterns, or both.
    let approval_required: Vec<ApprovalNeed> = credentials
        .iter()
        .filter(|(name, _)| draft.allows_credential(name))
        .filter_map(|(name, entries)| {
            let reasons = Reasons {
                vault_field: entries.iter().any(|e| e.approval_required),
                key_policy: draft.requires_approval(name),
            };
            reasons.any().then(|| ApprovalNeed {
                item: name.clone(),
                reasons,
            })
        })
        .collect();

    let request_check = match request {
        None => None,
        Some(request) => Some(match check_only(state, &draft, request).await {
            Ok(approval) => RequestCheck {
                allowed: true,
                status: None,
                reason: None,
                message: None,
                approval,
            },
            Err(e) => RequestCheck {
                allowed: false,
                status: Some(e.status_code().as_u16()),
                reason: Some(Reason::from(&e)),
                message: Some(e.to_string()),
                approval: Vec::new(),
            },
        }),
    };

    Ok(Preview {
        key: KeySummary::new(&key),
        saved,
        draft,
        credentials: details,
        gained,
        lost,
        approval_required,
        request_check,
    })
}

// ── Audit ─────────────────────────────────────────────────────────────────────

/// Which events to return from the ring buffer. All set fields must match.
#[derive(Debug, Default, Clone)]
pub struct AuditFilter {
    pub action: Option<Action>,
    pub outcome: Option<Outcome>,
    /// A key id or name, exact.
    pub key: Option<String>,
    pub ip: Option<IpAddr>,
}

impl AuditFilter {
    pub fn is_empty(&self) -> bool {
        self.action.is_none() && self.outcome.is_none() && self.key.is_none() && self.ip.is_none()
    }

    fn matches(&self, e: &SecurityEvent) -> bool {
        self.action.is_none_or(|a| e.event.action == a)
            && self.outcome.is_none_or(|o| e.event.outcome == o)
            && self.key.as_ref().is_none_or(|k| {
                e.ferrowarden
                    .key
                    .as_ref()
                    .is_some_and(|ki| &ki.id == k || &ki.name == k)
            })
            && self
                .ip
                .is_none_or(|ip| e.source.as_ref().is_some_and(|s| s.ip == ip))
    }
}

/// The newest `limit` events that match `filter`, newest first. Emits
/// `audit_read` after the snapshot, so a read does not list itself.
pub fn read_audit(
    state: &Arc<AppState>,
    caller: Caller<'_>,
    limit: usize,
    filter: &AuditFilter,
) -> Vec<Arc<SecurityEvent>> {
    let events: Vec<Arc<SecurityEvent>> = if filter.is_empty() {
        state.events.recent(limit)
    } else {
        state
            .events
            .recent(state.events.capacity())
            .into_iter()
            .filter(|e| filter.matches(e))
            .take(limit)
            .collect()
    };
    let mut event = caller
        .event(Action::AuditRead)
        .status(200)
        .detail("limit", limit)
        .detail("count", events.len());
    if !filter.is_empty() {
        event = event.detail("filtered", true);
    }
    state.events.emit(event);
    events
}

/// Generate a cryptographically random 48-character alphanumeric token.
fn generate_token() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..48)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}
