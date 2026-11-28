//! Rotating a credential's password in two phases (`POST
//! /v1/credentials/{name}/rotate`, `.../commit`, `.../abort`,
//! docs/managed-credentials.md).
//!
//! A password cannot be changed in the vault and at the service it belongs to
//! in one step, and doing it in the wrong order locks the service out. So the
//! rotation has two phases, and the old password is never lost:
//!
//! 1. **Start** ([`start`]): after a human approves it, Ferrowarden generates
//!    a new password and stores it on the item as a pending value (the
//!    reserved hidden field `ferrowarden_next`). `{{vault:NAME}}` is still the
//!    current password and `{{vault:NAME:next}}` is the new one. The agent
//!    changes the password at the service, signing in with one and sending
//!    the other, all through Ferrowarden.
//! 2. **Finish**: [`commit`] makes the pending value the password (the old
//!    one goes to the item's password history), or [`abort`] throws it away.
//!    Neither needs a second approval: the approval of the start covered the
//!    rotation.
//!
//! **The value never reaches the agent**: it is generated here, encrypted in
//! `vault::native::rotate` and sent to the vault; the responses, the events,
//! the logs and the metrics carry names and codes only.
//!
//! **Only items in the managed collection are ever changed**, and only
//! logins that have a password, no master password re-prompt and a name that
//! matches the key's `rotate` patterns. Every check comes before any prompt,
//! every prompt before any generation or write ([`start`]):
//!
//! 1. the agent key (the handler), the strict body ([`RotatePayload`]);
//! 2. the key's `rotate` patterns match the name, and the name is in the
//!    key's `credentials` scope (a name outside it gets the same answer as a
//!    name that does not exist, so this is no existence oracle);
//! 3. rotating is on and the managed collection is usable;
//! 4. a fresh sync, and the item checks ([`check_item`]);
//! 5. no rotation is pending on the item already;
//! 6. **a human approves this one operation** ([`crate::approvals::gate_rotate`]);
//! 7. under the write lock: a fresh sync, the checks again (and the item must
//!    be **the one that was approved**: the approval named its id, and an item
//!    with another id, though it has the same name, is `vault_conflict`, with
//!    nothing written), the value is generated, encrypted and written, and the
//!    cache is refreshed.
//!
//! **A finish names what it finishes.** A start answers with a `rotation_id`,
//! an opaque identifier of exactly that rotation (random, kept on
//! the item). A commit or an abort must send it, and the write happens only
//! if the pending value found on the item now has that id: a replayed or
//! stale request cannot finish a rotation it did not start
//! (`rotation_mismatch`).
//!
//! Every write sends the revision of the item that was read, and a change a
//! person made in between makes it fail (`vault_conflict`): it is never
//! overwritten.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::approvals::{self, RotateDetail};
use crate::create::{fresh, GeneratePayload};
use crate::error::{FerroError, FerroResult};
use crate::generate::{self, Charset};
use crate::middleware::request_context::RequestContext;
use crate::policy::some_not_null;
use crate::proxy::placeholder::{Placeholder, Selector};
use crate::state::{AgentKey, AppState};
use crate::vault::model::{CredentialEntry, ItemKind, ManagedCollection, ManagedState};
use crate::vault::refresh::{refresh_credentials, reunlock_if_possible};
use crate::vault::Vault;

// ── The request ───────────────────────────────────────────────────────────────

/// The body of `POST /v1/credentials/{name}/rotate`. Unknown fields are
/// refused, and so is `null`; the whole body may be left out. (That a request
/// body is a JSON object is checked for every route by
/// [`parse_request`](crate::api::strict_json::parse_request).)
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotatePayload {
    #[serde(default, deserialize_with = "some_not_null")]
    pub generate: Option<GeneratePayload>,
}

/// A validated rotate request: the options checked, the defaults filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateRequest {
    pub charset: Charset,
    pub length: u32,
}

impl RotatePayload {
    /// Check the generation options and fill in the defaults (the same rules
    /// and defaults as a create).
    pub fn validate(self) -> FerroResult<RotateRequest> {
        let generate = self.generate.unwrap_or(GeneratePayload {
            length: None,
            charset: None,
        });
        let length = match generate.length {
            None => generate::DEFAULT_LENGTH,
            Some(n) => u32::try_from(n)
                .map_err(|_| FerroError::InvalidRequest("`generate.length` is out of range".into()))
                .and_then(generate::check_length)?,
        };
        let charset = match generate.charset.as_deref() {
            None => Charset::default(),
            Some(c) => Charset::parse(c).ok_or_else(|| {
                FerroError::InvalidRequest(format!(
                    "`generate.charset` must be one of {}",
                    Charset::ALL.map(Charset::as_str).join(", ")
                ))
            })?,
        };
        Ok(RotateRequest { charset, length })
    }
}

/// What a fingerprint is made of, in a fixed order.
#[derive(Serialize)]
struct Canonical<'a> {
    kind: &'static str,
    agent: &'a str,
    item: &'a str,
    name: &'a str,
    charset: &'a str,
    length: u32,
}

impl RotateRequest {
    /// Identifies this one operation for the approval: a SHA-256 over the
    /// agent key's id, the item's id, its name and the generation options. The
    /// same request from the same key for the same item has the same
    /// fingerprint; change any of them, or ask from another key, or for
    /// another item that happens to have the name, and it differs.
    pub fn fingerprint(&self, agent_id: &str, item_id: &str, name: &str) -> String {
        let canonical = Canonical {
            kind: "rotate",
            agent: agent_id,
            item: item_id,
            name,
            charset: self.charset.as_str(),
            length: self.length,
        };
        // A struct of strings and numbers always serializes.
        let text = serde_json::to_string(&canonical).unwrap_or_default();
        Sha256::digest(text.as_bytes())
            .iter()
            .fold(String::with_capacity(64), |mut out, b| {
                use std::fmt::Write;
                let _ = write!(out, "{b:02x}");
                out
            })
    }

    /// What the approval shows the human, with the collection the item is in.
    pub fn detail(&self, name: &str, collection: &str) -> RotateDetail {
        RotateDetail {
            name: name.to_string(),
            collection: collection.to_string(),
            charset: self.charset.as_str().to_string(),
            length: self.length,
        }
    }
}

// ── The item checks ───────────────────────────────────────────────────────────

/// Which item is meant, and what the item must be, for any phase (§2 of the
/// design: the managed collection, one item, a login with a password and no
/// re-prompt). `entries` are the vault items with this name. The answer for
/// "not in the managed collection" is the same whether the name exists
/// somewhere else or not at all.
///
/// The order matters: **membership first**. A name with no item in the managed
/// collection is `credential_not_managed` however many items elsewhere share
/// it, so the answer never says that an item outside the collection exists.
/// Only when the collection has the name is a second item of that name (in it
/// or out of it) `AmbiguousCredential`: that is not an oracle, because an
/// in-scope name's existence and its ambiguity are already visible to the
/// key in `GET /v1/credentials`, and a name outside the key's `credentials`
/// scope never gets here ([`check_policy`] answers it first, as a missing
/// name).
pub fn check_item<'a>(
    name: &str,
    entries: &'a [CredentialEntry],
    collection: &ManagedCollection,
) -> FerroResult<&'a CredentialEntry> {
    let mut managed = entries
        .iter()
        .filter(|e| e.collection_ids.contains(&collection.id));
    let Some(entry) = managed.next() else {
        return Err(FerroError::CredentialNotManaged(name.to_string()));
    };
    if managed.next().is_some() || entries.len() > 1 {
        return Err(FerroError::AmbiguousCredential(name.to_string()));
    }
    if entry.kind != ItemKind::Login || !entry.has_password || entry.reprompt {
        return Err(FerroError::CredentialNotRotatable(name.to_string()));
    }
    Ok(entry)
}

/// The rotation id an **operator's abort** of `name` would name, when that
/// abort would be accepted: the item passes [`check_item`] (one item with the
/// name, in the managed collection, a login with a password and no re-prompt),
/// has a rotation pending, and the pending value can be named (exactly one
/// pending field, with a value). The admin UI shows its Abort button only for
/// such items, with this id in the form.
pub fn abortable_rotation<'a>(
    name: &str,
    entries: &'a [CredentialEntry],
    collection: &ManagedCollection,
) -> Option<&'a str> {
    check_item(name, entries, collection)
        .ok()
        .filter(|entry| entry.has_next)
        .and_then(|entry| entry.rotation_id.as_deref())
}

// ── The answers ───────────────────────────────────────────────────────────────

/// The answer to a start: names and placeholders only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Started {
    pub name: String,
    /// `{{vault:NAME}}`: still the current password.
    pub current: String,
    /// `{{vault:NAME:next}}`: the new password, until it is committed.
    pub next: String,
    /// Identifies exactly this rotation (a random identifier). A commit and an
    /// abort must send it back.
    pub rotation_id: String,
}

/// The body of a commit or an abort: the rotation it finishes, as the start
/// (or the detailed listing) named it. Strict: nothing else is accepted.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishPayload {
    pub rotation_id: String,
}

/// The longest `rotation_id` accepted: ours is 22 characters.
pub const MAX_ROTATION_ID_CHARS: usize = 64;

impl FinishPayload {
    /// The id, checked to be the shape of one (it is compared, never used to
    /// size or build anything).
    pub fn validate(self) -> FerroResult<String> {
        let id = self.rotation_id;
        if id.is_empty()
            || id.len() > MAX_ROTATION_ID_CHARS
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(FerroError::InvalidRequest(
                "`rotation_id` must be the rotation_id the start returned".into(),
            ));
        }
        Ok(id)
    }
}

/// The answer to a commit or an abort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finished {
    pub name: String,
    /// `{{vault:NAME}}`: the password (the new one after a commit).
    pub placeholder: String,
}

/// What a rotate request learned on the way, for its event.
#[derive(Debug, Default)]
pub struct Progress {
    /// The managed collection, once it is known to be usable.
    pub collection_id: Option<String>,
    /// The vault item, once it is known.
    pub item_id: Option<String>,
    /// False when the item was written but the credential cache could not be
    /// refreshed (the next refresh catches up).
    pub cache_refreshed: Option<bool>,
}

fn placeholder(name: &str, selector: Selector) -> String {
    Placeholder {
        item: name.to_string(),
        selector,
    }
    .render()
}

/// Who asks: an agent key (its policy applies), or an operator (the admin API
/// or the admin UI), who may only abort.
#[derive(Clone, Copy)]
pub enum Who<'a> {
    Agent(&'a AgentKey),
    Admin,
}

/// Which finishing step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
    Commit,
    Abort,
}

// ── The flow ──────────────────────────────────────────────────────────────────

/// The managed collection, with a locked vault unlocked again first in file
/// mode like a listing does.
async fn collection(
    state: &Arc<AppState>,
    progress: &mut Progress,
) -> FerroResult<ManagedCollection> {
    if state.is_locked().await && !reunlock_if_possible(state).await {
        return Err(FerroError::VaultLocked);
    }
    match state.vault.managed_collection().await? {
        ManagedState::Off => Err(FerroError::CredentialCreateDisabled),
        ManagedState::Unavailable { problem, .. } => {
            tracing::warn!(
                reason = problem.code(),
                "A rotation was requested but the managed collection cannot be written to"
            );
            Err(FerroError::ManagedCollectionUnavailable(problem))
        }
        ManagedState::Usable(c) => {
            progress.collection_id = Some(c.id.clone());
            Ok(c)
        }
    }
}

/// The checked item named `name`, from the cache as it is now.
async fn item(
    state: &AppState,
    name: &str,
    collection: &ManagedCollection,
    progress: &mut Progress,
) -> FerroResult<CredentialEntry> {
    let credentials = state.credentials.read().await;
    let entries = credentials.get(name).map_or(&[][..], Vec::as_slice);
    let entry = check_item(name, entries, collection)?.clone();
    progress.item_id = Some(entry.id.clone());
    Ok(entry)
}

/// The key's own permissions for `name`: the `rotate` patterns, then the
/// `credentials` scope (a name outside it is answered like a name that does
/// not exist).
fn check_policy(agent: &AgentKey, name: &str) -> FerroResult<()> {
    if !agent.policy.allows_rotate(name) {
        return Err(FerroError::CredentialRotateOutOfScope(name.to_string()));
    }
    if !agent.policy.allows_credential(name) {
        return Err(FerroError::CredentialNotManaged(name.to_string()));
    }
    Ok(())
}

/// The same checks as [`check_policy`] on the key as it is **now**: a key that
/// was revoked in the meantime is refused like an unknown key.
async fn recheck_agent(state: &AppState, agent: &AgentKey, name: &str) -> FerroResult<()> {
    let live = state
        .live_key(&agent.id)
        .await
        .ok_or(FerroError::Unauthorized)?;
    check_policy(&live, name)
}

/// A vault that locked behind our back is said to be locked, like a forward
/// does.
async fn note_locked<T>(state: &Arc<AppState>, result: &FerroResult<T>) {
    if let Err(FerroError::VaultLocked) = result {
        state.set_locked(state.vault.lock_cause()).await;
    }
}

/// The cache is refreshed after a write; a refresh that fails does not undo it.
async fn refresh_after_write(state: &AppState, progress: &mut Progress) {
    progress.cache_refreshed = Some(match refresh_credentials(state).await {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(error = %e, "The credential was rotated but the cache could not be refreshed");
            false
        }
    });
}

/// A write whose outcome is not known may have been applied: the cache is
/// brought up to date, so that the listing the agent is told to read
/// (`rotation_pending`, `rotation_id`) shows what is really there.
async fn refresh_if_unknown(state: &AppState, e: &FerroError) {
    if matches!(e, FerroError::VaultWriteUnknown) {
        if let Err(e) = refresh_credentials(state).await {
            tracing::warn!(error = %e, "The cache could not be refreshed after a write of unknown outcome");
        }
    }
}

/// Start a rotation for `agent`, up to and including the write of the pending
/// value. See the module documentation for the order. `Err` leaves nothing
/// written, except when the write itself failed (the vault decides what it
/// kept).
pub async fn start(
    state: &Arc<AppState>,
    agent: &AgentKey,
    ctx: &RequestContext,
    name: &str,
    req: &RotateRequest,
    progress: &mut Progress,
) -> FerroResult<Started> {
    let result = start_inner(state, agent, ctx, name, req, progress).await;
    note_locked(state, &result).await;
    result
}

async fn start_inner(
    state: &Arc<AppState>,
    agent: &AgentKey,
    ctx: &RequestContext,
    name: &str,
    req: &RotateRequest,
    progress: &mut Progress,
) -> FerroResult<Started> {
    // 2. The key's own permission.
    check_policy(agent, name)?;

    // 3. On, and an item in the managed collection to rotate.
    let collection = collection(state, progress).await?;

    // 4. The item, from a fresh copy. 5. Nothing pending on it.
    fresh(state).await?;
    let entry = item(state, name, &collection, progress).await?;
    if entry.has_next {
        return Err(FerroError::RotationInProgress(name.to_string()));
    }

    // 6. A human approves this one operation. Nothing has been generated.
    let approved_item = entry.id.clone();
    approvals::gate_rotate(
        state,
        agent,
        ctx,
        &req.fingerprint(&agent.id, &entry.id, name),
        &req.detail(name, &collection.name),
    )
    .await?;

    // 7. One write at a time from here: the item is checked again against a
    // fresh copy, so that whatever happened while the request waited for the
    // human is seen.
    let _one_at_a_time = state.create_lock.lock().await;
    // The key's permission as it is now (it may have been revoked or narrowed
    // while the request waited for the human and the lock): nothing is written
    // then.
    recheck_agent(state, agent, name).await?;
    fresh(state).await?;
    let collection = self::collection(state, progress).await?;
    let entry = item(state, name, &collection, progress).await?;
    // The human approved one item, named by its id. Another item that has the
    // name now is not what was approved.
    if entry.id != approved_item {
        return Err(FerroError::VaultItemReplaced);
    }
    if entry.has_next {
        return Err(FerroError::RotationInProgress(name.to_string()));
    }

    let value = generate::generate(req.charset, req.length)?;
    // The value moves into the vault call and is wiped when it is dropped.
    let rotation_id = match state.vault.rotate_start(&entry.id, name, value).await {
        Ok(id) => id,
        Err(e) => {
            refresh_if_unknown(state, &e).await;
            return Err(e);
        }
    };
    refresh_after_write(state, progress).await;

    Ok(Started {
        name: name.to_string(),
        current: placeholder(name, Selector::Password),
        next: placeholder(name, Selector::Next),
        rotation_id,
    })
}

/// Commit or abort the pending rotation of `name` that `rotation_id` names. An
/// agent's policy applies; an operator (`Who::Admin`) is checked against the
/// managed collection only. No approval: the start was approved.
pub async fn finish(
    state: &Arc<AppState>,
    who: Who<'_>,
    name: &str,
    how: Finish,
    rotation_id: &str,
    progress: &mut Progress,
) -> FerroResult<Finished> {
    let result = finish_inner(state, who, name, how, rotation_id, progress).await;
    note_locked(state, &result).await;
    result
}

async fn finish_inner(
    state: &Arc<AppState>,
    who: Who<'_>,
    name: &str,
    how: Finish,
    rotation_id: &str,
    progress: &mut Progress,
) -> FerroResult<Finished> {
    if let Who::Agent(agent) = who {
        check_policy(agent, name)?;
    }
    let collection = collection(state, progress).await?;

    // One write at a time, like a start: and the item is read afresh.
    let _one_at_a_time = state.create_lock.lock().await;
    if let Who::Agent(agent) = who {
        recheck_agent(state, agent, name).await?;
    }
    fresh(state).await?;
    let entry = item(state, name, &collection, progress).await?;
    if !entry.has_next {
        return Err(FerroError::NoRotationPending(name.to_string()));
    }

    let written = match how {
        Finish::Commit => {
            state
                .vault
                .rotate_commit(&entry.id, name, rotation_id)
                .await
        }
        Finish::Abort => state.vault.rotate_abort(&entry.id, name, rotation_id).await,
    };
    if let Err(e) = written {
        refresh_if_unknown(state, &e).await;
        return Err(e);
    }
    refresh_after_write(state, progress).await;

    Ok(Finished {
        name: name.to_string(),
        placeholder: placeholder(name, Selector::Password),
    })
}

#[cfg(test)]
mod tests;
