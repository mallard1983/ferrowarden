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
//! 7. under the write lock: a fresh sync, the checks again, the value is
//!    generated, encrypted and written, and the cache is refreshed.
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

/// The body of `POST /v1/credentials/{name}/rotate`, as parsed. Unknown fields
/// are refused, and so is `null`. The whole body may be left out.
#[derive(Debug, Default)]
pub struct RotatePayload {
    pub generate: Option<GeneratePayload>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateFields {
    #[serde(default, deserialize_with = "some_not_null")]
    generate: Option<GeneratePayload>,
}

/// The body is a JSON object: serde would also read a struct from an array
/// (`[]`), which is not what a rotation takes.
impl<'de> Deserialize<'de> for RotatePayload {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Object;
        impl<'de> serde::de::Visitor<'de> for Object {
            type Value = RotateFields;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<RotateFields, A::Error> {
                RotateFields::deserialize(serde::de::value::MapAccessDeserializer::new(map))
            }
        }
        d.deserialize_map(Object).map(|f| RotatePayload {
            generate: f.generate,
        })
    }
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
    key: &'a str,
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
    pub fn fingerprint(&self, key_id: &str, item_id: &str, name: &str) -> String {
        let canonical = Canonical {
            kind: "rotate",
            key: key_id,
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
pub fn check_item<'a>(
    name: &str,
    entries: &'a [CredentialEntry],
    collection: &ManagedCollection,
) -> FerroResult<&'a CredentialEntry> {
    let entry = match entries {
        [] => return Err(FerroError::CredentialNotManaged(name.to_string())),
        [one] => one,
        _ => return Err(FerroError::AmbiguousCredential(name.to_string())),
    };
    if !entry.collection_ids.contains(&collection.id) {
        return Err(FerroError::CredentialNotManaged(name.to_string()));
    }
    if entry.kind != ItemKind::Login || !entry.has_password || entry.reprompt {
        return Err(FerroError::CredentialNotRotatable(name.to_string()));
    }
    Ok(entry)
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
    fresh(state).await?;
    let collection = self::collection(state, progress).await?;
    let entry = item(state, name, &collection, progress).await?;
    if entry.has_next {
        return Err(FerroError::RotationInProgress(name.to_string()));
    }

    let value = generate::generate(req.charset, req.length)?;
    // The value moves into the vault call and is wiped when it is dropped.
    state.vault.rotate_start(&entry.id, name, value).await?;
    refresh_after_write(state, progress).await;

    Ok(Started {
        name: name.to_string(),
        current: placeholder(name, Selector::Password),
        next: placeholder(name, Selector::Next),
    })
}

/// Commit or abort the pending rotation of `name`. An agent's policy applies;
/// an operator (`Who::Admin`) is checked against the managed collection only.
/// No approval: the start was approved.
pub async fn finish(
    state: &Arc<AppState>,
    who: Who<'_>,
    name: &str,
    how: Finish,
    progress: &mut Progress,
) -> FerroResult<Finished> {
    let result = finish_inner(state, who, name, how, progress).await;
    note_locked(state, &result).await;
    result
}

async fn finish_inner(
    state: &Arc<AppState>,
    who: Who<'_>,
    name: &str,
    how: Finish,
    progress: &mut Progress,
) -> FerroResult<Finished> {
    if let Who::Agent(agent) = who {
        check_policy(agent, name)?;
    }
    let collection = collection(state, progress).await?;

    // One write at a time, like a start: and the item is read afresh.
    let _one_at_a_time = state.create_lock.lock().await;
    fresh(state).await?;
    let entry = item(state, name, &collection, progress).await?;
    if !entry.has_next {
        return Err(FerroError::NoRotationPending(name.to_string()));
    }

    match how {
        Finish::Commit => state.vault.rotate_commit(&entry.id, name).await?,
        Finish::Abort => state.vault.rotate_abort(&entry.id, name).await?,
    }
    refresh_after_write(state, progress).await;

    Ok(Finished {
        name: name.to_string(),
        placeholder: placeholder(name, Selector::Password),
    })
}

#[cfg(test)]
mod tests;
