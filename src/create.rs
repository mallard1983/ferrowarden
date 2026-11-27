//! Creating a credential (`POST /v1/credentials`, docs/managed-credentials.md).
//!
//! An agent asks Ferrowarden to make a new credential: a name, a username, the
//! URIs it is for and how to generate its password. Ferrowarden generates the
//! value, encrypts it and writes it into the **managed collection**, and
//! answers with a placeholder. **The value never reaches the agent**: it is
//! generated here, encrypted in `vault::native::write` and sent to the vault;
//! the response, the events, the logs and the metrics carry names and codes
//! only.
//!
//! The order is fixed, every check before any prompt, every prompt before any
//! generation or write ([`run`]):
//!
//! 1. the agent key (the handler), the strict body and every field
//!    ([`CreatePayload::validate`]), the URIs against the outbound target
//!    policy (the handler);
//! 2. the key's `create` patterns match the name;
//! 3. creating is on and the managed collection is usable;
//! 4. a fresh sync, and the name must not exist anywhere in the vault;
//! 5. **a human approves this one operation** ([`crate::approvals::gate_create`]);
//! 6. under the create lock: the name is checked again, the value is
//!    generated, encrypted and written, and the cache is refreshed.
//!
//! Nothing outside the managed collection is ever written: the vault backend
//! takes the target from its own evaluated managed-collection state, never
//! from the request.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::approvals::{self, CreateDetail};
use crate::error::{FerroError, FerroResult};
use crate::generate::{self, Charset};
use crate::middleware::request_context::RequestContext;
use crate::policy::some_not_null;
use crate::proxy::placeholder::{self, Placeholder, Selector, Token};
use crate::state::{AgentKey, AppState};
use crate::vault::model::{ManagedState, NewLogin};
use crate::vault::refresh::{refresh_credentials, reunlock_if_possible};
use crate::vault::Vault;

/// Longest credential name, in characters.
pub const MAX_NAME_CHARS: usize = 128;
/// Longest username, in characters.
pub const MAX_USERNAME_CHARS: usize = 256;
/// Most URIs on one credential.
pub const MAX_URIS: usize = 16;
/// Longest URI, in characters.
pub const MAX_URI_CHARS: usize = 2048;

// ── The request ───────────────────────────────────────────────────────────────

/// The body of `POST /v1/credentials`, as parsed. Unknown fields are refused,
/// and so is `null` for every field that is given (leave it out instead).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePayload {
    pub name: String,
    #[serde(default, deserialize_with = "some_not_null")]
    pub username: Option<String>,
    pub uris: Vec<String>,
    pub generate: GeneratePayload,
    #[serde(default, deserialize_with = "some_not_null")]
    pub approval_required: Option<bool>,
}

/// `generate` of the body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratePayload {
    #[serde(default, deserialize_with = "some_not_null")]
    pub length: Option<u64>,
    #[serde(default, deserialize_with = "some_not_null")]
    pub charset: Option<String>,
}

/// A validated create request: every field checked, defaults filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRequest {
    pub name: String,
    pub username: Option<String>,
    /// As sent, in the order sent.
    pub uris: Vec<String>,
    pub charset: Charset,
    pub length: u32,
    pub approval_required: bool,
}

fn invalid(text: impl Into<String>) -> FerroError {
    FerroError::InvalidRequest(text.into())
}

/// A name or username must have no control characters (newlines included).
fn no_controls(field: &str, text: &str) -> FerroResult<()> {
    if text.chars().any(char::is_control) {
        return Err(invalid(format!(
            "`{field}` may not contain control characters"
        )));
    }
    Ok(())
}

/// Can `name` be written as a `{{vault:...}}` placeholder and read back as
/// the same name? A plain word is, and so is any other text in single quotes;
/// this checks it by doing exactly that, with the placeholder parser.
fn referenceable(name: &str) -> bool {
    let rendered = Placeholder {
        item: name.to_string(),
        selector: Selector::Password,
    }
    .render();
    match placeholder::scan(&rendered).as_deref() {
        Ok([one]) => {
            one.start == 0
                && one.end == rendered.len()
                && matches!(
                    &one.token,
                    Token::Vault(p) if p.item == name && p.selector == Selector::Password
                )
        }
        _ => false,
    }
}

impl CreatePayload {
    /// Check every field and fill in the defaults. Does not look at the
    /// vault, the key's policy or the target policy (the caller does: the URIs
    /// are returned parsed for that).
    pub fn validate(self) -> FerroResult<(CreateRequest, Vec<reqwest::Url>)> {
        // Name.
        let name = self.name;
        let chars = name.chars().count();
        if chars == 0 || chars > MAX_NAME_CHARS || name.trim().is_empty() {
            return Err(invalid(format!(
                "`name` must be 1-{MAX_NAME_CHARS} characters"
            )));
        }
        no_controls("name", &name)?;
        if !referenceable(&name) {
            return Err(invalid(
                "`name` cannot be written as a {{vault:...}} placeholder; choose another",
            ));
        }

        // Username.
        if let Some(u) = &self.username {
            let chars = u.chars().count();
            if chars == 0 || chars > MAX_USERNAME_CHARS {
                return Err(invalid(format!(
                    "`username` must be 1-{MAX_USERNAME_CHARS} characters (leave it out for none)"
                )));
            }
            no_controls("username", u)?;
        }

        // URIs.
        if self.uris.is_empty() || self.uris.len() > MAX_URIS {
            return Err(invalid(format!(
                "`uris` must list 1-{MAX_URIS} URLs the credential is for"
            )));
        }
        let mut parsed = Vec::new();
        for (i, uri) in self.uris.iter().enumerate() {
            if uri.chars().count() > MAX_URI_CHARS || uri.chars().any(char::is_control) {
                return Err(invalid(format!(
                    "uris[{i}]: at most {MAX_URI_CHARS} characters, without control characters"
                )));
            }
            let url = reqwest::Url::parse(uri)
                .map_err(|_| invalid(format!("uris[{i}] is not an absolute URL")))?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(invalid(format!("uris[{i}] must be an http or https URL")));
            }
            if url.host_str().is_none() {
                return Err(invalid(format!("uris[{i}] has no host")));
            }
            if !url.username().is_empty() || url.password().is_some() {
                return Err(invalid(format!(
                    "uris[{i}] may not contain a username or password"
                )));
            }
            if self.uris[..i].contains(uri) {
                return Err(invalid(format!("uris[{i}] is listed twice")));
            }
            parsed.push(url);
        }

        // Generation options.
        let length = match self.generate.length {
            None => generate::DEFAULT_LENGTH,
            Some(n) => u32::try_from(n)
                .map_err(|_| invalid("`generate.length` is out of range"))
                .and_then(generate::check_length)?,
        };
        let charset = match self.generate.charset.as_deref() {
            None => Charset::default(),
            Some(c) => Charset::parse(c).ok_or_else(|| {
                invalid(format!(
                    "`generate.charset` must be one of {}",
                    Charset::ALL.map(Charset::as_str).join(", ")
                ))
            })?,
        };

        Ok((
            CreateRequest {
                name,
                username: self.username,
                uris: self.uris,
                charset,
                length,
                approval_required: self.approval_required.unwrap_or(false),
            },
            parsed,
        ))
    }
}

/// What a fingerprint is made of, in a fixed order.
#[derive(Serialize)]
struct Canonical<'a> {
    key: &'a str,
    name: &'a str,
    username: Option<&'a str>,
    uris: Vec<&'a str>,
    charset: &'a str,
    length: u32,
    approval_required: bool,
}

impl CreateRequest {
    /// The URIs, sorted.
    pub fn sorted_uris(&self) -> Vec<String> {
        let mut uris = self.uris.clone();
        uris.sort();
        uris
    }

    /// Identifies this one operation for the approval: a SHA-256 over the agent
    /// key's id, the name, the username, the **sorted** URIs, the generation
    /// options and the approval flag. The same request from the same key has
    /// the same fingerprint (the URIs in any order); change any field, or ask
    /// from another key, and it differs.
    pub fn fingerprint(&self, key_id: &str) -> String {
        let uris = self.sorted_uris();
        let canonical = Canonical {
            key: key_id,
            name: &self.name,
            username: self.username.as_deref(),
            uris: uris.iter().map(String::as_str).collect(),
            charset: self.charset.as_str(),
            length: self.length,
            approval_required: self.approval_required,
        };
        // A struct of strings, numbers and booleans always serializes.
        let text = serde_json::to_string(&canonical).unwrap_or_default();
        Sha256::digest(text.as_bytes())
            .iter()
            .fold(String::with_capacity(64), |mut out, b| {
                use std::fmt::Write;
                let _ = write!(out, "{b:02x}");
                out
            })
    }

    /// What the approval shows the human, with the collection it will go to.
    pub fn detail(&self, collection: &str) -> CreateDetail {
        CreateDetail {
            name: self.name.clone(),
            username: self.username.clone(),
            uris: self.sorted_uris(),
            charset: self.charset.as_str().to_string(),
            length: self.length,
            approval_required: self.approval_required,
            collection: collection.to_string(),
        }
    }
}

// ── The flow ──────────────────────────────────────────────────────────────────

/// What a create request learned on the way, for its event.
#[derive(Debug, Default)]
pub struct Progress {
    /// The managed collection, once it is known to be usable.
    pub collection_id: Option<String>,
}

/// The answer to a create request: names only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Created {
    pub name: String,
    /// `{{vault:...}}`, ready to use (quoted when the name needs it).
    pub placeholder: String,
    /// False when the item was written but the credential cache could not be
    /// refreshed: the placeholder works once the next refresh has run.
    pub cache_refreshed: bool,
}

/// Sync with the vault, so that what is checked next is not stale. A sync that
/// fails is an error here (unlike a background refresh, which falls back to
/// its cached copy): a name must not be checked against a copy that may be old.
pub(crate) async fn fresh(state: &AppState) -> FerroResult<()> {
    match state.vault.sync().await {
        Ok(()) => {}
        Err(FerroError::VaultLocked) => return Err(FerroError::VaultLocked),
        Err(_) => return Err(FerroError::VaultUnavailable),
    }
    refresh_credentials(state).await
}

/// `409` when any vault item already has this name (any collection, or none).
async fn ensure_absent(state: &AppState, name: &str) -> FerroResult<()> {
    if state.credentials.read().await.contains_key(name) {
        return Err(FerroError::CredentialExists(name.to_string()));
    }
    Ok(())
}

/// Run a validated request for `agent` up to and including the write. See the
/// module documentation for the order. `Err` leaves nothing written, except
/// when the write itself failed (the vault decides what it kept).
pub async fn run(
    state: &Arc<AppState>,
    agent: &AgentKey,
    ctx: &RequestContext,
    req: &CreateRequest,
    progress: &mut Progress,
) -> FerroResult<Created> {
    let result = run_inner(state, agent, ctx, req, progress).await;
    if let Err(FerroError::VaultLocked) = &result {
        // The vault locked behind our back: say so, like a forward does.
        state.set_locked(state.vault.lock_cause()).await;
    }
    result
}

async fn run_inner(
    state: &Arc<AppState>,
    agent: &AgentKey,
    ctx: &RequestContext,
    req: &CreateRequest,
    progress: &mut Progress,
) -> FerroResult<Created> {
    // 2. The key's own permission. It is independent of the key's credential
    // and method lists.
    if !agent.policy.allows_create(&req.name) {
        return Err(FerroError::CredentialCreateOutOfScope(req.name.clone()));
    }

    // 3. On, and somewhere to write. In file mode a locked vault is unlocked
    // again first, like a listing does.
    if state.is_locked().await && !reunlock_if_possible(state).await {
        return Err(FerroError::VaultLocked);
    }
    let collection = match state.vault.managed_collection().await? {
        ManagedState::Off => return Err(FerroError::CredentialCreateDisabled),
        ManagedState::Unavailable { problem, .. } => {
            tracing::warn!(
                reason = problem.code(),
                "A credential was requested but the managed collection cannot be written to"
            );
            return Err(FerroError::ManagedCollectionUnavailable(problem));
        }
        ManagedState::Usable(c) => c,
    };
    progress.collection_id = Some(collection.id.clone());

    // 4. The name must be free, checked against a fresh copy.
    fresh(state).await?;
    ensure_absent(state, &req.name).await?;

    // 5. A human approves this one operation. Nothing has been generated.
    approvals::gate_create(
        state,
        agent,
        ctx,
        &req.fingerprint(&agent.id),
        &req.detail(&collection.name),
    )
    .await?;

    // 6. One create at a time from here: of two requests for one name that
    // were both approved, the second sees the first's item and gets 409.
    let _one_at_a_time = state.create_lock.lock().await;
    // The key's permission as it is now: the request may have waited a long
    // time for the human and for the lock, and the key may have been revoked
    // or narrowed since (nothing is written then).
    let live = state
        .live_key(&agent.id)
        .await
        .ok_or(FerroError::Unauthorized)?;
    if !live.policy.allows_create(&req.name) {
        return Err(FerroError::CredentialCreateOutOfScope(req.name.clone()));
    }
    fresh(state).await?;
    ensure_absent(state, &req.name).await?;

    let value = generate::generate(req.charset, req.length)?;
    let new = NewLogin {
        name: req.name.clone(),
        username: req.username.clone(),
        uris: req.uris.clone(),
        password: value,
        created_by: agent.name.clone(),
        approval_required: req.approval_required,
    };
    // The value moves into the vault call and is wiped when it is dropped.
    if let Err(e) = state.vault.create_login(new).await {
        if matches!(e, FerroError::VaultWriteUnknown) {
            // It may have been applied: bring the cache up to date, so that the
            // agent's listing (and a retry's 409) show what is really there.
            if let Err(e) = refresh_credentials(state).await {
                tracing::warn!(error = %e, "The cache could not be refreshed after a write of unknown outcome");
            }
        }
        return Err(e);
    }

    // The write is done. A cache that cannot be refreshed does not undo it.
    let cache_refreshed = match refresh_credentials(state).await {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(error = %e, "The credential was created but the cache could not be refreshed");
            false
        }
    };
    Ok(Created {
        name: req.name.clone(),
        placeholder: Placeholder {
            item: req.name.clone(),
            selector: Selector::Password,
        }
        .render(),
        cache_refreshed,
    })
}

#[cfg(test)]
mod tests;
