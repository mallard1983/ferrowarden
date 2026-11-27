//! The native vault backend: the Bitwarden client protocol and cryptography
//! implemented in Rust, directly against Vaultwarden (docs/native-vault.md).
//!
//! How it holds the vault:
//! - **Ciphertext at rest in memory.** A sync stores the items exactly as the
//!   server sent them ([`api::RawCipher`]: EncStrings and structure). Plain
//!   text exists only for the metadata Ferrowarden needs to decide whether a
//!   request may proceed (names, URIs, field names, which values exist).
//! - **Keys in `Zeroizing` buffers**, derived at unlock from the master
//!   password, which is wiped as soon as the user key is unwrapped.
//! - **Secrets are decrypted per request**, one value at a time, into a
//!   `Zeroizing<String>` that the caller drops. Nothing decrypted crosses the
//!   network, and there is no whole-item fetch to scrub.
//! - **Fail closed, per item**: see [`cipher`].
//!
//! Lifecycle: `unlock` logs in with the API key, syncs, derives the keys and
//! builds the metadata. `sync` (the refresher's tick) logs in again when the
//! token is about to expire, asks for the account revision, and fetches the
//! full vault only when it changed (and, as a safety net, periodically). A
//! changed user key or security stamp means a password change or key
//! rotation: the vault locks. `lock` drops every key and the metadata.

pub mod api;
pub mod cipher;
pub mod collections;
pub mod enc;
pub mod hardening;
pub mod keys;
pub mod rotate;
pub mod totp;
pub mod write;

use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

use self::api::{Api, ApiError, RawCipher, RawCollection, RawOrganization, Session, SyncResponse};
use self::cipher::{KeyRing, Keys};
use self::keys::{derive_user_key, load_rsa_key, unwrap_org_key, UnlockError};
use super::model::{
    Builtin, CredentialMap, ExclusionReport, Listing, ManagedProblem, ManagedState, NewLogin,
    VaultStatus,
};
use super::Vault;
use crate::config::Config;
use crate::error::{FerroError, FerroResult};

/// How long a full sync may be skipped while the revision date is unchanged,
/// as a multiple of the refresh interval.
const FULL_SYNC_EVERY_TICKS: u32 = 10;
/// ... but never more often than this.
const MIN_FULL_SYNC_INTERVAL: Duration = Duration::from_secs(300);
/// Bound on the status page's email lookup.
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);

/// A request that is retried once with a fresh login when the token is
/// rejected (API-key login returns no refresh token).
macro_rules! authed {
    ($self:ident, |$t:ident| $call:expr) => {{
        let first: Result<_, ApiError> = match $self.token(false).await {
            Ok($t) => $call.await,
            Err(e) => Err(e),
        };
        match first {
            Err(ApiError::Unauthorized) => match $self.token(true).await {
                Ok($t) => $call.await,
                Err(e) => Err(e),
            },
            other => other,
        }
    }};
}

/// Like [`authed!`], for a **write**: a login that fails means the write was
/// never sent (`ApiError::Refused`, nothing was applied), and a 401 is retried
/// once with a fresh login (the request was refused, not applied). Nothing
/// else is retried: a request that timed out may have been applied.
macro_rules! authed_write {
    ($self:ident, |$t:ident| $call:expr) => {{
        let first: Result<_, ApiError> = match $self.token(false).await {
            Ok($t) => $call.await,
            Err(_) => Err(ApiError::Refused),
        };
        match first {
            Err(ApiError::Unauthorized) => match $self.token(true).await {
                Ok($t) => $call.await,
                Err(_) => Err(ApiError::Refused),
            },
            other => other,
        }
    }};
}

/// Everything held while unlocked.
struct Unlocked {
    ring: KeyRing,
    /// Ciphertext of the supported, readable items by id.
    ciphers: HashMap<String, RawCipher>,
    /// What the rest of Ferrowarden sees.
    meta: CredentialMap,
    /// `profile.key` and `profile.securityStamp` at unlock: a change in either
    /// is a password change or key rotation.
    profile_key: String,
    security_stamp: Option<String>,
    /// Account revision date the current copy corresponds to.
    revision: String,
    email: String,
    /// The account's id, sent as `encryptedFor` when writing.
    user_id: Option<String>,
    /// `vault.managed.collection` as of the last sync: whether Ferrowarden
    /// may write, and where.
    managed: ManagedState,
    last_sync: DateTime<Utc>,
    last_full_sync: Instant,
    /// Exclusions from the last rebuild, handed out once.
    pending_report: Option<ExclusionReport>,
    /// How many items the last rebuild left out (kept, for the metrics).
    excluded_count: usize,
}

enum State {
    Locked,
    Unlocked(Box<Unlocked>),
}

pub struct NativeVault {
    api: Api,
    client_id: Zeroizing<String>,
    client_secret: Zeroizing<String>,
    /// Safety-net full sync period; `None` when the refresher is disabled.
    full_sync_every: Option<Duration>,
    /// `vault.allow_hidden_passwords`: keep items whose collection hides
    /// passwords from this account (refused by default).
    allow_hidden_passwords: bool,
    /// `vault.managed.collection`: the one collection Ferrowarden may create
    /// items in (`None`: creating is off).
    managed_setting: Option<String>,
    /// Serializes unlock, lock and sync: the state is only written by the
    /// holder, so a sync can read, work without holding the state lock, and
    /// swap the result in.
    gate: Mutex<()>,
    session: Mutex<Option<Session>>,
    state: RwLock<State>,
    /// The account email, once known (it never changes for an API key).
    email: StdMutex<Option<String>>,
    cause: StdMutex<&'static str>,
}

impl NativeVault {
    pub fn new(config: &Config) -> FerroResult<Self> {
        let creds = &config.vault.credentials;
        let (Some(id), Some(secret)) = (&creds.client_id, &creds.client_secret) else {
            return Err(FerroError::Config(
                "the native vault backend needs FERROWARDEN_VAULT_CLIENT_ID and \
                 FERROWARDEN_VAULT_CLIENT_SECRET"
                    .to_string(),
            ));
        };
        let api = Api::new(&config.vault.url, &config.vault.ca_file).map_err(FerroError::Config)?;
        let full_sync_every = (config.refresh_interval_secs > 0).then(|| {
            Duration::from_secs(config.refresh_interval_secs)
                .saturating_mul(FULL_SYNC_EVERY_TICKS)
                .max(MIN_FULL_SYNC_INTERVAL)
        });
        Ok(Self {
            api,
            client_id: id.clone(),
            client_secret: secret.clone(),
            full_sync_every,
            allow_hidden_passwords: config.vault.allow_hidden_passwords,
            managed_setting: config.vault.managed.setting().map(str::to_string),
            gate: Mutex::new(()),
            session: Mutex::new(None),
            state: RwLock::new(State::Locked),
            email: StdMutex::new(None),
            cause: StdMutex::new("vault_locked"),
        })
    }

    /// A bearer token, logging in when there is none or it is about to expire
    /// (`force`: it was just rejected).
    async fn token(&self, force: bool) -> Result<Zeroizing<String>, ApiError> {
        let mut session = self.session.lock().await;
        if !force {
            if let Some(s) = session.as_ref().filter(|s| s.is_fresh()) {
                return Ok(s.token.clone());
            }
        }
        let login = self.api.login(&self.client_id, &self.client_secret).await?;
        let token = login.session.token.clone();
        *session = Some(login.session);
        Ok(token)
    }

    #[cfg(test)]
    fn api_base_for_tests(&self) -> String {
        self.api.base().to_string()
    }

    fn set_cause(&self, cause: &'static str) {
        *self.cause.lock().unwrap_or_else(|e| e.into_inner()) = cause;
    }

    fn known_email(&self) -> Option<String> {
        self.email.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn remember_email(&self, email: &str) {
        *self.email.lock().unwrap_or_else(|e| e.into_inner()) = Some(email.to_string());
    }

    /// Drop every key and the metadata. The caller holds the gate.
    async fn lock_inner(&self, cause: &'static str) {
        self.set_cause(cause);
        *self.state.write().await = State::Locked;
        *self.session.lock().await = None;
    }

    /// Edit one item of the managed collection for a rotation: read it as it
    /// is now, work out the new item with [`rotate`], and write it back with
    /// the revision that was read. See [`rotate`] for what changes.
    ///
    /// Nothing outside the managed collection is ever written: the item must
    /// be in the collection and organisation of the evaluated managed state,
    /// both in the cached copy and in the copy read now. `label` (the
    /// credential's name) is only used in error messages.
    ///
    /// Returns the rotation id of the pending value after a start, and `None`
    /// after a commit or an abort.
    async fn rotate(&self, id: &str, label: &str, op: RotateOp<'_>) -> FerroResult<Option<String>> {
        // 1. The collection, and the cached copy must be in it.
        let (collection_id, organization_id) = {
            let guard = self.state.read().await;
            let State::Unlocked(u) = &*guard else {
                return Err(FerroError::VaultLocked);
            };
            let collection = managed_usable(&u.managed)?;
            let cached = u
                .ciphers
                .get(id)
                .ok_or_else(|| FerroError::CredentialNotFound(label.to_string()))?;
            if cached.organization_id.as_deref() != Some(collection.organization_id.as_str())
                || !cached.collection_ids.contains(&collection.id)
            {
                return Err(FerroError::CredentialNotManaged(label.to_string()));
            }
            (collection.id.clone(), collection.organization_id.clone())
        };

        // 2. The item as the server holds it now. The login (if one is due) is
        // done first, and the same token is used for the write, so that no
        // network call but the write itself lies between this read and the
        // write (docs/native-vault.md, "The window that remains").
        let mut token = self.token(false).await.map_err(api_error)?;
        let read = match self.api.get_cipher(&token, id).await {
            Err(ApiError::Unauthorized) => {
                token = self.token(true).await.map_err(api_error)?;
                self.api.get_cipher(&token, id).await
            }
            other => other,
        };
        let item = read.map_err(|e| match e {
            ApiError::NotFound => FerroError::VaultItemGone,
            other => api_error(other),
        })?;
        let revision = item
            .get("revisionDate")
            .and_then(serde_json::Value::as_str)
            .filter(|r| !r.is_empty())
            .map(str::to_string)
            .ok_or(FerroError::VaultWriteFailed)?;

        // 3. The new item, under the keys of the current state.
        let (body, started) = {
            let guard = self.state.read().await;
            let State::Unlocked(u) = &*guard else {
                return Err(FerroError::VaultLocked);
            };
            // The managed collection must be the one it was a moment ago.
            let collection = managed_usable(&u.managed)?;
            if collection.id != collection_id || collection.organization_id != organization_id {
                return Err(FerroError::CredentialNotManaged(label.to_string()));
            }
            let in_collection = item
                .get("collectionIds")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|ids| {
                    ids.iter()
                        .any(|c| c.as_str() == Some(collection_id.as_str()))
                });
            if item
                .get("organizationId")
                .and_then(serde_json::Value::as_str)
                != Some(organization_id.as_str())
                || !in_collection
            {
                return Err(FerroError::CredentialNotManaged(label.to_string()));
            }
            let org_key = u.ring.org.get(&organization_id).ok_or(
                FerroError::ManagedCollectionUnavailable(ManagedProblem::NoOrganizationKey),
            )?;
            let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
            let (mut body, started) = match op {
                RotateOp::Start(next) => rotate::start(&item, org_key, &revision, next)
                    .map(|(body, rotation_id)| (body, Some(rotation_id))),
                RotateOp::Commit(rotation_id) => {
                    rotate::commit(&item, org_key, &revision, &now, rotation_id)
                        .map(|body| (body, None))
                }
                RotateOp::Abort(rotation_id) => {
                    rotate::abort(&item, org_key, &revision, &now, rotation_id)
                        .map(|body| (body, None))
                }
            }
            .map_err(|e| rotate_error(e, label))?;
            // Vaultwarden 1.37 refuses a `PUT` without `encryptedFor`, which
            // the answer to a `GET` does not have: the account's own id, as
            // a create sends it.
            if let Some(user) = &u.user_id {
                body["encryptedFor"] = serde_json::json!(user);
            }
            (body, started)
        };

        // 4. Write it with the token the read used. A 401 is the server
        // refusing, not applying: it is retried once with a fresh login (the
        // only call that can lie after the read, and only after a refusal).
        // Nothing else is retried: a request that timed out may have been
        // applied.
        let written = match self.api.put_cipher(&token, id, &body).await {
            Err(ApiError::Unauthorized) => match self.token(true).await {
                Ok(fresh) => self.api.put_cipher(&fresh, id, &body).await,
                Err(_) => Err(ApiError::Refused),
            },
            other => other,
        };
        // A success status is the write applied, whatever the body says (it
        // is not read for anything).
        match written {
            Ok(_) => Ok(started),
            Err(e) => Err(write_error(e)),
        }
    }
}

/// A failed write, as the error the caller sees, saying exactly what is known:
/// a refused login (or a write that was never sent) changed nothing; anything
/// else that is not a clean answer may have been applied; a changed or deleted
/// item is a conflict.
fn write_error(e: ApiError) -> FerroError {
    tracing::warn!(error = ?e, "Writing to the vault failed");
    match e {
        ApiError::Conflict => FerroError::VaultConflict,
        ApiError::NotFound => FerroError::VaultItemGone,
        ApiError::Unauthorized | ApiError::Refused | ApiError::BadResponse => {
            FerroError::VaultWriteFailed
        }
        ApiError::RateLimited | ApiError::Unavailable => FerroError::VaultWriteUnknown,
    }
}

/// What a rotation does to an item.
enum RotateOp<'a> {
    /// Add the pending value (the plaintext, encrypted by [`rotate::start`]).
    Start(&'a str),
    /// Make the pending value the rotation id names the password.
    Commit(&'a str),
    /// Throw the pending value the rotation id names away (into the history).
    Abort(&'a str),
}

/// The usable managed collection, or the reason there is none.
fn managed_usable(managed: &ManagedState) -> FerroResult<&super::model::ManagedCollection> {
    match managed {
        ManagedState::Usable(c) => Ok(c),
        ManagedState::Unavailable { problem, .. } => {
            Err(FerroError::ManagedCollectionUnavailable(*problem))
        }
        ManagedState::Off => Err(FerroError::CredentialCreateDisabled),
    }
}

/// A rotation edit that could not be made, as the error the caller sees.
fn rotate_error(e: rotate::RotateError, label: &str) -> FerroError {
    use rotate::RotateError as E;
    match e {
        E::NotRotatable => FerroError::CredentialNotRotatable(label.to_string()),
        E::AlreadyPending => FerroError::RotationInProgress(label.to_string()),
        E::NoPending => FerroError::NoRotationPending(label.to_string()),
        // Something on the item needs a person: never guessed at.
        E::DuplicatePending | E::CorruptPending => FerroError::VaultConflict,
        E::RotationMismatch => FerroError::RotationMismatch(label.to_string()),
        E::PasswordChanged => FerroError::VaultPasswordChanged,
        E::Crypto(e) => {
            tracing::warn!(reason = e.code(), "A vault item could not be edited");
            FerroError::VaultWriteFailed
        }
    }
}

fn api_error(e: ApiError) -> FerroError {
    // Rejected credentials, rate limits, network trouble and bad bodies all
    // look the same to callers: the vault could not be reached usefully.
    let _ = e;
    FerroError::VaultUnavailable
}

/// Organisation keys: unwrap each with the RSA key. An organisation whose key
/// cannot be unwrapped is left out (its items are then excluded, by reason).
fn unwrap_orgs(
    rsa: Option<&enc::RsaKey>,
    orgs: &[RawOrganization],
) -> (HashMap<String, enc::SymKey>, usize) {
    let mut map = HashMap::new();
    let mut failed = 0;
    for o in orgs {
        let Some(wrapped) = o.key.as_deref() else {
            continue;
        };
        match rsa.map(|k| unwrap_org_key(k, wrapped)) {
            Some(Ok(key)) => {
                map.insert(o.id.clone(), key);
            }
            _ => failed += 1,
        }
    }
    (map, failed)
}

/// Decrypt the metadata of every readable item and keep the ciphertext of
/// those. Trashed and unsupported items are skipped silently; unreadable
/// ones are excluded and counted.
fn build_all(
    keys: &Keys<'_>,
    ciphers: Vec<RawCipher>,
    allow_hidden_passwords: bool,
) -> (HashMap<String, RawCipher>, CredentialMap, ExclusionReport) {
    let mut kept = HashMap::new();
    let mut meta = CredentialMap::new();
    let mut report = ExclusionReport::default();
    for c in ciphers {
        if c.deleted_date.is_some() || c.archived_date.is_some() || !cipher::is_supported_kind(&c) {
            continue;
        }
        // The owner of the collection chose to hide passwords from this
        // account: Ferrowarden would hand them to an agent. Refused unless
        // the operator opted in (`vault.allow_hidden_passwords`).
        if !allow_hidden_passwords && cipher::is_password_hidden(&c) {
            report.add(cipher::reason::HIDDEN_PASSWORD, &c.id);
            continue;
        }
        match cipher::build_metadata(keys, &c) {
            Ok((name, entry)) => {
                meta.entry(name).or_default().push(entry);
                kept.insert(c.id.clone(), c);
            }
            Err(reason) => report.add(reason, &c.id),
        }
    }
    (kept, meta, report)
}

/// The managed collection's state for this sync: the setting evaluated against
/// the collections, with how many of the kept items are in it.
fn managed_state(
    setting: Option<&str>,
    collections: &[RawCollection],
    org: &HashMap<String, enc::SymKey>,
    kept: &HashMap<String, RawCipher>,
) -> ManagedState {
    match collections::evaluate(setting, collections, org) {
        ManagedState::Usable(mut c) => {
            c.items = kept
                .values()
                .filter(|i| i.collection_ids.contains(&c.id))
                .count();
            ManagedState::Usable(c)
        }
        other => other,
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Vault for NativeVault {
    fn name(&self) -> &'static str {
        "native"
    }

    fn lock_cause(&self) -> &'static str {
        *self.cause.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn status(&self) -> FerroResult<VaultStatus> {
        if let State::Unlocked(u) = &*self.state.read().await {
            return Ok(VaultStatus {
                status: "unlocked".to_string(),
                user_email: Some(u.email.clone()),
                last_sync: Some(u.last_sync.to_rfc3339()),
            });
        }
        // Locked. The admin UI needs the account email before anyone has
        // unlocked: an API-key login can supply it without the master password.
        let email = match self.known_email() {
            Some(e) => e,
            None => {
                let fetched = tokio::time::timeout(STATUS_TIMEOUT, async {
                    authed!(self, |t| self.api.profile_email(&t))
                })
                .await
                .map_err(|_| FerroError::VaultUnavailable)?
                .map_err(api_error)?;
                self.remember_email(&fetched);
                fetched
            }
        };
        Ok(VaultStatus {
            status: "locked".to_string(),
            user_email: Some(email),
            last_sync: None,
        })
    }

    async fn unlock(&self, password: Zeroizing<String>) -> FerroResult<()> {
        let _gate = self.gate.lock().await;

        let login = self
            .api
            .login(&self.client_id, &self.client_secret)
            .await
            .map_err(|e| match e {
                ApiError::Unauthorized => {
                    FerroError::UnlockFailed("Vaultwarden rejected the API key".to_string())
                }
                other => api_error(other),
            })?;
        let token = login.session.token.clone();
        *self.session.lock().await = Some(login.session);
        let kdf = login.kdf.ok_or_else(|| {
            FerroError::UnlockFailed(
                "Vaultwarden did not report the key derivation settings".into(),
            )
        })?;

        // The revision is read before the sync, so a change in between is
        // noticed by the next check instead of being missed.
        let revision = self.api.revision_date(&token).await.map_err(api_error)?;
        let sync = self.api.sync(&token).await.map_err(api_error)?;
        let SyncResponse {
            profile,
            ciphers,
            collections,
        } = sync;
        let profile_key = profile
            .key
            .clone()
            .ok_or_else(|| FerroError::UnlockFailed("the account has no vault key".to_string()))?;
        self.remember_email(&profile.email);

        // The KDF is deliberately slow (Argon2id can use up to 1 GiB): off the
        // async threads. The password moves into the closure and is wiped
        // there.
        let (email, enc_key) = (profile.email.clone(), profile_key.clone());
        let user =
            tokio::task::spawn_blocking(move || derive_user_key(&password, &email, kdf, &enc_key))
                .await
                .map_err(|_| FerroError::Internal("key derivation task failed".to_string()))?
                .map_err(|e| match e {
                    UnlockError::BadPasswordOrKey => {
                        FerroError::UnlockFailed("Invalid master password.".to_string())
                    }
                    other => FerroError::UnlockFailed(other.to_string()),
                })?;

        let rsa = match profile.private_key.as_deref() {
            Some(pk) => match load_rsa_key(&user, pk) {
                Ok(k) => Some(k),
                Err(e) => {
                    tracing::warn!(reason = e.code(), "The account's RSA key could not be read; organisation items will be unavailable");
                    None
                }
            },
            None => None,
        };
        let (org, org_failed) = unwrap_orgs(rsa.as_ref(), &profile.organizations);
        if org_failed > 0 {
            tracing::warn!(
                organizations = org_failed,
                "Organisation keys could not be unwrapped; their items are unavailable"
            );
        }
        let ring = KeyRing { user, rsa, org };
        let (kept, meta, report) = build_all(&ring.view(), ciphers, self.allow_hidden_passwords);
        let managed = managed_state(
            self.managed_setting.as_deref(),
            &collections,
            &ring.org,
            &kept,
        );

        let now = Instant::now();
        *self.state.write().await = State::Unlocked(Box::new(Unlocked {
            ring,
            ciphers: kept,
            meta,
            profile_key,
            security_stamp: profile.security_stamp,
            revision,
            email: profile.email,
            user_id: profile.id,
            managed,
            last_sync: Utc::now(),
            last_full_sync: now,
            excluded_count: report.total(),
            pending_report: (!report.is_empty()).then_some(report),
        }));
        self.set_cause("vault_locked");
        Ok(())
    }

    async fn lock(&self) {
        let _gate = self.gate.lock().await;
        self.lock_inner("vault_locked").await;
    }

    async fn sync(&self) -> FerroResult<()> {
        let _gate = self.gate.lock().await;

        let (known_revision, due, profile_key, stamp) = match &*self.state.read().await {
            State::Locked => return Err(FerroError::VaultLocked),
            State::Unlocked(u) => (
                u.revision.clone(),
                self.full_sync_every
                    .is_some_and(|every| u.last_full_sync.elapsed() >= every),
                u.profile_key.clone(),
                u.security_stamp.clone(),
            ),
        };

        let revision = authed!(self, |t| self.api.revision_date(&t)).map_err(api_error)?;
        if revision == known_revision && !due {
            // Nothing changed: the copy in memory is current as of now.
            if let State::Unlocked(u) = &mut *self.state.write().await {
                u.last_sync = Utc::now();
            }
            return Ok(());
        }
        let SyncResponse {
            profile,
            ciphers,
            collections,
        } = authed!(self, |t| self.api.sync(&t)).map_err(api_error)?;

        if profile.key.as_deref() != Some(profile_key.as_str()) {
            self.lock_inner("vault_key_changed").await;
            return Err(FerroError::VaultLocked);
        }
        if profile.security_stamp != stamp {
            self.lock_inner("security_stamp_changed").await;
            return Err(FerroError::VaultLocked);
        }

        // Decrypt the metadata with the user key of the current state and the
        // organisation keys of this sync, without holding the write lock.
        let (org, org_failed, kept, meta, report, managed) = {
            let guard = self.state.read().await;
            let State::Unlocked(u) = &*guard else {
                return Err(FerroError::VaultLocked);
            };
            let (org, org_failed) = unwrap_orgs(u.ring.rsa.as_ref(), &profile.organizations);
            let keys = Keys {
                user: &u.ring.user,
                org: &org,
            };
            let (kept, meta, report) = build_all(&keys, ciphers, self.allow_hidden_passwords);
            let managed = managed_state(self.managed_setting.as_deref(), &collections, &org, &kept);
            (org, org_failed, kept, meta, report, managed)
        };
        if org_failed > 0 {
            tracing::warn!(
                organizations = org_failed,
                "Organisation keys could not be unwrapped; their items are unavailable"
            );
        }

        let mut guard = self.state.write().await;
        let State::Unlocked(u) = &mut *guard else {
            return Err(FerroError::VaultLocked);
        };
        u.ring.org = org;
        u.ciphers = kept;
        u.meta = meta;
        u.managed = managed;
        if profile.id.is_some() {
            u.user_id = profile.id;
        }
        u.revision = revision;
        u.last_sync = Utc::now();
        u.last_full_sync = Instant::now();
        u.excluded_count = report.total();
        u.pending_report = (!report.is_empty()).then_some(report);
        Ok(())
    }

    async fn list_credentials(&self) -> FerroResult<Listing> {
        let mut guard = self.state.write().await;
        let State::Unlocked(u) = &mut *guard else {
            return Err(FerroError::VaultLocked);
        };
        Ok(Listing {
            map: u.meta.clone(),
            excluded: u.pending_report.take(),
            excluded_count: u.excluded_count,
        })
    }

    async fn get_value(
        &self,
        value: Builtin,
        id: &str,
        label: &str,
    ) -> FerroResult<Zeroizing<String>> {
        let guard = self.state.read().await;
        let State::Unlocked(u) = &*guard else {
            return Err(FerroError::VaultLocked);
        };
        let c = u
            .ciphers
            .get(id)
            .ok_or_else(|| FerroError::CredentialNotFound(label.to_string()))?;
        cipher::builtin_value(&u.ring.view(), c, value, unix_now(), label)
    }

    async fn get_field(
        &self,
        id: &str,
        field: &str,
        label: &str,
    ) -> FerroResult<Zeroizing<String>> {
        let guard = self.state.read().await;
        let State::Unlocked(u) = &*guard else {
            return Err(FerroError::VaultLocked);
        };
        let c = u
            .ciphers
            .get(id)
            .ok_or_else(|| FerroError::CredentialNotFound(label.to_string()))?;
        cipher::field_value(&u.ring.view(), c, field, label)
    }

    async fn managed_collection(&self) -> FerroResult<ManagedState> {
        match &*self.state.read().await {
            State::Locked => Err(FerroError::VaultLocked),
            State::Unlocked(u) => Ok(u.managed.clone()),
        }
    }

    async fn create_login(&self, new: NewLogin) -> FerroResult<Option<String>> {
        // Encrypt under the keys of the current state, then let go of it for
        // the network call. The target is the evaluated managed collection and
        // nothing else: if it is not usable, nothing is written.
        let body = {
            let guard = self.state.read().await;
            let State::Unlocked(u) = &*guard else {
                return Err(FerroError::VaultLocked);
            };
            let collection = match &u.managed {
                ManagedState::Usable(collection) => collection,
                ManagedState::Unavailable { problem, .. } => {
                    return Err(FerroError::ManagedCollectionUnavailable(*problem));
                }
                ManagedState::Off => return Err(FerroError::CredentialCreateDisabled),
            };
            let org_key = u.ring.org.get(&collection.organization_id).ok_or(
                FerroError::ManagedCollectionUnavailable(ManagedProblem::NoOrganizationKey),
            )?;
            write::create_body(
                &write::Target {
                    organization_id: &collection.organization_id,
                    collection_id: &collection.id,
                    organization_key: org_key,
                    user_id: u.user_id.as_deref(),
                },
                &new,
            )
            .map_err(|e| {
                tracing::warn!(reason = e.code(), "A new vault item could not be encrypted");
                FerroError::VaultWriteFailed
            })?
        };
        // See `authed_write!`. `None` is an item that was created whose id the
        // answer did not give: the caller syncs afterwards anyway.
        authed_write!(self, |t| self.api.create_cipher(&t, &body)).map_err(write_error)
    }

    async fn rotate_start(
        &self,
        id: &str,
        label: &str,
        next: Zeroizing<String>,
    ) -> FerroResult<String> {
        self.rotate(id, label, RotateOp::Start(next.as_str()))
            .await?
            .ok_or(FerroError::VaultWriteFailed)
    }

    async fn rotate_commit(&self, id: &str, label: &str, rotation_id: &str) -> FerroResult<()> {
        self.rotate(id, label, RotateOp::Commit(rotation_id))
            .await
            .map(|_| ())
    }

    async fn rotate_abort(&self, id: &str, label: &str, rotation_id: &str) -> FerroResult<()> {
        self.rotate(id, label, RotateOp::Abort(rotation_id))
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests;
