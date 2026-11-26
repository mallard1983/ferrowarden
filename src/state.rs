use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::error::FerroResult;
use crate::events::{Action, EventLog, SecurityEvent};
use crate::keys::hash_token;
use crate::net::TargetPolicy;
use crate::notify::NotifyHandle;
use crate::policy::KeyPolicy;
use crate::sessions::{DeleteCause, SessionStore};
use crate::vault::model::SyncStats;
use crate::vault::{ActiveVault, CredentialMap, Vault};

/// A single agent API key entry.
/// The token itself is never stored here — only metadata. The HashMap is
/// keyed by `sha256(token)`, so authentication hashes the incoming token
/// and does an O(1) lookup.
#[derive(Debug, Clone)]
pub struct AgentKey {
    pub id: String,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// What this key may do. A legacy key without a policy is deny-all.
    pub policy: KeyPolicy,
    /// False for a key loaded from a 0.1.0 key file that has no policy yet
    /// (it runs deny-all until a policy is set with PATCH).
    pub policy_set: bool,
}

/// Lock state of the vault.
#[derive(Debug, Clone, PartialEq)]
pub enum LockState {
    Locked,
    Unlocked,
}

/// Shared application state passed to every axum handler via Extension.
/// All mutable fields are behind RwLock — reads are cheap and concurrent,
/// writes (unlock, key rotation, cache refresh) are exclusive.
#[derive(Clone)]
pub struct AppState {
    pub config: Config,

    /// Current vault lock state. Handlers check this before any vault call.
    pub lock_state: Arc<RwLock<LockState>>,

    /// Active agent API keys, keyed by sha256(token) for O(1) auth lookup.
    /// Token plaintext is never stored — authentication hashes the incoming
    /// token and looks it up here.
    pub agent_keys: Arc<RwLock<HashMap<String, AgentKey>>>,

    /// The vault backend chosen at startup (`vault.backend`). Everything that
    /// reads the vault goes through it.
    pub vault: Arc<ActiveVault>,

    /// Credential cache — item names, ids, URIs and which values exist, from
    /// the vault backend. Refreshed on unlock and every
    /// `refresh_interval_secs`. Never holds credential values.
    pub credentials: Arc<RwLock<CredentialMap>>,

    /// Serializes read-modify-write cycles on the agent key file so that
    /// concurrent create/revoke calls cannot drop each other's changes.
    pub keys_file_lock: Arc<tokio::sync::Mutex<()>>,

    /// Serializes vault re-unlock attempts, so a burst of requests arriving
    /// while the vault is locked triggers one unlock, not one per request.
    pub unlock_lock: Arc<tokio::sync::Mutex<()>>,

    /// Outbound target policy (SSRF protection), built once from config.
    pub target_policy: Arc<TargetPolicy>,

    /// Security event stream (ring buffer + sinks) — the one emitter, also
    /// read by the admin audit endpoint.
    pub events: Arc<EventLog>,

    /// The push notifier: what is enabled, its counters and the test
    /// notification. Disabled until `main` starts it.
    pub notify: Arc<NotifyHandle>,

    /// When the vault was last synced and how many items it left out, for the
    /// metrics endpoint. Numbers only.
    pub sync_stats: Arc<SyncStats>,

    /// Captured login sessions (`{{session:NAME}}`), per agent key. In memory
    /// only: never written to disk, a restart empties it, and the vault
    /// locking clears it.
    pub sessions: Arc<SessionStore>,
}

impl AppState {
    /// The state for tests that do not need a real vault: backed by the
    /// in-memory [`FakeVault`](crate::vault::fake::FakeVault), which never
    /// connects anywhere. Test builds only; tests of the native backend build
    /// theirs with [`try_new`](Self::try_new).
    #[cfg(test)]
    pub fn new(config: Config, events: Arc<EventLog>) -> Self {
        let vault = ActiveVault::Fake(Default::default());
        Self::with_vault(config, events, vault)
    }

    /// Build the state, including the configured vault backend. Fails when the
    /// native backend's settings are unusable (unreadable CA file, no API key).
    pub fn try_new(config: Config, events: Arc<EventLog>) -> FerroResult<Self> {
        let vault = ActiveVault::from_config(&config)?;
        Ok(Self::with_vault(config, events, vault))
    }

    fn with_vault(config: Config, events: Arc<EventLog>, vault: ActiveVault) -> Self {
        let vault = Arc::new(vault);
        // Start locked regardless of unlock mode — unlock happens during
        // startup (file mode) or on first POST /v1/unlock (manual mode).
        let target_policy = Arc::new(TargetPolicy::from_config(&config));
        let notify = Arc::new(NotifyHandle::disabled(config.notify.categories()));
        Self {
            config,
            vault,
            lock_state: Arc::new(RwLock::new(LockState::Locked)),
            agent_keys: Arc::new(RwLock::new(HashMap::new())),
            credentials: Arc::new(RwLock::new(CredentialMap::new())),
            keys_file_lock: Arc::new(tokio::sync::Mutex::new(())),
            unlock_lock: Arc::new(tokio::sync::Mutex::new(())),
            target_policy,
            events,
            notify,
            sync_stats: Arc::new(SyncStats::default()),
            sessions: Arc::new(SessionStore::default()),
        }
    }

    /// Use `notify` as the notifier (the one `main` started).
    pub fn with_notify(mut self, notify: Arc<NotifyHandle>) -> Self {
        self.notify = notify;
        self
    }

    /// Load the persisted agent keys from `path` into the key ring. Returns
    /// how many of them have no policy (written by 0.1.0): those load as
    /// deny-all and are marked `policy_set: false`, so the operator can find
    /// them. A key file that is malformed, or has `null` or invalid policy
    /// values, is an error (startup fails closed).
    pub async fn load_keys(&self, path: &std::path::Path) -> std::io::Result<usize> {
        let stored = crate::keys::load(path)?;
        let mut without_policy = 0;
        let mut map = self.agent_keys.write().await;
        for k in stored {
            let policy = k.policy();
            let policy_set = k.policy_set();
            if !policy_set {
                without_policy += 1;
            }
            map.insert(
                k.token_hash,
                AgentKey {
                    id: k.id,
                    name: k.name,
                    created_at: k.created_at,
                    policy,
                    policy_set,
                },
            );
        }
        tracing::info!("Loaded {} agent key(s) from {:?}", map.len(), path);
        Ok(without_policy)
    }

    pub async fn is_locked(&self) -> bool {
        *self.lock_state.read().await == LockState::Locked
    }

    pub async fn set_unlocked(&self) {
        *self.lock_state.write().await = LockState::Unlocked;
    }

    /// Mark the vault locked. Emits a `vault_lock` event on the transition
    /// from unlocked only — repeated checks of an already-locked vault are
    /// silent. `cause` is a fixed code such as `vault_locked`. Locking also
    /// drops the backend's keys and the credential map.
    pub async fn set_locked(&self, cause: &'static str) {
        self.vault.lock().await;
        self.credentials.write().await.clear();
        // A captured session is a credential too: it does not outlive the
        // unlocked vault.
        crate::sessions::clear_all(self, DeleteCause::VaultLock);
        let was_unlocked = {
            let mut state = self.lock_state.write().await;
            let was_unlocked = *state == LockState::Unlocked;
            *state = LockState::Locked;
            was_unlocked
        };
        if was_unlocked {
            self.events
                .emit(SecurityEvent::new(Action::VaultLock).detail("cause", cause));
        }
    }

    /// Validate a bearer token and return the matching key entry if found.
    /// Hashes the token before lookup — never does a plaintext comparison.
    pub async fn authenticate(&self, token: &str) -> Option<AgentKey> {
        let hash = hash_token(token);
        let keys = self.agent_keys.read().await;
        keys.get(&hash).cloned()
    }

    /// Validate the admin key. Uses constant-time comparison.
    pub fn authenticate_admin(&self, token: &str) -> bool {
        constant_time_eq(self.config.admin_key.as_str(), token)
    }
}

/// Constant-time string comparison to prevent timing-based token enumeration.
/// Compares all bytes regardless of where a mismatch occurs.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();

    if a.len() != b.len() {
        return false;
    }

    // XOR each byte pair and OR the results — any mismatch sets a bit.
    // This runs in constant time for equal-length inputs.
    let result = a
        .iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    result == 0
}

#[cfg(test)]
mod tests;
