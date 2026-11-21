use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::events::{Action, EventLog, SecurityEvent};
use crate::keys::hash_token;
use crate::net::TargetPolicy;
use crate::policy::KeyPolicy;
use crate::vault::CredentialMap;

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

    /// Credential cache — login item names, ids and URIs from bw serve
    /// GET /list/object/items. Refreshed on unlock and every
    /// `refresh_interval_secs`. Never holds credential values.
    pub credentials: Arc<RwLock<CredentialMap>>,

    /// Serializes read-modify-write cycles on the agent key file so that
    /// concurrent create/revoke calls cannot drop each other's changes.
    pub keys_file_lock: Arc<tokio::sync::Mutex<()>>,

    /// Serializes vault re-unlock attempts, so a burst of requests arriving
    /// while bw serve is locked triggers one unlock, not one per request.
    pub unlock_lock: Arc<tokio::sync::Mutex<()>>,

    /// Outbound target policy (SSRF protection), built once from config.
    pub target_policy: Arc<TargetPolicy>,

    /// Security event stream (ring buffer + sinks) — the one emitter, also
    /// read by the admin audit endpoint.
    pub events: Arc<EventLog>,
}

impl AppState {
    pub fn new(config: Config, events: Arc<EventLog>) -> Self {
        // Start locked regardless of unlock mode — unlock happens during
        // startup (file mode) or on first POST /v1/unlock (manual mode).
        let target_policy = Arc::new(TargetPolicy::from_config(&config));
        Self {
            config,
            lock_state: Arc::new(RwLock::new(LockState::Locked)),
            agent_keys: Arc::new(RwLock::new(HashMap::new())),
            credentials: Arc::new(RwLock::new(CredentialMap::new())),
            keys_file_lock: Arc::new(tokio::sync::Mutex::new(())),
            unlock_lock: Arc::new(tokio::sync::Mutex::new(())),
            target_policy,
            events,
        }
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
    /// silent. `cause` is a fixed code such as `bw_serve_locked`.
    pub async fn set_locked(&self, cause: &'static str) {
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
mod tests {
    use super::*;
    use crate::config::{Config, UnlockMode};

    fn test_config() -> Config {
        Config {
            bind_addr: "127.0.0.1:3000".to_string(),
            bw_serve_url: "http://127.0.0.1:8087".to_string(),
            unlock_mode: UnlockMode::Manual,
            unlock_file: None,
            admin_key: "a".repeat(32),
            keys_file: None,
            tls_enabled: false,
            tls_cert_file: None,
            tls_key_file: None,
            allow_private_targets: false,
            allowed_targets: String::new(),
            enforce_credential_hosts: true,
            refresh_interval_secs: 0,
            max_response_bytes: 1024,
            forward_timeout_secs: 30,
            trusted_proxies: String::new(),
            api_prefix: String::new(),
            agent_rate_limit_per_minute: 120,
            agent_rate_limit_burst: 20,
            admin_rate_limit_per_minute: 30,
            admin_rate_limit_burst: 5,
            events: Default::default(),
        }
    }

    fn test_state() -> AppState {
        AppState::new(test_config(), Arc::new(EventLog::buffer_only(10)))
    }

    #[tokio::test]
    async fn lock_state_starts_locked() {
        let state = test_state();
        assert!(state.is_locked().await);
    }

    #[tokio::test]
    async fn set_unlocked_clears_lock() {
        let state = test_state();
        state.set_unlocked().await;
        assert!(!state.is_locked().await);
    }

    #[tokio::test]
    async fn set_locked_restores_lock() {
        let state = test_state();
        state.set_unlocked().await;
        state.set_locked("test").await;
        assert!(state.is_locked().await);
    }

    #[tokio::test]
    async fn vault_lock_event_is_emitted_on_the_transition_only() {
        let state = test_state();
        // Already locked at start: no transition, no event.
        state.set_locked("bw_serve_locked").await;
        assert!(state.events.recent(10).is_empty());

        state.set_unlocked().await;
        state.set_locked("bw_serve_locked").await;
        state.set_locked("bw_serve_locked").await;
        let events = state.events.recent(10);
        assert_eq!(events.len(), 1);
        let v = serde_json::to_value(&*events[0]).unwrap();
        assert_eq!(v["event"]["action"], "vault_lock");
        assert_eq!(v["ferrowarden"]["details"]["cause"], "bw_serve_locked");
    }

    #[tokio::test]
    async fn authenticate_admin_accepts_correct_key() {
        let state = test_state();
        assert!(state.authenticate_admin(&"a".repeat(32)));
    }

    #[tokio::test]
    async fn authenticate_admin_rejects_wrong_key() {
        let state = test_state();
        assert!(!state.authenticate_admin("wrong_key"));
    }

    #[tokio::test]
    async fn authenticate_admin_rejects_prefix_match() {
        // Constant-time comparison must not accept a prefix of the real key
        let state = test_state();
        assert!(!state.authenticate_admin(&"a".repeat(16)));
    }

    #[tokio::test]
    async fn authenticate_returns_none_on_empty_keyring() {
        let state = test_state();
        assert!(state.authenticate("any_token").await.is_none());
    }

    #[tokio::test]
    async fn authenticate_finds_inserted_key() {
        let state = test_state();
        let key = AgentKey {
            id: "test-id".to_string(),
            name: "test-agent".to_string(),
            created_at: chrono::Utc::now(),
            policy: KeyPolicy::default(),
            policy_set: true,
        };
        // Insert keyed by hash — matches how the admin create_key handler works
        state
            .agent_keys
            .write()
            .await
            .insert(hash_token("secret_token_value_xyz"), key);

        let found = state.authenticate("secret_token_value_xyz").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "test-agent");
    }

    #[tokio::test]
    async fn authenticate_rejects_wrong_token() {
        let state = test_state();
        let key = AgentKey {
            id: "test-id".to_string(),
            name: "test-agent".to_string(),
            created_at: chrono::Utc::now(),
            policy: KeyPolicy::default(),
            policy_set: true,
        };
        state
            .agent_keys
            .write()
            .await
            .insert(hash_token("correct_token"), key);

        assert!(state.authenticate("wrong_token").await.is_none());
    }
}
