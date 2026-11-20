use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::audit::AuditLog;
use crate::config::Config;

/// A single agent API key entry.
#[derive(Debug, Clone)]
pub struct AgentKey {
    pub id: String,
    pub name: String,
    /// The bearer token the agent presents. Stored as a Zeroizing string so it
    /// is wiped from memory if the entry is dropped (e.g. on key revocation).
    pub token: Zeroizing<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
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

    /// Active agent API keys keyed by token string for O(1) auth lookup.
    /// Token strings are Zeroizing so revoked keys are wiped from memory.
    pub agent_keys: Arc<RwLock<HashMap<String, AgentKey>>>,

    /// Credential name cache — item names from bw serve GET /list/object/items.
    /// Refreshed on unlock and periodically. Names only, never values.
    pub credential_names: Arc<RwLock<Vec<String>>>,

    /// Audit log — shared with the admin API handler.
    pub audit: Arc<AuditLog>,
}

impl AppState {
    pub fn new_with_audit(config: Config, audit: Arc<AuditLog>) -> Self {
        // Start locked regardless of unlock mode — unlock happens during
        // startup (file mode) or on first POST /v1/unlock (manual mode).
        Self {
            config,
            lock_state: Arc::new(RwLock::new(LockState::Locked)),
            agent_keys: Arc::new(RwLock::new(HashMap::new())),
            credential_names: Arc::new(RwLock::new(Vec::new())),
            audit,
        }
    }

    pub async fn is_locked(&self) -> bool {
        *self.lock_state.read().await == LockState::Locked
    }

    pub async fn set_unlocked(&self) {
        *self.lock_state.write().await = LockState::Unlocked;
    }

    pub async fn set_locked(&self) {
        *self.lock_state.write().await = LockState::Locked;
    }

    /// Validate a bearer token and return the matching key entry if found.
    /// Uses a constant-time comparison to prevent timing attacks.
    pub async fn authenticate(&self, token: &str) -> Option<AgentKey> {
        let keys = self.agent_keys.read().await;
        keys.values()
            .find(|k| constant_time_eq(k.token.as_str(), token))
            .cloned()
    }

    /// Validate the admin key. Uses constant-time comparison.
    pub fn authenticate_admin(&self, token: &str) -> bool {
        constant_time_eq(self.config.admin_key.as_str(), token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;
    use crate::config::{Config, UnlockMode};

    fn test_config() -> Config {
        Config {
            bind_addr: "127.0.0.1:3000".to_string(),
            bw_serve_url: "http://127.0.0.1:8087".to_string(),
            unlock_mode: UnlockMode::Manual,
            unlock_file: None,
            admin_key: "a".repeat(32),
        }
    }

    fn test_state() -> AppState {
        AppState::new_with_audit(test_config(), Arc::new(AuditLog::new(10)))
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
        state.set_locked().await;
        assert!(state.is_locked().await);
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
            token: Zeroizing::new("secret_token_value_xyz".to_string()),
            created_at: chrono::Utc::now(),
        };
        state.agent_keys.write().await.insert(key.token.clone().to_string(), key);

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
            token: Zeroizing::new("correct_token".to_string()),
            created_at: chrono::Utc::now(),
        };
        state.agent_keys.write().await.insert(key.token.clone().to_string(), key);

        assert!(state.authenticate("wrong_token").await.is_none());
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
