use super::*;
use crate::config::{Config, UnlockMode};

fn test_config() -> Config {
    Config {
        bind_addr: "127.0.0.1:3000".to_string(),
        bw_serve_url: "http://127.0.0.1:8087".to_string(),
        unlock_mode: UnlockMode::Manual,
        unlock_file: None,
        admin_key: "a".repeat(32).into(),
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
        ui: Default::default(),
        notify: Default::default(),
        vault: Default::default(),
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
