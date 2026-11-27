//! The native backend against a mock Vaultwarden: login, sync, unlock,
//! on-demand decryption, refresh decisions, locking and fail-closed
//! exclusion. The mock serves a synthetic vault encrypted by the test with the
//! same primitives (so these tests prove the pieces fit together; the
//! known-answer vectors in `enc`/`keys` prove the primitives against an
//! independent implementation).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    extract::State as AxState,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::enc::test_support::encrypt2;
use super::enc::{EncString, SymKey};
use super::keys::stretch;
use super::*;
use crate::config::{Config, VaultBackend, VaultConfig, VaultCredentials};
use crate::ui::crypto::{master_key, Kdf};

const EMAIL: &str = "Admin@Ferrowarden.test";
const PASSWORD: &str = "correct horse battery";
const KDF: Kdf = Kdf::Pbkdf2 { iterations: 5000 };
const CLIENT_ID: &str = "user.11111111-2222-3333-4444-555555555555";
const CLIENT_SECRET: &str = "api-secret-for-tests";
const USER_ID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ── The synthetic account ─────────────────────────────────────────────────────

struct Account {
    user: SymKey,
    org: SymKey,
    profile_key: String,
    private_key: String,
    org_key: String,
}

fn account() -> Account {
    account_with(KDF)
}

fn account_with(kdf: Kdf) -> Account {
    let vectors: Value = serde_json::from_str(include_str!("testdata/vectors.json")).unwrap();
    let master = master_key(PASSWORD.as_bytes(), EMAIL, kdf).unwrap();
    let user_bytes: Vec<u8> = (0..64u8)
        .map(|i| i.wrapping_mul(3).wrapping_add(17))
        .collect();
    let user = SymKey::from_slice(&user_bytes).unwrap();
    let profile_key = encrypt2(&stretch(&master).unwrap(), [1; 16], &user_bytes);
    let der = STANDARD
        .decode(vectors["rsa"]["pkcs8_der_b64"].as_str().unwrap())
        .unwrap();
    Account {
        private_key: encrypt2(&user, [2; 16], &der),
        // The organisation key is the RSA-OAEP(SHA-1) payload of the vectors.
        org: SymKey::from_slice(&unhex(vectors["rsa"]["payload"].as_str().unwrap())).unwrap(),
        org_key: vectors["rsa"]["sha1"].as_str().unwrap().to_string(),
        user,
        profile_key,
    }
}

fn enc(k: &SymKey, s: &str) -> Value {
    json!(encrypt2(k, [9; 16], s.as_bytes()))
}

fn login_item(id: &str, k: &SymKey, name: &str, extra: Value) -> Value {
    let mut v = json!({
        "id": id, "type": 1, "reprompt": 0, "name": enc(k, name),
        "notes": enc(k, "NOTES"),
        "login": {
            "username": enc(k, "USER"), "password": enc(k, &format!("PASS-{name}")),
            "totp": enc(k, "JBSWY3DPEHPK3PXP"),
            "uris": [{"uri": enc(k, "https://a.example"), "match": null}]
        },
        "fields": [{"name": enc(k, "api"), "value": enc(k, "FV"), "type": 1, "linkedId": null}],
        "deletedDate": null, "archivedDate": null, "organizationId": null, "key": null
    });
    for (key, val) in extra.as_object().unwrap() {
        v[key] = val.clone();
    }
    v
}

fn default_ciphers(a: &Account) -> Vec<Value> {
    let item_key_bytes = [0x21u8; 64];
    let ik = SymKey::from_slice(&item_key_bytes).unwrap();
    let org_item_key_bytes = [0x22u8; 64];
    let oik = SymKey::from_slice(&org_item_key_bytes).unwrap();
    vec![
        login_item("c1", &a.user, "plain", json!({})),
        login_item(
            "c2",
            &ik,
            "withkey",
            json!({ "key": encrypt2(&a.user, [3; 16], &item_key_bytes) }),
        ),
        login_item("c3", &a.org, "orgitem", json!({ "organizationId": "org1" })),
        login_item(
            "c4",
            &oik,
            "orgwithkey",
            json!({ "organizationId": "org1", "key": encrypt2(&a.org, [3; 16], &org_item_key_bytes) }),
        ),
        login_item(
            "c5",
            &a.user,
            "trashed",
            json!({ "deletedDate": "2026-01-01T00:00:00Z" }),
        ),
        json!({"id": "c6", "type": 3, "name": enc(&a.user, "card"), "card": {"number": enc(&a.user, "4111")}}),
        json!({"id": "c7", "type": 2, "name": enc(&a.user, "note"), "notes": enc(&a.user, "BODY"),
               "secureNote": {"type": 0}, "fields": [], "reprompt": 1}),
    ]
}

// ── The mock server ───────────────────────────────────────────────────────────

#[derive(Default)]
struct Mock {
    revision: u64,
    stamp: String,
    profile_key: String,
    private_key: String,
    org_key: String,
    ciphers: Vec<Value>,
    expires_in: u64,
    logins: usize,
    syncs: usize,
    revisions: usize,
    fail: bool,
    /// Answer the next `/api/sync` or revision call with 401.
    reject_once: bool,
    last_login: HashMap<String, String>,
    last_version: String,
    /// The `Kdf*` members of the token response; PBKDF2 when `None`.
    kdf: Option<Value>,
    /// The `collections` of `/api/sync`.
    collections: Vec<Value>,
    /// The bodies `POST /api/ciphers/create` received, in order.
    created: Vec<Value>,
    /// Answer `POST /api/ciphers/create` with this status instead of 200.
    create_status: Option<u16>,
    /// Answer the next create call with 401.
    create_reject_once: bool,
    /// The `Authorization` headers of the create calls.
    create_auth: Vec<String>,
    /// The ids `GET /api/ciphers/{id}` was asked for, in order.
    gets: Vec<String>,
    /// The (id, body) of every `PUT /api/ciphers/{id}` that was applied.
    puts: Vec<(String, Value)>,
    /// How many `PUT` calls arrived (applied or not).
    put_calls: usize,
    /// Answer the next `PUT` with this status instead of applying it.
    put_status: Option<u16>,
    /// Answer the next `PUT` with 401.
    put_reject_once: bool,
    /// Answer the next `PUT` with "the client copy is out of date" (as
    /// if someone had edited the item between the read and the write).
    put_stale_once: bool,
    /// Counts the revisions the server gives an item.
    item_revisions: u64,
    /// Apply the next `PUT`, then answer 200 with a body that is not JSON (a
    /// truncated answer). 2: and let every read fail afterwards.
    put_garbage: u8,
    /// Apply the next create, then answer 200 with a body that is not JSON.
    create_garbage: bool,
    /// Answer a read or a write of an item that does not exist with a 404
    /// instead of the 400 Vaultwarden gives.
    missing_is_404: bool,
    /// Answer every `GET /api/ciphers/{id}` with this status.
    get_status: Option<u16>,
    /// Delete the item right after the next `GET` has returned it (it is gone
    /// by the time the write arrives).
    vanish_after_get: bool,
}

/// What Vaultwarden 1.36.0 and 1.37.5 answer for a cipher that does not exist,
/// for a read and for a write: a 400 with this message (checked against both,
/// with a hard-deleted item and an id that never existed).
fn missing_cipher_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "message": "Cipher doesn't exist",
            "validationErrors": {"": ["Cipher doesn't exist"]},
            "errorModel": {"message": "Cipher doesn't exist", "object": "error"},
            "object": "error"
        })),
    )
        .into_response()
}

type Shared = Arc<Mutex<Mock>>;

async fn token(AxState(m): AxState<Shared>, headers: HeaderMap, body: String) -> Response {
    let mut m = m.lock().unwrap();
    m.logins += 1;
    m.last_login = form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    m.last_version = headers
        .get("bitwarden-client-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if m.fail {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if m.last_login.get("client_secret").map(String::as_str) != Some(CLIENT_SECRET) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_client"})),
        )
            .into_response();
    }
    let mut body = json!({
        "access_token": format!("token-{}", m.logins), "expires_in": m.expires_in,
        "token_type": "Bearer", "Kdf": 0, "KdfIterations": 5000,
        "Key": m.profile_key
    });
    if let Some(kdf) = &m.kdf {
        for (k, v) in kdf.as_object().unwrap() {
            body[k] = v.clone();
        }
    }
    Json(body).into_response()
}

fn authorized(m: &mut Mock, headers: &HeaderMap) -> Option<Response> {
    if m.fail {
        return Some(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    let ok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Bearer token-"));
    if !ok || std::mem::take(&mut m.reject_once) {
        return Some(StatusCode::UNAUTHORIZED.into_response());
    }
    None
}

async fn revision_date(AxState(m): AxState<Shared>, headers: HeaderMap) -> Response {
    let mut m = m.lock().unwrap();
    m.revisions += 1;
    if let Some(r) = authorized(&mut m, &headers) {
        return r;
    }
    m.revision.to_string().into_response()
}

async fn sync(AxState(m): AxState<Shared>, headers: HeaderMap) -> Response {
    let mut m = m.lock().unwrap();
    m.syncs += 1;
    if let Some(r) = authorized(&mut m, &headers) {
        return r;
    }
    Json(json!({
        "object": "sync",
        "profile": {
            "id": USER_ID,
            "email": EMAIL, "key": m.profile_key, "privateKey": m.private_key,
            "securityStamp": m.stamp,
            "organizations": [{"id": "org1", "key": m.org_key}]
        },
        "ciphers": m.ciphers, "folders": [], "collections": m.collections
    }))
    .into_response()
}

async fn create_cipher(
    AxState(m): AxState<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let mut m = m.lock().unwrap();
    m.create_auth.push(
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string(),
    );
    if std::mem::take(&mut m.create_reject_once) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if let Some(status) = m.create_status {
        return StatusCode::from_u16(status).unwrap().into_response();
    }
    m.created.push(body);
    if m.create_garbage {
        return (StatusCode::OK, "{\"id\": \"new-").into_response();
    }
    Json(json!({"id": format!("new-{}", m.created.len()), "object": "cipher"})).into_response()
}

async fn get_cipher(
    AxState(m): AxState<Shared>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let mut m = m.lock().unwrap();
    if let Some(r) = authorized(&mut m, &headers) {
        return r;
    }
    m.gets.push(id.clone());
    if let Some(status) = m.get_status {
        return StatusCode::from_u16(status).unwrap().into_response();
    }
    match m.ciphers.iter().find(|c| c["id"] == id.as_str()) {
        Some(c) => {
            let mut c = c.clone();
            c["object"] = json!("cipherDetails");
            if c.get("revisionDate").is_none() {
                c["revisionDate"] = json!("2026-11-26T10:00:00.000000Z");
            }
            if std::mem::take(&mut m.vanish_after_get) {
                m.ciphers.retain(|x| x["id"] != id.as_str());
            }
            Json(c).into_response()
        }
        None if m.missing_is_404 => StatusCode::NOT_FOUND.into_response(),
        None => missing_cipher_response(),
    }
}

async fn put_cipher(
    AxState(m): AxState<Shared>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let mut m = m.lock().unwrap();
    m.put_calls += 1;
    if let Some(r) = authorized(&mut m, &headers) {
        return r;
    }
    if std::mem::take(&mut m.put_reject_once) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if let Some(status) = m.put_status {
        return StatusCode::from_u16(status).unwrap().into_response();
    }
    let stale = std::mem::take(&mut m.put_stale_once);
    let Some(i) = m.ciphers.iter().position(|c| c["id"] == id.as_str()) else {
        if m.missing_is_404 {
            return StatusCode::NOT_FOUND.into_response();
        }
        return missing_cipher_response();
    };
    let current = m.ciphers[i]
        .get("revisionDate")
        .and_then(Value::as_str)
        .unwrap_or("2026-11-26T10:00:00.000000Z")
        .to_string();
    if stale || body["lastKnownRevisionDate"].as_str() != Some(current.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "The client copy of this cipher is out of date. Resync the client and try again."})),
        )
            .into_response();
    }
    m.item_revisions += 1;
    let revision = format!("2026-11-26T11:00:{:02}.000000Z", m.item_revisions);
    for (k, v) in body.as_object().unwrap() {
        if k != "lastKnownRevisionDate" {
            m.ciphers[i][k] = v.clone();
        }
    }
    m.ciphers[i]["revisionDate"] = json!(revision);
    m.revision += 1;
    m.puts.push((id, body));
    match std::mem::take(&mut m.put_garbage) {
        0 => {}
        broken => {
            if broken == 2 {
                m.get_status = Some(500);
            }
            return (StatusCode::OK, "{\"id\": \"c3\", \"revisio").into_response();
        }
    }
    Json(m.ciphers[i].clone()).into_response()
}

async fn profile(AxState(m): AxState<Shared>, headers: HeaderMap) -> Response {
    let mut m = m.lock().unwrap();
    if let Some(r) = authorized(&mut m, &headers) {
        return r;
    }
    Json(json!({"email": EMAIL})).into_response()
}

struct Harness {
    vault: NativeVault,
    mock: Shared,
    acct: Account,
    config: Config,
}

async fn harness_with(ciphers: impl FnOnce(&Account) -> Vec<Value>) -> Harness {
    harness_opts(false, ciphers).await
}

async fn harness_opts(
    allow_hidden_passwords: bool,
    ciphers: impl FnOnce(&Account) -> Vec<Value>,
) -> Harness {
    harness_full(allow_hidden_passwords, account(), None, ciphers).await
}

async fn harness_full(
    allow_hidden_passwords: bool,
    acct: Account,
    kdf: Option<Value>,
    ciphers: impl FnOnce(&Account) -> Vec<Value>,
) -> Harness {
    let mock: Shared = Arc::new(Mutex::new(Mock {
        kdf,
        revision: 100,
        stamp: "stamp-1".into(),
        profile_key: acct.profile_key.clone(),
        private_key: acct.private_key.clone(),
        org_key: acct.org_key.clone(),
        ciphers: ciphers(&acct),
        expires_in: 3600,
        ..Mock::default()
    }));
    let app = Router::new()
        .route("/identity/connect/token", post(token))
        .route("/api/accounts/revision-date", get(revision_date))
        .route("/api/sync", get(sync))
        .route("/api/ciphers/create", post(create_cipher))
        .route("/api/ciphers/{id}", get(get_cipher).put(put_cipher))
        .route("/api/accounts/profile", get(profile))
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let cfg = Config {
        vault: VaultConfig {
            backend: VaultBackend::Native,
            url: format!("http://{addr}"),
            ca_file: String::new(),
            allow_hidden_passwords,
            managed: Default::default(),
            credentials: VaultCredentials {
                client_id: Some(Zeroizing::new(CLIENT_ID.into())),
                client_secret: Some(Zeroizing::new(CLIENT_SECRET.into())),
            },
        },
        refresh_interval_secs: 30,
        ..test_config()
    };
    Harness {
        vault: NativeVault::new(&cfg).unwrap(),
        mock,
        acct,
        config: cfg,
    }
}

async fn harness() -> Harness {
    harness_with(default_ciphers).await
}

fn test_config() -> Config {
    Config {
        bind_addr: "127.0.0.1:3000".to_string(),
        bw_serve_url: None,
        unlock_mode: crate::config::UnlockMode::Manual,
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
        metrics: Default::default(),
        sessions: Default::default(),
        approval: Default::default(),
    }
}

fn pw() -> Zeroizing<String> {
    Zeroizing::new(PASSWORD.to_string())
}

async fn unlocked() -> Harness {
    let h = harness().await;
    h.vault.unlock(pw()).await.unwrap();
    h
}

fn counts(h: &Harness) -> (usize, usize, usize) {
    let m = h.mock.lock().unwrap();
    (m.logins, m.revisions, m.syncs)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn unlock_lists_metadata_and_decrypts_values_on_demand() {
    let h = unlocked().await;
    let listing = h.vault.list_credentials().await.unwrap();
    let names: Vec<_> = listing.map.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        ["note", "orgitem", "orgwithkey", "plain", "withkey"],
        "trashed and card items are not offered"
    );
    assert!(listing.excluded.is_none());
    let plain = &listing.map["plain"][0];
    assert_eq!(plain.id, "c1");
    assert_eq!(plain.uris, vec!["https://a.example"]);
    assert!(listing.map["note"][0].reprompt);

    let v = &h.vault;
    for (name, id) in [
        ("plain", "c1"),
        ("withkey", "c2"),
        ("orgitem", "c3"),
        ("orgwithkey", "c4"),
    ] {
        let pass = v.get_value(Builtin::Password, id, name).await.unwrap();
        assert_eq!(pass.as_str(), format!("PASS-{name}"));
        assert_eq!(
            v.get_value(Builtin::Username, id, name)
                .await
                .unwrap()
                .as_str(),
            "USER"
        );
        assert_eq!(
            v.get_value(Builtin::Notes, id, name)
                .await
                .unwrap()
                .as_str(),
            "NOTES"
        );
        assert_eq!(v.get_field(id, "api", name).await.unwrap().as_str(), "FV");
        let totp = v.get_value(Builtin::Totp, id, name).await.unwrap();
        assert_eq!(totp.len(), 6);
    }
    // Unknown ids and excluded kinds are "not found", not an error of the vault.
    assert!(matches!(
        v.get_value(Builtin::Password, "c5", "trashed").await,
        Err(FerroError::CredentialNotFound(_))
    ));
    assert!(matches!(
        v.get_value(Builtin::Password, "nope", "x").await,
        Err(FerroError::CredentialNotFound(_))
    ));
}

#[tokio::test]
async fn login_request_is_an_api_key_grant_with_a_stable_device() {
    let h = unlocked().await;
    let m = h.mock.lock().unwrap();
    let f = &m.last_login;
    assert_eq!(f["grant_type"], "client_credentials");
    assert_eq!(f["scope"], "api");
    assert_eq!(f["client_id"], CLIENT_ID);
    assert_eq!(f["device_name"], "ferrowarden");
    assert_eq!(
        f["device_identifier"],
        api::device_identifier(CLIENT_ID).to_string()
    );
    // SSH-key items are only in the sync from this client version on.
    assert_eq!(m.last_version, "2024.12.0");
}

#[tokio::test]
async fn wrong_password_fails_and_the_vault_stays_locked() {
    let h = harness().await;
    let err = h
        .vault
        .unlock(Zeroizing::new("not the password".into()))
        .await
        .unwrap_err();
    assert!(matches!(err, FerroError::UnlockFailed(_)));
    assert!(matches!(
        h.vault.list_credentials().await,
        Err(FerroError::VaultLocked)
    ));
    assert!(matches!(
        h.vault.get_value(Builtin::Password, "c1", "x").await,
        Err(FerroError::VaultLocked)
    ));
}

#[tokio::test]
async fn a_rejected_api_key_is_an_unlock_failure() {
    let h = harness().await;
    // Rebuild with the wrong secret.
    let mut cfg = test_config();
    cfg.vault = VaultConfig {
        backend: VaultBackend::Native,
        url: h.vault.api_base_for_tests(),
        ca_file: String::new(),
        allow_hidden_passwords: false,
        managed: Default::default(),
        credentials: VaultCredentials {
            client_id: Some(Zeroizing::new(CLIENT_ID.into())),
            client_secret: Some(Zeroizing::new("wrong".into())),
        },
    };
    let v = NativeVault::new(&cfg).unwrap();
    assert!(matches!(
        v.unlock(pw()).await,
        Err(FerroError::UnlockFailed(_))
    ));
}

#[tokio::test]
async fn an_unchanged_revision_does_not_sync() {
    let h = unlocked().await;
    assert_eq!(counts(&h), (1, 1, 1));
    for _ in 0..3 {
        h.vault.sync().await.unwrap();
    }
    // Three cheap revision checks, no full sync, no new login.
    assert_eq!(counts(&h), (1, 4, 1));
}

#[tokio::test]
async fn a_changed_revision_syncs_and_rebuilds_the_metadata() {
    let h = unlocked().await;
    {
        let mut m = h.mock.lock().unwrap();
        m.revision += 1;
        let extra = login_item("c8", &h.acct.user, "added", json!({}));
        m.ciphers.push(extra);
        m.ciphers.retain(|c| c["id"] != "c1");
    }
    h.vault.sync().await.unwrap();
    assert_eq!(counts(&h).2, 2);
    let map = h.vault.list_credentials().await.unwrap().map;
    assert!(map.contains_key("added") && !map.contains_key("plain"));
    assert!(matches!(
        h.vault.get_value(Builtin::Password, "c1", "plain").await,
        Err(FerroError::CredentialNotFound(_))
    ));
    assert_eq!(
        h.vault
            .get_value(Builtin::Password, "c8", "added")
            .await
            .unwrap()
            .as_str(),
        "PASS-added"
    );
}

#[tokio::test]
async fn a_periodic_safety_sync_happens_even_when_the_revision_is_unchanged() {
    let mut h = unlocked().await;
    h.vault.full_sync_every = Some(std::time::Duration::ZERO);
    h.vault.sync().await.unwrap();
    assert_eq!(counts(&h).2, 2);
}

#[tokio::test]
async fn a_changed_security_stamp_locks_and_drops_everything() {
    let h = unlocked().await;
    {
        let mut m = h.mock.lock().unwrap();
        m.revision += 1;
        m.stamp = "stamp-2".into();
    }
    assert!(matches!(h.vault.sync().await, Err(FerroError::VaultLocked)));
    assert_eq!(h.vault.lock_cause(), "security_stamp_changed");
    assert!(matches!(
        h.vault.list_credentials().await,
        Err(FerroError::VaultLocked)
    ));
    assert!(matches!(
        h.vault.get_value(Builtin::Password, "c1", "x").await,
        Err(FerroError::VaultLocked)
    ));
    // Locked stays locked: no more network traffic for syncs.
    let before = counts(&h);
    assert!(matches!(h.vault.sync().await, Err(FerroError::VaultLocked)));
    assert_eq!(counts(&h), before);
}

#[tokio::test]
async fn a_changed_user_key_locks() {
    let h = unlocked().await;
    {
        let mut m = h.mock.lock().unwrap();
        m.revision += 1;
        // Same key bytes, re-wrapped: what a password change produces.
        let master = master_key(b"another password", EMAIL, KDF).unwrap();
        let bytes: Vec<u8> = (0..64u8)
            .map(|i| i.wrapping_mul(3).wrapping_add(17))
            .collect();
        m.profile_key = encrypt2(&stretch(&master).unwrap(), [4; 16], &bytes);
    }
    assert!(matches!(h.vault.sync().await, Err(FerroError::VaultLocked)));
    assert_eq!(h.vault.lock_cause(), "vault_key_changed");
}

#[tokio::test]
async fn an_unreachable_vaultwarden_keeps_serving_the_copy_in_memory() {
    let h = unlocked().await;
    h.mock.lock().unwrap().fail = true;
    assert!(matches!(
        h.vault.sync().await,
        Err(FerroError::VaultUnavailable)
    ));
    // Still unlocked, still decrypting from memory.
    assert_eq!(
        h.vault
            .get_value(Builtin::Password, "c1", "plain")
            .await
            .unwrap()
            .as_str(),
        "PASS-plain"
    );
    assert_eq!(h.vault.list_credentials().await.unwrap().map.len(), 5);
}

#[tokio::test]
async fn a_rejected_token_logs_in_again_once_and_retries() {
    let h = unlocked().await;
    {
        let mut m = h.mock.lock().unwrap();
        m.revision += 1;
        m.reject_once = true;
    }
    h.vault.sync().await.unwrap();
    let (logins, _, syncs) = counts(&h);
    assert_eq!(logins, 2, "one re-login");
    assert_eq!(syncs, 2);
}

#[tokio::test]
async fn the_token_is_renewed_before_it_expires() {
    let h = harness().await;
    h.mock.lock().unwrap().expires_in = 1; // renewed after half a second
    h.vault.unlock(pw()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    h.vault.sync().await.unwrap();
    assert_eq!(counts(&h).0, 2);
}

#[tokio::test]
async fn lock_drops_the_keys_but_keeps_the_account_email() {
    let h = unlocked().await;
    h.vault.lock().await;
    assert!(matches!(
        h.vault.get_field("c1", "api", "x").await,
        Err(FerroError::VaultLocked)
    ));
    let status = h.vault.status().await.unwrap();
    assert_eq!(status.status, "locked");
    assert_eq!(status.user_email.as_deref(), Some(EMAIL));
    // And it unlocks again.
    h.vault.unlock(pw()).await.unwrap();
    assert_eq!(h.vault.status().await.unwrap().status, "unlocked");
}

#[tokio::test]
async fn the_account_email_is_known_before_the_first_unlock() {
    let h = harness().await;
    let status = h.vault.status().await.unwrap();
    assert_eq!(
        (status.status.as_str(), status.user_email.as_deref()),
        ("locked", Some(EMAIL))
    );
    h.vault.unlock(pw()).await.unwrap();
    let status = h.vault.status().await.unwrap();
    assert_eq!(status.status, "unlocked");
    assert!(status.last_sync.is_some());
}

#[tokio::test]
async fn unreadable_items_are_excluded_with_counts_by_reason_and_the_rest_still_works() {
    let h = harness_with(|a| {
        let mut items = default_ciphers(a);
        // type 0 name: refused, never decrypted
        items.push(json!({"id": "x1", "type": 1, "name": "0.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==",
                          "login": {"password": enc(&a.user, "P")}}));
        // wrong key
        let other = SymKey::from_slice(&[0x77u8; 64]).unwrap();
        items.push(login_item("x2", &other, "wrongkey", json!({})));
        // org without a key
        items.push(login_item("x3", &a.org, "noorg", json!({"organizationId": "ghost-org"})));
        // 32-byte item key
        items.push(login_item("x4", &a.user, "shortkey", json!({"key": encrypt2(&a.user, [3; 16], &[1u8; 32])})));
        // garbage and an unknown future type
        items.push(json!({"id": "x5", "type": 1, "name": "garbage"}));
        items.push(json!({"id": "x6", "type": 1, "name": "7.AAAA"}));
        items
    })
    .await;
    h.vault.unlock(pw()).await.unwrap();
    let listing = h.vault.list_credentials().await.unwrap();
    assert_eq!(
        listing.map.len(),
        5,
        "the readable items are all still there"
    );
    let report = listing.excluded.expect("a report");
    assert_eq!(report.total(), 6);
    assert_eq!(report.counts["unsupported_encstring_type"], 2);
    assert_eq!(report.counts["mac_failure"], 1);
    assert_eq!(report.counts["missing_org_key"], 1);
    assert_eq!(report.counts["bad_key_length"], 1);
    assert_eq!(report.counts["malformed_encstring"], 1);
    assert!(report.ids.contains(&"x1".to_string()));
    // The excluded items cannot be fetched either.
    assert!(matches!(
        h.vault.get_value(Builtin::Password, "x2", "wrongkey").await,
        Err(FerroError::CredentialNotFound(_))
    ));
    // The report is handed out once.
    assert!(h.vault.list_credentials().await.unwrap().excluded.is_none());
}

#[tokio::test]
async fn totp_codes_come_from_the_item_secret() {
    let h = harness_with(|a| {
        vec![
            login_item(
                "t1",
                &a.user,
                "sha256",
                json!({"login": {"totp": enc(&a.user, "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60"),
                                 "password": enc(&a.user, "p")}}),
            ),
            login_item("t2", &a.user, "steam", json!({"login": {"totp": enc(&a.user, "steam://JBSWY3DPEHPK3PXP"), "password": enc(&a.user, "p")}})),
            login_item("t3", &a.user, "bad", json!({"login": {"totp": enc(&a.user, "!!!"), "password": enc(&a.user, "p")}})),
        ]
    })
    .await;
    h.vault.unlock(pw()).await.unwrap();
    assert_eq!(
        h.vault
            .get_value(Builtin::Totp, "t1", "x")
            .await
            .unwrap()
            .len(),
        8
    );
    assert_eq!(
        h.vault
            .get_value(Builtin::Totp, "t2", "x")
            .await
            .unwrap()
            .len(),
        5
    );
    assert!(matches!(
        h.vault.get_value(Builtin::Totp, "t3", "x").await,
        Err(FerroError::CredentialNotFound(_))
    ));
}

#[tokio::test]
async fn nothing_secret_shows_in_debug_output() {
    let h = unlocked().await;
    let listing = h.vault.list_credentials().await.unwrap();
    let dbg = format!("{listing:?}");
    for secret in ["PASS-plain", "JBSWY3DPEHPK3PXP", CLIENT_SECRET, PASSWORD] {
        assert!(!dbg.contains(secret));
    }
    let guard = h.vault.state.read().await;
    if let State::Unlocked(u) = &*guard {
        let dbg = format!("{:?} {:?}", u.ring, u.ciphers.values().next().unwrap());
        assert!(!dbg.contains("SymKey") || dbg.contains("redacted"));
    }
}

// ── Through AppState: refresh, events, lock ───────────────────────────────────

fn event_json(state: &crate::state::AppState, action: &str) -> Vec<Value> {
    state
        .events
        .recent(100)
        .iter()
        .map(|e| serde_json::to_value(&**e).unwrap())
        .filter(|v| v["event"]["action"] == action)
        .collect()
}

#[tokio::test]
async fn refresh_fills_the_credential_map_and_reports_exclusions_in_one_event() {
    use crate::events::EventLog;
    use crate::vault::refresh::refresh_credentials;
    let h = harness_with(|a| {
        let mut items = default_ciphers(a);
        items.push(json!({"id": "bad1", "type": 1, "name": "0.AAAA|BBBB"}));
        items.push(json!({"id": "bad2", "type": 1, "name": "2.not-base64|x|y"}));
        items
    })
    .await;
    let state =
        crate::state::AppState::try_new(h.config.clone(), Arc::new(EventLog::buffer_only(100)))
            .unwrap();
    assert_eq!(state.vault.name(), "native");
    state.vault.unlock(pw()).await.unwrap();
    refresh_credentials(&state).await.unwrap();
    state.set_unlocked().await;

    assert_eq!(state.credentials.read().await.len(), 5);
    let syncs = event_json(&state, "vault_sync");
    assert_eq!(syncs.len(), 1, "one event for the sync");
    let d = &syncs[0]["ferrowarden"]["details"];
    assert_eq!(d["credential_count"], 5);
    assert_eq!(d["excluded"], 2);
    assert_eq!(d["excluded_reasons"]["unsupported_encstring_type"], 1);
    assert_eq!(d["excluded_reasons"]["malformed_encstring"], 1);
    assert_eq!(d["excluded_ids"], json!(["bad1", "bad2"]));
    // Ids and counts only: no item names and no values anywhere in the event.
    let text = syncs[0].to_string();
    for needle in ["plain", "orgitem", "PASS-", "NOTES"] {
        assert!(!text.contains(needle), "{needle}");
    }
    // A refresh with nothing new is quiet.
    refresh_credentials(&state).await.unwrap();
    assert_eq!(event_json(&state, "vault_sync").len(), 1);

    // The metrics see the sync, and the exclusion count outlives the
    // one-time report.
    assert_eq!(state.sync_stats.excluded(), 2);
    assert!(state.sync_stats.last_sync_unix() > 1_700_000_000);
}

#[tokio::test]
async fn a_key_change_found_by_the_refresher_locks_the_state_and_clears_the_map() {
    use crate::events::EventLog;
    use crate::vault::refresh::refresh_credentials;
    let h = harness().await;
    let state =
        crate::state::AppState::try_new(h.config.clone(), Arc::new(EventLog::buffer_only(100)))
            .unwrap();
    state.vault.unlock(pw()).await.unwrap();
    refresh_credentials(&state).await.unwrap();
    state.set_unlocked().await;
    assert!(!state.credentials.read().await.is_empty());

    {
        let mut m = h.mock.lock().unwrap();
        m.revision += 1;
        m.stamp = "rotated".into();
    }
    assert!(matches!(
        refresh_credentials(&state).await,
        Err(FerroError::VaultLocked)
    ));
    assert!(state.is_locked().await);
    assert!(
        state.credentials.read().await.is_empty(),
        "the map is dropped with the keys"
    );
    let locks = event_json(&state, "vault_lock");
    assert_eq!(locks.len(), 1);
    assert_eq!(
        locks[0]["ferrowarden"]["details"]["cause"],
        "security_stamp_changed"
    );
}

// ── Hidden passwords (viewPassword = false) ───────────────────────────────────

/// A regular item, one whose collection hides passwords, and one that says
/// `viewPassword: true`.
fn hidden_password_items(a: &Account) -> Vec<Value> {
    vec![
        login_item("v1", &a.user, "visible_default", json!({})),
        login_item(
            "v2",
            &a.org,
            "hidden_org",
            json!({"organizationId": "org1", "viewPassword": false}),
        ),
        login_item(
            "v3",
            &a.org,
            "visible_org",
            json!({"organizationId": "org1", "viewPassword": true}),
        ),
    ]
}

#[tokio::test]
async fn items_with_a_hidden_password_are_excluded_by_default() {
    let h = harness_opts(false, hidden_password_items).await;
    h.vault.unlock(pw()).await.unwrap();
    let listing = h.vault.list_credentials().await.unwrap();
    let names: Vec<&str> = listing.map.keys().map(String::as_str).collect();
    assert_eq!(names, ["visible_default", "visible_org"]);
    let report = listing.excluded.expect("a report");
    assert_eq!(report.counts["hidden_password"], 1);
    assert_eq!(report.total(), 1);
    assert_eq!(report.ids, ["v2"]);
    assert_eq!(listing.excluded_count, 1);
    // Not fetchable by id either.
    assert!(matches!(
        h.vault
            .get_value(Builtin::Password, "v2", "hidden_org")
            .await,
        Err(FerroError::CredentialNotFound(_))
    ));
}

#[tokio::test]
async fn items_with_a_hidden_password_are_usable_when_allowed() {
    let h = harness_opts(true, hidden_password_items).await;
    h.vault.unlock(pw()).await.unwrap();
    let listing = h.vault.list_credentials().await.unwrap();
    assert_eq!(listing.map.len(), 3);
    assert!(listing.excluded.is_none());
    assert_eq!(listing.excluded_count, 0);
    let pass = h
        .vault
        .get_value(Builtin::Password, "v2", "hidden_org")
        .await
        .unwrap();
    assert_eq!(pass.as_str(), "PASS-hidden_org");
}

#[tokio::test]
async fn a_hidden_password_is_reported_in_the_sync_event_without_names_or_values() {
    use crate::events::EventLog;
    use crate::vault::refresh::refresh_credentials;
    let h = harness_opts(false, hidden_password_items).await;
    let state =
        crate::state::AppState::try_new(h.config.clone(), Arc::new(EventLog::buffer_only(100)))
            .unwrap();
    state.vault.unlock(pw()).await.unwrap();
    refresh_credentials(&state).await.unwrap();
    assert!(!state.credentials.read().await.contains_key("hidden_org"));
    let syncs = event_json(&state, "vault_sync");
    assert_eq!(syncs.len(), 1);
    let d = &syncs[0]["ferrowarden"]["details"];
    assert_eq!(d["excluded"], 1);
    assert_eq!(d["excluded_reasons"]["hidden_password"], 1);
    let text = syncs[0].to_string();
    assert!(!text.contains("hidden_org") && !text.contains("PASS-"));
    assert_eq!(state.sync_stats.excluded(), 1);
}

// ── Argon2id accounts ─────────────────────────────────────────────────────────

#[tokio::test]
async fn an_argon2id_account_unlocks_and_decrypts() {
    // The KDF settings come from the login response (`KdfMemory` in MiB),
    // exactly as Vaultwarden reports them for an Argon2id account.
    let kdf = Kdf::Argon2id {
        memory_mib: 16,
        iterations: 2,
        parallelism: 1,
    };
    let h = harness_full(
        false,
        account_with(kdf),
        Some(json!({"Kdf": 1, "KdfIterations": 2, "KdfMemory": 16, "KdfParallelism": 1})),
        default_ciphers,
    )
    .await;
    h.vault.unlock(pw()).await.unwrap();
    let listing = h.vault.list_credentials().await.unwrap();
    assert_eq!(listing.map.len(), 5);
    let pass = h
        .vault
        .get_value(Builtin::Password, "c3", "orgitem")
        .await
        .unwrap();
    assert_eq!(pass.as_str(), "PASS-orgitem");

    // A wrong password is a failed MAC, as with PBKDF2.
    h.vault.lock().await;
    assert!(matches!(
        h.vault
            .unlock(Zeroizing::new("wrong password".to_string()))
            .await,
        Err(FerroError::UnlockFailed(_))
    ));
}

#[tokio::test]
async fn argon2id_settings_outside_the_accepted_range_are_refused() {
    let kdf = Kdf::Argon2id {
        memory_mib: 16,
        iterations: 2,
        parallelism: 1,
    };
    // Memory below the client minimum: refused, not derived.
    let h = harness_full(
        false,
        account_with(kdf),
        Some(json!({"Kdf": 1, "KdfIterations": 2, "KdfMemory": 1, "KdfParallelism": 1})),
        default_ciphers,
    )
    .await;
    assert!(matches!(
        h.vault.unlock(pw()).await,
        Err(FerroError::UnlockFailed(_))
    ));
}

// ── A vault written by the real web vault ─────────────────────────────────────
//
// `testdata/webvault/` is a throwaway account created in the web vault that
// ships with Vaultwarden 1.37.5 (Argon2id, m=32 MiB, t=6, p=4): the token and
// `/api/sync` responses captured verbatim (ciphertext only), and the values
// the Bitwarden CLI 2026.11.0 decrypted from the same account as the
// reference. Every item has a per-item key; the org key is RSA-OAEP. All
// values are dummies (see testdata/README.md).

struct WebVault {
    token: Value,
    sync: Value,
}

async fn webvault_token(AxState(w): AxState<Arc<WebVault>>) -> Response {
    let mut body = w.token.clone();
    body["access_token"] = json!("token-webvault");
    body["expires_in"] = json!(7200);
    Json(body).into_response()
}

async fn webvault_sync(AxState(w): AxState<Arc<WebVault>>, headers: HeaderMap) -> Response {
    let ok =
        headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer token-webvault");
    if !ok {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(w.sync.clone()).into_response()
}

async fn webvault_revision() -> Response {
    "1".into_response()
}

async fn webvault_profile(AxState(w): AxState<Arc<WebVault>>) -> Response {
    Json(json!({"email": w.sync["profile"]["email"]})).into_response()
}

fn webvault_expected() -> Value {
    serde_json::from_str(include_str!("testdata/webvault/expected.json")).unwrap()
}

async fn webvault_vault() -> NativeVault {
    webvault_vault_from(
        include_str!("testdata/webvault/token.json"),
        include_str!("testdata/webvault/sync.json"),
        false,
    )
    .await
}

/// A native vault against a mock serving a captured token and sync response.
async fn webvault_vault_from(token: &str, sync: &str, allow_hidden_passwords: bool) -> NativeVault {
    let w = Arc::new(WebVault {
        token: serde_json::from_str(token).unwrap(),
        sync: serde_json::from_str(sync).unwrap(),
    });
    let app = Router::new()
        .route("/identity/connect/token", post(webvault_token))
        .route("/api/accounts/revision-date", get(webvault_revision))
        .route("/api/sync", get(webvault_sync))
        .route("/api/accounts/profile", get(webvault_profile))
        .with_state(w);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let cfg = Config {
        vault: VaultConfig {
            backend: VaultBackend::Native,
            url: format!("http://{addr}"),
            ca_file: String::new(),
            allow_hidden_passwords,
            managed: Default::default(),
            credentials: VaultCredentials {
                client_id: Some(Zeroizing::new(CLIENT_ID.into())),
                client_secret: Some(Zeroizing::new(CLIENT_SECRET.into())),
            },
        },
        ..test_config()
    };
    NativeVault::new(&cfg).unwrap()
}

/// The same org items seen by `capture3`, a member whose collection hides
/// passwords. Vaultwarden still sends the password ciphertext (hiding is
/// enforced by clients only), so the native backend must refuse the items
/// itself unless `vault.allow_hidden_passwords` is on.
async fn webvault_hidden(allow: bool) -> (NativeVault, Value) {
    let exp: Value =
        serde_json::from_str(include_str!("testdata/webvault-hidden/expected.json")).unwrap();
    let v = webvault_vault_from(
        include_str!("testdata/webvault-hidden/token.json"),
        include_str!("testdata/webvault-hidden/sync.json"),
        allow,
    )
    .await;
    v.unlock(Zeroizing::new(
        exp["password"].as_str().unwrap().to_string(),
    ))
    .await
    .unwrap();
    (v, exp)
}

#[tokio::test]
async fn web_vault_items_with_hidden_passwords_are_refused_by_default() {
    let (v, exp) = webvault_hidden(false).await;
    let hidden: Vec<&str> = exp["hidden_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i.as_str().unwrap())
        .collect();
    assert_eq!(hidden.len(), 2, "the org login and the org note");
    let sync: Value =
        serde_json::from_str(include_str!("testdata/webvault-hidden/sync.json")).unwrap();
    let login = sync["ciphers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["type"] == 1)
        .unwrap();
    assert!(
        login["login"]["password"].is_string(),
        "the server sends the hidden password's ciphertext"
    );

    let listing = v.list_credentials().await.unwrap();
    assert!(listing.map.is_empty(), "{:?}", listing.map.keys());
    assert_eq!(listing.excluded_count, 2);
    let report = listing.excluded.expect("an exclusion report");
    assert_eq!(report.total(), 2);
    for id in hidden {
        for b in [Builtin::Password, Builtin::Username, Builtin::Notes] {
            assert!(matches!(
                v.get_value(b, id, "wv_org_login").await,
                Err(FerroError::CredentialNotFound(_))
            ));
        }
    }
}

#[tokio::test]
async fn web_vault_items_with_hidden_passwords_are_usable_when_allowed() {
    let (v, _) = webvault_hidden(true).await;
    // The same items as in the owner's capture: compare with its reference.
    let owner = webvault_expected();
    let listing = v.list_credentials().await.unwrap();
    let names: Vec<&str> = listing.map.keys().map(String::as_str).collect();
    assert_eq!(names, ["wv_org_login", "wv_org_note"]);
    assert_eq!(listing.excluded_count, 0);
    for o in owner["offered"].as_array().unwrap() {
        let name = o["name"].as_str().unwrap();
        if !names.contains(&name) {
            continue;
        }
        let id = o["id"].as_str().unwrap();
        for (b, key) in [
            (Builtin::Username, "username"),
            (Builtin::Password, "password"),
            (Builtin::Notes, "notes"),
        ] {
            if let Some(want) = o[key].as_str().filter(|s| !s.is_empty()) {
                assert_eq!(v.get_value(b, id, name).await.unwrap().as_str(), want);
            }
        }
    }
}

#[tokio::test]
async fn a_vault_written_by_the_web_vault_matches_the_bitwarden_cli() {
    let exp = webvault_expected();
    let v = webvault_vault().await;
    v.unlock(Zeroizing::new(
        exp["password"].as_str().unwrap().to_string(),
    ))
    .await
    .unwrap();
    let listing = v.list_credentials().await.unwrap();
    assert!(
        listing.excluded.is_none(),
        "nothing is excluded as unreadable"
    );
    assert_eq!(listing.excluded_count, 0);

    // Exactly the logins and notes are offered: not the card, identity or
    // SSH key, not the trashed or archived item.
    let offered = exp["offered"].as_array().unwrap();
    let mut want: Vec<&str> = offered
        .iter()
        .map(|o| o["name"].as_str().unwrap())
        .collect();
    want.sort_unstable();
    let got: Vec<&str> = listing.map.keys().map(String::as_str).collect();
    assert_eq!(got, want);
    let other_ids = exp["not_offered_kinds"]
        .as_array()
        .unwrap()
        .iter()
        .chain(exp["skipped"].as_array().unwrap())
        .map(|o| o["id"].as_str().unwrap());
    for id in other_ids {
        assert!(
            listing.map.values().flatten().all(|e| e.id != id),
            "{id} is not offered"
        );
        assert!(matches!(
            v.get_value(Builtin::Password, id, "other").await,
            Err(FerroError::CredentialNotFound(_))
        ));
    }

    for o in offered {
        let name = o["name"].as_str().unwrap();
        let id = o["id"].as_str().unwrap();
        let entries = &listing.map[name];
        assert_eq!(entries.len(), 1, "{name}");
        let e = &entries[0];
        assert_eq!(e.id, id, "{name}");

        // Bindings: the login's URIs, or `ferrowarden_uris` for a note.
        let binding = o["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == "ferrowarden_uris")
            .map(|f| vec![f["value"].as_str().unwrap().to_string()]);
        let uris = binding.unwrap_or_else(|| {
            o["uris"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| u.as_str().unwrap().to_string())
                .collect()
        });
        assert_eq!(e.uris, uris, "{name}");

        for (builtin, key) in [
            (Builtin::Username, "username"),
            (Builtin::Password, "password"),
            (Builtin::Notes, "notes"),
        ] {
            // The web vault stores an emptied field as "" and the CLI reports
            // it as such; Ferrowarden has nothing to substitute: absent.
            match o[key].as_str().filter(|s| !s.is_empty()) {
                Some(want) => assert_eq!(
                    v.get_value(builtin, id, name).await.unwrap().as_str(),
                    want,
                    "{name} {key}"
                ),
                None => assert!(
                    v.get_value(builtin, id, name).await.is_err(),
                    "{name} {key}"
                ),
            }
        }
        // TOTP: the CLI's reference is the stored secret; the code length
        // follows it (8 digits for the otpauth URI with digits=8).
        match o["totp"].as_str() {
            Some(secret) => {
                let code = v.get_value(Builtin::Totp, id, name).await.unwrap();
                let digits = if secret.contains("digits=8") { 8 } else { 6 };
                assert_eq!(code.len(), digits, "{name} totp");
                assert!(code.chars().all(|c| c.is_ascii_digit()));
            }
            None => assert!(v.get_value(Builtin::Totp, id, name).await.is_err()),
        }

        // Custom fields: text, hidden and boolean by value; linked resolves
        // to the login field it points at (linkedId 100 = username).
        for f in o["fields"].as_array().unwrap() {
            let field = f["name"].as_str().unwrap();
            if field == "ferrowarden_uris" {
                continue;
            }
            let want = match f["type"].as_u64().unwrap() {
                3 => {
                    assert_eq!(f["linkedId"], 100, "the fixture links to the username");
                    o["username"].as_str().unwrap().to_string()
                }
                _ => f["value"].as_str().unwrap().to_string(),
            };
            assert_eq!(
                v.get_field(id, field, name).await.unwrap().as_str(),
                want,
                "{name}.{field}"
            );
        }
    }
}

#[tokio::test]
async fn the_web_vault_capture_uses_only_supported_formats() {
    // Guards the fixture itself: if a future capture brings type 7 (COSE)
    // strings or V2 key material, this test names it instead of the
    // comparison failing obscurely.
    let sync = include_str!("testdata/webvault/sync.json");
    let token = include_str!("testdata/webvault/token.json");
    for text in [sync, token] {
        for t in ["\"0.", "\"1.", "\"3.", "\"5.", "\"6.", "\"7."] {
            assert!(!text.contains(t), "unexpected EncString type {t}");
        }
    }
    let s: Value = serde_json::from_str(sync).unwrap();
    assert!(s["ciphers"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["key"].is_string()));
}

// ── The reserved approval field through the whole backend ─────────────────────

fn approval_items(a: &Account) -> Vec<Value> {
    let field = |k: &SymKey, value: Option<&str>| {
        json!([
            {"name": enc(k, "api"), "value": enc(k, "FV"), "type": 1, "linkedId": null},
            {"name": enc(k, "ferrowarden_approval"),
             "value": value.map(|v| enc(k, v)), "type": 0, "linkedId": null}
        ])
    };
    vec![
        login_item(
            "a1",
            &a.user,
            "guarded",
            json!({"fields": field(&a.user, Some("required"))}),
        ),
        login_item(
            "a2",
            &a.user,
            "typo",
            json!({"fields": field(&a.user, Some("requird"))}),
        ),
        login_item(
            "a3",
            &a.user,
            "blank",
            json!({"fields": field(&a.user, None)}),
        ),
        login_item("a4", &a.user, "ordinary", json!({})),
    ]
}

#[tokio::test]
async fn the_listing_carries_the_approval_flags_and_hides_the_field() {
    let h = harness_with(approval_items).await;
    h.vault.unlock(pw()).await.unwrap();
    let listing = h.vault.list_credentials().await.unwrap();
    let entry = |name: &str| listing.map[name][0].clone();
    assert!(entry("guarded").approval_required && !entry("guarded").approval_field_invalid);
    assert!(entry("typo").approval_required && entry("typo").approval_field_invalid);
    assert!(entry("blank").approval_required && entry("blank").approval_field_invalid);
    assert!(!entry("ordinary").approval_required && !entry("ordinary").approval_field_invalid);
    // The field is not offered as a custom field (so no placeholder can name it).
    for name in ["guarded", "typo", "blank"] {
        let names: Vec<_> = entry(name).fields.iter().map(|f| f.name.clone()).collect();
        assert_eq!(names, ["api"], "{name}");
    }
}

#[tokio::test]
async fn the_sync_reports_misspelt_approval_fields_once() {
    use crate::events::EventLog;
    use crate::vault::refresh::refresh_credentials;
    let h = harness_with(approval_items).await;
    let state =
        crate::state::AppState::try_new(h.config.clone(), Arc::new(EventLog::buffer_only(100)))
            .unwrap();
    state.vault.unlock(pw()).await.unwrap();
    refresh_credentials(&state).await.unwrap();
    state.set_unlocked().await;

    let syncs = event_json(&state, "vault_sync");
    assert_eq!(syncs.len(), 1);
    let d = &syncs[0]["ferrowarden"]["details"];
    assert_eq!(d["warnings"]["approval_field_invalid"], 2, "{d}");
    // Counts only: not the names of the items, nor the field's value.
    let text = syncs[0].to_string();
    for needle in ["guarded", "typo", "blank", "requird", "required"] {
        assert!(!text.contains(needle), "{needle}");
    }
    // The same number again is not news.
    refresh_credentials(&state).await.unwrap();
    assert_eq!(event_json(&state, "vault_sync").len(), 1);
    // The items that carry the field are all in the cache and flagged.
    let map = state.credentials.read().await;
    assert!(["guarded", "typo", "blank"]
        .iter()
        .all(|n| map[*n][0].approval_required));
}

// ── The managed collection and the write path ─────────────────────────────────

const COLL_MANAGED: &str = "0f9b3a52-1c1e-4a0e-9d57-1a2b3c4d5e6f";
const COLL_OTHER: &str = "6c0d7f0e-52d0-4b5b-8a39-0e8a7f6d5c4b";

fn raw_collection(a: &Account, id: &str, name: &str, read_only: bool, hide: bool) -> Value {
    json!({
        "id": id, "organizationId": "org1", "name": enc(&a.org, name),
        "readOnly": read_only, "hidePasswords": hide, "manage": !read_only,
        "externalId": null, "object": "collectionDetails"
    })
}

/// A vault with two writable collections in the organisation, the managed
/// one holding the item `orgitem` (c3).
async fn managed_harness(setting: &str) -> Harness {
    let mut h = harness().await;
    {
        let mut m = h.mock.lock().unwrap();
        m.collections = vec![
            raw_collection(&h.acct, COLL_OTHER, "Other", false, false),
            raw_collection(&h.acct, COLL_MANAGED, "Ferrowarden managed", false, false),
        ];
        for c in &mut m.ciphers {
            if c["id"] == "c3" {
                c["collectionIds"] = json!([COLL_MANAGED]);
            }
            if c["id"] == "c4" {
                c["collectionIds"] = json!([COLL_OTHER]);
            }
        }
    }
    h.config.vault.managed.collection = setting.to_string();
    h.vault = NativeVault::new(&h.config).unwrap();
    h
}

fn new_login() -> NewLogin {
    NewLogin {
        name: "agent_keycloak_admin".into(),
        username: Some("admin".into()),
        uris: vec!["https://keycloak.example.com".into()],
        password: Zeroizing::new("GENERATED-VALUE-0123456789".to_string()),
        created_by: "homelab-claude".into(),
        approval_required: false,
    }
}

fn set_collection(h: &Harness, id: &str, read_only: bool, hide: bool) {
    let mut m = h.mock.lock().unwrap();
    for c in &mut m.collections {
        if c["id"] == id {
            c["readOnly"] = json!(read_only);
            c["hidePasswords"] = json!(hide);
        }
    }
    m.revision += 1;
}

#[tokio::test]
async fn the_managed_collection_is_found_by_name_or_id_at_unlock() {
    for setting in ["Ferrowarden managed", COLL_MANAGED] {
        let h = managed_harness(setting).await;
        assert!(matches!(
            h.vault.managed_collection().await,
            Err(FerroError::VaultLocked)
        ));
        h.vault.unlock(pw()).await.unwrap();
        match h.vault.managed_collection().await.unwrap() {
            ManagedState::Usable(c) => {
                assert_eq!(c.id, COLL_MANAGED, "{setting}");
                assert_eq!(c.organization_id, "org1");
                assert_eq!(c.name, "Ferrowarden managed");
                // Its items are counted from the cipher's `collectionIds`:
                // c3 is in it, c4 is in the other one.
                assert_eq!(c.items, 1, "{setting}");
            }
            other => panic!("{setting}: {other:?}"),
        }
    }
}

#[tokio::test]
async fn without_the_setting_creating_is_off_and_nothing_is_sent() {
    let h = managed_harness("").await;
    h.vault.unlock(pw()).await.unwrap();
    assert_eq!(
        h.vault.managed_collection().await.unwrap(),
        ManagedState::Off
    );
    let e = h.vault.create_login(new_login()).await.unwrap_err();
    assert!(matches!(e, FerroError::CredentialCreateDisabled), "{e}");
    assert!(
        h.mock.lock().unwrap().create_auth.is_empty(),
        "no request was made"
    );
}

#[tokio::test]
async fn a_locked_vault_refuses_to_write() {
    let h = managed_harness(COLL_MANAGED).await;
    let e = h.vault.create_login(new_login()).await.unwrap_err();
    assert!(matches!(e, FerroError::VaultLocked), "{e}");
    assert!(h.mock.lock().unwrap().create_auth.is_empty());
}

#[tokio::test]
async fn a_view_only_or_hiding_collection_is_unavailable_and_refuses_writes() {
    for (read_only, hide, problem) in [
        (true, false, ManagedProblem::ReadOnly),
        (false, true, ManagedProblem::HidesPasswords),
    ] {
        let h = managed_harness(COLL_MANAGED).await;
        set_collection(&h, COLL_MANAGED, read_only, hide);
        h.vault.unlock(pw()).await.unwrap();
        match h.vault.managed_collection().await.unwrap() {
            ManagedState::Unavailable {
                problem: p,
                setting,
            } => {
                assert_eq!(p, problem);
                assert_eq!(setting, COLL_MANAGED);
            }
            other => panic!("{other:?}"),
        }
        let e = h.vault.create_login(new_login()).await.unwrap_err();
        assert!(
            matches!(e, FerroError::ManagedCollectionUnavailable(p) if p == problem),
            "{e}"
        );
        assert!(
            h.mock.lock().unwrap().create_auth.is_empty(),
            "nothing was sent"
        );
    }
}

#[tokio::test]
async fn a_missing_or_ambiguous_collection_is_unavailable() {
    let h = managed_harness("No such collection").await;
    h.vault.unlock(pw()).await.unwrap();
    assert!(matches!(
        h.vault.managed_collection().await.unwrap(),
        ManagedState::Unavailable {
            problem: ManagedProblem::NotFound,
            ..
        }
    ));

    let h = managed_harness("Other").await;
    {
        let mut m = h.mock.lock().unwrap();
        let dup = raw_collection(
            &h.acct,
            "11111111-1111-4111-8111-111111111111",
            "Other",
            false,
            false,
        );
        m.collections.push(dup);
    }
    h.vault.unlock(pw()).await.unwrap();
    assert!(matches!(
        h.vault.managed_collection().await.unwrap(),
        ManagedState::Unavailable {
            problem: ManagedProblem::Ambiguous,
            ..
        }
    ));
    let e = h.vault.create_login(new_login()).await.unwrap_err();
    assert!(matches!(
        e,
        FerroError::ManagedCollectionUnavailable(ManagedProblem::Ambiguous)
    ));
}

#[tokio::test]
async fn the_state_is_evaluated_again_on_every_sync() {
    let h = managed_harness(COLL_MANAGED).await;
    h.vault.unlock(pw()).await.unwrap();
    assert!(matches!(
        h.vault.managed_collection().await.unwrap(),
        ManagedState::Usable(_)
    ));
    // The owner takes edit rights away: the next sync notices, and writes stop.
    set_collection(&h, COLL_MANAGED, true, false);
    h.vault.sync().await.unwrap();
    assert!(matches!(
        h.vault.managed_collection().await.unwrap(),
        ManagedState::Unavailable {
            problem: ManagedProblem::ReadOnly,
            ..
        }
    ));
    assert!(h.vault.create_login(new_login()).await.is_err());
    assert!(h.mock.lock().unwrap().created.is_empty());
    // And back.
    set_collection(&h, COLL_MANAGED, false, false);
    h.vault.sync().await.unwrap();
    assert!(matches!(
        h.vault.managed_collection().await.unwrap(),
        ManagedState::Usable(_)
    ));
}

#[tokio::test]
async fn a_create_is_posted_to_the_managed_collection_and_nowhere_else() {
    let h = managed_harness("Ferrowarden managed").await;
    h.vault.unlock(pw()).await.unwrap();
    let id = h.vault.create_login(new_login()).await.unwrap();
    assert_eq!(id.as_deref(), Some("new-1"));

    let m = h.mock.lock().unwrap();
    assert_eq!(m.created.len(), 1);
    let body = &m.created[0];
    // Exactly the managed collection (not the other writable one), and its
    // organisation.
    assert_eq!(body["collectionIds"], json!([COLL_MANAGED]));
    assert_eq!(body["cipher"]["organizationId"], "org1");
    assert_eq!(body["cipher"]["encryptedFor"], USER_ID);
    assert!(body.as_object().unwrap().len() == 2);
    // With the session's bearer token.
    assert!(m.create_auth[0].starts_with("Bearer token-"));

    // Everything in it opens with the item key, which opens with the
    // organisation key; none of it is readable text.
    let text = body.to_string();
    for plain in [
        "GENERATED-VALUE-0123456789",
        "keycloak",
        "agent_keycloak_admin",
        "homelab-claude",
    ] {
        assert!(!text.contains(plain), "{plain}");
    }
    let c = &body["cipher"];
    let item_key = super::keys::unwrap_sym_key(&h.acct.org, c["key"].as_str().unwrap()).unwrap();
    let open = |v: &Value| {
        EncString::parse(v.as_str().unwrap())
            .unwrap()
            .decrypt_string(&item_key)
            .unwrap()
            .as_str()
            .to_string()
    };
    assert_eq!(open(&c["name"]), "agent_keycloak_admin");
    assert_eq!(open(&c["login"]["password"]), "GENERATED-VALUE-0123456789");
    assert_eq!(open(&c["login"]["username"]), "admin");
    assert_eq!(open(&c["fields"][0]["name"]), "ferrowarden_created_by");
    assert_eq!(open(&c["fields"][0]["value"]), "homelab-claude");
}

#[tokio::test]
async fn a_rejected_token_is_replaced_once_and_the_write_goes_through() {
    let h = managed_harness(COLL_MANAGED).await;
    h.vault.unlock(pw()).await.unwrap();
    let logins = h.mock.lock().unwrap().logins;
    h.mock.lock().unwrap().create_reject_once = true;
    h.vault.create_login(new_login()).await.unwrap();
    let m = h.mock.lock().unwrap();
    assert_eq!(m.logins, logins + 1, "one fresh login");
    assert_eq!(m.create_auth.len(), 2, "tried twice");
    assert_ne!(m.create_auth[0], m.create_auth[1], "with a new token");
    assert_eq!(m.created.len(), 1, "applied once");
}

#[tokio::test]
async fn a_server_error_is_not_retried_and_a_refusal_is_retried_once() {
    let h = managed_harness(COLL_MANAGED).await;
    h.vault.unlock(pw()).await.unwrap();
    // A 5xx may have been applied: it is not sent again, and the answer says
    // that the outcome is not known.
    h.mock.lock().unwrap().create_status = Some(500);
    let e = h.vault.create_login(new_login()).await.unwrap_err();
    assert!(matches!(e, FerroError::VaultWriteUnknown), "{e}");
    assert_eq!(h.mock.lock().unwrap().create_auth.len(), 1);
    // A 403 (no permission) is tried once more with a fresh login, then fails.
    h.mock.lock().unwrap().create_status = Some(403);
    let e = h.vault.create_login(new_login()).await.unwrap_err();
    assert!(matches!(e, FerroError::VaultWriteFailed), "{e}");
    assert_eq!(h.mock.lock().unwrap().create_auth.len(), 3);
    assert!(h.mock.lock().unwrap().created.is_empty());
    // Any other 4xx may have come after the item was saved: unknown, not sent
    // again.
    for status in [400, 422, 429] {
        let before = h.mock.lock().unwrap().create_auth.len();
        h.mock.lock().unwrap().create_status = Some(status);
        let e = h.vault.create_login(new_login()).await.unwrap_err();
        assert!(matches!(e, FerroError::VaultWriteUnknown), "{status}: {e}");
        assert_eq!(h.mock.lock().unwrap().create_auth.len(), before + 1);
    }
}

#[tokio::test]
async fn the_sync_reads_collections_and_collection_ids_of_the_real_shape() {
    // The shape Vaultwarden 1.36 and 1.37 send: the collection carries
    // `readOnly`, `hidePasswords` and `manage`; a cipher carries
    // `collectionIds`.
    let sync: super::api::SyncResponse = serde_json::from_value(json!({
        "profile": {"id": USER_ID, "email": EMAIL, "key": "k", "organizations": []},
        "ciphers": [{"id": "c", "type": 1, "collectionIds": [COLL_MANAGED, COLL_OTHER]}],
        "collections": [{
            "id": COLL_MANAGED, "organizationId": "org1", "name": "2.a|b|c",
            "externalId": null, "readOnly": false, "hidePasswords": false,
            "manage": true, "object": "collectionDetails"
        }]
    }))
    .unwrap();
    assert_eq!(sync.profile.id.as_deref(), Some(USER_ID));
    assert_eq!(sync.ciphers[0].collection_ids, [COLL_MANAGED, COLL_OTHER]);
    let c = &sync.collections[0];
    assert_eq!((c.read_only, c.hide_passwords), (Some(false), Some(false)));
    assert_eq!(c.organization_id.as_deref(), Some("org1"));
    // A sync without collections is an empty list.
    let none: super::api::SyncResponse = serde_json::from_value(json!({
        "profile": {"email": EMAIL}, "ciphers": []
    }))
    .unwrap();
    assert!(none.collections.is_empty());
}

mod rotation;
