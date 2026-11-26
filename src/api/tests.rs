use super::*;
use crate::config::{Config, UnlockMode};
use crate::events::EventLog;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

fn app(prefix: &str) -> Router {
    app_with_state(prefix).0
}

/// Router plus state, with a high admin burst so tests can make many
/// admin calls; the rate-limit test uses [`build`] with the real default.
fn app_with_state(prefix: &str) -> (Router, Arc<AppState>) {
    build(prefix, 1000)
}

fn build(prefix: &str, admin_burst: u32) -> (Router, Arc<AppState>) {
    build_with(prefix, admin_burst, None)
}

fn build_with(
    prefix: &str,
    admin_burst: u32,
    keys_file: Option<std::path::PathBuf>,
) -> (Router, Arc<AppState>) {
    let cfg = Config {
        bind_addr: "127.0.0.1:3000".to_string(),
        bw_serve_url: "http://127.0.0.1:8087".to_string(),
        unlock_mode: UnlockMode::Manual,
        unlock_file: None,
        admin_key: "a".repeat(32).into(),
        keys_file,
        tls_enabled: false,
        tls_cert_file: None,
        tls_key_file: None,
        allow_private_targets: false,
        allowed_targets: String::new(),
        enforce_credential_hosts: true,
        refresh_interval_secs: 0,
        max_response_bytes: 1024,
        forward_timeout_secs: 5,
        trusted_proxies: String::new(),
        api_prefix: prefix.to_string(),
        agent_rate_limit_per_minute: 120,
        agent_rate_limit_burst: 20,
        admin_rate_limit_per_minute: 30,
        admin_rate_limit_burst: admin_burst,
        events: Default::default(),
        ui: Default::default(),
        notify: Default::default(),
        vault: Default::default(),
        metrics: Default::default(),
    };
    let state = Arc::new(AppState::new(cfg, Arc::new(EventLog::buffer_only(100))));
    (router(state.clone()), state)
}

async fn status(app: Router, path: &str) -> StatusCode {
    app.oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn default_routes_have_no_prefix() {
    assert_eq!(status(app(""), "/health").await, StatusCode::OK);
    // Reaches the handler: rejected for the missing agent key, not 404.
    assert_eq!(
        status(app(""), "/v1/credentials").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn prefix_moves_api_but_not_health() {
    assert_eq!(
        status(app("/k7f3q9"), "/k7f3q9/v1/credentials").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(app("/k7f3q9"), "/k7f3q9/v1/admin/status").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(app("/k7f3q9"), "/v1/credentials").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(status(app("/k7f3q9"), "/health").await, StatusCode::OK);
    assert_eq!(
        status(app("/k7f3q9"), "/k7f3q9/health").await,
        StatusCode::NOT_FOUND
    );
}

// ── Security events through the real router ───────────────────────────────

const ADMIN_KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    let mut req = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let body = match body {
        Some(b) => {
            req = req.header("content-type", "application/json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, headers, json)
}

/// Events with this action, newest first.
fn events_of(state: &AppState, action: &str) -> Vec<serde_json::Value> {
    state
        .events
        .recent(1000)
        .iter()
        .map(|e| serde_json::to_value(&**e).unwrap())
        .filter(|v| v["event"]["action"] == action)
        .collect()
}

fn all_events_text(state: &AppState) -> String {
    state
        .events
        .recent(1000)
        .iter()
        .map(|e| serde_json::to_string(&**e).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Create an unrestricted agent key through the admin API; returns
/// (id, token).
async fn make_agent(app: &Router, name: &str) -> (String, String) {
    make_agent_with(app, name, r#"["*"]"#, r#"["*"]"#).await
}

/// Create an agent key with the given policy (raw JSON arrays).
async fn make_agent_with(
    app: &Router,
    name: &str,
    credentials: &str,
    methods: &str,
) -> (String, String) {
    let (status, _, body) = call(
        app,
        "POST",
        "/v1/admin/keys",
        &[("x-admin-key", ADMIN_KEY)],
        Some(&format!(
            r#"{{"name":"{name}","credentials":{credentials},"methods":{methods}}}"#
        )),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    (
        body["id"].as_str().unwrap().to_string(),
        body["token"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn every_response_carries_a_fresh_request_id() {
    let app = app("");
    for path in ["/health", "/v1/credentials", "/nope"] {
        let (_, headers, _) = call(
            &app,
            "GET",
            path,
            &[("x-request-id", "attacker-chosen")],
            None,
        )
        .await;
        let id = headers["x-request-id"].to_str().unwrap();
        assert_ne!(id, "attacker-chosen", "{path}");
        assert!(uuid::Uuid::parse_str(id).is_ok(), "{path}");
    }
}

#[tokio::test]
async fn unauthenticated_bad_bodies_get_401_not_400_and_leak_nothing() {
    let (app, state) = app_with_state("");
    for (path, expected_action) in [
        ("/v1/forward", "agent_auth"),
        ("/v1/unlock", "admin_auth"),
        ("/v1/admin/keys", "admin_auth"),
    ] {
        for body in [
            r#"{"request": {"a":1, "a":2}}"#, // duplicate key
            r#"not json"#,
            r#"{"unknown_field": true}"#,
        ] {
            let (status, headers, json) = call(&app, "POST", path, &[], Some(body)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} {body}");
            let msg = json["error"].as_str().unwrap();
            assert!(!msg.contains("JSON") && !msg.contains("duplicate"), "{msg}");

            // The failure is recorded, with the same request id as the header.
            let last = &events_of(&state, expected_action)[0];
            assert_eq!(
                last["ferrowarden"]["request_id"],
                headers["x-request-id"].to_str().unwrap()
            );
            assert_eq!(last["ferrowarden"]["details"]["endpoint"], path);
        }
    }
    // No parse detail reached the stream before authentication.
    assert!(events_of(&state, "request_rejected").is_empty());
    // A missing body / content type is also just a 401.
    let (status, _, _) = call(&app, "POST", "/v1/forward", &[], None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_auth_failures_are_recorded_without_the_token() {
    let (app, state) = app_with_state("/k7f3q9");
    let presented = "presented-secret-token-0123456789";

    let (s1, _, _) = call(&app, "GET", "/k7f3q9/v1/credentials", &[], None).await;
    let (s2, _, _) = call(
        &app,
        "GET",
        "/k7f3q9/v1/credentials",
        &[("x-agent-key", presented)],
        None,
    )
    .await;
    assert_eq!(
        (s1, s2),
        (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED)
    );

    let events = events_of(&state, "agent_auth");
    assert_eq!(events.len(), 2);
    // newest first
    assert_eq!(events[0]["event"]["reason"], "invalid_key");
    assert_eq!(events[1]["event"]["reason"], "missing_key");
    for e in &events {
        assert_eq!(e["event"]["outcome"], "failure");
        assert_eq!(e["event"]["category"][0], "authentication");
        assert_eq!(e["source"]["ip"], "127.0.0.1");
        // Route template, not the raw (prefixed) path.
        assert_eq!(e["ferrowarden"]["details"]["endpoint"], "/v1/credentials");
    }
    let text = all_events_text(&state);
    assert!(
        !text.contains(presented),
        "presented token must not be logged"
    );
    assert!(!text.contains("presented-sec"), "nor a prefix of it");
    assert!(
        !text.contains("k7f3q9"),
        "api prefix must not appear in events"
    );
}

#[tokio::test]
async fn admin_auth_failures_are_recorded_on_every_admin_route() {
    let (app, state) = app_with_state("");
    let bad = "wrong-admin-key-wrong-admin-key-xx";
    let routes = [
        ("GET", "/v1/admin/status"),
        ("GET", "/v1/admin/audit"),
        ("GET", "/v1/admin/keys"),
        ("DELETE", "/v1/admin/keys/some-id"),
        ("POST", "/v1/unlock"),
    ];
    for (method, path) in routes {
        let (s, _, _) = call(&app, method, path, &[], None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
        let (s, _, _) = call(&app, method, path, &[("x-admin-key", bad)], None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}");
    }
    let events = events_of(&state, "admin_auth");
    assert_eq!(events.len(), routes.len() * 2);
    let reasons: Vec<_> = events
        .iter()
        .map(|e| e["event"]["reason"].clone())
        .collect();
    assert!(reasons.contains(&"missing_admin_key".into()));
    assert!(reasons.contains(&"invalid_admin_key".into()));
    assert!(!all_events_text(&state).contains(bad));
}

#[tokio::test]
async fn admin_auth_distinguishes_bearer_and_templates_the_route() {
    let (app, state) = app_with_state("");
    let (s, _, _) = call(
        &app,
        "DELETE",
        "/v1/admin/keys/abc",
        &[("authorization", "Bearer nope")],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = call(
        &app,
        "GET",
        "/v1/admin/status",
        &[("authorization", "Basic abc")],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let events = events_of(&state, "admin_auth");
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[1]["ferrowarden"]["details"]["endpoint"],
        "/v1/admin/keys/{id}"
    );
    assert_eq!(events[1]["event"]["reason"], "invalid_admin_key");
    assert_eq!(events[0]["event"]["reason"], "invalid_admin_key");
}

#[tokio::test]
async fn authenticated_bad_body_is_recorded_as_request_rejected() {
    let (app, state) = app_with_state("");
    let (id, token) = make_agent(&app, "rejecter").await;

    let (status, _, json) = call(
        &app,
        "POST",
        "/v1/forward",
        &[("x-agent-key", &token)],
        Some(r#"{"request":{"method":"GET","url":"http://x","url":"http://y"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let client_msg = json["error"].as_str().unwrap().to_string();

    let events = events_of(&state, "request_rejected");
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e["event"]["reason"], "invalid_json");
    assert_eq!(e["event"]["type"][0], "denied");
    assert_eq!(e["ferrowarden"]["key"]["id"], id.as_str());
    assert_eq!(e["ferrowarden"]["key"]["name"], "rejecter");
    assert_eq!(e["ferrowarden"]["details"]["endpoint"], "/v1/forward");
    // Exactly the sanitized message the client got.
    assert_eq!(e["ferrowarden"]["details"]["error"], client_msg.as_str());

    // A bad query is rejected the same way.
    let (status, _, _) = call(
        &app,
        "GET",
        "/v1/credentials?detial=true",
        &[("x-agent-key", &token)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let events = events_of(&state, "request_rejected");
    assert_eq!(events[0]["event"]["reason"], "invalid_request");
    assert_eq!(
        events[0]["ferrowarden"]["details"]["endpoint"],
        "/v1/credentials"
    );
}

#[tokio::test]
async fn key_lifecycle_emits_events_without_token_or_hash() {
    let (app, state) = app_with_state("");
    let admin = [("x-admin-key", ADMIN_KEY)];
    let (id, token) = make_agent(&app, "lifecycle").await;

    let (s, _, _) = call(&app, "GET", "/v1/admin/keys", &admin, None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = call(
        &app,
        "DELETE",
        &format!("/v1/admin/keys/{id}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = call(
        &app,
        "DELETE",
        "/v1/admin/keys/does-not-exist",
        &admin,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND); // unknown key id → 404

    let create = &events_of(&state, "key_create")[0];
    assert_eq!(create["event"]["category"][0], "iam");
    assert_eq!(create["event"]["type"][0], "creation");
    assert_eq!(create["ferrowarden"]["details"]["key_id"], id.as_str());
    assert_eq!(create["ferrowarden"]["details"]["key_name"], "lifecycle");

    assert_eq!(
        events_of(&state, "key_list")[0]["ferrowarden"]["details"]["count"],
        1
    );

    let revokes = events_of(&state, "key_revoke");
    assert_eq!(revokes.len(), 2);
    assert_eq!(revokes[1]["event"]["outcome"], "success");
    assert_eq!(revokes[1]["event"]["type"][0], "deletion");
    assert_eq!(revokes[1]["ferrowarden"]["details"]["key_id"], id.as_str());
    assert_eq!(
        revokes[1]["ferrowarden"]["details"]["key_name"],
        "lifecycle"
    );
    assert_eq!(revokes[0]["event"]["outcome"], "failure");
    assert_eq!(revokes[0]["event"]["reason"], "key_not_found");

    let text = all_events_text(&state);
    assert!(!text.contains(&token), "token leaked into an event");
    assert!(
        !text.contains(&crate::keys::hash_token(&token)),
        "token hash leaked into an event"
    );
    assert!(!text.contains(ADMIN_KEY));
}

#[tokio::test]
async fn credentials_list_event_reports_outcome_and_count() {
    let (app, state) = app_with_state("");
    let (id, token) = make_agent(&app, "lister").await;
    let agent = [("x-agent-key", token.as_str())];

    // Vault is locked in this test state.
    let (s, _, _) = call(&app, "GET", "/v1/credentials?detail=true", &agent, None).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    let e = &events_of(&state, "credentials_list")[0];
    assert_eq!(e["event"]["outcome"], "failure");
    assert_eq!(e["event"]["reason"], "vault_locked");
    assert_eq!(e["ferrowarden"]["key"]["id"], id.as_str());
    assert_eq!(e["ferrowarden"]["details"]["detail"], true);

    state.set_unlocked().await;
    let (s, _, _) = call(&app, "GET", "/v1/credentials", &agent, None).await;
    assert_eq!(s, StatusCode::OK);
    let e = &events_of(&state, "credentials_list")[0];
    assert_eq!(e["event"]["outcome"], "success");
    assert_eq!(e["event"]["category"][0], "web");
    assert_eq!(e["http"]["response"]["status_code"], 200);
    assert_eq!(e["ferrowarden"]["details"]["detail"], false);
    assert_eq!(e["ferrowarden"]["details"]["count"], 0);
}

#[tokio::test]
async fn forward_failure_event_has_reason_status_and_url_before_substitution() {
    let (app, state) = app_with_state("");
    let (_, token) = make_agent(&app, "fw").await;
    state.set_unlocked().await;

    let body = r#"{"request":{"method":"POST","url":"https://api.example.com/x?token={{vault:t}}","headers":{"Authorization":"Bearer {{vault:other}}"}}}"#;
    let (s, _, _) = call(
        &app,
        "POST",
        "/v1/forward",
        &[("x-agent-key", &token)],
        Some(body),
    )
    .await;
    // Neither credential exists in the (empty) cache.
    assert!(s.is_client_error(), "{s}");
    let e = &events_of(&state, "forward")[0];
    assert_eq!(e["event"]["outcome"], "failure");
    assert_eq!(e["event"]["reason"], "unknown_credential");
    assert_eq!(e["http"]["response"]["status_code"], s.as_u16());
    assert_eq!(e["http"]["request"]["method"], "POST");
    assert_eq!(
        e["url"]["original"],
        "https://api.example.com/x?token={{vault:t}}"
    );
    assert_eq!(e["url"]["domain"], "api.example.com");
    assert_eq!(
        e["ferrowarden"]["credentials"],
        serde_json::json!(["other", "t"])
    );
    assert!(e["event"]["duration"].is_u64());
}

#[tokio::test]
async fn audit_endpoint_returns_events_newest_first_with_strict_limit() {
    let (app, state) = app_with_state("");
    let admin = [("x-admin-key", ADMIN_KEY)];
    for _ in 0..3 {
        call(&app, "GET", "/v1/admin/status", &admin, None).await;
    }

    let (s, _, all) = call(&app, "GET", "/v1/admin/audit", &admin, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(all.as_array().unwrap().len(), 3);
    assert_eq!(all[0]["event"]["action"], "status_read");
    // This read is not part of its own response, but is recorded after.
    assert_eq!(events_of(&state, "audit_read").len(), 1);

    let (_, _, two) = call(&app, "GET", "/v1/admin/audit?limit=2", &admin, None).await;
    assert_eq!(two.as_array().unwrap().len(), 2);
    assert_eq!(two[0]["event"]["action"], "audit_read");
}

#[tokio::test]
async fn audit_endpoint_query_is_strict() {
    // A fresh router per call keeps each under the admin burst limit.
    for bad in [
        "limit=0",
        "limit=101",
        "limit=x",
        "foo=1",
        "limit=1&limit=2",
    ] {
        let (app, state) = app_with_state("");
        let (s, _, _) = call(
            &app,
            "GET",
            &format!("/v1/admin/audit?{bad}"),
            &[("x-admin-key", ADMIN_KEY)],
            None,
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(events_of(&state, "request_rejected").len(), 1, "{bad}");
    }
}

#[tokio::test]
async fn rate_limited_requests_emit_one_aggregated_event_with_the_limiter_name() {
    let (app, state) = build("", 5);
    // Admin burst is 5: the sixth and later requests are 429.
    let mut limited = 0;
    for _ in 0..12 {
        let (s, headers, _) = call(&app, "GET", "/v1/admin/status", &[], None).await;
        if s == StatusCode::TOO_MANY_REQUESTS {
            limited += 1;
            assert!(headers.contains_key("x-request-id"));
        }
    }
    assert!(limited >= 6);
    let events = events_of(&state, "rate_limited");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["ferrowarden"]["details"]["limiter"], "admin");
    assert_eq!(events[0]["event"]["category"][0], "network");
}

/// The 429 the spec describes: plain text, `Retry-After` in whole seconds
/// (at least 1) and an `X-Request-Id`.
#[tokio::test]
async fn the_429_response_matches_the_spec() {
    let spec = openapi::parse_spec().unwrap();
    let documented = &spec["components"]["responses"]["RateLimited"];
    assert!(documented["content"]["text/plain"].is_object());
    assert!(documented["headers"]["Retry-After"].is_object());
    assert!(documented["headers"]["X-Request-Id"].is_object());
    assert_eq!(
        spec["components"]["headers"]["RetryAfter"]["schema"]["minimum"],
        1
    );

    let app = build("", 2).0;
    let mut seen = None;
    for _ in 0..6 {
        let resp = app
            .clone()
            .oneshot(
                Request::get("/v1/admin/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            seen = Some(resp);
            break;
        }
    }
    let resp = seen.expect("the admin limiter answers 429");
    let content_type = resp.headers()["content-type"].to_str().unwrap().to_string();
    assert!(content_type.starts_with("text/plain"), "{content_type}");
    let retry: u64 = resp.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry >= 1);
    assert!(resp.headers().contains_key("x-request-id"));
}

// ── Per-key policy ────────────────────────────────────────────────────────

use crate::vault::model::CredentialEntry;
use serde_json::json;

const ADMIN: [(&str, &str); 1] = [("x-admin-key", ADMIN_KEY)];

async fn admin(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let (s, _, j) = call(app, method, path, &ADMIN, body).await;
    (s, j)
}

/// Cache a few credentials (no vault is involved: only names and
/// metadata) and unlock.
async fn seed(state: &AppState) {
    let mut creds = state.credentials.write().await;
    for (name, uri) in [
        ("lab_nas", "https://nas.lab"),
        ("lab_router", "https://router.lab"),
        ("prod_db", "https://db.prod"),
    ] {
        creds.insert(name.to_string(), vec![CredentialEntry::login("1", &[uri])]);
    }
    drop(creds);
    state.set_unlocked().await;
}

async fn forward_as(
    app: &Router,
    token: &str,
    method: &str,
    url: &str,
) -> (StatusCode, serde_json::Value) {
    let body = json!({"request": {"method": method, "url": url}}).to_string();
    let (s, _, j) = call(
        app,
        "POST",
        "/v1/forward",
        &[("x-agent-key", token)],
        Some(&body),
    )
    .await;
    (s, j)
}

#[tokio::test]
async fn create_requires_both_policy_fields_and_rejects_null() {
    let (app, state) = app_with_state("");
    for (body, needle) in [
        (r#"{"name":"a"}"#, "missing field `credentials`"),
        (
            r#"{"name":"a","credentials":["*"]}"#,
            "missing field `methods`",
        ),
        (
            r#"{"name":"a","methods":["*"]}"#,
            "missing field `credentials`",
        ),
        (
            r#"{"name":"a","credentials":null,"methods":["*"]}"#,
            "`credentials` must be an array of strings, not null",
        ),
        (
            r#"{"name":"a","credentials":["*"],"methods":null}"#,
            "`methods` must be an array of strings, not null",
        ),
        (
            r#"{"name":"a","credentials":"*","methods":["*"]}"#,
            "`credentials`",
        ),
        (
            r#"{"name":"a","credentials":[""],"methods":["*"]}"#,
            "pattern",
        ),
        (
            r#"{"name":"a","credentials":["*"],"methods":["TRACE"]}"#,
            "unsupported method",
        ),
        (
            r#"{"name":"a","credentials":["*"],"methods":["*","GET"]}"#,
            "only entry",
        ),
    ] {
        let (s, j) = admin(&app, "POST", "/v1/admin/keys", Some(body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
        let msg = j["error"].as_str().unwrap();
        assert!(msg.contains(needle), "{body}: {msg}");
    }
    assert!(state.agent_keys.read().await.is_empty(), "nothing created");
}

#[tokio::test]
async fn create_and_list_report_the_normalised_policy() {
    let (app, _state) = app_with_state("");
    let (s, j) = admin(
            &app,
            "POST",
            "/v1/admin/keys",
            Some(r#"{"name":"mon","credentials":["uptime_*","uptime_*"],"methods":["get","Head","GET"]}"#),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(j["credentials"], json!(["uptime_*"]));
    assert_eq!(j["methods"], json!(["GET", "HEAD"]));
    assert_eq!(j["policy_set"], true);

    let (_, list) = admin(&app, "GET", "/v1/admin/keys", None).await;
    assert_eq!(list[0]["credentials"], json!(["uptime_*"]));
    assert_eq!(list[0]["methods"], json!(["GET", "HEAD"]));
    assert_eq!(list[0]["policy_set"], true);
    assert!(!list.to_string().contains("null"));
}

#[tokio::test]
async fn scoped_key_lists_only_matching_credentials_with_filtered_count() {
    let (app, state) = app_with_state("");
    seed(&state).await;
    let (_, token) = make_agent_with(&app, "lab", r#"["lab_*"]"#, r#"["*"]"#).await;
    let agent = [("x-agent-key", token.as_str())];

    let (s, _, plain) = call(&app, "GET", "/v1/credentials", &agent, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(plain, json!(["lab_nas", "lab_router"]));
    let (_, _, detail) = call(&app, "GET", "/v1/credentials?detail=true", &agent, None).await;
    let names: Vec<&str> = detail
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["lab_nas", "lab_router"]);
    let events = events_of(&state, "credentials_list");
    assert_eq!(events[0]["ferrowarden"]["details"]["count"], 2);
    assert_eq!(events[1]["ferrowarden"]["details"]["count"], 2);

    let (_, none) = make_agent_with(&app, "none", "[]", r#"["*"]"#).await;
    let (_, _, empty) = call(
        &app,
        "GET",
        "/v1/credentials",
        &[("x-agent-key", none.as_str())],
        None,
    )
    .await;
    assert_eq!(empty, json!([]));
}

#[tokio::test]
async fn out_of_scope_forward_is_403_before_vault_or_target_and_has_no_existence_oracle() {
    let (app, state) = app_with_state("");
    // The vault is LOCKED and the cache holds `prod_db`: if the policy
    // check ran after the vault or target checks we would see 503/other.
    state
        .credentials
        .write()
        .await
        .insert("prod_db".into(), vec![CredentialEntry::login("1", &[])]);
    let (_, token) = make_agent_with(&app, "lab", r#"["lab_*"]"#, r#"["GET"]"#).await;

    // `http://127.0.0.1:1` would be a target-policy failure if reached.
    let url = |name: &str| format!("http://127.0.0.1:1/x?k={{{{vault:{name}}}}}");
    let (s1, b1) = forward_as(&app, &token, "GET", &url("prod_db")).await;
    let (s2, b2) = forward_as(&app, &token, "GET", &url("no_such_credential")).await;
    assert_eq!(s1, StatusCode::FORBIDDEN);
    assert_eq!(s2, StatusCode::FORBIDDEN);
    assert_eq!(
        b1["error"],
        "Credential prod_db is not available to this agent key"
    );
    assert_eq!(
        b2["error"],
        "Credential no_such_credential is not available to this agent key"
    );
    // Same shape: only the echoed name differs.
    assert_eq!(
        b1["error"].as_str().unwrap().replace("prod_db", "X"),
        b2["error"]
            .as_str()
            .unwrap()
            .replace("no_such_credential", "X")
    );

    let events = events_of(&state, "forward");
    for e in &events {
        assert_eq!(e["event"]["outcome"], "failure");
        assert_eq!(e["event"]["reason"], "credential_out_of_scope");
        assert_eq!(e["event"]["type"], json!(["access", "denied"]));
        assert_eq!(e["http"]["response"]["status_code"], 403);
    }
    assert_eq!(
        events[0]["ferrowarden"]["credentials"],
        json!(["no_such_credential"])
    );
}

#[tokio::test]
async fn scope_is_checked_before_unknown_and_method_before_scope() {
    let (app, state) = app_with_state("");
    seed(&state).await;
    let (_, token) = make_agent_with(&app, "lab", r#"["lab_*"]"#, r#"["GET"]"#).await;

    // In-scope unknown name + out-of-scope name: scope wins (403, not 422).
    let url = "http://127.0.0.1:1/?a={{vault:lab_missing}}&b={{vault:prod_db}}";
    let (s, b) = forward_as(&app, &token, "GET", url).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
    // In-scope unknown name alone is the ordinary unknown-credential 422.
    let (s, _) = forward_as(
        &app,
        &token,
        "GET",
        "http://a.example/?a={{vault:lab_missing}}",
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    // Method policy comes first.
    let (s, b) = forward_as(&app, &token, "POST", url).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(b["error"], "Method POST is not allowed for this agent key");
    let e = &events_of(&state, "forward")[0];
    assert_eq!(e["event"]["reason"], "method_not_allowed");
}

#[tokio::test]
async fn trace_and_unknown_methods_are_400_for_every_key() {
    let (app, state) = app_with_state("");
    let (_, token) = make_agent(&app, "open").await;
    for m in ["TRACE", "CONNECT", "FOO", "", "get x"] {
        let (s, _) = forward_as(&app, &token, m, "http://a.example/").await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{m:?}");
    }
    assert_eq!(
        events_of(&state, "forward")[0]["event"]["reason"],
        "invalid_request"
    );
    // Lower case is accepted and normalised (and then fails later, not as
    // a method error: the vault is locked here).
    let (s, _) = forward_as(&app, &token, "get", "http://a.example/").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn empty_credentials_cannot_use_placeholders_but_plain_forwards_pass_the_policy() {
    let (app, state) = app_with_state("");
    seed(&state).await;
    let (_, token) = make_agent_with(&app, "none", "[]", r#"["GET"]"#).await;
    let (s, _) = forward_as(&app, &token, "GET", "http://a.example/?k={{vault:lab_nas}}").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // No placeholders: the policy passes. (It then fails at the target
    // check or the network, which is the ordinary forward flow.)
    let (s, b) = forward_as(&app, &token, "GET", "ftp://a.example/").await;
    assert_ne!(s, StatusCode::FORBIDDEN, "{b}");
    let (s, _) = forward_as(&app, &token, "POST", "ftp://a.example/").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "method [GET] only");
}

#[tokio::test]
async fn patch_semantics_absent_value_null_empty_and_unknown_id() {
    let (app, state) = app_with_state("");
    seed(&state).await;
    let (id, token) = make_agent_with(&app, "p", r#"["lab_*"]"#, r#"["GET"]"#).await;
    let path = format!("/v1/admin/keys/{id}");
    let agent = [("x-agent-key", token.as_str())];

    // Nothing to change / null / wrong type / unknown field: 400.
    for body in [
        "{}",
        r#"{"credentials":null}"#,
        r#"{"methods":null}"#,
        r#"{"credentials":null,"methods":["*"]}"#,
        r#"{"methods":"GET"}"#,
        r#"{"credential":["*"]}"#,
    ] {
        let (s, j) = admin(&app, "PATCH", &path, Some(body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {j}");
    }
    let (_, j) = admin(&app, "PATCH", &path, Some(r#"{"credentials":null}"#)).await;
    assert!(j["error"].as_str().unwrap().contains("`credentials`"));
    // Nothing changed.
    let (_, _, listed) = call(&app, "GET", "/v1/credentials", &agent, None).await;
    assert_eq!(listed, json!(["lab_nas", "lab_router"]));

    // Absent field unchanged; present field replaced; immediate effect on
    // the same token.
    let (s, j) = admin(&app, "PATCH", &path, Some(r#"{"credentials":["prod_*"]}"#)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j["credentials"], json!(["prod_*"]));
    assert_eq!(j["methods"], json!(["GET"]));
    let (_, _, listed) = call(&app, "GET", "/v1/credentials", &agent, None).await;
    assert_eq!(listed, json!(["prod_db"]));

    // Widen with ["*"]; narrow with [].
    let (_, j) = admin(
        &app,
        "PATCH",
        &path,
        Some(r#"{"credentials":["*"],"methods":["*"]}"#),
    )
    .await;
    assert_eq!(j["credentials"], json!(["*"]));
    let (_, _, listed) = call(&app, "GET", "/v1/credentials", &agent, None).await;
    assert_eq!(listed.as_array().unwrap().len(), 3);
    admin(&app, "PATCH", &path, Some(r#"{"credentials":[]}"#)).await;
    let (_, _, listed) = call(&app, "GET", "/v1/credentials", &agent, None).await;
    assert_eq!(listed, json!([]));

    // Unknown ids: 404 for patch, preview and revoke.
    for (m, p, b) in [
        ("PATCH", "/v1/admin/keys/nope", Some(r#"{"methods":["*"]}"#)),
        ("POST", "/v1/admin/keys/nope/preview", Some("{}")),
        ("DELETE", "/v1/admin/keys/nope", None),
    ] {
        let (s, _) = admin(&app, m, p, b).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{m} {p}");
    }
}

#[tokio::test]
async fn patch_emits_key_policy_change_with_before_and_after() {
    let (app, state) = app_with_state("");
    let (id, token) = make_agent_with(&app, "audited", r#"["a"]"#, r#"["GET"]"#).await;
    let path = format!("/v1/admin/keys/{id}");
    admin(&app, "PATCH", &path, Some(r#"{"methods":["post"]}"#)).await;
    admin(&app, "PATCH", &path, Some("{}")).await;
    admin(
        &app,
        "PATCH",
        "/v1/admin/keys/missing",
        Some(r#"{"methods":["*"]}"#),
    )
    .await;

    let events = events_of(&state, "key_policy_change");
    assert_eq!(events.len(), 3);
    let ok = &events[2];
    assert_eq!(ok["event"]["category"][0], "iam");
    assert_eq!(ok["event"]["type"][0], "change");
    assert_eq!(ok["event"]["outcome"], "success");
    let d = &ok["ferrowarden"]["details"];
    assert_eq!(d["key_id"], id.as_str());
    assert_eq!(d["key_name"], "audited");
    assert_eq!(
        d["before"],
        json!({"credentials": ["a"], "methods": ["GET"]})
    );
    assert_eq!(
        d["after"],
        json!({"credentials": ["a"], "methods": ["POST"]})
    );
    assert_eq!(events[1]["event"]["reason"], "invalid_request");
    assert_eq!(events[0]["event"]["reason"], "key_not_found");
    assert_eq!(events[0]["http"]["response"]["status_code"], 404);

    let create = &events_of(&state, "key_create")[0];
    assert_eq!(
        create["ferrowarden"]["details"]["credentials"],
        json!(["a"])
    );
    assert_eq!(create["ferrowarden"]["details"]["methods"], json!(["GET"]));
    assert!(!all_events_text(&state).contains(&token));
}

#[tokio::test]
async fn preview_diffs_draft_against_saved_and_saves_nothing() {
    let (app, state) = app_with_state("");
    seed(&state).await;
    let (id, _) = make_agent_with(&app, "pv", r#"["lab_*"]"#, r#"["*"]"#).await;
    let path = format!("/v1/admin/keys/{id}/preview");
    let (_, before) = admin(&app, "GET", "/v1/admin/keys", None).await;

    let (s, j) = admin(
        &app,
        "POST",
        &path,
        Some(r#"{"credentials":["lab_nas","prod_*"],"methods":["GET"]}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["key"]["name"], "pv");
    assert_eq!(
        j["saved_policy"],
        json!({"credentials": ["lab_*"], "methods": ["*"]})
    );
    assert_eq!(
        j["draft_policy"],
        json!({"credentials": ["lab_nas", "prod_*"], "methods": ["GET"]})
    );
    assert_eq!(j["gained"], json!(["prod_db"]));
    assert_eq!(j["lost"], json!(["lab_router"]));
    let names: Vec<&str> = j["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["lab_nas", "prod_db"]);
    assert!(j.get("request_check").is_none());

    // Absent draft fields mean the saved value: no diff.
    let (_, same) = admin(&app, "POST", &path, Some("{}")).await;
    assert_eq!(same["gained"], json!([]));
    assert_eq!(same["lost"], json!([]));
    assert_eq!(same["draft_policy"], same["saved_policy"]);

    // null anywhere is rejected, including request.
    for body in [
        r#"{"credentials":null}"#,
        r#"{"methods":null}"#,
        r#"{"request":null}"#,
    ] {
        let (s, _) = admin(&app, "POST", &path, Some(body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    }
    let (s, _) = admin(
        &app,
        "POST",
        &path,
        Some(r#"{"credentials":["*"],"extra":1}"#),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Nothing was saved.
    let (_, after) = admin(&app, "GET", "/v1/admin/keys", None).await;
    assert_eq!(before, after);

    let ev = &events_of(&state, "policy_preview")[0];
    assert_eq!(ev["event"]["category"][0], "iam");
    assert_eq!(ev["event"]["type"][0], "access");
}

#[tokio::test]
async fn preview_request_check_reports_what_a_forward_would() {
    let (app, state) = app_with_state("");
    seed(&state).await;
    let (id, _) = make_agent_with(&app, "pv", r#"["lab_*"]"#, r#"["GET"]"#).await;
    let path = format!("/v1/admin/keys/{id}/preview");
    let check = |method: &str, url: &str, headers: serde_json::Value| {
        json!({"request": {"method": method, "url": url, "headers": headers}}).to_string()
    };
    let run = |body: String| {
        let app = app.clone();
        let path = path.clone();
        async move { admin(&app, "POST", &path, Some(&body)).await.1["request_check"].clone() }
    };

    let ok = run(check(
        "get",
        "https://nas.lab/api?k={{vault:lab_nas}}",
        json!({}),
    ))
    .await;
    assert_eq!(ok["allowed"], true);
    assert!(ok.get("reason").is_none());
    assert!(ok["note"].as_str().unwrap().contains("DNS"));

    let scope = run(check(
        "GET",
        "https://db.prod/",
        json!({"A": "{{vault:prod_db}}"}),
    ))
    .await;
    assert_eq!(scope["allowed"], false);
    assert_eq!(scope["status"], 403);
    assert_eq!(scope["reason"], "credential_out_of_scope");
    // Identical for a name that does not exist.
    let ghost = run(check(
        "GET",
        "https://db.prod/",
        json!({"A": "{{vault:ghost}}"}),
    ))
    .await;
    assert_eq!(ghost["status"], 403);
    assert_eq!(ghost["reason"], "credential_out_of_scope");

    let method = run(check("POST", "https://nas.lab/", json!({}))).await;
    assert_eq!(
        (method["status"].as_u64(), method["reason"].as_str()),
        (Some(403), Some("method_not_allowed"))
    );
    let bad_method = run(check("TRACE", "https://nas.lab/", json!({}))).await;
    assert_eq!(
        (bad_method["status"].as_u64(), bad_method["reason"].as_str()),
        (Some(400), Some("invalid_request"))
    );
    let dup = run(check("GET", "https://nas.lab/", json!({"a":"1","A":"2"}))).await;
    assert_eq!(dup["status"], 400);

    let bound = run(check(
        "GET",
        "https://evil.example/?k={{vault:lab_nas}}",
        json!({}),
    ))
    .await;
    assert_eq!(bound["reason"], "credential_host_not_allowed");
    assert_eq!(bound["status"], 403);
    let unknown = run(check(
        "GET",
        "https://nas.lab/?k={{vault:lab_ghost}}",
        json!({}),
    ))
    .await;
    assert_eq!(unknown["reason"], "unknown_credential");
    assert_eq!(unknown["status"], 422);
    let malformed = run(check("GET", "https://nas.lab/?k={{vault:}}", json!({}))).await;
    assert_eq!(malformed["reason"], "malformed_placeholder");
    let target = run(check("GET", "ftp://nas.lab/", json!({}))).await;
    assert_eq!(target["reason"], "invalid_target_url");

    // A draft in the request body is what the request is checked against.
    let draft = json!({"credentials": ["*"], "methods": ["*"],
            "request": {"method": "POST", "url": "https://db.prod/?k={{vault:prod_db}}"}})
    .to_string();
    let r = run(draft).await;
    assert_eq!(r["allowed"], true, "{r}");
}

#[tokio::test]
async fn preview_needs_a_credential_list_when_the_vault_is_locked() {
    let (app, state) = app_with_state("");
    let (id, _) = make_agent(&app, "pv").await;
    let path = format!("/v1/admin/keys/{id}/preview");
    // Locked, no cache: 503, like GET /v1/credentials.
    let (s, _) = admin(&app, "POST", &path, Some("{}")).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    // Locked with a cache: answers from the cache.
    seed(&state).await;
    state.set_locked("test").await;
    let (s, j) = admin(&app, "POST", &path, Some("{}")).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["credentials"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn preview_and_patch_require_admin_before_parsing() {
    let (app, _state) = app_with_state("");
    for (m, p) in [
        ("PATCH", "/v1/admin/keys/x"),
        ("POST", "/v1/admin/keys/x/preview"),
    ] {
        let (s, _, j) = call(&app, m, p, &[], Some("not json")).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{m} {p}");
        assert!(!j["error"].as_str().unwrap().contains("JSON"));
    }
}

#[tokio::test]
async fn legacy_key_file_entries_load_deny_all_until_patched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.json");
    let legacy_token = "legacy-token-for-tests";
    let file = json!([
        {"id": "legacy-id", "name": "old", "token_hash": crate::keys::hash_token(legacy_token),
         "created_at": "2024-01-01T00:00:00Z"},
        {"id": "new-id", "name": "new", "token_hash": crate::keys::hash_token("new-token"),
         "created_at": "2024-01-01T00:00:00Z", "credentials": ["*"], "methods": ["*"]},
    ]);
    std::fs::write(&path, file.to_string()).unwrap();

    let (app, state) = build_with("", 1000, Some(path.clone()));
    let n = state.load_keys(&path).await.unwrap();
    assert_eq!(n, 1, "one key without a policy");
    seed(&state).await;

    let (_, list) = admin(&app, "GET", "/v1/admin/keys", None).await;
    let by_name = |n: &str| {
        list.as_array()
            .unwrap()
            .iter()
            .find(|k| k["name"] == n)
            .unwrap()
            .clone()
    };
    assert_eq!(by_name("old")["policy_set"], false);
    assert_eq!(by_name("old")["credentials"], json!([]));
    assert_eq!(by_name("old")["methods"], json!([]));
    assert_eq!(by_name("new")["policy_set"], true);

    // Deny-all: lists nothing, forwards nothing.
    let agent = [("x-agent-key", legacy_token)];
    let (s, _, listed) = call(&app, "GET", "/v1/credentials", &agent, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(listed, json!([]));
    let (s, _) = forward_as(&app, legacy_token, "GET", "http://a.example/").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = forward_as(
        &app,
        legacy_token,
        "GET",
        "http://a.example/?k={{vault:lab_nas}}",
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // A partial PATCH leaves the other field deny-all, but marks it set.
    let (s, j) = admin(
        &app,
        "PATCH",
        "/v1/admin/keys/legacy-id",
        Some(r#"{"credentials":["lab_*"]}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j["policy_set"], true);
    assert_eq!(j["methods"], json!([]));
    let (s, _) = forward_as(&app, legacy_token, "GET", "http://a.example/").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "no methods yet");

    // Both fields: usable. The file now has explicit fields.
    let (s, _) = admin(
        &app,
        "PATCH",
        "/v1/admin/keys/legacy-id",
        Some(r#"{"methods":["GET"]}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, _, listed) = call(&app, "GET", "/v1/credentials", &agent, None).await;
    assert_eq!(listed, json!(["lab_nas", "lab_router"]));
    let stored = crate::keys::load(&path).unwrap();
    assert!(stored.iter().all(|k| k.policy_set()));

    // A fresh load sees no legacy keys any more.
    let (_app2, state2) = build_with("", 1000, Some(path.clone()));
    assert_eq!(state2.load_keys(&path).await.unwrap(), 0);
}

#[tokio::test]
async fn null_in_the_key_file_fails_the_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.json");
    std::fs::write(
            &path,
            r#"[{"id":"i","name":"n","token_hash":"h","created_at":"2024-01-01T00:00:00Z","credentials":null,"methods":["*"]}]"#,
        )
        .unwrap();
    let (_app, state) = build_with("", 1000, Some(path.clone()));
    assert!(state.load_keys(&path).await.is_err());
    assert!(state.agent_keys.read().await.is_empty());
}

#[tokio::test]
async fn startup_event_reports_keys_without_policy() {
    let (_app, state) = app_with_state("");
    let e = serde_json::to_value(crate::startup_event(&state.config, 3, 2)).unwrap();
    assert_eq!(e["ferrowarden"]["details"]["keys_without_policy"], 2);
    assert_eq!(e["ferrowarden"]["details"]["agent_key_count"], 3);
}

#[tokio::test]
async fn startup_event_reports_the_metrics_settings() {
    use crate::config::{MetricsConfig, MetricsToken};
    let (_app, state) = app_with_state("");
    let details = |config: &Config| {
        let e = serde_json::to_value(crate::startup_event(config, 0, 0)).unwrap();
        e["ferrowarden"]["details"].clone()
    };
    // Off (the default).
    let d = details(&state.config);
    assert_eq!(d["metrics_enabled"], false);
    assert_eq!(d["metrics_tls"], false);
    assert_eq!(d["metrics_credential_labels"], false);

    let mut config = state.config.clone();
    config.metrics = MetricsConfig {
        bind: "127.0.0.1:9095".into(),
        token: MetricsToken(Some("0123456789abcdef0123".to_string().into())),
        ..Default::default()
    };
    let d = details(&config);
    assert_eq!(d["metrics_enabled"], true);
    assert_eq!(d["metrics_auth"], "token");
    assert_eq!(d["metrics_tls"], false);
    // The token itself is nowhere in it.
    let all = serde_json::to_string(&crate::startup_event(&config, 0, 0)).unwrap();
    assert!(!all.contains("0123456789abcdef0123"));

    config.tls_enabled = true;
    config.metrics.token = MetricsToken(None);
    config.metrics.allow_unauthenticated = true;
    config.metrics.credential_labels = true;
    let d = details(&config);
    assert_eq!(d["metrics_auth"], "none");
    assert_eq!(d["metrics_tls"], true);
    assert_eq!(d["metrics_credential_labels"], true);
}

#[tokio::test]
async fn startup_event_reports_whether_hidden_passwords_are_allowed() {
    let (_app, state) = app_with_state("");
    let e = serde_json::to_value(crate::startup_event(&state.config, 0, 0)).unwrap();
    assert_eq!(
        e["ferrowarden"]["details"]["vault_allow_hidden_passwords"],
        false
    );
    let mut config = state.config.clone();
    config.vault.allow_hidden_passwords = true;
    let e = serde_json::to_value(crate::startup_event(&config, 0, 0)).unwrap();
    assert_eq!(
        e["ferrowarden"]["details"]["vault_allow_hidden_passwords"],
        true
    );
}

#[tokio::test]
async fn startup_event_and_admin_status_name_the_vault_backend() {
    let (_app, state) = app_with_state("");
    let e = serde_json::to_value(crate::startup_event(&state.config, 0, 0)).unwrap();
    assert_eq!(e["ferrowarden"]["details"]["vault_backend"], "bw-serve");
    let mut config = state.config.clone();
    config.vault.backend = crate::config::VaultBackend::Native;
    let e = serde_json::to_value(crate::startup_event(&config, 0, 0)).unwrap();
    assert_eq!(e["ferrowarden"]["details"]["vault_backend"], "native");

    let app = router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/admin/status")
                .header("X-Admin-Key", "a".repeat(32))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(body["vault_backend"], "bw-serve");
}
// ── POST /v1/admin/notify/test ────────────────────────────────────────────

/// Router and state with the notifier started against `notify`.
fn build_notify(notify: crate::config::NotifyConfig) -> (Router, Arc<AppState>) {
    let (_, state) = build("", 1000);
    let mut state = Arc::try_unwrap(state).ok().expect("sole owner");
    state.config.notify = notify;
    let notify = crate::notify::start_with(
        &state.config.notify,
        &state.events,
        crate::notify::senders::SendOptions {
            timeout: std::time::Duration::from_secs(2),
            retry_delays: vec![std::time::Duration::from_millis(10)],
        },
    )
    .unwrap();
    let state = Arc::new(state.with_notify(notify));
    (router(state.clone()), state)
}

fn webhook_config(base: &str) -> crate::config::NotifyConfig {
    crate::config::NotifyConfig {
        webhook_url: format!("{base}/secret-hook-path/abc123"),
        allow_http: true,
        min_interval_secs: 0,
        tokens: crate::config::NotifyTokens {
            webhook: Some(zeroize::Zeroizing::new("hook-token-ZZZ-9876".into())),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[tokio::test]
async fn the_test_endpoint_needs_the_admin_key() {
    let (app, state) = app_with_state("");
    for headers in [
        vec![],
        vec![("x-admin-key", "nope")],
        vec![("x-agent-key", "an-agent-key")],
    ] {
        let (s, _, _) = call(&app, "POST", "/v1/admin/notify/test", &headers, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(events_of(&state, "admin_auth").len(), 3);
    assert!(events_of(&state, "notify_test").is_empty());
    let (s, _, _) = call(
        &app,
        "GET",
        "/v1/admin/notify/test",
        &[("x-admin-key", ADMIN_KEY)],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn the_test_endpoint_without_a_notifier_reports_an_empty_list() {
    let (app, state) = app_with_state("");
    let (s, _, body) = call(
        &app,
        "POST",
        "/v1/admin/notify/test",
        &[("x-admin-key", ADMIN_KEY)],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body, json!({ "results": [] }));
    let e = &events_of(&state, "notify_test")[0];
    assert_eq!(e["event"]["outcome"], "success");
    assert_eq!(e["ferrowarden"]["details"]["senders"], 0);
    assert_eq!(e["ferrowarden"]["details"]["via"], "api");
}

#[tokio::test]
async fn the_test_endpoint_sends_to_the_notifier_and_allows_one_per_ten_seconds() {
    let recv = crate::notify::tests::receiver(vec![], std::time::Duration::ZERO).await;
    let (app, state) = build_notify(webhook_config(&recv.url));
    let admin = [("x-admin-key", ADMIN_KEY)];

    let (s, _, body) = call(&app, "POST", "/v1/admin/notify/test", &admin, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "results": [{ "sender": "webhook", "ok": true, "status": 200 }] })
    );
    let got = recv.requests();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].path, "/secret-hook-path/abc123");
    assert_eq!(
        got[0].headers["authorization"],
        "Bearer hook-token-ZZZ-9876"
    );
    let payload: serde_json::Value = serde_json::from_str(&got[0].body).unwrap();
    assert_eq!(payload["title"], "Ferrowarden: test notification");
    assert_eq!(payload["category"], "system");

    // A second one right away is refused like a rate limit.
    let (s, headers, _) = call(&app, "POST", "/v1/admin/notify/test", &admin, None).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = headers["retry-after"].to_str().unwrap().parse().unwrap();
    assert!((1..=10).contains(&retry));
    assert!(headers["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/plain"));
    assert!(headers.contains_key("x-request-id"));
    assert_eq!(recv.requests().len(), 1, "nothing more was sent");

    assert_eq!(events_of(&state, "notify_test").len(), 1);
    let limited = events_of(&state, "rate_limited");
    assert_eq!(
        limited[0]["ferrowarden"]["details"]["limiter"],
        "notify_test"
    );
    // The test itself is never turned into a notification.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(recv.requests().len(), 1);
}

#[tokio::test]
async fn a_failing_notifier_is_reported_without_urls_or_tokens() {
    let recv = crate::notify::tests::receiver(vec![403], std::time::Duration::ZERO).await;
    let (app, state) = build_notify(webhook_config(&recv.url));
    let (s, _, body) = call(
        &app,
        "POST",
        "/v1/admin/notify/test",
        &[("x-admin-key", ADMIN_KEY)],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        body,
        json!({ "results": [{
                "sender": "webhook", "ok": false, "status": 403,
                "error": "the notifier answered HTTP 403"
            }] })
    );
    let text = body.to_string();
    for bad in ["secret-hook-path", "abc123", "127.0.0.1", "hook-token"] {
        assert!(!text.contains(bad), "{bad}");
    }
    let e = &events_of(&state, "notify_test")[0];
    assert_eq!(e["event"]["outcome"], "failure");
    assert_eq!(e["event"]["reason"], "upstream_error");
    assert_eq!(e["ferrowarden"]["details"]["failed"], 1);
    let events = serde_json::to_string(&events_of(&state, "notify_test")).unwrap();
    assert!(!events.contains("hook-token") && !events.contains("secret-hook-path"));
}

#[tokio::test]
async fn a_blocked_forward_through_the_router_reaches_the_notifier_with_allow_listed_fields() {
    let recv = crate::notify::tests::receiver(vec![], std::time::Duration::ZERO).await;
    let (app, state) = build_notify(webhook_config(&recv.url));
    seed(&state).await;
    let (_, token) = make_agent_with(&app, "lab", r#"["lab_*"]"#, r#"["GET"]"#).await;
    let url = "https://db.prod/api/v1/rows?apikey={{vault:prod_db}}&q=1";
    let (s, _) = forward_as(&app, &token, "GET", url).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    let got = recv.wait_for(1).await;
    let payload: serde_json::Value = serde_json::from_str(&got[0].body).unwrap();
    assert_eq!(payload["category"], "blocked");
    assert_eq!(payload["event"]["reason"], "credential_out_of_scope");
    assert_eq!(payload["event"]["key_name"], "lab");
    assert_eq!(payload["event"]["target_host"], "db.prod");
    assert_eq!(payload["event"]["credentials"], json!(["prod_db"]));
    let text = got[0].body.clone();
    for bad in [
        "/api/v1/rows",
        "apikey",
        "q=1",
        "{{",
        token.as_str(),
        ADMIN_KEY,
    ] {
        assert!(!text.contains(bad), "{bad} in {text}");
    }
}

#[tokio::test]
async fn repeated_bad_agent_keys_make_one_auth_failure_notification() {
    let recv = crate::notify::tests::receiver(vec![], std::time::Duration::ZERO).await;
    let mut cfg = webhook_config(&recv.url);
    cfg.min_interval_secs = 60;
    let (app, _state) = build_notify(cfg);
    for _ in 0..8 {
        let (s, _, _) = call(
            &app,
            "GET",
            "/v1/credentials",
            &[("x-agent-key", "wrong-key-0123456789")],
            None,
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    let got = recv.wait_for(1).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        recv.requests().len(),
        1,
        "one notification, the rest suppressed"
    );
    let payload: serde_json::Value = serde_json::from_str(&got[0].body).unwrap();
    assert_eq!(payload["category"], "auth_failure");
    assert_eq!(payload["event"]["count"], 5);
    assert!(!got[0].body.contains("wrong-key"));
}

// ── The route table and docs/openapi.yaml ─────────────────────────────────

#[test]
fn the_route_table_and_the_spec_describe_the_same_routes() {
    let table: std::collections::BTreeSet<(String, String)> = ROUTES
        .iter()
        .map(|r| (r.method.to_string(), r.path.to_string()))
        .collect();
    assert_eq!(table.len(), ROUTES.len(), "a route is listed twice");

    let spec = openapi::parse_spec().unwrap();
    let documented = openapi::operations(&spec);

    let undocumented: Vec<_> = table.difference(&documented).collect();
    let unserved: Vec<_> = documented.difference(&table).collect();
    assert!(
        undocumented.is_empty() && unserved.is_empty(),
        "routes missing from docs/openapi.yaml: {undocumented:?}; \
             operations in docs/openapi.yaml that are not routes: {unserved:?}"
    );
}

/// The table drives the router: every entry answers with its own method
/// (not 404 or 405), with and without a prefix, and /health is never
/// prefixed. Methods the table does not list for a path are 405.
#[tokio::test]
async fn every_route_in_the_table_is_served_with_its_method() {
    for prefix in ["", "/k7f3q9"] {
        let app = app(prefix);
        for r in ROUTES {
            let path = r.path.replace("{id}", "some-id");
            let full = if r.group == Group::Public {
                path.clone()
            } else {
                format!("{prefix}{path}")
            };
            let (s, _, _) = call(&app, r.method, &full, &[], None).await;
            assert!(
                s != StatusCode::NOT_FOUND && s != StatusCode::METHOD_NOT_ALLOWED,
                "{} {full} -> {s}",
                r.method
            );
            for other in ["GET", "POST", "PATCH", "DELETE"] {
                let listed = ROUTES.iter().any(|o| o.path == r.path && o.method == other);
                if !listed {
                    let (s, _, _) = call(&app, other, &full, &[], None).await;
                    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED, "{other} {full}");
                }
            }
        }
    }
}

// ── GET /v1/openapi.json ──────────────────────────────────────────────────

#[tokio::test]
async fn openapi_needs_a_key() {
    let (app, state) = app_with_state("/k7f3q9");
    for (headers, action, reason) in [
        (vec![], "agent_auth", "missing_key"),
        (vec![("x-agent-key", "nope")], "agent_auth", "invalid_key"),
        (
            vec![("x-admin-key", "wrong-admin-key-wrong-admin-key-xx")],
            "admin_auth",
            "invalid_admin_key",
        ),
        (
            vec![("authorization", "Bearer wrong")],
            "admin_auth",
            "invalid_admin_key",
        ),
    ] {
        let (s, h, body) = call(&app, "GET", "/k7f3q9/v1/openapi.json", &headers, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        // Nothing of the document, and no prefix, in an unauthenticated answer.
        assert_eq!(body.as_object().map(|o| o.len()), Some(1));
        assert!(!body.to_string().contains("k7f3q9"));
        assert!(h.get("x-request-id").is_some());
        let e = &events_of(&state, action)[0];
        assert_eq!(e["event"]["reason"], reason);
        assert_eq!(e["ferrowarden"]["details"]["endpoint"], "/v1/openapi.json");
    }
    assert!(events_of(&state, "openapi_read").is_empty());
    assert!(!all_events_text(&state).contains("k7f3q9"));
}

#[tokio::test]
async fn openapi_gives_each_key_its_own_view() {
    let (app, state) = app_with_state("/k7f3q9");
    let (s, _, created) = call(
        &app,
        "POST",
        "/k7f3q9/v1/admin/keys",
        &[("x-admin-key", ADMIN_KEY)],
        Some(r#"{"name":"reader","credentials":["*"],"methods":["*"]}"#),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let token = created["token"].as_str().unwrap().to_string();

    let path = "/k7f3q9/v1/openapi.json";
    let (s, h, agent) = call(&app, "GET", path, &[("x-agent-key", &token)], None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["content-type"], "application/json");
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(agent["servers"][0]["url"], "/k7f3q9");
    assert!(agent["paths"]["/v1/forward"].is_object());
    assert!(agent["paths"].get("/v1/admin/keys").is_none());
    assert!(agent["paths"].get("/v1/unlock").is_none());

    for headers in [
        vec![("x-admin-key", ADMIN_KEY)],
        vec![("authorization", "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")],
    ] {
        let (s, _, admin) = call(&app, "GET", path, &headers, None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(admin["servers"][0]["url"], "/k7f3q9");
        assert!(admin["paths"]["/v1/admin/keys"].is_object());
        assert!(admin["paths"]["/v1/unlock"].is_object());
        assert!(admin["components"]["schemas"]["SecurityEvent"].is_object());
    }

    // Recorded with the variant, and the agent's key on the agent read.
    let reads = events_of(&state, "openapi_read");
    assert_eq!(reads.len(), 3);
    let variants: Vec<_> = reads
        .iter()
        .map(|e| e["ferrowarden"]["details"]["variant"].as_str().unwrap())
        .collect();
    assert_eq!(variants, ["admin", "admin", "agent"]);
    assert_eq!(reads[2]["ferrowarden"]["key"]["name"], "reader");
    assert!(reads[0]["ferrowarden"].get("key").is_none());
    assert_eq!(reads[2]["event"]["category"][0], "web");
    assert_eq!(reads[2]["event"]["type"][0], "access");
    assert_eq!(reads[2]["http"]["response"]["status_code"], 200);
    let text = all_events_text(&state);
    assert!(!text.contains("k7f3q9"), "the prefix is not logged");
    assert!(!text.contains(&token));
}

#[tokio::test]
async fn openapi_without_a_prefix_serves_slash() {
    let app = app("");
    let (s, _, doc) = call(
        &app,
        "GET",
        "/v1/openapi.json",
        &[("x-admin-key", ADMIN_KEY)],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(doc["servers"][0]["url"], "/");
    assert_eq!(doc["openapi"], "3.1.0");
}

#[tokio::test]
async fn openapi_query_is_strict_after_authentication() {
    let (app, state) = app_with_state("");
    let (_, token) = make_agent(&app, "reader").await;
    // Unauthenticated: 401, not 400.
    let (s, _, _) = call(&app, "GET", "/v1/openapi.json?x=1", &[], None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    for q in ["?x=1", "?pretty", "?a=1&a=2"] {
        let uri = format!("/v1/openapi.json{q}");
        let (s, _, _) = call(&app, "GET", &uri, &[("x-agent-key", &token)], None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{q}");
        let (s, _, _) = call(&app, "GET", &uri, &[("x-admin-key", ADMIN_KEY)], None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{q}");
    }
    let rejected = events_of(&state, "request_rejected");
    assert_eq!(rejected.len(), 6);
    assert_eq!(
        rejected[0]["ferrowarden"]["details"]["endpoint"],
        "/v1/openapi.json"
    );
    assert!(events_of(&state, "openapi_read").is_empty());
}

#[tokio::test]
async fn openapi_shares_the_agent_rate_limit_even_for_the_admin_key() {
    let burst = 20; // the agent burst in `build_with`
    let app = app("");
    let mut limited = None;
    for i in 0..(burst + 5) {
        let (s, h, _) = call(
            &app,
            "GET",
            "/v1/openapi.json",
            &[("x-admin-key", ADMIN_KEY)],
            None,
        )
        .await;
        if s == StatusCode::TOO_MANY_REQUESTS {
            limited = Some((i, h));
            break;
        }
    }
    let (i, h) = limited.expect("the agent limiter applies");
    assert_eq!(i, burst, "burst of the agent limiter");
    assert!(h.get("retry-after").is_some());
    // The admin limiter is a separate bucket and still has room.
    let (s, _, _) = call(
        &app,
        "GET",
        "/v1/admin/status",
        &[("x-admin-key", ADMIN_KEY)],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}
