pub mod admin;
pub mod credentials;
pub mod forward;
pub mod health;
pub mod strict_json;
pub mod unlock;

use axum::{
    middleware,
    routing::{delete, get, post},
    Extension, Router,
};
use std::sync::Arc;

use crate::config::split_list;
use crate::middleware::rate_limit::{rate_limit, LimitState};
use crate::middleware::request_context::{request_context, TrustedProxies};
use crate::net::Cidr;
use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    // Agent endpoints: configurable, default 120 requests/min sustained with a
    // burst of 20 — a single agent making one call per second (60/min) fits
    // with headroom. Validated > 0 in Config::validate.
    let agent_limiter = LimitState::new(
        "agent",
        state.config.agent_rate_limit_per_minute,
        state.config.agent_rate_limit_burst,
        state.events.clone(),
    );

    // Admin endpoints: configurable, default 30 requests/min sustained with a
    // burst of 5. Admin actions (unlock, key management, audit queries) are
    // infrequent by design; stricter limits slow down admin key guessing.
    let admin_limiter = LimitState::new(
        "admin",
        state.config.admin_rate_limit_per_minute,
        state.config.admin_rate_limit_burst,
        state.events.clone(),
    );

    // Validated in Config::validate, so every entry parses.
    let trusted = TrustedProxies(Arc::new(
        split_list(&state.config.trusted_proxies)
            .iter()
            .filter_map(|e| Cidr::parse(e))
            .collect(),
    ));

    // Layer ordering: Axum runs the last-added layer first.
    // Extension (outer, added second) adds the limiter to request extensions.
    // rate_limit middleware (inner, added first) reads it from extensions.
    // The client IP it keys on comes from the request-context middleware,
    // which wraps the whole router (see the end of this function).
    let agent_routes = Router::new()
        .route("/v1/forward", post(forward::forward))
        .route("/v1/credentials", get(credentials::list_credentials))
        .layer(middleware::from_fn(rate_limit))
        .layer(Extension(agent_limiter));

    let admin_routes = Router::new()
        .route("/v1/unlock", post(unlock::unlock))
        .route("/v1/admin/keys", post(admin::create_key))
        .route("/v1/admin/keys", get(admin::list_keys))
        .route("/v1/admin/keys/{id}", delete(admin::revoke_key))
        .route("/v1/admin/audit", get(admin::get_audit))
        .route("/v1/admin/status", get(admin::get_status))
        .layer(middleware::from_fn(rate_limit))
        .layer(Extension(admin_limiter));

    let api = agent_routes.merge(admin_routes);
    let prefix = state.config.api_prefix.clone();

    // Health check: public, no auth, no rate limit, never prefixed.
    // Used by Docker healthcheck and reverse proxies.
    let router = Router::new().route("/health", get(health::health));
    let router = if prefix.is_empty() {
        router.merge(api)
    } else {
        // Config::load normalizes the prefix to "/seg[/seg...]".
        router.nest(&prefix, api)
    };
    // Outermost layer, added last: every response (including /health, 404s and
    // 429s) gets an X-Request-Id, and the client IP is computed exactly once.
    router
        .with_state(state)
        .layer(middleware::from_fn_with_state(trusted, request_context))
}

#[cfg(test)]
mod tests {
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
        let cfg = Config {
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
            forward_timeout_secs: 5,
            trusted_proxies: String::new(),
            api_prefix: prefix.to_string(),
            agent_rate_limit_per_minute: 120,
            agent_rate_limit_burst: 20,
            admin_rate_limit_per_minute: 30,
            admin_rate_limit_burst: admin_burst,
            events: Default::default(),
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

    /// Create an agent key through the admin API; returns (id, token).
    async fn make_agent(app: &Router, name: &str) -> (String, String) {
        let (status, _, body) = call(
            app,
            "POST",
            "/v1/admin/keys",
            &[("x-admin-key", ADMIN_KEY)],
            Some(&format!(r#"{{"name":"{name}"}}"#)),
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
        assert_eq!(s, StatusCode::UNAUTHORIZED); // AgentKeyNotFound → 401, as before

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
}
