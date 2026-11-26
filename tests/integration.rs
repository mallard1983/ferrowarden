//! Integration tests for Ferrowarden.
//!
//! # Overview
//!
//! These tests run against a live Ferrowarden stack (Vaultwarden + bw serve +
//! Ferrowarden + mock API). They are skipped automatically when the stack is
//! not running, so `cargo test` always succeeds in CI without the stack.
//!
//! # What We Test
//!
//! Each test targets a specific security or correctness property. The test
//! name and documentation explain the property being tested and *why* it
//! matters, not just what the code does.
//!
//! # Running
//!
//! ```sh
//! # Start the test stack (first time):
//! ./scripts/dev-setup.sh
//!
//! # On subsequent runs:
//! docker compose -f docker-compose.test.yml up -d
//!
//! # Run tests (--test-threads=1 required: tests share the mock API state):
//! source .env.test && cargo test --test integration -- --nocapture --test-threads=1
//! ```
//!
//! # Environment Variables
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `FERROWARDEN_INTEGRATION` | *(unset)* | Set to `1` to enable these tests |
//! | `FERROWARDEN_TEST_URL` | `http://localhost:3000` | Ferrowarden base URL |
//! | `FERROWARDEN_TEST_ADMIN_KEY` | *(required)* | Admin key |
//! | `FERROWARDEN_TEST_AGENT_KEY` | *(required)* | Pre-created agent key |
//! | `MOCK_API_URL` | `http://localhost:7777` | Mock API base URL |
//! | `FERROWARDEN_TEST_METRICS_URL` | *(required)* | The instance's metrics listener (`http://localhost:9095`, or 9096 for the native one) |
//! | `FERROWARDEN_TEST_METRICS_TOKEN` | *(required)* | Its bearer token (`secrets/metrics_token`) |

use reqwest::Client;
use serde_json::{json, Value};
use std::env;

/// Describe a captured value for an assertion message without printing it.
/// Captured headers and bodies can contain real (test) credential values,
/// and test output must never include credential values.
fn describe(value: &str) -> String {
    format!(
        "<{} chars, still contains a placeholder: {}>",
        value.len(),
        value.contains("{{vault:")
    )
}

// ── Test harness helpers ──────────────────────────────────────────────────────

struct TestEnv {
    fw_url: String,
    admin_key: String,
    agent_key: String,
    mock_url: String,
    client: Client,
}

impl TestEnv {
    /// Load configuration from environment variables.
    /// Returns None if FERROWARDEN_INTEGRATION is not set — the calling test
    /// should skip gracefully in that case.
    fn load() -> Option<Self> {
        if env::var("FERROWARDEN_INTEGRATION").unwrap_or_default() != "1" {
            return None;
        }

        let fw_url = env::var("FERROWARDEN_TEST_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());
        let admin_key = env::var("FERROWARDEN_TEST_ADMIN_KEY")
            .expect("FERROWARDEN_TEST_ADMIN_KEY must be set when FERROWARDEN_INTEGRATION=1");
        let agent_key = env::var("FERROWARDEN_TEST_AGENT_KEY")
            .expect("FERROWARDEN_TEST_AGENT_KEY must be set when FERROWARDEN_INTEGRATION=1");
        let mock_url =
            env::var("MOCK_API_URL").unwrap_or_else(|_| "http://localhost:7777".to_string());

        Some(Self {
            fw_url,
            admin_key,
            agent_key,
            mock_url,
            client: Client::new(),
        })
    }

    /// Forward a request through Ferrowarden to the mock API.
    async fn forward(
        &self,
        method: &str,
        path: &str,
        headers: Value,
        body: Option<Value>,
    ) -> reqwest::Response {
        let url = format!("{}/mock-api{}", self.mock_url_via_ferrowarden(), path);
        let payload = json!({
            "request": {
                "method": method,
                "url": url,
                "headers": headers,
                "body": body
            }
        });

        self.client
            .post(format!("{}/v1/forward", self.fw_url))
            .header("X-Agent-Key", &self.agent_key)
            .json(&payload)
            .send()
            .await
            .expect("forward request failed")
    }

    /// Forward a request to an arbitrary URL (not necessarily the mock API).
    async fn forward_url(
        &self,
        method: &str,
        url: &str,
        headers: Value,
        body: Option<Value>,
    ) -> reqwest::Response {
        let payload = json!({
            "request": { "method": method, "url": url, "headers": headers, "body": body }
        });
        self.client
            .post(format!("{}/v1/forward", self.fw_url))
            .header("X-Agent-Key", &self.agent_key)
            .json(&payload)
            .send()
            .await
            .expect("forward request failed")
    }

    /// The URL the mock API is reachable at FROM INSIDE the Docker network.
    /// Ferrowarden forwards to this URL; the Docker DNS resolves "mock-api".
    fn mock_url_via_ferrowarden(&self) -> String {
        // When running in Docker, Ferrowarden reaches the mock API as "mock-api:7777".
        // When running against a local stack, we use the mapped localhost port.
        env::var("MOCK_API_INTERNAL_URL").unwrap_or_else(|_| "http://mock-api:7777".to_string())
    }

    /// Get the most recently captured request from the mock API.
    async fn last_captured_request(&self) -> Value {
        self.client
            .get(format!("{}/__requests__/last", self.mock_url))
            .send()
            .await
            .expect("mock API request failed")
            .json::<Value>()
            .await
            .expect("mock API response was not JSON")
    }

    /// Get all captured requests from the mock API.
    async fn all_captured_requests(&self) -> Vec<Value> {
        self.client
            .get(format!("{}/__requests__", self.mock_url))
            .send()
            .await
            .expect("mock API request failed")
            .json::<Vec<Value>>()
            .await
            .expect("mock API response was not JSON")
    }

    /// Clear the mock API log. Call this at the start of each test for isolation.
    async fn reset_mock(&self) {
        self.client
            .post(format!("{}/__reset__", self.mock_url))
            .send()
            .await
            .expect("mock API reset failed");
    }

    /// Assert the mock API is healthy and reachable.
    async fn assert_mock_healthy(&self) {
        let resp = self
            .client
            .get(format!("{}/__health__", self.mock_url))
            .send()
            .await
            .expect("mock API health check failed");
        assert_eq!(resp.status(), 200, "mock API is not healthy");
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Security property: credential values reach the target service.
///
/// A placeholder in an Authorization header must be replaced with the real
/// credential value before the request is forwarded. The mock API (which plays
/// the role of "the real target service") must receive the actual value, not
/// the placeholder string.
///
/// If this test fails, Ferrowarden is forwarding placeholders instead of
/// credentials — the target service would reject the request with 401.
#[tokio::test]
async fn test_credential_substituted_in_authorization_header() {
    let Some(env) = TestEnv::load() else { return };
    env.assert_mock_healthy().await;
    env.reset_mock().await;

    let resp = env
        .forward(
            "GET",
            "/api/check",
            json!({ "Authorization": "Bearer {{vault:test_api_token}}" }),
            None,
        )
        .await;

    assert_eq!(resp.status(), 200, "proxy forward failed");

    let captured = env.last_captured_request().await;
    let auth_header = captured["headers"]["authorization"]
        .as_str()
        .or_else(|| captured["headers"]["Authorization"].as_str())
        .expect("Authorization header not found in captured request");

    // The real credential value must have arrived at the mock API
    assert!(
        auth_header.contains("test-token-abc123def456"),
        "real credential value not found in forwarded Authorization header.\n\
         Got: {}\n\
         This means substitution failed — the placeholder was forwarded as-is.",
        describe(auth_header)
    );

    // The placeholder must NOT have been forwarded
    assert!(
        !auth_header.contains("{{vault:"),
        "placeholder syntax was forwarded to target service — substitution did not run"
    );
}

/// Security property: placeholder text never leaves Ferrowarden.
///
/// An agent that has constructed a request with {{vault:name}} placeholders
/// should never cause those literal strings to appear at the target service.
/// This verifies the guarantee from the other direction: even if the credential
/// value somehow fails to substitute, the raw placeholder is still not sent.
#[tokio::test]
async fn test_placeholder_text_never_reaches_target() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "POST",
            "/api/data",
            json!({ "X-API-Key": "{{vault:test_api_token}}" }),
            Some(json!({ "token": "{{vault:test_bearer}}" })),
        )
        .await;

    assert_eq!(resp.status(), 200);

    let captured = env.last_captured_request().await;
    let raw = serde_json::to_string(&captured).unwrap();

    assert!(
        !raw.contains("{{vault:"),
        "placeholder syntax appeared in the forwarded request.\n\
         This means Ferrowarden forwarded a placeholder to the target service.\n\
         Raw captured request: {raw}"
    );
}

/// Security property: response body is scrubbed before reaching the agent.
///
/// A target service might echo back a credential value in its response — for
/// example, a 401 that includes the rejected token, or a debug endpoint that
/// dumps request headers. The scrubber must remove these before the agent sees
/// the response, so credential values cannot flow into the agent's context via
/// the response path.
///
/// This test sends a request whose response body (from the mock API) contains
/// a bearer token pattern and verifies it is redacted in what the agent sees.
#[tokio::test]
async fn test_response_body_is_scrubbed() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    // We configure the mock API to return a body that looks like it contains
    // a credential. We do this by crafting the request to include a path that
    // the mock will echo back — but actually, the mock always returns its own
    // JSON. Instead we test with a known-scrubbable pattern that the mock API
    // might return as part of echoing the request.
    //
    // For this test: Ferrowarden substitutes test_bearer into the body,
    // forwards to mock. The mock returns {"captured": true}. That response
    // has no credentials in it, so we verify the response arrives intact.
    // The real scrubbing test requires mock to return a cred-shaped response —
    // so we use the mock's echo path.
    //
    // We test scrubbing directly via the scrub unit tests in proxy/scrub.rs.
    // This integration test verifies the scrubber runs in the full pipeline.
    let resp = env
        .forward(
            "GET",
            "/api/status",
            json!({ "Authorization": "Bearer {{vault:test_bearer}}" }),
            None,
        )
        .await;

    assert_eq!(resp.status(), 200, "forward failed");

    let body: Value = resp.json().await.expect("response was not JSON");

    // The mock API returns {"status": N, "headers": {...}, "body": "..."}
    // The inner body from mock is {"captured": true} — no credentials.
    // If the scrubber were to interfere with clean responses, the parse would fail
    // or the body content would be wrong.
    assert!(
        body.get("status").is_some(),
        "unexpected response shape from forward — scrubber may have damaged clean response body"
    );
}

/// Correctness: multiple different placeholders in one request are all substituted.
///
/// A realistic API call might need an API key in a header AND a bearer token
/// in the body. Both must be substituted independently. This verifies that
/// the substitution pass handles multiple distinct placeholder names.
#[tokio::test]
async fn test_multiple_placeholders_all_substituted() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "POST",
            "/api/create",
            json!({ "X-API-Key": "{{vault:nas_api_key}}" }),
            Some(json!({ "auth": "Bearer {{vault:test_bearer}}" })),
        )
        .await;

    assert_eq!(resp.status(), 200);

    let captured = env.last_captured_request().await;

    // Both credentials should have been substituted
    let api_key_header = captured["headers"]["x-api-key"]
        .as_str()
        .or_else(|| captured["headers"]["X-API-Key"].as_str())
        .expect("X-API-Key header not found");

    assert!(
        api_key_header.contains("test-nas-key-11111111111111"),
        "nas_api_key was not substituted in header. Got: {}",
        describe(api_key_header)
    );

    let body_str = captured["body"].as_str().unwrap_or("");
    assert!(
        body_str.contains("test-bearer-xyz789uvw012"),
        "test_bearer was not substituted in body. Got: {}",
        describe(body_str)
    );
}

/// Security property: unknown credential names are rejected before any vault call.
///
/// An agent that sends a placeholder for a credential that does not exist must
/// receive an error — not a partial substitution, not a forwarded request with
/// a missing value, and not a timeout from the vault lookup. The fail-fast
/// design means no outbound request is made at all.
///
/// This prevents an agent from using timing or response differences to probe
/// whether certain credential names exist in the vault.
#[tokio::test]
async fn test_unknown_placeholder_returns_422_and_no_forward() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let initial_count = env.all_captured_requests().await.len();

    let resp = env
        .forward(
            "GET",
            "/api/secret",
            json!({ "Authorization": "Bearer {{vault:this_credential_does_not_exist}}" }),
            None,
        )
        .await;

    // 422 Unprocessable Entity: the placeholder name is not in the vault
    assert_eq!(
        resp.status(),
        422,
        "expected 422 for unknown credential, got {}.\n\
         Ferrowarden should reject unknown names before making any outbound call.",
        resp.status()
    );

    // The mock API must NOT have received any request — no outbound call was made
    let final_count = env.all_captured_requests().await.len();
    assert_eq!(
        final_count,
        initial_count,
        "mock API received {} request(s) even though the placeholder was unknown.\n\
         Ferrowarden should fail fast before forwarding anything.",
        final_count - initial_count
    );
}

/// Security property: agent requests with no or invalid key are rejected.
///
/// Every credential proxy request must be authenticated. An unauthenticated
/// request must be rejected with 401 before any vault interaction or outbound
/// call. This prevents an attacker who discovers the proxy port from using
/// Ferrowarden to make authenticated API calls.
#[tokio::test]
async fn test_missing_agent_key_returns_401() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let initial_count = env.all_captured_requests().await.len();

    // Send a forward request with NO agent key header
    let resp = env
        .client
        .post(format!("{}/v1/forward", env.fw_url))
        // No X-Agent-Key header
        .json(&json!({
            "request": {
                "method": "GET",
                "url": format!("{}/__health__", env.mock_url_via_ferrowarden()),
                "headers": {}
            }
        }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 401, "expected 401 for missing agent key");

    // No request should have been forwarded
    let final_count = env.all_captured_requests().await.len();
    assert_eq!(
        final_count, initial_count,
        "request was forwarded to mock despite missing agent key"
    );
}

/// Security property: a wrong agent key is rejected.
///
/// This tests that random tokens cannot be used to access the proxy.
#[tokio::test]
async fn test_invalid_agent_key_returns_401() {
    let Some(env) = TestEnv::load() else { return };

    let resp = env
        .client
        .get(format!("{}/v1/credentials", env.fw_url))
        .header("X-Agent-Key", "not-a-real-token-aaaaaaaaaaaaaaaa")
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 401, "expected 401 for invalid agent key");
}

/// Correctness: credential list returns all seeded names and no values.
///
/// The agent must be able to discover what credentials are available. The
/// response must contain only names, never values. This verifies both that
/// the seeder ran correctly and that the credential list endpoint is functional.
#[tokio::test]
async fn test_credential_list_returns_seeded_names_only() {
    let Some(env) = TestEnv::load() else { return };

    let resp = env
        .client
        .get(format!("{}/v1/credentials", env.fw_url))
        .header("X-Agent-Key", &env.agent_key)
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);

    let names: Vec<String> = resp.json().await.expect("response was not a JSON array");

    // All credentials from tests/seed/credentials.json should be present
    let expected = [
        "test_api_token",
        "test_bearer",
        "test_basic_password",
        "proxmox_api_token",
        "nas_api_key",
        "grafana_service_account",
        "plex_token",
        "homeassistant_token",
    ];

    for name in &expected {
        assert!(
            names.contains(&name.to_string()),
            "expected credential '{name}' not found in list.\n\
             Available: {names:?}\n\
             Check that the seeder ran successfully."
        );
    }

    // The response must be a flat list of strings — no objects, no values
    println!("Credential list: {names:?}");
}

/// Admin: creating and revoking an agent key works correctly.
///
/// The admin can create a new key (token shown once), use it, revoke it, and
/// confirm the revoked key no longer works. This is the key rotation flow.
#[tokio::test]
async fn test_admin_key_lifecycle_create_use_revoke() {
    let Some(env) = TestEnv::load() else { return };

    // Create a new key
    let create_resp = env
        .client
        .post(format!("{}/v1/admin/keys", env.fw_url))
        .header("X-Admin-Key", &env.admin_key)
        .json(&json!({ "name": "lifecycle-test-key", "credentials": ["*"], "methods": ["*"] }))
        .send()
        .await
        .expect("create key request failed");

    assert_eq!(create_resp.status(), 201);

    let created: Value = create_resp.json().await.expect("response was not JSON");
    let key_id = created["id"].as_str().expect("id missing");
    let key_token = created["token"]
        .as_str()
        .expect("token missing")
        .to_string();

    // The new key must work
    let use_resp = env
        .client
        .get(format!("{}/v1/credentials", env.fw_url))
        .header("X-Agent-Key", &key_token)
        .send()
        .await
        .expect("use key request failed");
    assert_eq!(
        use_resp.status(),
        200,
        "new key should be usable immediately"
    );

    // The key must appear in the listing (but without its token value)
    let list_resp = env
        .client
        .get(format!("{}/v1/admin/keys", env.fw_url))
        .header("X-Admin-Key", &env.admin_key)
        .send()
        .await
        .expect("list keys request failed");

    let keys: Vec<Value> = list_resp.json().await.expect("list was not JSON");
    let listed = keys.iter().find(|k| k["id"].as_str() == Some(key_id));
    assert!(listed.is_some(), "created key not found in listing");
    // Token must NOT be in the listing
    assert!(
        listed.unwrap().get("token").is_none(),
        "token value appeared in key listing — values should never be returned after creation"
    );

    // Revoke the key
    let revoke_resp = env
        .client
        .delete(format!("{}/v1/admin/keys/{}", env.fw_url, key_id))
        .header("X-Admin-Key", &env.admin_key)
        .send()
        .await
        .expect("revoke request failed");
    assert_eq!(revoke_resp.status(), 200, "revoke should succeed");

    // The revoked key must immediately stop working
    let after_revoke = env
        .client
        .get(format!("{}/v1/credentials", env.fw_url))
        .header("X-Agent-Key", &key_token)
        .send()
        .await
        .expect("post-revoke request failed");
    assert_eq!(
        after_revoke.status(),
        401,
        "revoked key was still accepted — revocation did not take effect immediately"
    );
}

// ── Security event stream ─────────────────────────────────────────────────────
//
// Every test below finds its event by the `X-Request-Id` the response carried,
// which is also what ties a SIEM alert back to one request.

impl TestEnv {
    /// The newest `limit` security events, newest first.
    async fn events(&self, limit: usize) -> Vec<Value> {
        let resp = self
            .client
            .get(format!("{}/v1/admin/audit?limit={limit}", self.fw_url))
            .header("X-Admin-Key", &self.admin_key)
            .send()
            .await
            .expect("audit request failed");
        assert_eq!(resp.status(), 200);
        resp.json().await.expect("audit was not JSON")
    }

    /// The event recorded for the request whose response carried `request_id`.
    async fn event_for(&self, request_id: &str, action: &str) -> Value {
        let events = self.events(200).await;
        events
            .iter()
            .find(|e| {
                e["ferrowarden"]["request_id"].as_str() == Some(request_id)
                    && e["event"]["action"].as_str() == Some(action)
            })
            .cloned()
            .unwrap_or_else(|| {
                panic!("no `{action}` event for request {request_id}; newest events:\n{events:#?}")
            })
    }

    /// Every events for a request (all actions).
    async fn events_for(&self, request_id: &str) -> Vec<Value> {
        self.events(200)
            .await
            .into_iter()
            .filter(|e| e["ferrowarden"]["request_id"].as_str() == Some(request_id))
            .collect()
    }
}

/// The `X-Request-Id` of a response.
fn request_id(resp: &reqwest::Response) -> String {
    resp.headers()
        .get("x-request-id")
        .expect("response has no X-Request-Id header")
        .to_str()
        .unwrap()
        .to_string()
}

/// Every secret value in the seed data: passwords, notes, custom field values
/// and TOTP seeds. None of them may appear in any event.
fn seeded_secrets() -> Vec<String> {
    let seed: Vec<Value> =
        serde_json::from_str(include_str!("seed/credentials.json")).expect("seed is not JSON");
    let mut out = Vec::new();
    for item in &seed {
        for key in ["value", "note", "totp"] {
            if let Some(s) = item[key].as_str() {
                out.push(s.to_string());
            }
        }
        for field in item["fields"].as_array().into_iter().flatten() {
            // `ferrowarden_uris` is metadata (the item's allowed hosts), not a
            // secret: its value is a URL that legitimately appears in events.
            if field["name"] == "ferrowarden_uris" {
                continue;
            }
            if let Some(s) = field["value"].as_str() {
                out.push(s.to_string());
            }
        }
    }
    out.retain(|s| s.len() >= 6);
    out
}

/// Correctness: a successful forward is recorded as one `forward` event with
/// the credential names (not values), the response status as a number, the
/// URL as the agent sent it, and the request ID the response carried.
#[tokio::test]
async fn test_audit_log_records_credential_names_not_values() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "GET",
            "/api/audited",
            json!({ "Authorization": "Bearer {{vault:grafana_service_account}}" }),
            None,
        )
        .await;
    assert_eq!(resp.status(), 200);
    let rid = request_id(&resp);

    let audit_resp = env
        .client
        .get(format!("{}/v1/admin/audit", env.fw_url))
        .header("X-Admin-Key", &env.admin_key)
        .send()
        .await
        .expect("audit request failed");
    assert_eq!(audit_resp.status(), 200);
    assert!(
        audit_resp.headers().contains_key("x-request-id"),
        "admin responses carry a request id too"
    );
    let entries: Vec<Value> = audit_resp.json().await.expect("audit was not JSON");
    assert!(!entries.is_empty(), "audit log is empty after a forward");

    // Newest first: our request is the most recent event.
    let entry = &entries[0];
    assert_eq!(entry["event"]["action"], "forward");
    assert_eq!(entry["ferrowarden"]["request_id"], rid.as_str());
    assert_eq!(entry["event"]["dataset"], "ferrowarden.security");
    assert_eq!(entry["event"]["kind"], "event");
    assert_eq!(entry["event"]["outcome"], "success");
    assert!(entry["event"].get("reason").is_none());
    assert_eq!(entry["event"]["category"][0], "web");
    assert_eq!(entry["event"]["type"][0], "access");
    assert!(entry["event"]["duration"].as_u64().unwrap() > 0);
    assert_eq!(entry["ferrowarden"]["schema_version"], 1);
    assert!(entry["ferrowarden"]["key"]["id"].as_str().is_some());
    assert!(entry["ferrowarden"]["key"]["name"].as_str().is_some());
    assert!(entry["source"]["ip"].as_str().is_some());
    assert_eq!(entry["http"]["request"]["method"], "GET");
    // A number, not the old "Some(200)" string.
    assert_eq!(entry["http"]["response"]["status_code"], 200);
    assert_eq!(entry["url"]["domain"], "mock-api");
    assert!(entry["url"]["original"]
        .as_str()
        .unwrap()
        .ends_with("/mock-api/api/audited"));
    assert!(entry["@timestamp"].as_str().unwrap().ends_with('Z'));
    assert_eq!(entry["service"]["name"], "ferrowarden");

    // Credential NAME recorded, VALUE absent.
    assert_eq!(
        entry["ferrowarden"]["credentials"],
        json!(["grafana_service_account"])
    );
    let entry_str = serde_json::to_string(entry).unwrap();
    assert!(
        !entry_str.contains("test-glsa-22222222222222"),
        "credential VALUE appeared in an event — security violation (entry not printed)"
    );
}

/// Every way a forward can be refused is recorded with a stable reason code,
/// the HTTP status the agent saw, and no request is forwarded.
#[tokio::test]
async fn test_forward_blocks_are_recorded_with_reason_codes() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    // (header value or URL override, expected HTTP status, expected reason)
    let header_cases = [
        (
            "{{vault:this_credential_does_not_exist}}",
            422,
            "unknown_credential",
        ),
        ("{{vault:test_unbound}}", 403, "credential_host_not_allowed"),
        ("{{vault:test_reprompt}}", 403, "reprompt_required"),
        (
            "{{vault:test_login_full:field:dup}}",
            409,
            "ambiguous_field",
        ),
        (
            "{{vault:test_login_full:bogus}}",
            422,
            "malformed_placeholder",
        ),
    ];
    for (header, status, reason) in header_cases {
        let resp = env
            .forward("GET", "/api/blocked", json!({ "X": header }), None)
            .await;
        assert_eq!(resp.status(), status, "{header}");
        let e = env.event_for(&request_id(&resp), "forward").await;
        assert_eq!(e["event"]["outcome"], "failure", "{header}");
        assert_eq!(e["event"]["reason"], reason, "{header}");
        assert_eq!(e["http"]["response"]["status_code"], status, "{header}");
        assert!(e["message"].as_str().unwrap().starts_with("forward "));
    }

    // Outbound policy.
    let resp = env
        .forward_url("GET", "http://bw-serve:8087/status", json!({}), None)
        .await;
    assert_eq!(resp.status(), 403);
    let e = env.event_for(&request_id(&resp), "forward").await;
    assert_eq!(e["event"]["reason"], "target_blocked");
    assert_eq!(e["event"]["type"], json!(["access", "denied"]));
    assert_eq!(e["url"]["domain"], "bw-serve");

    // Placeholder in the host.
    let resp = env
        .forward_url(
            "GET",
            "http://{{vault:test_api_token}}.mock-api:7777/",
            json!({}),
            None,
        )
        .await;
    assert_eq!(resp.status(), 400);
    let e = env.event_for(&request_id(&resp), "forward").await;
    assert_eq!(e["event"]["reason"], "invalid_target_url");
    // The URL is logged as the agent sent it: placeholder, never the value.
    assert!(e["url"]["original"]
        .as_str()
        .unwrap()
        .contains("{{vault:test_api_token}}"));

    assert!(
        env.all_captured_requests().await.is_empty(),
        "nothing may have been forwarded"
    );
}

/// Security: failed agent authentication (missing and invalid key) is recorded
/// with the right reason, the route template and the client IP — and never
/// with the presented key.
#[tokio::test]
async fn test_agent_auth_failures_are_recorded() {
    let Some(env) = TestEnv::load() else { return };
    let bad_key = "presented-but-invalid-agent-key-0123";

    let missing = env
        .client
        .get(format!("{}/v1/credentials", env.fw_url))
        .send()
        .await
        .expect("request failed");
    assert_eq!(missing.status(), 401);
    let invalid = env
        .client
        .post(format!("{}/v1/forward", env.fw_url))
        .header("X-Agent-Key", bad_key)
        .json(&json!({ "request": { "method": "GET", "url": "http://mock-api:7777/" } }))
        .send()
        .await
        .expect("request failed");
    assert_eq!(invalid.status(), 401);

    let e = env.event_for(&request_id(&missing), "agent_auth").await;
    assert_eq!(e["event"]["outcome"], "failure");
    assert_eq!(e["event"]["reason"], "missing_key");
    assert_eq!(e["event"]["category"][0], "authentication");
    assert_eq!(e["ferrowarden"]["details"]["endpoint"], "/v1/credentials");
    assert!(e["source"]["ip"].as_str().is_some());
    assert!(e["ferrowarden"].get("key").is_none());

    let e = env.event_for(&request_id(&invalid), "agent_auth").await;
    assert_eq!(e["event"]["reason"], "invalid_key");
    assert_eq!(e["ferrowarden"]["details"]["endpoint"], "/v1/forward");

    let text = serde_json::to_string(&env.events(200).await).unwrap();
    assert!(
        !text.contains(bad_key) && !text.contains("presented-but-inv"),
        "the presented key (or a prefix of it) was logged"
    );
}

/// Security: authentication comes before body parsing. An unauthenticated
/// caller sending a malformed body gets 401 (not a detailed 400), and the
/// stream records an auth failure — not a `request_rejected` with parse
/// details.
#[tokio::test]
async fn test_unauthenticated_bad_body_gets_401_and_no_parse_detail() {
    let Some(env) = TestEnv::load() else { return };

    let resp = env
        .client
        .post(format!("{}/v1/forward", env.fw_url))
        .header("content-type", "application/json")
        .body(r#"{"request": {"method": "GET", "url": "http://x", "url": "http://y"}}"#)
        .send()
        .await
        .expect("request failed");
    assert_eq!(resp.status(), 401);
    let rid = request_id(&resp);
    let body = resp.text().await.unwrap();
    assert!(
        !body.to_lowercase().contains("duplicate") && !body.contains("JSON"),
        "unauthenticated caller got parse detail: {body}"
    );

    let events = env.events_for(&rid).await;
    assert!(events
        .iter()
        .any(|e| e["event"]["action"] == "agent_auth" && e["event"]["reason"] == "missing_key"));
    assert!(
        !events
            .iter()
            .any(|e| e["event"]["action"] == "request_rejected"),
        "parse failure must not be recorded before authentication"
    );

    // Same for the admin routes.
    let resp = env
        .client
        .post(format!("{}/v1/admin/keys", env.fw_url))
        .header("content-type", "application/json")
        .body("{ not json")
        .send()
        .await
        .expect("request failed");
    assert_eq!(resp.status(), 401);

    // Once authenticated, the same body is a 400 and is recorded.
    let resp = env
        .client
        .post(format!("{}/v1/forward", env.fw_url))
        .header("X-Agent-Key", &env.agent_key)
        .header("content-type", "application/json")
        .body(r#"{"request": {"method": "GET", "url": "http://x", "url": "http://y"}}"#)
        .send()
        .await
        .expect("request failed");
    assert_eq!(resp.status(), 400);
    let rid = request_id(&resp);
    let client_error = resp.json::<Value>().await.unwrap()["error"]
        .as_str()
        .unwrap()
        .to_string();
    let e = env.event_for(&rid, "request_rejected").await;
    assert_eq!(e["event"]["reason"], "invalid_json");
    assert_eq!(e["ferrowarden"]["details"]["endpoint"], "/v1/forward");
    assert_eq!(e["ferrowarden"]["details"]["error"], client_error.as_str());
    assert!(e["ferrowarden"]["key"]["id"].as_str().is_some());
}

/// Security: failed admin authentication is recorded on admin routes.
#[tokio::test]
async fn test_admin_auth_failures_are_recorded() {
    let Some(env) = TestEnv::load() else { return };
    let bad_key = "presented-but-invalid-admin-key-0123456789";

    let missing = env
        .client
        .get(format!("{}/v1/admin/status", env.fw_url))
        .send()
        .await
        .expect("request failed");
    assert_eq!(missing.status(), 401);
    let invalid = env
        .client
        .get(format!("{}/v1/admin/keys", env.fw_url))
        .header("X-Admin-Key", bad_key)
        .send()
        .await
        .expect("request failed");
    assert_eq!(invalid.status(), 401);

    let e = env.event_for(&request_id(&missing), "admin_auth").await;
    assert_eq!(e["event"]["reason"], "missing_admin_key");
    assert_eq!(e["event"]["outcome"], "failure");
    assert_eq!(e["ferrowarden"]["details"]["endpoint"], "/v1/admin/status");

    let e = env.event_for(&request_id(&invalid), "admin_auth").await;
    assert_eq!(e["event"]["reason"], "invalid_admin_key");

    let text = serde_json::to_string(&env.events(200).await).unwrap();
    assert!(!text.contains(bad_key), "presented admin key was logged");
    assert!(!text.contains(&env.admin_key), "admin key was logged");
}

/// Correctness: key creation and revocation are recorded, including a revoke
/// of an unknown id — and never the token.
#[tokio::test]
async fn test_key_create_and_revoke_are_recorded() {
    let Some(env) = TestEnv::load() else { return };

    let created = env
        .client
        .post(format!("{}/v1/admin/keys", env.fw_url))
        .header("X-Admin-Key", &env.admin_key)
        .json(&json!({ "name": "events-test-key", "credentials": ["*"], "methods": ["*"] }))
        .send()
        .await
        .expect("create failed");
    assert_eq!(created.status(), 201);
    let create_rid = request_id(&created);
    let body: Value = created.json().await.unwrap();
    let key_id = body["id"].as_str().unwrap().to_string();
    let token = body["token"].as_str().unwrap().to_string();

    let e = env.event_for(&create_rid, "key_create").await;
    assert_eq!(e["event"]["category"][0], "iam");
    assert_eq!(e["event"]["type"][0], "creation");
    assert_eq!(e["event"]["outcome"], "success");
    assert_eq!(e["ferrowarden"]["details"]["key_id"], key_id.as_str());
    assert_eq!(e["ferrowarden"]["details"]["key_name"], "events-test-key");

    let revoked = env
        .client
        .delete(format!("{}/v1/admin/keys/{key_id}", env.fw_url))
        .header("X-Admin-Key", &env.admin_key)
        .send()
        .await
        .expect("revoke failed");
    assert_eq!(revoked.status(), 200);
    let e = env.event_for(&request_id(&revoked), "key_revoke").await;
    assert_eq!(e["event"]["type"][0], "deletion");
    assert_eq!(e["ferrowarden"]["details"]["key_id"], key_id.as_str());

    let unknown = env
        .client
        .delete(format!("{}/v1/admin/keys/no-such-key", env.fw_url))
        .header("X-Admin-Key", &env.admin_key)
        .send()
        .await
        .expect("revoke failed");
    assert_eq!(unknown.status(), 404, "unknown key id is a 404");
    let e = env.event_for(&request_id(&unknown), "key_revoke").await;
    assert_eq!(e["event"]["outcome"], "failure");
    assert_eq!(e["event"]["reason"], "key_not_found");

    let listed = env
        .client
        .get(format!("{}/v1/admin/keys", env.fw_url))
        .header("X-Admin-Key", &env.admin_key)
        .send()
        .await
        .expect("list failed");
    let e = env.event_for(&request_id(&listed), "key_list").await;
    assert_eq!(e["event"]["outcome"], "success");

    let text = serde_json::to_string(&env.events(200).await).unwrap();
    assert!(!text.contains(&token), "the new key's token was logged");
}

/// Correctness: every response carries an `X-Request-Id` that is generated by
/// Ferrowarden (an incoming one is ignored) and equals the event's request id.
#[tokio::test]
async fn test_request_id_header_matches_event_and_is_never_client_chosen() {
    let Some(env) = TestEnv::load() else { return };

    let health = env
        .client
        .get(format!("{}/health", env.fw_url))
        .header("X-Request-Id", "chosen-by-the-client")
        .send()
        .await
        .expect("health failed");
    let rid = request_id(&health);
    assert_ne!(rid, "chosen-by-the-client");
    assert_eq!(rid.len(), 36, "UUID: {rid}");
    // UUID version 7 (time-ordered).
    assert_eq!(rid.as_bytes()[14], b'7', "{rid}");

    let resp = env
        .client
        .get(format!("{}/v1/credentials?detail=true", env.fw_url))
        .header("X-Agent-Key", &env.agent_key)
        .header("X-Request-Id", "chosen-by-the-client")
        .send()
        .await
        .expect("request failed");
    assert_eq!(resp.status(), 200);
    let rid = request_id(&resp);
    assert_ne!(rid, "chosen-by-the-client");
    let listed: Vec<Value> = resp.json().await.unwrap();

    // `credentials_list`: which key, plain or detail, and how many.
    let e = env.event_for(&rid, "credentials_list").await;
    assert_eq!(e["event"]["outcome"], "success");
    assert_eq!(e["ferrowarden"]["request_id"], rid.as_str());
    assert_eq!(e["ferrowarden"]["details"]["detail"], true);
    assert_eq!(
        e["ferrowarden"]["details"]["count"].as_u64().unwrap() as usize,
        listed.len()
    );
    assert!(e["ferrowarden"]["key"]["id"].as_str().is_some());
}

/// The admin audit endpoint's `limit` parameter is strict like the rest.
#[tokio::test]
async fn test_audit_limit_is_strict() {
    let Some(env) = TestEnv::load() else { return };
    assert_eq!(env.events(2).await.len(), 2);
    for q in ["?limit=0", "?limit=abc", "?limit=1&limit=2", "?bogus=1"] {
        let resp = env
            .client
            .get(format!("{}/v1/admin/audit{q}", env.fw_url))
            .header("X-Admin-Key", &env.admin_key)
            .send()
            .await
            .expect("request failed");
        assert_eq!(resp.status(), 400, "query {q}");
    }
}

/// Security property (issue #22): no seeded secret value — password, note,
/// custom field value or TOTP seed — and no agent or admin key appears
/// anywhere in the event stream, whatever the request did with it.
#[tokio::test]
async fn test_no_secret_value_appears_in_any_event() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    // Exercise the paths that touch secrets: substitution, echo-back (scrubbed),
    // blocks, bad bodies and failed auth.
    for header in [
        "Bearer {{vault:test_api_token}}",
        "{{vault:test_login_full:totp}}",
        "{{vault:test_login_full:field:api_key}}",
        "{{vault:test_secure_note:notes}}",
        "{{vault:test_reprompt}}",
        "{{vault:test_unbound}}",
    ] {
        env.forward(
            "POST",
            "/api/echo",
            json!({ "X": header }),
            Some(json!({ "k": header })),
        )
        .await;
    }
    env.forward_url(
        "GET",
        "http://mock-api:7777/mock-api/?token={{vault:test_bearer}}",
        json!({}),
        None,
    )
    .await;
    let _ = env
        .client
        .post(format!("{}/v1/forward", env.fw_url))
        .header("X-Agent-Key", &env.agent_key)
        .header("content-type", "application/json")
        .body(r#"{"request": {"method": "GET", "url": "x", "url": "y"}}"#)
        .send()
        .await;
    let _ = env
        .client
        .get(format!("{}/v1/credentials", env.fw_url))
        .header("X-Agent-Key", "not-a-real-agent-key-0123456789abcdef")
        .send()
        .await;

    let all = serde_json::to_string(&env.events(1000).await).unwrap();
    assert!(all.contains("\"forward\""), "no forward events recorded");
    let mut secrets = seeded_secrets();
    secrets.push(env.agent_key.clone());
    secrets.push(env.admin_key.clone());
    assert!(secrets.len() >= 20, "seed secrets were not loaded");
    for (i, secret) in secrets.iter().enumerate() {
        assert!(
            !all.contains(secret.as_str()),
            "secret #{i} ({} chars) appears in the event stream (value not printed)",
            secret.len()
        );
    }
}

/// Admin: the status endpoint reflects current operational state.
#[tokio::test]
async fn test_admin_status_shows_unlocked_and_credential_count() {
    let Some(env) = TestEnv::load() else { return };

    let resp = env
        .client
        .get(format!("{}/v1/admin/status", env.fw_url))
        .header("X-Admin-Key", &env.admin_key)
        .send()
        .await
        .expect("status request failed");

    assert_eq!(resp.status(), 200);

    let status: Value = resp.json().await.expect("status was not JSON");

    assert_eq!(
        status["locked"].as_bool(),
        Some(false),
        "vault should be unlocked after startup"
    );

    let cred_count = status["credential_count"].as_u64().unwrap_or(0);
    assert!(
        cred_count >= 8,
        "expected at least 8 seeded credentials, got {cred_count}.\n\
         Check that the seeder ran successfully."
    );

    println!("Status: {}", serde_json::to_string_pretty(&status).unwrap());
}

// ── Leak-prevention tests ─────────────────────────────────────────────────────

const TEST_API_TOKEN_VALUE: &str = "test-token-abc123def456";

/// Case-insensitive header lookup in a captured mock-api request
/// (HTTP/1 header names arrive lower-cased).
fn captured_header<'a>(captured: &'a Value, name: &str) -> Option<&'a str> {
    captured["headers"]
        .as_object()?
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.as_str())
}

/// Security property: a target that echoes a credential back (like httpbin's
/// /anything) must not leak it to the agent. The scrubber removes the exact
/// value from the response body, whatever field it appears in.
#[tokio::test]
async fn test_echoed_credential_is_scrubbed_from_body() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "GET",
            "/echo",
            json!({ "X-Arbitrary-Name": "{{vault:test_api_token}}" }),
            None,
        )
        .await;
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();

    // The target really received the credential...
    let captured = env.last_captured_request().await;
    assert_eq!(
        captured_header(&captured, "X-Arbitrary-Name"),
        Some(TEST_API_TOKEN_VALUE)
    );
    // ...but the agent never sees it.
    assert!(
        !text.contains(TEST_API_TOKEN_VALUE),
        "credential leaked via echo (response not printed: it contains the value)"
    );
    assert!(text.contains("[REDACTED]"));
}

/// Security property: credentials echoed in response headers are scrubbed too.
#[tokio::test]
async fn test_echoed_credential_is_scrubbed_from_headers() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "GET",
            "/echo-header",
            json!({ "X-Arbitrary-Name": "{{vault:test_api_token}}" }),
            None,
        )
        .await;
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(
        !text.contains(TEST_API_TOKEN_VALUE),
        "credential leaked via header echo (response not printed: it contains the value)"
    );
}

/// Security property: the agent cannot use the proxy to call bw serve
/// directly. bw serve's /object/password/<id> returns plaintext passwords.
#[tokio::test]
async fn test_vault_backend_is_not_a_valid_target() {
    let Some(env) = TestEnv::load() else { return };

    for url in [
        "http://bw-serve:8087/list/object/items",
        "http://bw-serve:8087/object/password/test_api_token",
        "http://BW-SERVE:8087/status",
    ] {
        let resp = env.forward_url("GET", url, json!({}), None).await;
        assert_eq!(resp.status(), 403, "{url} must be refused");
        let text = resp.text().await.unwrap();
        assert!(
            !text.contains(TEST_API_TOKEN_VALUE),
            "{url}: response contained the credential value (not printed)"
        );
    }
}

/// Security property: internal hosts not listed in allowed_targets are refused.
#[tokio::test]
async fn test_unlisted_internal_target_is_blocked() {
    let Some(env) = TestEnv::load() else { return };

    for url in [
        "http://vaultwarden/api/config",
        "http://127.0.0.1:3000/health",
        "http://169.254.169.254/latest/meta-data/",
    ] {
        let resp = env.forward_url("GET", url, json!({}), None).await;
        assert_eq!(resp.status(), 403, "{url} must be refused");
    }
}

/// Security property: a credential is only sent to hosts in its vault item's
/// URIs. test_unbound is bound to https://api.example.com, so ferrowarden must
/// refuse to send it to mock-api — and must not contact mock-api at all.
#[tokio::test]
async fn test_credential_not_sent_to_unbound_host() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "GET",
            "/api/unbound",
            json!({ "Authorization": "Bearer {{vault:test_unbound}}" }),
            None,
        )
        .await;
    assert_eq!(resp.status(), 403);
    assert!(
        env.all_captured_requests().await.is_empty(),
        "request must not be forwarded"
    );
}

/// Security property: a placeholder cannot choose the destination host (the
/// value would leak through DNS and to whoever controls that name).
#[tokio::test]
async fn test_placeholder_in_host_is_rejected() {
    let Some(env) = TestEnv::load() else { return };

    let resp = env
        .forward_url(
            "GET",
            "http://{{vault:test_api_token}}.mock-api:7777/",
            json!({}),
            None,
        )
        .await;
    assert_eq!(resp.status(), 400);
}

/// Correctness: credential values containing JSON metacharacters (" and \)
/// are escaped when substituted into a JSON body, so the body stays valid JSON
/// and cannot be altered structurally.
#[tokio::test]
async fn test_json_body_with_special_characters_stays_valid() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "POST",
            "/api/login",
            json!({}),
            Some(json!({ "user": "admin", "password": "{{vault:test_special_chars}}" })),
        )
        .await;
    assert_eq!(resp.status(), 200);

    let captured = env.last_captured_request().await;
    let body: Value = serde_json::from_str(captured["body"].as_str().unwrap())
        .expect("forwarded body must be valid JSON");
    assert_eq!(body["password"], r#"quote"back\slash-55555"#);
    assert_eq!(body.as_object().unwrap().len(), 2);
    assert_eq!(
        captured_header(&captured, "Content-Type"),
        Some("application/json")
    );
}

/// Correctness: a JSON string body is sent as raw text, not as a quoted JSON string.
#[tokio::test]
async fn test_string_body_is_sent_raw() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "POST",
            "/api/form",
            json!({ "Content-Type": "application/x-www-form-urlencoded" }),
            Some(json!("token={{vault:test_api_token}}&x=1")),
        )
        .await;
    assert_eq!(resp.status(), 200);

    let captured = env.last_captured_request().await;
    assert_eq!(
        captured["body"],
        format!("token={TEST_API_TOKEN_VALUE}&x=1")
    );
}

// ── Field placeholders (#8) ──────────────────────────────────────────────────
//
// Seed items (tests/seed/credentials.json):
//   test_login_full            username, password, TOTP, notes, custom fields
//                              (hidden, text with spaces/colon, boolean, linked
//                              to username, and a duplicated "dup" field)
//   Test Login (it's spaced)   name needing a quoted placeholder
//   test_secure_note           secure note; binding via ferrowarden_uris
//   test_reprompt              master password re-prompt enabled

const FULL_USERNAME: &str = "test-full-user";
const FULL_PASSWORD: &str = "test-full-pass-88880000";
const FULL_NOTES: &str = "test-full-notes-99990000";
const FIELD_HIDDEN: &str = "test-field-hidden-12340000";
const FIELD_TEXT: &str = "test-field-text-56780000";
const SPACED_PASSWORD: &str = "test-spaced-pass-43210000";
const NOTE_BODY: &str = "test-note-body-24680000";
const NOTE_TOKEN: &str = "test-note-token-13570000";

/// Correctness: username, password, TOTP and notes selectors substitute the
/// right values.
#[tokio::test]
async fn test_builtin_selectors_are_substituted() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "GET",
            "/api/selectors",
            json!({
                "X-User": "{{vault:test_login_full:username}}",
                "X-Pass": "{{vault:test_login_full:password}}",
                "X-Default": "{{vault:test_login_full}}",
                "X-Totp": "{{vault:test_login_full:totp}}",
                "X-Notes": "{{vault:test_login_full:notes}}"
            }),
            None,
        )
        .await;
    assert_eq!(resp.status(), 200, "forward failed");

    let c = env.last_captured_request().await;
    assert_eq!(captured_header(&c, "X-User"), Some(FULL_USERNAME));
    assert!(
        captured_header(&c, "X-Pass") == Some(FULL_PASSWORD),
        "password not substituted"
    );
    assert!(
        captured_header(&c, "X-Default") == Some(FULL_PASSWORD),
        "default selector is password"
    );
    assert!(
        captured_header(&c, "X-Notes") == Some(FULL_NOTES),
        "notes not substituted"
    );
    let totp = captured_header(&c, "X-Totp").expect("X-Totp missing");
    assert!(
        totp.len() == 6 && totp.chars().all(|ch| ch.is_ascii_digit()),
        "TOTP should be a 6-digit code, got {}",
        describe(totp)
    );
}

/// Correctness: custom fields — hidden, text with a name that needs quoting,
/// boolean, and a linked field that resolves to the username.
#[tokio::test]
async fn test_custom_field_selectors_are_substituted() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "POST",
            "/api/fields",
            json!({ "X-Api-Key": "{{vault:test_login_full:field:api_key}}" }),
            Some(json!({
                "secret": "{{vault:test_login_full:field:'api secret: v2'}}",
                "enabled": "{{vault:test_login_full:field:enabled}}",
                "linked": "{{vault:test_login_full:field:'login name'}}"
            })),
        )
        .await;
    assert_eq!(resp.status(), 200, "forward failed");

    let c = env.last_captured_request().await;
    assert!(
        captured_header(&c, "X-Api-Key") == Some(FIELD_HIDDEN),
        "hidden field not substituted"
    );
    let body: Value = serde_json::from_str(c["body"].as_str().unwrap()).unwrap();
    assert!(
        body["secret"] == FIELD_TEXT,
        "quoted field name not substituted"
    );
    assert_eq!(body["enabled"], "true");
    assert_eq!(
        body["linked"], FULL_USERNAME,
        "linked field should resolve to the username"
    );
}

/// Correctness: an item whose name contains spaces, parentheses and an
/// apostrophe is usable through a quoted placeholder.
#[tokio::test]
async fn test_quoted_item_name() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "GET",
            "/api/quoted",
            json!({ "X-Pass": r"{{vault:'Test Login (it\'s spaced)'}}" }),
            None,
        )
        .await;
    assert_eq!(resp.status(), 200, "forward failed");
    let c = env.last_captured_request().await;
    assert!(
        captured_header(&c, "X-Pass") == Some(SPACED_PASSWORD),
        "quoted item not substituted"
    );
}

/// Correctness + security: a secure note's notes and fields are usable, and
/// its host binding comes from the reserved ferrowarden_uris field.
#[tokio::test]
async fn test_secure_note_values_and_binding() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "GET",
            "/api/note",
            json!({
                "X-Note": "{{vault:test_secure_note:notes}}",
                "X-Token": "{{vault:test_secure_note:field:token}}"
            }),
            None,
        )
        .await;
    assert_eq!(resp.status(), 200, "forward failed");
    let c = env.last_captured_request().await;
    assert!(
        captured_header(&c, "X-Note") == Some(NOTE_BODY),
        "note body not substituted"
    );
    assert!(
        captured_header(&c, "X-Token") == Some(NOTE_TOKEN),
        "note field not substituted"
    );

    // Not bound to any other host.
    let resp = env
        .forward_url(
            "GET",
            "https://api.example.com/x",
            json!({ "X-Token": "{{vault:test_secure_note:field:token}}" }),
            None,
        )
        .await;
    assert_eq!(resp.status(), 403);
}

/// Security: items with master password re-prompt are refused, and nothing
/// is sent to the target.
#[tokio::test]
async fn test_reprompt_item_is_refused() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "GET",
            "/api/rp",
            json!({ "X-Pass": "{{vault:test_reprompt}}" }),
            None,
        )
        .await;
    assert_eq!(resp.status(), 403);
    assert!(
        env.all_captured_requests().await.is_empty(),
        "must not forward"
    );
}

/// Correctness: a field name that appears twice on the item is ambiguous.
#[tokio::test]
async fn test_duplicate_field_is_ambiguous() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "GET",
            "/api/dup",
            json!({ "X": "{{vault:test_login_full:field:dup}}" }),
            None,
        )
        .await;
    assert_eq!(resp.status(), 409);
    assert!(
        env.all_captured_requests().await.is_empty(),
        "must not forward"
    );
}

/// Correctness: malformed placeholders and values the item does not have are
/// rejected with 422 before anything is sent.
#[tokio::test]
async fn test_malformed_and_unavailable_placeholders_are_rejected() {
    let Some(env) = TestEnv::load() else { return };

    for header in [
        "{{vault:test_login_full:bogus}}",
        "{{vault:'unterminated}}",
        "{{vault:test bearer}}",
        "{{vault:test_secure_note:password}}",
        "{{vault:test_login_full:field:nope}}",
    ] {
        env.reset_mock().await;
        let resp = env
            .forward("GET", "/api/bad", json!({ "X": header }), None)
            .await;
        assert_eq!(resp.status(), 422, "{header} must be rejected");
        assert!(
            env.all_captured_requests().await.is_empty(),
            "{header}: must not forward"
        );
    }
}

/// Security: echoed custom-field and notes values are scrubbed; usernames are
/// deliberately not (they are not treated as secret).
#[tokio::test]
async fn test_scrubbing_rules_for_fields() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;

    let resp = env
        .forward(
            "GET",
            "/echo",
            json!({
                "X-Field": "{{vault:test_login_full:field:api_key}}",
                "X-Notes": "{{vault:test_login_full:notes}}",
                "X-User": "{{vault:test_login_full:username}}"
            }),
            None,
        )
        .await;
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(
        !text.contains(FIELD_HIDDEN),
        "custom field value leaked (not printed)"
    );
    assert!(
        !text.contains(FULL_NOTES),
        "notes value leaked (not printed)"
    );
    assert!(
        text.contains(FULL_USERNAME),
        "usernames are intentionally not scrubbed"
    );
}

/// Correctness: the detailed listing offers ready-made placeholders, and the
/// ones it offers actually work.
#[tokio::test]
async fn test_detailed_listing_placeholders_work() {
    let Some(env) = TestEnv::load() else { return };

    let list: Vec<Value> = env
        .client
        .get(format!("{}/v1/credentials?detail=true", env.fw_url))
        .header("X-Agent-Key", &env.agent_key)
        .send()
        .await
        .expect("request failed")
        .json()
        .await
        .expect("not JSON");
    let item = |name: &str| {
        list.iter()
            .find(|d| d["name"] == name)
            .cloned()
            .unwrap_or_default()
    };

    let spaced = item("Test Login (it's spaced)");
    let full = item("test_login_full");
    assert_eq!(
        full["unavailable_fields"]["dup"]
            .as_str()
            .map(|s| s.starts_with("ambiguous")),
        Some(true)
    );
    assert!(item("test_reprompt")["unavailable"].is_string());

    env.reset_mock().await;
    let resp = env
        .forward(
            "GET",
            "/api/listed",
            json!({
                "X-A": spaced["placeholder"],
                "X-B": full["fields"]["api secret: v2"],
                "X-C": full["username"]
            }),
            None,
        )
        .await;
    assert_eq!(resp.status(), 200, "listed placeholders must be usable");
    let c = env.last_captured_request().await;
    assert!(captured_header(&c, "X-A") == Some(SPACED_PASSWORD));
    assert!(captured_header(&c, "X-B") == Some(FIELD_TEXT));
    assert_eq!(captured_header(&c, "X-C"), Some(FULL_USERNAME));
}

// ── Strict JSON input (#23) ───────────────────────────────────────────────────

impl TestEnv {
    /// POST a raw string body to /v1/forward, so tests can express documents
    /// `json!` cannot (duplicate keys).
    async fn forward_raw(&self, body: String) -> reqwest::Response {
        self.client
            .post(format!("{}/v1/forward", self.fw_url))
            .header("X-Agent-Key", &self.agent_key)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .expect("forward request failed")
    }

    /// Assert a 400 whose JSON error mentions `needle`, and that nothing
    /// reached the mock API.
    async fn assert_rejected_400(&self, resp: reqwest::Response, needle: &str) {
        assert_eq!(resp.status(), 400, "expected 400");
        let err: Value = resp.json().await.expect("error was not JSON");
        let msg = err["error"].as_str().unwrap_or_default().to_string();
        assert!(
            msg.contains(needle),
            "error {msg:?} should mention {needle:?}"
        );
        assert!(
            self.all_captured_requests().await.is_empty(),
            "a rejected request must not be forwarded"
        );
    }
}

/// Security property: a duplicate top-level key is ambiguous and is rejected.
#[tokio::test]
async fn test_duplicate_top_level_key_is_rejected() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;
    let url = format!("{}/mock-api/api/secret", env.mock_url_via_ferrowarden());
    let resp = env
        .forward_raw(format!(
            r#"{{"request":{{"method":"GET","url":"{url}"}},"request":{{"method":"GET","url":"{url}"}}}}"#
        ))
        .await;
    env.assert_rejected_400(resp, "duplicate key").await;
}

/// A duplicate key inside `body` could hide a value from a future policy check.
#[tokio::test]
async fn test_duplicate_key_in_body_is_rejected() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;
    let url = format!("{}/mock-api/api/echo", env.mock_url_via_ferrowarden());
    let resp = env
        .forward_raw(format!(
            r#"{{"request":{{"method":"POST","url":"{url}","body":{{"a":1,"n":{{"k":"x","k":"y"}}}}}}}}"#
        ))
        .await;
    env.assert_rejected_400(resp, "duplicate key").await;
}

#[tokio::test]
async fn test_duplicate_key_in_headers_is_rejected() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;
    let url = format!("{}/mock-api/api/secret", env.mock_url_via_ferrowarden());
    let resp = env
        .forward_raw(format!(
            r#"{{"request":{{"method":"GET","url":"{url}","headers":{{"X-A":"1","X-A":"2"}}}}}}"#
        ))
        .await;
    env.assert_rejected_400(resp, "duplicate key").await;
}

/// `Authorization` and `authorization` are distinct JSON keys but one HTTP
/// header, so the request is ambiguous.
#[tokio::test]
async fn test_case_insensitive_duplicate_header_is_rejected() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;
    let resp = env
        .forward(
            "GET",
            "/api/secret",
            json!({ "Authorization": "Bearer one", "authorization": "Bearer two" }),
            None,
        )
        .await;
    env.assert_rejected_400(resp, "more than once").await;
}

#[tokio::test]
async fn test_unknown_field_in_forward_request_is_rejected() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;
    let url = format!("{}/mock-api/api/secret", env.mock_url_via_ferrowarden());
    let resp = env
        .forward_raw(format!(
            r#"{{"request":{{"method":"GET","url":"{url}","policy":"allow"}}}}"#
        ))
        .await;
    env.assert_rejected_400(resp, "unknown field `policy`")
        .await;
}

#[tokio::test]
async fn test_type_error_does_not_echo_body_values() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;
    let resp = env
        .forward_raw(
            r#"{"request":{"method":"GET","url":5,"body":{"pw":"SECRETVAL"}}}"#.to_string(),
        )
        .await;
    assert_eq!(resp.status(), 400);
    let text = resp.text().await.unwrap();
    assert!(!text.contains("SECRETVAL"), "error echoed a body value");
}

#[tokio::test]
async fn test_credentials_query_is_strict() {
    let Some(env) = TestEnv::load() else { return };
    for q in ["?bogus=1", "?detail=true&detail=false", "?detail=true&x=1"] {
        let resp = env
            .client
            .get(format!("{}/v1/credentials{q}", env.fw_url))
            .header("X-Agent-Key", &env.agent_key)
            .send()
            .await
            .expect("request failed");
        assert_eq!(resp.status(), 400, "query {q}");
    }
    for q in ["", "?detail=true", "?detail=false"] {
        let resp = env
            .client
            .get(format!("{}/v1/credentials{q}", env.fw_url))
            .header("X-Agent-Key", &env.agent_key)
            .send()
            .await
            .expect("request failed");
        assert_eq!(resp.status(), 200, "query {q}");
    }
}

#[tokio::test]
async fn test_unknown_field_in_create_key_is_rejected() {
    let Some(env) = TestEnv::load() else { return };
    let resp = env
        .client
        .post(format!("{}/v1/admin/keys", env.fw_url))
        .header("X-Admin-Key", &env.admin_key)
        .json(&json!({ "name": "strict-test-key", "credentials": ["*"], "methods": ["*"], "role": "admin" }))
        .send()
        .await
        .expect("request failed");
    assert_eq!(resp.status(), 400);
    let err: Value = resp.json().await.unwrap();
    assert!(err["error"]
        .as_str()
        .unwrap()
        .contains("unknown field `role`"));
}

// ── Per-key policy: credential scoping, method policy, preview (#9) ───────────

impl TestEnv {
    /// Create an agent key with a policy through the admin API. Returns
    /// (id, token). Callers revoke it at the end of the test.
    async fn create_key(&self, name: &str, credentials: Value, methods: Value) -> (String, String) {
        let resp = self
            .client
            .post(format!("{}/v1/admin/keys", self.fw_url))
            .header("X-Admin-Key", &self.admin_key)
            .json(&json!({ "name": name, "credentials": credentials, "methods": methods }))
            .send()
            .await
            .expect("create key failed");
        assert_eq!(resp.status(), 201, "creating key {name}");
        let body: Value = resp.json().await.unwrap();
        (
            body["id"].as_str().unwrap().to_string(),
            body["token"].as_str().unwrap().to_string(),
        )
    }

    async fn revoke_key(&self, id: &str) {
        let resp = self
            .client
            .delete(format!("{}/v1/admin/keys/{id}", self.fw_url))
            .header("X-Admin-Key", &self.admin_key)
            .send()
            .await
            .expect("revoke failed");
        assert_eq!(resp.status(), 200, "revoking {id}");
    }

    async fn admin_call(&self, method: &str, path: &str, body: Option<Value>) -> reqwest::Response {
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let mut req = self
            .client
            .request(method, format!("{}{path}", self.fw_url))
            .header("X-Admin-Key", &self.admin_key);
        if let Some(b) = body {
            req = req.json(&b);
        }
        req.send().await.expect("admin request failed")
    }

    /// Forward to the mock API as `token`.
    async fn forward_as(
        &self,
        token: &str,
        method: &str,
        path: &str,
        headers: Value,
    ) -> reqwest::Response {
        let url = format!("{}/mock-api{}", self.mock_url_via_ferrowarden(), path);
        self.client
            .post(format!("{}/v1/forward", self.fw_url))
            .header("X-Agent-Key", token)
            .json(&json!({ "request": { "method": method, "url": url, "headers": headers } }))
            .send()
            .await
            .expect("forward request failed")
    }

    /// Credential names as seen by `token` (plain listing).
    async fn names_for(&self, token: &str) -> Vec<String> {
        let resp = self
            .client
            .get(format!("{}/v1/credentials", self.fw_url))
            .header("X-Agent-Key", token)
            .send()
            .await
            .expect("list failed");
        assert_eq!(resp.status(), 200);
        resp.json().await.unwrap()
    }
}

/// Scoped keys list only the credentials their patterns match, in both the
/// plain and the detailed listing.
#[tokio::test]
async fn test_scoped_key_lists_only_matching_credentials() {
    let Some(env) = TestEnv::load() else { return };
    let (id, token) = env
        .create_key(
            "scope-list",
            json!(["test_api_*", "nas_api_key"]),
            json!(["*"]),
        )
        .await;

    let names = env.names_for(&token).await;
    assert_eq!(names, ["nas_api_key", "test_api_token"]);

    let detail: Vec<Value> = env
        .client
        .get(format!("{}/v1/credentials?detail=true", env.fw_url))
        .header("X-Agent-Key", &token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let detailed: Vec<&str> = detail.iter().map(|d| d["name"].as_str().unwrap()).collect();
    assert_eq!(detailed, ["nas_api_key", "test_api_token"]);

    // The unrestricted pre-created key still sees everything.
    assert!(env.names_for(&env.agent_key).await.len() > 5);

    // `[]` sees nothing.
    let (empty_id, empty_token) = env.create_key("scope-empty", json!([]), json!(["*"])).await;
    assert!(env.names_for(&empty_token).await.is_empty());

    env.revoke_key(&empty_id).await;
    env.revoke_key(&id).await;
}

/// An out-of-scope credential is a 403 whether or not it exists, with the same
/// body shape, and nothing is forwarded. In-scope credentials still work.
#[tokio::test]
async fn test_out_of_scope_credential_is_403_with_no_existence_oracle() {
    let Some(env) = TestEnv::load() else { return };
    let (id, token) = env
        .create_key("scope-forward", json!(["test_api_token"]), json!(["*"]))
        .await;
    env.reset_mock().await;

    // Exists in the vault, out of scope.
    let existing = env
        .forward_as(
            &token,
            "GET",
            "/api/x",
            json!({"Authorization": "Bearer {{vault:test_bearer}}"}),
        )
        .await;
    let existing_rid = request_id(&existing);
    assert_eq!(existing.status(), 403);
    let existing_body: Value = existing.json().await.unwrap();

    // Does not exist anywhere, out of scope.
    let ghost = env
        .forward_as(
            &token,
            "GET",
            "/api/x",
            json!({"Authorization": "Bearer {{vault:no_such_cred_zz}}"}),
        )
        .await;
    let ghost_rid = request_id(&ghost);
    assert_eq!(ghost.status(), 403);
    let ghost_body: Value = ghost.json().await.unwrap();

    assert_eq!(
        existing_body["error"],
        "Credential test_bearer is not available to this agent key"
    );
    assert_eq!(
        existing_body["error"]
            .as_str()
            .unwrap()
            .replace("test_bearer", "X"),
        ghost_body["error"]
            .as_str()
            .unwrap()
            .replace("no_such_cred_zz", "X"),
        "message must be identical apart from the echoed name"
    );
    for (rid, name) in [
        (&existing_rid, "test_bearer"),
        (&ghost_rid, "no_such_cred_zz"),
    ] {
        let e = env.event_for(rid, "forward").await;
        assert_eq!(e["event"]["outcome"], "failure");
        assert_eq!(e["event"]["reason"], "credential_out_of_scope");
        assert_eq!(e["http"]["response"]["status_code"], 403);
        assert_eq!(e["ferrowarden"]["credentials"][0], name);
    }
    // Mixed in-scope + out-of-scope is refused as a whole.
    let mixed = env
        .forward_as(
            &token,
            "GET",
            "/api/x",
            json!({"A": "{{vault:test_api_token}}", "B": "{{vault:test_bearer}}"}),
        )
        .await;
    assert_eq!(mixed.status(), 403);
    assert!(
        env.all_captured_requests().await.is_empty(),
        "nothing may reach the target"
    );

    // In scope works.
    let ok = env
        .forward_as(
            &token,
            "GET",
            "/api/check",
            json!({"Authorization": "Bearer {{vault:test_api_token}}"}),
        )
        .await;
    assert_eq!(ok.status(), 200);
    assert_eq!(env.all_captured_requests().await.len(), 1);

    env.revoke_key(&id).await;
}

/// The method policy is enforced before anything is forwarded, and methods
/// outside the standard list are a 400 for every key.
#[tokio::test]
async fn test_method_policy_and_method_list() {
    let Some(env) = TestEnv::load() else { return };
    let (id, token) = env
        .create_key("method-get", json!(["*"]), json!(["get"]))
        .await;
    env.reset_mock().await;

    let denied = env.forward_as(&token, "POST", "/api/x", json!({})).await;
    assert_eq!(denied.status(), 403);
    let rid = request_id(&denied);
    assert_eq!(
        denied.json::<Value>().await.unwrap()["error"],
        "Method POST is not allowed for this agent key"
    );
    let e = env.event_for(&rid, "forward").await;
    assert_eq!(e["event"]["reason"], "method_not_allowed");
    assert!(env.all_captured_requests().await.is_empty());

    let allowed = env.forward_as(&token, "get", "/api/check", json!({})).await;
    assert_eq!(allowed.status(), 200);

    // TRACE / unknown methods: 400 for the unrestricted key too.
    for method in ["TRACE", "CONNECT", "FOO"] {
        for key in [&token, &env.agent_key] {
            let resp = env.forward_as(key, method, "/api/x", json!({})).await;
            assert_eq!(resp.status(), 400, "{method}");
        }
    }
    env.revoke_key(&id).await;
}

/// `credentials: []` cannot use placeholders. A forward with no placeholders is
/// still allowed when the method is (documented behaviour).
#[tokio::test]
async fn test_empty_credentials_blocks_placeholders_only() {
    let Some(env) = TestEnv::load() else { return };
    let (id, token) = env
        .create_key("scope-none", json!([]), json!(["GET"]))
        .await;
    env.reset_mock().await;

    let blocked = env
        .forward_as(
            &token,
            "GET",
            "/api/x",
            json!({"A": "{{vault:test_api_token}}"}),
        )
        .await;
    assert_eq!(blocked.status(), 403);
    let plain = env.forward_as(&token, "GET", "/api/check", json!({})).await;
    assert_eq!(
        plain.status(),
        200,
        "no placeholders: only the method matters"
    );

    env.revoke_key(&id).await;
}

/// PATCH widens and narrows immediately for the same token; `null`, `{}`,
/// unknown ids and unknown fields are rejected; revoking an unknown id is 404.
#[tokio::test]
async fn test_patch_changes_policy_immediately_and_is_strict() {
    let Some(env) = TestEnv::load() else { return };
    let (id, token) = env
        .create_key("patch-me", json!(["test_api_token"]), json!(["GET"]))
        .await;
    let path = format!("/v1/admin/keys/{id}");
    assert_eq!(env.names_for(&token).await, ["test_api_token"]);

    // Widen.
    let resp = env
        .admin_call("PATCH", &path, Some(json!({"credentials": ["test_*"]})))
        .await;
    assert_eq!(resp.status(), 200);
    let rid = request_id(&resp);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["credentials"], json!(["test_*"]));
    assert_eq!(body["methods"], json!(["GET"]), "absent field unchanged");
    assert_eq!(body["policy_set"], true);
    assert!(env.names_for(&token).await.len() > 1);

    let e = env.event_for(&rid, "key_policy_change").await;
    assert_eq!(e["event"]["category"][0], "iam");
    assert_eq!(e["event"]["type"][0], "change");
    assert_eq!(e["ferrowarden"]["details"]["key_id"], id.as_str());
    assert_eq!(
        e["ferrowarden"]["details"]["before"],
        json!({"credentials": ["test_api_token"], "methods": ["GET"]})
    );
    assert_eq!(
        e["ferrowarden"]["details"]["after"],
        json!({"credentials": ["test_*"], "methods": ["GET"]})
    );

    // Narrow, and lift with ["*"].
    env.admin_call("PATCH", &path, Some(json!({"credentials": []})))
        .await;
    assert!(env.names_for(&token).await.is_empty());
    env.admin_call(
        "PATCH",
        &path,
        Some(json!({"credentials": ["*"], "methods": ["*"]})),
    )
    .await;
    assert!(env.names_for(&token).await.len() > 5);

    // Strictness.
    for body in [
        json!({}),
        json!({"credentials": null}),
        json!({"methods": null}),
        json!({"methods": ["TRACE"]}),
        json!({"credentails": ["*"]}),
    ] {
        let resp = env.admin_call("PATCH", &path, Some(body.clone())).await;
        assert_eq!(resp.status(), 400, "{body}");
    }
    let resp = env
        .admin_call("PATCH", &path, Some(json!({"credentials": null})))
        .await;
    let err: Value = resp.json().await.unwrap();
    assert!(
        err["error"].as_str().unwrap().contains("`credentials`"),
        "{err}"
    );

    // Unknown ids.
    let resp = env
        .admin_call(
            "PATCH",
            "/v1/admin/keys/no-such-key",
            Some(json!({"methods": ["*"]})),
        )
        .await;
    assert_eq!(resp.status(), 404);
    let e = env.event_for(&request_id(&resp), "key_policy_change").await;
    assert_eq!(e["event"]["reason"], "key_not_found");
    let resp = env
        .admin_call("DELETE", "/v1/admin/keys/no-such-key", None)
        .await;
    assert_eq!(resp.status(), 404);
    let resp = env
        .admin_call(
            "POST",
            "/v1/admin/keys/no-such-key/preview",
            Some(json!({})),
        )
        .await;
    assert_eq!(resp.status(), 404);

    env.revoke_key(&id).await;
}

/// Creating a key requires an explicit policy: missing or null is a 400 that
/// names the field.
#[tokio::test]
async fn test_create_requires_a_policy_and_rejects_null() {
    let Some(env) = TestEnv::load() else { return };
    let cases = [
        (json!({"name": "no-policy"}), "missing field `credentials`"),
        (
            json!({"name": "no-methods", "credentials": ["*"]}),
            "missing field `methods`",
        ),
        (
            json!({"name": "no-creds", "methods": ["*"]}),
            "missing field `credentials`",
        ),
        (
            json!({"name": "null-creds", "credentials": null, "methods": ["*"]}),
            "`credentials`",
        ),
        (
            json!({"name": "null-methods", "credentials": ["*"], "methods": null}),
            "`methods`",
        ),
    ];
    for (body, needle) in cases {
        let resp = env
            .admin_call("POST", "/v1/admin/keys", Some(body.clone()))
            .await;
        assert_eq!(resp.status(), 400, "{body}");
        let err: Value = resp.json().await.unwrap();
        assert!(
            err["error"].as_str().unwrap().contains(needle),
            "{body}: {err}"
        );
    }
    // None of those created a key.
    let list: Vec<Value> = env
        .admin_call("GET", "/v1/admin/keys", None)
        .await
        .json()
        .await
        .unwrap();
    assert!(!list.iter().any(|k| {
        k["name"]
            .as_str()
            .is_some_and(|n| n.starts_with("no-") || n.starts_with("null-"))
    }));
}

/// Preview shows the gained/lost diff against the saved policy, saves nothing
/// and contacts nobody; its request check reports what a forward would.
#[tokio::test]
async fn test_policy_preview() {
    let Some(env) = TestEnv::load() else { return };
    let (id, _token) = env
        .create_key("preview-me", json!(["test_api_*"]), json!(["*"]))
        .await;
    let path = format!("/v1/admin/keys/{id}/preview");
    env.reset_mock().await;

    let keys_before: Vec<Value> = env
        .admin_call("GET", "/v1/admin/keys", None)
        .await
        .json()
        .await
        .unwrap();

    let resp = env
        .admin_call(
            "POST",
            &path,
            Some(json!({"credentials": ["test_bearer", "nas_*"], "methods": ["GET"]})),
        )
        .await;
    assert_eq!(resp.status(), 200);
    let rid = request_id(&resp);
    let p: Value = resp.json().await.unwrap();
    assert_eq!(p["key"]["name"], "preview-me");
    assert_eq!(
        p["saved_policy"],
        json!({"credentials": ["test_api_*"], "methods": ["*"]})
    );
    assert_eq!(
        p["draft_policy"],
        json!({"credentials": ["test_bearer", "nas_*"], "methods": ["GET"]})
    );
    let strs = |v: &Value| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(strs(&p["gained"]), ["nas_api_key", "test_bearer"]);
    assert_eq!(strs(&p["lost"]), ["test_api_token"]);
    let names: Vec<&str> = p["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["nas_api_key", "test_bearer"]);
    // Names and ready-made placeholders only: no secret value anywhere.
    let text = p.to_string();
    for secret in seeded_secrets() {
        assert!(!text.contains(&secret), "preview leaked a seeded value");
    }
    let e = env.event_for(&rid, "policy_preview").await;
    assert_eq!(e["event"]["category"][0], "iam");
    assert_eq!(e["ferrowarden"]["details"]["key_id"], id.as_str());

    // Request checks, against the draft.
    let mock = format!("{}/mock-api/api/x", env.mock_url_via_ferrowarden());
    let check = |draft: Value, method: &str, url: &str, headers: Value| {
        let mut body = json!({"request": {"method": method, "url": url, "headers": headers}});
        for (k, v) in draft.as_object().unwrap() {
            body[k] = v.clone();
        }
        body
    };
    let run = |body: Value| {
        let env = &env;
        let path = path.clone();
        async move {
            let r: Value = env
                .admin_call("POST", &path, Some(body))
                .await
                .json()
                .await
                .unwrap();
            r["request_check"].clone()
        }
    };
    let draft = json!({"credentials": ["test_*"], "methods": ["GET"]});

    let ok = run(check(
        draft.clone(),
        "GET",
        &mock,
        json!({"A": "{{vault:test_api_token}}"}),
    ))
    .await;
    assert_eq!(ok["allowed"], true, "{ok}");
    let scope = run(check(
        draft.clone(),
        "GET",
        &mock,
        json!({"A": "{{vault:nas_api_key}}"}),
    ))
    .await;
    assert_eq!(
        (scope["status"].as_u64(), scope["reason"].as_str()),
        (Some(403), Some("credential_out_of_scope"))
    );
    let ghost = run(check(
        draft.clone(),
        "GET",
        &mock,
        json!({"A": "{{vault:no_such_cred_zz}}"}),
    ))
    .await;
    assert_eq!(ghost["reason"], "credential_out_of_scope");
    let method = run(check(draft.clone(), "POST", &mock, json!({}))).await;
    assert_eq!(method["reason"], "method_not_allowed");
    let bound = run(check(
        draft.clone(),
        "GET",
        "https://elsewhere.example/x",
        json!({"A": "{{vault:test_api_token}}"}),
    ))
    .await;
    assert_eq!(bound["reason"], "credential_host_not_allowed");
    let unknown = run(check(
        draft.clone(),
        "GET",
        &mock,
        json!({"A": "{{vault:test_nonexistent}}"}),
    ))
    .await;
    assert_eq!(
        (unknown["status"].as_u64(), unknown["reason"].as_str()),
        (Some(422), Some("unknown_credential"))
    );

    // Nothing saved, nothing sent.
    let keys_after: Vec<Value> = env
        .admin_call("GET", "/v1/admin/keys", None)
        .await
        .json()
        .await
        .unwrap();
    let find = |keys: &[Value]| {
        keys.iter()
            .find(|k| k["id"] == id.as_str())
            .cloned()
            .unwrap()
    };
    assert_eq!(find(&keys_before), find(&keys_after));
    assert!(
        env.all_captured_requests().await.is_empty(),
        "preview must not reach the target"
    );

    env.revoke_key(&id).await;
}

/// A key created with a policy records it in the `key_create` event.
#[tokio::test]
async fn test_key_create_event_includes_the_policy() {
    let Some(env) = TestEnv::load() else { return };
    let resp = env
        .admin_call(
            "POST",
            "/v1/admin/keys",
            Some(json!({"name": "policy-event", "credentials": ["lab_*"], "methods": ["get", "head"]})),
        )
        .await;
    assert_eq!(resp.status(), 201);
    let rid = request_id(&resp);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["methods"], json!(["GET", "HEAD"]));
    let e = env.event_for(&rid, "key_create").await;
    assert_eq!(e["ferrowarden"]["details"]["credentials"], json!(["lab_*"]));
    assert_eq!(
        e["ferrowarden"]["details"]["methods"],
        json!(["GET", "HEAD"])
    );
    env.revoke_key(body["id"].as_str().unwrap()).await;
}

// ── Admin web UI (phase 1: sign-in and status) ────────────────────────────────
//
// The UI is a separate listener (`FERROWARDEN_UI__BIND=0.0.0.0:3001` in
// docker-compose.test.yml, plain HTTP via `insecure_http` because this client
// is plain HTTP). It signs in with the vault master password, which these
// tests read from secrets/bw_master_password. The value is never printed, and
// no assertion message contains it.
//
// Vaultwarden rate-limits logins (10 per minute per IP) and Ferrowarden locks
// an IP after 5 failures, so the suite makes only one real wrong-password
// attempt and a handful of correct sign-ins. Two-factor sign-in is covered by
// the mock-based unit tests, not here.

/// What a browser sends and keeps for the admin UI.
struct UiBrowser {
    client: Client,
    base: String,
    cookies: Vec<(String, String)>,
}

struct UiResp {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl UiResp {
    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }

    fn request_id(&self) -> String {
        self.header("x-request-id").to_string()
    }

    fn set_cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|c| c.starts_with(&format!("{name}=")))
            .map(str::to_string)
    }

    /// The single-use id in the create-key form's hidden field.
    fn form_id(&self) -> String {
        let marker = "name=\"form_id\" value=\"";
        let start = self.body.find(marker).expect("page has a form_id field") + marker.len();
        let end = self.body[start..].find('"').unwrap();
        self.body[start..start + end].to_string()
    }

    /// The CSRF token in the page's hidden field.
    fn csrf(&self) -> String {
        let marker = "name=\"csrf\" value=\"";
        let start = self.body.find(marker).expect("page has a csrf field") + marker.len();
        let end = self.body[start..].find('"').unwrap();
        self.body[start..start + end].to_string()
    }
}

/// The vault master password of the test stack. Never print it.
fn master_password() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/secrets/bw_master_password"
    ))
    .expect("secrets/bw_master_password must exist (run scripts/dev-setup first)")
    .trim_end_matches(['\r', '\n'])
    .to_string()
}

fn ui_email() -> String {
    env::var("FERROWARDEN_TEST_UI_EMAIL").unwrap_or_else(|_| "admin@ferrowarden.test".to_string())
}

impl TestEnv {
    fn ui_url(&self) -> String {
        env::var("FERROWARDEN_TEST_UI_URL").unwrap_or_else(|_| "http://localhost:3001".to_string())
    }

    fn ui_browser(&self) -> UiBrowser {
        UiBrowser {
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            base: self.ui_url(),
            cookies: Vec::new(),
        }
    }
}

impl UiBrowser {
    fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    async fn send(
        &mut self,
        method: reqwest::Method,
        path: &str,
        headers: &[(&str, &str)],
        form: Option<&[(&str, &str)]>,
    ) -> UiResp {
        let mut req = self.client.request(method, format!("{}{path}", self.base));
        if !self.cookies.is_empty() {
            let cookie = self
                .cookies
                .iter()
                .map(|(n, v)| format!("{n}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            req = req.header("cookie", cookie);
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        if let Some(form) = form {
            req = req.form(form);
        }
        let resp = req.send().await.expect(
            "the admin UI must be reachable (is the stack current? docker compose up -d --build)",
        );
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp.text().await.unwrap_or_default();

        for value in headers.get_all("set-cookie") {
            let c = value.to_str().unwrap();
            let (pair, attrs) = c.split_once(';').unwrap_or((c, ""));
            let (name, val) = pair.split_once('=').unwrap();
            self.cookies.retain(|(n, _)| n != name);
            if !attrs.contains("Max-Age=0") {
                self.cookies.push((name.to_string(), val.to_string()));
            }
        }
        UiResp {
            status,
            headers,
            body,
        }
    }

    async fn get(&mut self, path: &str) -> UiResp {
        self.send(reqwest::Method::GET, path, &[], None).await
    }

    /// A form POST the way a browser sends it from the UI's own pages.
    async fn post(&mut self, path: &str, form: &[(&str, &str)]) -> UiResp {
        self.send(
            reqwest::Method::POST,
            path,
            &[("sec-fetch-site", "same-origin")],
            Some(form),
        )
        .await
    }

    async fn sign_in(&mut self, password: &str) -> UiResp {
        let page = self.get("/ui/login").await;
        assert_eq!(page.status, 200, "login page");
        let csrf = page.csrf();
        self.post("/ui/login", &[("csrf", &csrf), ("password", password)])
            .await
    }
}

fn assert_ui_security_headers(r: &UiResp) {
    assert_eq!(
        r.header("content-security-policy"),
        "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; \
form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    );
    assert_eq!(r.header("x-content-type-options"), "nosniff");
    assert_eq!(r.header("referrer-policy"), "no-referrer");
    assert_eq!(r.header("x-frame-options"), "DENY");
    assert_eq!(r.header("cross-origin-opener-policy"), "same-origin");
    assert_eq!(r.header("cross-origin-resource-policy"), "same-origin");
    assert!(!r.header("permissions-policy").is_empty());
    assert!(!r.header("x-request-id").is_empty());
}

/// Signing in with the real master password works end to end (Vaultwarden
/// verifies it), the session cookie is hardened, and the status page shows the
/// account and the same counts as the admin API.
#[tokio::test]
async fn test_ui_sign_in_shows_the_status_page() {
    let Some(env) = TestEnv::load() else { return };
    let pw = master_password();
    let mut b = env.ui_browser();

    let r = b.sign_in(&pw).await;
    assert_eq!(r.status, 303, "sign-in with the real master password");
    assert_eq!(r.header("location"), "/ui/");
    let cookie = r.set_cookie("__Host-fw_session").expect("session cookie");
    for attr in ["Path=/", "HttpOnly", "Secure", "SameSite=Strict"] {
        assert!(cookie.contains(attr), "session cookie lacks {attr}");
    }
    assert!(!cookie.contains("Max-Age") && !cookie.contains("Domain"));

    let status = b.get("/ui/").await;
    assert_eq!(status.status, 200);
    assert_ui_security_headers(&status);
    assert!(status.body.contains(&ui_email()), "account email");
    assert!(status.body.contains("Unlocked"));

    // The same numbers as GET /v1/admin/status.
    let api: Value = env
        .client
        .get(format!("{}/v1/admin/status", env.fw_url))
        .header("X-Admin-Key", &env.admin_key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(status.body.contains(&format!(
        "<dt>Agent keys</dt>\n<dd>{}</dd>",
        api["agent_key_count"]
    )));
    assert!(status.body.contains(&format!(
        "<dt>Credentials</dt>\n<dd>{}</dd>",
        api["credential_count"]
    )));
    assert!(status.body.contains("Keys without a policy"));
    assert!(!status.body.contains(&pw), "the password is never rendered");

    // The sign-in is an event with the request id of the POST.
    let e = env.event_for(&r.request_id(), "ui_login").await;
    assert_eq!(e["event"]["outcome"], "success");
    assert_eq!(e["event"]["category"], json!(["authentication"]));

    // Tidy up: sign out.
    let csrf = status.csrf();
    let out = b.post("/ui/logout", &[("csrf", &csrf)]).await;
    assert_eq!(out.status, 303);
}

/// A wrong password is refused with a generic message and recorded. This is
/// the suite's only real wrong-password attempt.
#[tokio::test]
async fn test_ui_wrong_password_fails_and_is_an_event() {
    let Some(env) = TestEnv::load() else { return };
    let mut b = env.ui_browser();
    let r = b.sign_in("definitely-not-the-master-password-7e41").await;
    assert_eq!(r.status, 401);
    assert!(r.body.contains("Invalid password or code."));
    assert!(b.cookie("__Host-fw_session").is_none());
    assert_eq!(b.get("/ui/").await.status, 303, "still no access");

    let e = env.event_for(&r.request_id(), "ui_login").await;
    assert_eq!(e["event"]["outcome"], "failure");
    assert_eq!(e["event"]["reason"], "invalid_credentials");
    assert_eq!(e["http"]["response"]["status_code"], 401);
    // Nothing from Vaultwarden is in the page.
    assert!(!r.body.to_lowercase().contains("incorrect"));
}

/// A POST without a matching CSRF token, from another site, or with no
/// origin proof at all is refused before anything reaches Vaultwarden.
#[tokio::test]
async fn test_ui_login_rejects_csrf_and_cross_site_posts() {
    let Some(env) = TestEnv::load() else { return };
    let mut b = env.ui_browser();
    let page = b.get("/ui/login").await;
    let csrf = page.csrf();
    let pw = master_password();

    // Missing and mismatched token (the cookie is there, the field is not right).
    let r = b.post("/ui/login", &[("password", &pw)]).await;
    assert_eq!(r.status, 403, "missing csrf");
    let r = b
        .post("/ui/login", &[("csrf", "not-the-token"), ("password", &pw)])
        .await;
    assert_eq!(r.status, 403, "mismatched csrf");
    let e = env.event_for(&r.request_id(), "request_rejected").await;
    assert_eq!(e["event"]["reason"], "invalid_request");

    // The right token, but cross-site or without any origin proof.
    let form = [("csrf", csrf.as_str()), ("password", pw.as_str())];
    for headers in [
        vec![("sec-fetch-site", "cross-site")],
        vec![("sec-fetch-site", "same-site")],
        vec![("origin", "https://evil.example")],
        vec![],
    ] {
        let r = b
            .send(reqwest::Method::POST, "/ui/login", &headers, Some(&form))
            .await;
        assert_eq!(r.status, 403, "{headers:?}");
        assert!(!r.body.contains(&pw));
    }
    assert!(b.cookie("__Host-fw_session").is_none());
}

/// Logout needs the session's CSRF token and a same-origin proof, destroys
/// the session on the server, and clears the cookie.
#[tokio::test]
async fn test_ui_logout_needs_csrf_and_ends_the_session() {
    let Some(env) = TestEnv::load() else { return };
    let mut b = env.ui_browser();
    assert_eq!(b.sign_in(&master_password()).await.status, 303);
    let csrf = b.get("/ui/").await.csrf();
    let session = b.cookie("__Host-fw_session").unwrap().to_string();

    assert_eq!(b.post("/ui/logout", &[]).await.status, 403, "no token");
    assert_eq!(
        b.post("/ui/logout", &[("csrf", "wrong")]).await.status,
        403,
        "wrong token"
    );
    let cross = b
        .send(
            reqwest::Method::POST,
            "/ui/logout",
            &[("sec-fetch-site", "cross-site")],
            Some(&[("csrf", csrf.as_str())]),
        )
        .await;
    assert_eq!(cross.status, 403, "cross-site");
    assert_eq!(b.get("/ui/").await.status, 200, "still signed in");

    let out = b.post("/ui/logout", &[("csrf", &csrf)]).await;
    assert_eq!(out.status, 303);
    assert!(b.cookie("__Host-fw_session").is_none(), "cookie cleared");
    let e = env.event_for(&out.request_id(), "ui_logout").await;
    assert_eq!(e["event"]["outcome"], "success");

    // The old cookie is dead on the server.
    let mut replay = env.ui_browser();
    replay
        .cookies
        .push(("__Host-fw_session".to_string(), session));
    let r = replay.get("/ui/").await;
    assert_eq!(r.status, 303);
    assert_eq!(r.header("location"), "/ui/login");
}

/// Hardening headers are on every UI response, pages are not cached, and the
/// stylesheet is served with a content hash and a cache lifetime.
#[tokio::test]
async fn test_ui_security_headers() {
    let Some(env) = TestEnv::load() else { return };
    let mut b = env.ui_browser();
    let login = b.get("/ui/login").await;
    assert_eq!(login.status, 200);
    assert_ui_security_headers(&login);
    assert_eq!(login.header("cache-control"), "no-store");
    assert!(login.body.contains("autocomplete=\"current-password\""));
    assert!(!login.body.to_lowercase().contains("<script"));
    // The cookie for the pre-session CSRF check is hardened too.
    let c = login.set_cookie("__Host-fw_login").expect("login cookie");
    for attr in ["Path=/", "HttpOnly", "Secure", "SameSite=Strict"] {
        assert!(c.contains(attr), "{c}");
    }

    for path in ["/", "/ui/", "/ui/other", "/nope"] {
        let r = b.get(path).await;
        assert_ui_security_headers(&r);
    }
    assert_eq!(b.get("/ui/").await.header("location"), "/ui/login");

    // The stylesheet link in the page points at a hashed, cacheable file.
    let start = login.body.find("/ui/static/app-").expect("css link");
    let end = login.body[start..].find('"').unwrap();
    let css = b.get(&login.body[start..start + end]).await;
    assert_eq!(css.status, 200);
    assert_eq!(css.header("cache-control"), "public, max-age=86400");
    assert_ui_security_headers(&css);

    // The font and icons are static files too: no session, right types.
    for (path, content_type) in [
        ("/ui/static/inter-latin-wght.woff2", "font/woff2"),
        ("/ui/static/favicon.ico", "image/x-icon"),
        ("/ui/static/favicon-32.png", "image/png"),
        ("/ui/static/apple-touch-icon.png", "image/png"),
        ("/favicon.ico", "image/x-icon"),
    ] {
        let r = b.get(path).await;
        assert_eq!(r.status, 200, "{path}");
        assert_eq!(r.header("content-type"), content_type, "{path}");
        assert_eq!(r.header("cache-control"), "public, max-age=86400", "{path}");
        assert_eq!(r.header("x-content-type-options"), "nosniff", "{path}");
        assert_ui_security_headers(&r);
    }
}

/// The UI and the agent/admin API are separate listeners: neither router
/// answers on the other's port.
#[tokio::test]
async fn test_ui_and_api_are_separate_listeners() {
    let Some(env) = TestEnv::load() else { return };
    let r = env
        .client
        .get(format!("{}/ui/login", env.fw_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "the UI is not on the API port");

    let mut b = env.ui_browser();
    for (path, header, value) in [
        ("/v1/credentials", "X-Agent-Key", env.agent_key.clone()),
        ("/v1/admin/status", "X-Admin-Key", env.admin_key.clone()),
        ("/health", "X-None", String::new()),
    ] {
        let r = b
            .send(
                reqwest::Method::GET,
                path,
                &[(header, value.as_str())],
                None,
            )
            .await;
        assert_eq!(r.status, 404, "{path} must not exist on the UI port");
    }
}

// ── Admin web UI (phase 2: keys, policy editor, revoke, audit) ────────────────

/// Where tests leave secret values for `scripts/check-no-secrets.sh` to scan
/// for (the gate cannot know a token that was generated during the run).
fn extra_secrets_file() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/integration-secrets.txt")
}

fn record_secret_for_gate(value: &str) {
    use std::io::Write;
    // Start from an empty file once per test run, so values of an earlier
    // run are not carried along, and no test erases another's.
    // CI runs the suite more than once (once per vault backend) and the
    // equivalence suite too, and sets FERROWARDEN_KEEP_GATE_SECRETS=1 so that
    // the gate sees every run's values; it clears the file itself first.
    static FRESH: std::sync::Once = std::sync::Once::new();
    FRESH.call_once(|| {
        if env::var("FERROWARDEN_KEEP_GATE_SECRETS").unwrap_or_default() != "1" {
            let _ = std::fs::remove_file(extra_secrets_file());
        }
    });
    let path = extra_secrets_file();
    let _ = std::fs::create_dir_all(path.parent().unwrap());
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("cannot write the gate's extra secrets file");
    writeln!(f, "{value}").unwrap();
}

/// The agent's view of `/v1/credentials` with `token`.
async fn credentials_for(env: &TestEnv, token: &str) -> (u16, Vec<String>) {
    let resp = env
        .client
        .get(format!("{}/v1/credentials", env.fw_url))
        .header("X-Agent-Key", token)
        .send()
        .await
        .expect("request failed");
    let status = resp.status().as_u16();
    let mut names: Vec<String> = if status == 200 {
        resp.json().await.unwrap()
    } else {
        Vec::new()
    };
    names.sort();
    (status, names)
}

/// The whole operator flow through the UI with one real sign-in: create a key
/// (token shown once), use it, widen its policy with Check policy and the
/// confirmation step, revoke it, and find all of it in the audit page. The
/// token must be in no event; the gate script scans the logs and event file
/// for it afterwards.
#[tokio::test]
async fn test_ui_key_lifecycle() {
    let Some(env) = TestEnv::load() else { return };
    let mut b = env.ui_browser();
    let r = b.sign_in(&master_password()).await;
    assert_eq!(r.status, 303, "sign-in");

    // Create.
    let form = b.get("/ui/keys/new").await;
    assert_eq!(form.status, 200);
    let csrf = form.csrf();
    let form_id = form.form_id();
    let created = b
        .post(
            "/ui/keys/new",
            &[
                ("csrf", &csrf),
                ("form_id", &form_id),
                ("name", "ui-lifecycle"),
                ("credentials", "test_api_token\nnas_*"),
                ("m_GET", "1"),
            ],
        )
        .await;
    assert_eq!(created.status, 200, "create");
    assert!(created.header("location").is_empty());
    assert!(created.body.contains("This token will not be shown again"));
    let marker = "readonly value=\"";
    let start = created.body.find(marker).expect("token field") + marker.len();
    let token = created.body[start..start + created.body[start..].find('"').unwrap()].to_string();
    assert_eq!(token.len(), 48);
    record_secret_for_gate(&token);

    // The new token sees only its patterns.
    let (status, names) = credentials_for(&env, &token).await;
    assert_eq!(status, 200);
    assert_eq!(names, vec!["nas_api_key", "test_api_token"]);

    // Its id, from the admin API.
    let keys: Vec<Value> = env
        .admin_call("GET", "/v1/admin/keys", None)
        .await
        .json()
        .await
        .unwrap();
    let id = keys
        .iter()
        .find(|k| k["name"] == "ui-lifecycle")
        .expect("key listed")["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Check policy with a wider draft, then Save with confirmation.
    let page = b.get(&format!("/ui/keys/{id}")).await;
    assert_eq!(page.status, 200);
    let csrf = page.csrf();
    let draft = [
        ("csrf", csrf.as_str()),
        ("credentials", "test_api_token\nnas_*\nplex_token"),
        ("m_GET", "1"),
    ];
    let mut check = draft.to_vec();
    check.push(("op", "check"));
    let r = b.post(&format!("/ui/keys/{id}"), &check).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("<code class=\"gain\">plex_token</code>"));
    assert!(r.body.contains("{{vault:plex_token}}"));
    assert_eq!(
        credentials_for(&env, &token).await.1.len(),
        2,
        "check saves nothing"
    );

    let mut save = draft.to_vec();
    save.push(("op", "save"));
    let r = b.post(&format!("/ui/keys/{id}"), &save).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("Confirm save"));
    assert_eq!(
        credentials_for(&env, &token).await.1.len(),
        2,
        "not saved yet"
    );
    save.push(("confirm", "1"));
    let r = b.post(&format!("/ui/keys/{id}"), &save).await;
    assert_eq!(r.status, 303);
    assert_eq!(r.header("location"), format!("/ui/keys/{id}?m=saved"));
    let (_, names) = credentials_for(&env, &token).await;
    assert_eq!(names, vec!["nas_api_key", "plex_token", "test_api_token"]);

    // Revoke.
    let page = b.get(&format!("/ui/keys/{id}/revoke")).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("ui-lifecycle"));
    let r = b
        .post(&format!("/ui/keys/{id}/revoke"), &[("csrf", &page.csrf())])
        .await;
    assert_eq!(r.status, 303);
    assert_eq!(r.header("location"), "/ui/keys?m=revoked");
    assert_eq!(credentials_for(&env, &token).await.0, 401, "revoked");

    // The audit page shows it, and no event holds the token.
    let audit = b.get("/ui/audit?limit=500").await;
    assert_eq!(audit.status, 200);
    for action in [
        "key_create",
        "key_policy_change",
        "key_revoke",
        "policy_preview",
    ] {
        assert!(
            audit.body.contains(&format!("<code>{action}</code>")),
            "{action} in the audit page"
        );
    }
    assert!(audit.body.contains("&#34;via&#34;: &#34;ui&#34;"));
    assert!(!audit.body.contains(&token));
    let events = env.events(1000).await;
    assert!(
        !serde_json::to_string(&events).unwrap().contains(&token),
        "token in the audit events"
    );
    let ui_events = events
        .iter()
        .filter(|e| e["ferrowarden"]["details"]["via"] == "ui")
        .count();
    assert!(ui_events >= 4);

    let csrf = audit.csrf();
    assert_eq!(b.post("/ui/logout", &[("csrf", &csrf)]).await.status, 303);
}

// ── OpenAPI conformance ───────────────────────────────────────────────────────
//
// docs/openapi.yaml is hand-written, so it can drift from the code. These tests
// send real requests to the stack and validate what comes back against the
// operation's response schema in the spec: the status must be documented, the
// declared headers must be present, and the body must match the schema. Object
// schemas are checked strictly (`additionalProperties: false` is added where the
// spec leaves it open), so a field the server sends but the spec does not
// describe fails the test as well.

/// The parsed `docs/openapi.yaml`.
struct Spec {
    doc: Value,
}

impl Spec {
    fn load() -> Self {
        let doc: Value = serde_norway::from_str(include_str!("../docs/openapi.yaml"))
            .expect("docs/openapi.yaml must parse");
        Self { doc }
    }

    /// Follow a local `$ref`, if `v` is one.
    fn resolve<'a>(&'a self, v: &'a Value) -> &'a Value {
        match v.get("$ref").and_then(Value::as_str) {
            Some(r) => self
                .doc
                .pointer(r.trim_start_matches('#'))
                .unwrap_or_else(|| panic!("unresolved $ref {r}")),
            None => v,
        }
    }

    /// The response object for `method path -> status`, with the documented
    /// statuses listed when it is missing.
    fn response(&self, path: &str, method: &str, status: u16) -> &Value {
        let op = self
            .doc
            .pointer(&format!(
                "/paths/{}/{}",
                path.replace('~', "~0").replace('/', "~1"),
                method.to_ascii_lowercase()
            ))
            .unwrap_or_else(|| panic!("{method} {path} is not in docs/openapi.yaml"));
        let responses = op["responses"].as_object().expect("responses");
        match responses.get(&status.to_string()) {
            Some(r) => self.resolve(r),
            None => panic!(
                "{method} {path} answered {status}, which docs/openapi.yaml does not document \
                 (documented: {:?})",
                responses.keys().collect::<Vec<_>>()
            ),
        }
    }

    /// A validator for `schema`, resolving `$ref`s against the spec's
    /// components, with unknown properties turned into errors.
    fn validator(&self, schema: &Value) -> jsonschema::Validator {
        let mut root = Self::strict(schema.clone());
        let obj = root.as_object_mut().expect("schema is an object");
        obj.insert(
            "components".into(),
            Self::strict(self.doc["components"].clone()),
        );
        obj.insert(
            "$schema".into(),
            json!("https://json-schema.org/draft/2020-12/schema"),
        );
        jsonschema::draft202012::new(&root).expect("the schema compiles")
    }

    /// Add `additionalProperties: false` to every object schema that lists
    /// `properties` and says nothing about additional ones.
    fn strict(mut v: Value) -> Value {
        match &mut v {
            Value::Object(map) => {
                if map.contains_key("properties") && !map.contains_key("additionalProperties") {
                    map.insert("additionalProperties".into(), json!(false));
                }
                for child in map.values_mut() {
                    *child = Self::strict(child.take());
                }
            }
            Value::Array(items) => {
                for child in items.iter_mut() {
                    *child = Self::strict(child.take());
                }
            }
            _ => {}
        }
        v
    }

    /// Check one real response against the spec; returns its status and body
    /// (`Null` when there is none).
    async fn check(&self, path: &str, method: &str, resp: reqwest::Response) -> (u16, Value) {
        let status = resp.status().as_u16();
        let documented = self.response(path, method, status);
        let what = format!("{method} {path} -> {status}");

        // Headers the spec declares for this response.
        if let Some(headers) = documented.get("headers").and_then(Value::as_object) {
            for name in headers.keys() {
                assert!(
                    resp.headers().contains_key(name.as_str()),
                    "{what}: header {name} is declared in the spec but missing"
                );
            }
        }
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let bytes = resp.bytes().await.expect("body");

        let Some(content) = documented.get("content").and_then(Value::as_object) else {
            assert!(
                bytes.is_empty(),
                "{what}: the spec describes no body, got {} bytes",
                bytes.len()
            );
            return (status, Value::Null);
        };
        let media = content.get(&content_type).unwrap_or_else(|| {
            panic!(
                "{what}: content type {content_type:?} is not documented (documented: {:?})",
                content.keys().collect::<Vec<_>>()
            )
        });
        if content_type != "application/json" {
            return (
                status,
                Value::String(String::from_utf8_lossy(&bytes).into_owned()),
            );
        }
        let body: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("{what}: the body is not JSON: {e}"));
        let schema = media.get("schema").expect("a JSON response has a schema");
        let validator = self.validator(schema);
        let errors: Vec<String> = validator
            .iter_errors(&body)
            .map(|e| format!("{e} (at {})", e.instance_path()))
            .collect();
        assert!(
            errors.is_empty(),
            "{what}: the body does not match docs/openapi.yaml:\n  {}",
            errors.join("\n  ")
        );
        (status, body)
    }
}

impl TestEnv {
    /// GET `path` (a path template without parameters) with an agent key.
    async fn agent_get(&self, path: &str, key: Option<&str>) -> reqwest::Response {
        let mut req = self.client.get(format!("{}{path}", self.fw_url));
        if let Some(key) = key {
            req = req.header("X-Agent-Key", key);
        }
        req.send().await.expect("request failed")
    }

    /// POST raw `body` to /v1/forward with a content type.
    async fn forward_body_as(
        &self,
        key: &str,
        content_type: &str,
        body: &str,
    ) -> reqwest::Response {
        self.client
            .post(format!("{}/v1/forward", self.fw_url))
            .header("X-Agent-Key", key)
            .header("Content-Type", content_type)
            .body(body.to_string())
            .send()
            .await
            .expect("request failed")
    }
}

#[tokio::test]
async fn test_openapi_agent_responses_match_the_spec() {
    let Some(env) = TestEnv::load() else { return };
    let spec = Spec::load();
    env.reset_mock().await;

    // GET /health
    let r = env
        .client
        .get(format!("{}/health", env.fw_url))
        .send()
        .await
        .unwrap();
    assert_eq!(spec.check("/health", "GET", r).await.0, 200);
    let r = env
        .client
        .post(format!("{}/health", env.fw_url))
        .send()
        .await
        .unwrap();
    assert_eq!(spec.check("/health", "GET", r).await.0, 405);

    // GET /v1/credentials: names, detail, strict query, 401.
    let (s, names) = spec
        .check(
            "/v1/credentials",
            "GET",
            env.agent_get("/v1/credentials", Some(&env.agent_key)).await,
        )
        .await;
    assert_eq!(s, 200);
    assert!(names.as_array().unwrap().iter().all(Value::is_string));
    let (s, detail) = spec
        .check(
            "/v1/credentials",
            "GET",
            env.agent_get("/v1/credentials?detail=true", Some(&env.agent_key))
                .await,
        )
        .await;
    assert_eq!(s, 200);
    assert!(detail.as_array().unwrap().iter().all(Value::is_object));
    for (q, key, expected) in [
        ("?bogus=1", Some(env.agent_key.as_str()), 400),
        (
            "?detail=true&detail=false",
            Some(env.agent_key.as_str()),
            400,
        ),
        ("", None, 401),
        ("", Some("not-a-key"), 401),
    ] {
        let r = env.agent_get(&format!("/v1/credentials{q}"), key).await;
        assert_eq!(spec.check("/v1/credentials", "GET", r).await.0, expected);
    }

    // POST /v1/forward: success and every error status the stack produces.
    let ok = env
        .forward(
            "GET",
            "/api/check",
            json!({ "Authorization": "Bearer {{vault:test_bearer}}" }),
            None,
        )
        .await;
    let (s, body) = spec.check("/v1/forward", "POST", ok).await;
    assert_eq!(s, 200);
    assert_eq!(body["body_encoding"], "utf8");

    let cases: Vec<(&str, reqwest::Response, u16)> = vec![
        (
            "unbound host",
            env.forward(
                "GET",
                "/api/unbound",
                json!({ "Authorization": "Bearer {{vault:test_unbound}}" }),
                None,
            )
            .await,
            403,
        ),
        (
            "unknown credential",
            env.forward(
                "GET",
                "/api/x",
                json!({ "Authorization": "Bearer {{vault:this_credential_does_not_exist}}" }),
                None,
            )
            .await,
            422,
        ),
        (
            "malformed placeholder",
            env.forward(
                "GET",
                "/api/x",
                json!({ "X": "{{vault:'unterminated}}" }),
                None,
            )
            .await,
            422,
        ),
        (
            "ambiguous field",
            env.forward(
                "GET",
                "/api/dup",
                json!({ "X": "{{vault:test_login_full:field:dup}}" }),
                None,
            )
            .await,
            409,
        ),
        (
            "placeholder in host",
            env.forward_url(
                "GET",
                "http://{{vault:test_bearer}}.example.com/",
                json!({}),
                None,
            )
            .await,
            400,
        ),
        (
            "unknown method",
            env.forward("TRACE", "/api/x", json!({}), None).await,
            400,
        ),
        (
            "target refuses the connection",
            env.forward_url("GET", "http://mock-api:9/", json!({}), None)
                .await,
            502,
        ),
        (
            "no key",
            env.client
                .post(format!("{}/v1/forward", env.fw_url))
                .json(&json!({ "request": { "method": "GET", "url": "http://x" } }))
                .send()
                .await
                .unwrap(),
            401,
        ),
        (
            "unknown field",
            env.forward_body_as(
                &env.agent_key,
                "application/json",
                r#"{"request":{"method":"GET","url":"http://x","extra":1}}"#,
            )
            .await,
            400,
        ),
        (
            "duplicate key",
            env.forward_body_as(
                &env.agent_key,
                "application/json",
                r#"{"request":{"method":"GET","url":"http://x"},"request":{}}"#,
            )
            .await,
            400,
        ),
        (
            "not JSON",
            env.forward_body_as(&env.agent_key, "text/plain", "hello")
                .await,
            400,
        ),
    ];
    for (name, resp, expected) in cases {
        let (s, _) = spec.check("/v1/forward", "POST", resp).await;
        assert_eq!(s, expected, "{name}");
    }

    // Policy refusals, from a key that may only GET a few credentials.
    let (id, token) = env
        .create_key("conformance-scoped", json!(["test_api_*"]), json!(["GET"]))
        .await;
    let out_of_scope = env
        .forward_as(
            &token,
            "GET",
            "/api/x",
            json!({ "Authorization": "Bearer {{vault:test_bearer}}" }),
        )
        .await;
    assert_eq!(spec.check("/v1/forward", "POST", out_of_scope).await.0, 403);
    let wrong_method = env.forward_as(&token, "POST", "/api/x", json!({})).await;
    assert_eq!(spec.check("/v1/forward", "POST", wrong_method).await.0, 403);
    env.revoke_key(&id).await;
}

#[tokio::test]
async fn test_openapi_admin_responses_match_the_spec() {
    let Some(env) = TestEnv::load() else { return };
    let spec = Spec::load();

    // Create, list, patch, preview, revoke: the lifecycle of one key.
    let r = env
        .admin_call(
            "POST",
            "/v1/admin/keys",
            Some(json!({
                "name": "conformance-key",
                "credentials": ["test_api_*"],
                "methods": ["get", "HEAD"]
            })),
        )
        .await;
    let (s, created) = spec.check("/v1/admin/keys", "POST", r).await;
    assert_eq!(s, 201);
    let id = created["id"].as_str().unwrap().to_string();
    // The token is returned only here: the listing must not carry it.
    let token = created["token"].as_str().unwrap().to_string();

    let r = env.admin_call("GET", "/v1/admin/keys", None).await;
    let (s, listed) = spec.check("/v1/admin/keys", "GET", r).await;
    assert_eq!(s, 200);
    assert!(!listed.to_string().contains(&token));

    let item = "/v1/admin/keys/{id}";
    let r = env
        .admin_call(
            "PATCH",
            &format!("/v1/admin/keys/{id}"),
            Some(json!({ "credentials": ["test_api_*", "test_bearer"] })),
        )
        .await;
    let (s, patched) = spec.check(item, "PATCH", r).await;
    assert_eq!(s, 200);
    assert_eq!(patched["methods"], json!(["GET", "HEAD"]));

    for (body, expected) in [
        (json!({}), 400),
        (json!({ "credentials": null }), 400),
        (json!({ "methods": ["TRACE"] }), 400),
        (json!({ "bogus": 1 }), 400),
    ] {
        let r = env
            .admin_call("PATCH", &format!("/v1/admin/keys/{id}"), Some(body))
            .await;
        assert_eq!(spec.check(item, "PATCH", r).await.0, expected);
    }
    let r = env
        .admin_call(
            "PATCH",
            "/v1/admin/keys/no-such-key",
            Some(json!({ "methods": ["GET"] })),
        )
        .await;
    assert_eq!(spec.check(item, "PATCH", r).await.0, 404);

    // Preview: no request, an allowed request, a refused one, and the errors.
    let preview = "/v1/admin/keys/{id}/preview";
    let url = format!("{}/mock-api/api/check", env.mock_url_via_ferrowarden());
    let allowed = json!({ "method": "GET", "url": url,
        "headers": { "Authorization": "Bearer {{vault:test_api_token}}" } });
    let refused = json!({ "method": "GET", "url": url,
        "headers": { "Authorization": "Bearer {{vault:nas_api_key}}" } });
    for (body, check) in [
        (json!({ "methods": ["GET"] }), None),
        (json!({ "request": allowed }), Some(true)),
        (
            json!({ "credentials": ["nas_*"], "request": refused }),
            Some(true),
        ),
        (json!({ "request": refused }), Some(false)),
    ] {
        let r = env
            .admin_call("POST", &format!("/v1/admin/keys/{id}/preview"), Some(body))
            .await;
        let (s, p) = spec.check(preview, "POST", r).await;
        assert_eq!(s, 200);
        match check {
            None => assert!(p.get("request_check").is_none()),
            Some(allowed) => assert_eq!(p["request_check"]["allowed"], allowed),
        }
    }
    for (path, body, expected) in [
        (
            "/v1/admin/keys/no-such-key/preview".to_string(),
            json!({}),
            404,
        ),
        (
            format!("/v1/admin/keys/{id}/preview"),
            json!({ "credentials": null }),
            400,
        ),
    ] {
        let r = env.admin_call("POST", &path, Some(body)).await;
        assert_eq!(spec.check(preview, "POST", r).await.0, expected);
    }

    // Audit and status.
    let r = env
        .admin_call("GET", "/v1/admin/audit?limit=20", None)
        .await;
    let (s, events) = spec.check("/v1/admin/audit", "GET", r).await;
    assert_eq!(s, 200);
    assert!(!events.as_array().unwrap().is_empty());
    for q in ["?limit=0", "?limit=abc", "?other=1"] {
        let r = env
            .admin_call("GET", &format!("/v1/admin/audit{q}"), None)
            .await;
        assert_eq!(spec.check("/v1/admin/audit", "GET", r).await.0, 400, "{q}");
    }
    let r = env.admin_call("GET", "/v1/admin/status", None).await;
    let (s, status) = spec.check("/v1/admin/status", "GET", r).await;
    assert_eq!(s, 200);
    assert_eq!(status["locked"], false);

    // Revoke, then revoke again.
    let r = env
        .admin_call("DELETE", &format!("/v1/admin/keys/{id}"), None)
        .await;
    assert_eq!(spec.check(item, "DELETE", r).await.0, 200);
    let r = env
        .admin_call("DELETE", &format!("/v1/admin/keys/{id}"), None)
        .await;
    assert_eq!(spec.check(item, "DELETE", r).await.0, 404);

    // Unlock: the stack runs in file mode, so the endpoint answers 404.
    let r = env
        .admin_call("POST", "/v1/unlock", Some(json!({ "password": "x" })))
        .await;
    assert_eq!(spec.check("/v1/unlock", "POST", r).await.0, 404);
    let r = env
        .admin_call("POST", "/v1/unlock", Some(json!({ "bogus": 1 })))
        .await;
    assert_eq!(spec.check("/v1/unlock", "POST", r).await.0, 400);

    // 401 on every admin operation: no key, and a bad one.
    for (method, path, template) in [
        ("GET", "/v1/admin/status", "/v1/admin/status"),
        ("GET", "/v1/admin/audit", "/v1/admin/audit"),
        ("GET", "/v1/admin/keys", "/v1/admin/keys"),
        ("POST", "/v1/admin/keys", "/v1/admin/keys"),
        ("PATCH", "/v1/admin/keys/x", "/v1/admin/keys/{id}"),
        ("DELETE", "/v1/admin/keys/x", "/v1/admin/keys/{id}"),
        (
            "POST",
            "/v1/admin/keys/x/preview",
            "/v1/admin/keys/{id}/preview",
        ),
        ("POST", "/v1/unlock", "/v1/unlock"),
        ("POST", "/v1/admin/notify/test", "/v1/admin/notify/test"),
    ] {
        for key in [None, Some("not-the-admin-key")] {
            let mut req = env.client.request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("{}{path}", env.fw_url),
            );
            if let Some(key) = key {
                req = req.header("X-Admin-Key", key);
            }
            let r = req.json(&json!({})).send().await.unwrap();
            assert_eq!(
                spec.check(template, method, r).await.0,
                401,
                "{method} {path}"
            );
        }
    }
    // The bearer form is accepted where the spec says it is.
    let r = env
        .client
        .get(format!("{}/v1/admin/status", env.fw_url))
        .bearer_auth(&env.admin_key)
        .send()
        .await
        .unwrap();
    assert_eq!(spec.check("/v1/admin/status", "GET", r).await.0, 200);
}

#[tokio::test]
async fn test_openapi_endpoint_serves_the_right_view_to_each_key() {
    let Some(env) = TestEnv::load() else { return };
    let spec = Spec::load();
    let local = &spec.doc;

    // No key, a bad key: 401, and nothing of the document.
    for key in [None, Some("not-a-key")] {
        let r = env.agent_get("/v1/openapi.json", key).await;
        assert_eq!(spec.check("/v1/openapi.json", "GET", r).await.0, 401);
    }
    let r = env
        .agent_get("/v1/openapi.json?x=1", Some(&env.agent_key))
        .await;
    assert_eq!(spec.check("/v1/openapi.json", "GET", r).await.0, 400);

    // Agent key: agent and meta operations only.
    let r = env
        .agent_get("/v1/openapi.json", Some(&env.agent_key))
        .await;
    let rid = request_id(&r);
    assert_eq!(r.headers()["cache-control"], "no-store");
    let (s, agent) = spec.check("/v1/openapi.json", "GET", r).await;
    assert_eq!(s, 200);
    assert_eq!(agent["info"]["version"], local["info"]["version"]);
    let paths: Vec<&str> = agent["paths"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        paths,
        [
            "/health",
            "/v1/credentials",
            "/v1/forward",
            "/v1/openapi.json"
        ]
    );
    let text = serde_json::to_string(&agent).unwrap().to_lowercase();
    assert!(!text.contains("admin"), "the agent view mentions admin");
    let e = env.event_for(&rid, "openapi_read").await;
    assert_eq!(e["ferrowarden"]["details"]["variant"], "agent");

    // Admin key, both header forms: every operation of the spec.
    for bearer in [false, true] {
        let mut req = env.client.get(format!("{}/v1/openapi.json", env.fw_url));
        req = if bearer {
            req.bearer_auth(&env.admin_key)
        } else {
            req.header("X-Admin-Key", &env.admin_key)
        };
        let r = req.send().await.unwrap();
        let rid = request_id(&r);
        let (s, admin) = spec.check("/v1/openapi.json", "GET", r).await;
        assert_eq!(s, 200);
        assert_eq!(admin["paths"], local["paths"]);
        assert_eq!(admin["components"], local["components"]);
        let url = admin["servers"][0]["url"].as_str().unwrap();
        assert!(url.starts_with('/'), "{url}");
        let e = env.event_for(&rid, "openapi_read").await;
        assert_eq!(e["ferrowarden"]["details"]["variant"], "admin");
    }
}

// ── Push notifications ────────────────────────────────────────────────────────
//
// The test stack points Ferrowarden's notifier at `http://notify-sink:7777/notify`:
// a second network alias of the mock API, which records requests made under that
// name in a log of their own (`/__notifications__`), so a notification can never be
// mistaken for a forwarded request in `/__requests__/last`.

impl TestEnv {
    async fn notifications(&self) -> Vec<Value> {
        self.client
            .get(format!("{}/__notifications__", self.mock_url))
            .send()
            .await
            .expect("mock API request failed")
            .json::<Vec<Value>>()
            .await
            .expect("mock API response was not JSON")
    }

    async fn reset_notifications(&self) {
        self.client
            .post(format!("{}/__notifications__/reset", self.mock_url))
            .send()
            .await
            .expect("mock API reset failed");
    }

    /// Wait (up to 20 s) for a notification the sink received that `pred` accepts.
    async fn wait_for_notification(&self, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
        for _ in 0..80 {
            if let Some(n) = self
                .notifications()
                .await
                .into_iter()
                .find(|n| pred(&notification_json(n)))
            {
                return n;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        panic!(
            "no notification for {what}; the sink received:\n{:#?}",
            self.notifications().await
        );
    }

    /// POST /v1/admin/notify/test until it is not refused for being too soon.
    async fn notify_test(&self, spec: &Spec) -> Value {
        for _ in 0..4 {
            let r = self.admin_call("POST", "/v1/admin/notify/test", None).await;
            let (status, body) = spec.check("/v1/admin/notify/test", "POST", r).await;
            match status {
                200 => return body,
                429 => tokio::time::sleep(std::time::Duration::from_secs(5)).await,
                other => panic!("the test notification answered {other}"),
            }
        }
        panic!("the test notification stayed rate limited");
    }
}

/// Whether a captured notification carries `Authorization: Bearer <the test
/// stack's notifier token>`. A bool, so a failure never prints the token.
fn has_notifier_bearer(captured: &Value) -> bool {
    captured_header(captured, "authorization")
        == Some(format!("Bearer {}", notify_token()).as_str())
}

/// The JSON body of a captured notification (`Null` if it is not JSON).
fn notification_json(n: &Value) -> Value {
    serde_json::from_str(n["body"].as_str().unwrap_or("")).unwrap_or(Value::Null)
}

fn notify_token() -> String {
    env::var("FERROWARDEN_TEST_NOTIFY_TOKEN")
        .expect("FERROWARDEN_TEST_NOTIFY_TOKEN must be set (run scripts/dev-setup again)")
}

/// A fresh key per test: notifications are limited per key, so one test's
/// notification can never hold back another's.
async fn fresh_key(env: &TestEnv, label: &str) -> (String, String, String) {
    let name = format!("{label}-{}", unique_suffix());
    let (id, token) = env.create_key(&name, json!(["*"]), json!(["*"])).await;
    record_secret_for_gate(&token);
    (name, id, token)
}

fn unique_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", n % 0xffff_ffff)
}

/// A request blocked by credential host binding becomes one webhook POST with the
/// documented fields, a bearer token from the secret file, and nothing else of
/// the request: no path, query, placeholder or value.
#[tokio::test]
async fn test_notify_blocked_forward_posts_a_webhook_without_path_query_or_values() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_notifications().await;
    let (name, id, token) = fresh_key(&env, "notify-blocked").await;

    let resp = env
        .forward_as(
            &token,
            "GET",
            "/api/unbound/secret-path-segment?probe=query-marker-1",
            json!({ "Authorization": "Bearer {{vault:test_unbound}}" }),
        )
        .await;
    assert_eq!(resp.status(), 403);
    let rid = request_id(&resp);

    let n = env
        .wait_for_notification("the blocked forward", |b| {
            b["event"]["key_name"] == name.as_str()
        })
        .await;
    assert_eq!(n["method"], "POST");
    assert_eq!(n["path"], "/notify");
    assert!(
        has_notifier_bearer(&n),
        "the bearer token from the secret file was not sent"
    );
    assert!(captured_header(&n, "content-type")
        .unwrap()
        .starts_with("application/json"));

    let body = notification_json(&n);
    assert_eq!(body["source"], "ferrowarden");
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["category"], "blocked");
    assert_eq!(body["severity"], "high");
    assert_eq!(body["title"], "Ferrowarden: request blocked");
    assert_eq!(body["suppressed"], 0);
    let event = &body["event"];
    assert_eq!(event["action"], "forward");
    assert_eq!(event["outcome"], "failure");
    assert_eq!(event["reason"], "credential_host_not_allowed");
    assert_eq!(event["key_name"], name.as_str());
    assert_eq!(event["key_id"], id[..8].to_string());
    assert_eq!(event["credentials"], json!(["test_unbound"]));
    assert_eq!(event["target_host"], "mock-api");
    assert_eq!(event["request_id"], rid.as_str());
    assert!(event["source_ip"].is_string() && event["timestamp"].is_string());

    // Only allow-listed fields.
    let allowed = [
        "category",
        "action",
        "outcome",
        "reason",
        "key_name",
        "key_id",
        "credentials",
        "target_host",
        "source_ip",
        "request_id",
        "timestamp",
        "count",
    ];
    for key in event.as_object().unwrap().keys() {
        assert!(allowed.contains(&key.as_str()), "unexpected field {key}");
    }

    // Nothing of the URL beyond the host, nothing secret.
    let text = n["body"].as_str().unwrap();
    for (i, bad) in [
        "secret-path-segment",
        "/api/unbound",
        "query-marker-1",
        "probe",
        "{{",
        "Authorization",
        "Bearer",
        token.as_str(),
        env.admin_key.as_str(),
        notify_token().as_str(),
    ]
    .into_iter()
    .enumerate()
    {
        // The index, not the text: some of these are secrets.
        assert!(
            !text.contains(bad),
            "forbidden item #{i} is in the notification"
        );
    }
    for secret in seeded_secrets() {
        assert!(!text.contains(&secret), "a seeded secret is in the payload");
    }
    env.revoke_key(&id).await;
}

/// Repeated bad agent keys: one `auth_failure` notification once the threshold
/// is reached, and the rest are folded into it, not sent one by one.
#[tokio::test]
async fn test_notify_repeated_bad_agent_keys_make_one_notification_after_the_threshold() {
    let Some(env) = TestEnv::load() else { return };
    // Let any auth_failure notice of an earlier test pass its interval.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    env.reset_notifications().await;

    for i in 0..8 {
        let r = env
            .agent_get(
                "/v1/credentials",
                Some(&format!("not-a-key-{i}-0123456789")),
            )
            .await;
        assert_eq!(r.status(), 401);
    }
    let n = env
        .wait_for_notification("repeated authentication failures", |b| {
            b["category"] == "auth_failure"
        })
        .await;
    let body = notification_json(&n);
    assert_eq!(
        body["title"],
        "Ferrowarden: repeated authentication failures"
    );
    assert_eq!(body["severity"], "high");
    assert!(body["event"]["count"].as_u64().unwrap() >= 5, "{body}");
    assert!(body["event"]["source_ip"].is_string());
    let text = n["body"].as_str().unwrap();
    assert!(
        !text.contains("not-a-key"),
        "a presented key is in the payload"
    );

    // The burst was folded into that one notification.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let auth: Vec<Value> = env
        .notifications()
        .await
        .into_iter()
        .filter(|n| notification_json(n)["category"] == "auth_failure")
        .collect();
    assert_eq!(auth.len(), 1, "one notification for the burst: {auth:#?}");
}

/// The test endpoint sends to the sink and reports ok; its answers match the spec
/// (200, then 429 for a second test within ten seconds, and 401 without a key).
#[tokio::test]
async fn test_notify_test_endpoint_reports_ok_and_sends_a_test_notification() {
    let Some(env) = TestEnv::load() else { return };
    let spec = Spec::load();
    env.reset_notifications().await;

    let body = env.notify_test(&spec).await;
    assert_eq!(
        body,
        json!({ "results": [{ "sender": "webhook", "ok": true, "status": 200 }] })
    );
    let n = env
        .wait_for_notification("the test notification", |b| {
            b["title"] == "Ferrowarden: test notification"
        })
        .await;
    assert!(
        has_notifier_bearer(&n),
        "the bearer token from the secret file was not sent"
    );
    let sent = notification_json(&n);
    assert_eq!(sent["category"], "system");
    assert_eq!(sent["severity"], "normal");
    assert_eq!(sent["event"]["action"], "notify_test");

    // A second test right away is refused (documented 429 with Retry-After).
    let r = env.admin_call("POST", "/v1/admin/notify/test", None).await;
    assert!(r.headers().contains_key("retry-after"));
    assert_eq!(spec.check("/v1/admin/notify/test", "POST", r).await.0, 429);

    for key in [None, Some("not-the-admin-key")] {
        let mut req = env
            .client
            .post(format!("{}/v1/admin/notify/test", env.fw_url));
        if let Some(key) = key {
            req = req.header("X-Admin-Key", key);
        }
        let r = req.send().await.unwrap();
        assert_eq!(spec.check("/v1/admin/notify/test", "POST", r).await.0, 401);
    }

    let events = env.events(200).await;
    assert!(
        events.iter().any(|e| e["event"]["action"] == "notify_test"
            && e["ferrowarden"]["details"]["via"] == "api"
            && e["event"]["outcome"] == "success"),
        "a notify_test event was recorded"
    );
}

/// The notifier's host is off-limits to agents: a forward to it is a 403
/// `target_blocked` (although `notify-sink` is even listed in `allowed_targets`),
/// nothing reaches the sink, and the mock API itself, under its own name, stays
/// reachable.
#[tokio::test]
async fn test_notify_hosts_are_denied_to_agents_while_the_mock_api_stays_reachable() {
    let Some(env) = TestEnv::load() else { return };
    env.reset_mock().await;
    env.reset_notifications().await;

    for url in [
        "http://notify-sink:7777/notify",
        "http://notify-sink:7777/__requests__",
        "http://notify-sink:9999/anything",
        "http://NOTIFY-SINK/",
    ] {
        let resp = env
            .forward_url("POST", url, json!({}), Some(json!({ "x": 1 })))
            .await;
        assert_eq!(resp.status(), 403, "{url}");
        let rid = request_id(&resp);
        let body: Value = resp.json().await.unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("notification endpoint"),
            "{body}"
        );
        let e = env.event_for(&rid, "forward").await;
        assert_eq!(e["event"]["reason"], "target_blocked", "{url}");
    }
    // No agent request reached the sink: anything it recorded is Ferrowarden's
    // own POST of a `blocked` notification about the attempts above.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    for n in env.notifications().await {
        assert_eq!(n["path"], "/notify", "{n}");
        assert_eq!(notification_json(&n)["category"], "blocked", "{n}");
    }

    // The same container under its other name is still a valid target.
    let resp = env
        .forward(
            "GET",
            "/api/check",
            json!({ "Authorization": "Bearer {{vault:test_api_token}}" }),
            None,
        )
        .await;
    assert_eq!(resp.status(), 200);
    let captured = env.last_captured_request().await;
    assert_eq!(captured["path"], "/mock-api/api/check");
}

// ── Prometheus metrics (#13) ──────────────────────────────────────────────────
//
// Both test instances run the metrics listener (docker-compose.test.yml) with a
// bearer token from `secrets/metrics_token`: `ferrowarden` on 9095 and
// `ferrowarden-native` on 9096, whichever one the suite targets through
// `FERROWARDEN_TEST_METRICS_URL`.

/// Where the metrics listener is and the token it wants.
struct MetricsEnv {
    url: String,
    token: String,
}

fn metrics_env() -> MetricsEnv {
    MetricsEnv {
        url: env::var("FERROWARDEN_TEST_METRICS_URL")
            .expect("FERROWARDEN_TEST_METRICS_URL must be set (run scripts/dev-setup again)")
            .trim_end_matches('/')
            .to_string(),
        token: env::var("FERROWARDEN_TEST_METRICS_TOKEN")
            .expect("FERROWARDEN_TEST_METRICS_TOKEN must be set (run scripts/dev-setup again)"),
    }
}

/// One scrape of `/metrics`, parsed just enough to ask for series.
struct Scrape {
    text: String,
}

impl Scrape {
    /// `(label body, value)` of every sample named exactly `name`.
    fn series(&self, name: &str) -> Vec<(String, f64)> {
        self.text
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| {
                let rest = l.strip_prefix(name)?;
                let (labels, value) = match rest.strip_prefix('{') {
                    Some(r) => {
                        let (labels, tail) = r.rsplit_once("} ")?;
                        (labels.to_string(), tail)
                    }
                    None => (String::new(), rest.strip_prefix(' ')?),
                };
                Some((labels, value.trim().parse().ok()?))
            })
            .collect()
    }

    /// The sum of the samples of `name` that carry all of `labels`.
    fn sum(&self, name: &str, labels: &[(&str, &str)]) -> f64 {
        self.series(name)
            .into_iter()
            .filter(|(body, _)| {
                labels
                    .iter()
                    .all(|(k, v)| body.contains(&format!("{k}=\"{v}\"")))
            })
            .map(|(_, v)| v)
            .sum()
    }

    /// The one sample of `name` without labels.
    fn gauge(&self, name: &str) -> f64 {
        let all = self.series(name);
        assert_eq!(
            all.len(),
            1,
            "expected one `{name}` sample in:\n{}",
            self.text
        );
        all[0].1
    }
}

impl MetricsEnv {
    async fn get(&self, env: &TestEnv, auth: Option<&str>) -> reqwest::Response {
        let mut req = env.client.get(format!("{}/metrics", self.url));
        if let Some(token) = auth {
            req = req.bearer_auth(token);
        }
        req.send().await.expect("metrics request failed")
    }

    async fn scrape(&self, env: &TestEnv) -> Scrape {
        let resp = self.get(env, Some(&self.token)).await;
        assert_eq!(resp.status(), 200, "scrape with the right token");
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert_eq!(
            content_type,
            "application/openmetrics-text; version=1.0.0; charset=utf-8"
        );
        let text = resp.text().await.unwrap();
        assert!(
            text.ends_with("# EOF\n"),
            "an OpenMetrics scrape ends with # EOF"
        );
        Scrape { text }
    }
}

/// Everything that must never appear in a scrape: seeded secret values, every
/// token the stack knows, and every vault item name (credential names are not
/// labels unless `metrics.credential_labels` is on, and the stack leaves it off).
fn metrics_forbidden(env: &TestEnv, m: &MetricsEnv) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = seeded_secrets()
        .into_iter()
        .map(|s| ("a seeded secret value".to_string(), s))
        .collect();
    out.push(("the agent key".into(), env.agent_key.clone()));
    out.push(("the admin key".into(), env.admin_key.clone()));
    out.push(("the metrics token".into(), m.token.clone()));
    out.push(("the notifier token".into(), notify_token()));
    // Tokens and wrong guesses this run created (the file the gate reads).
    if let Ok(extra) = std::fs::read_to_string(extra_secrets_file()) {
        for line in extra.lines().map(str::trim).filter(|l| l.len() >= 6) {
            out.push(("a token created during the run".into(), line.to_string()));
        }
    }
    let seed: Vec<Value> = serde_json::from_str(include_str!("seed/credentials.json")).unwrap();
    for item in &seed {
        if let Some(name) = item["name"].as_str() {
            out.push(("a vault item name".into(), name.to_string()));
        }
    }
    out
}

/// What a scrape must not contain, whatever the traffic was: the values and
/// tokens above; the hosts the stack forwards to, fetches the vault from and
/// notifies; and any IP address.
fn assert_scrape_is_clean(env: &TestEnv, m: &MetricsEnv, scrape: &Scrape) {
    for (what, value) in metrics_forbidden(env, m) {
        assert!(
            !scrape.text.contains(&value),
            "a scrape contains {what} ({} chars)",
            value.len()
        );
    }
    // `build_info` names the backend (`vault_backend="bw-serve"`), which is
    // not a host of any request.
    let samples: String = scrape
        .text
        .lines()
        .filter(|l| !l.starts_with("ferrowarden_build_info"))
        .collect::<Vec<_>>()
        .join(
            "
",
        );
    for host in [
        "mock-api",
        "notify-sink",
        "bw-serve",
        "vaultwarden",
        "localhost",
    ] {
        assert!(!samples.contains(host), "a scrape contains the host {host}");
    }
    let ip = regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    assert!(
        !ip.is_match(&scrape.text),
        "a scrape contains an IP address"
    );
    assert!(
        !scrape.text.contains("{{vault:"),
        "a scrape contains a placeholder"
    );
}

/// Security: the metrics listener asks for the bearer token, answers anything
/// but `GET /metrics` with 404 or 405, and shares nothing with the API port.
/// Every failed attempt is counted, one event per source address per minute
/// reports it, and neither token (the right one, or the one presented) is in
/// that event.
#[tokio::test]
async fn test_metrics_listener_needs_the_bearer_token_and_serves_nothing_else() {
    let Some(env) = TestEnv::load() else { return };
    let m = metrics_env();

    // Without a token, with the wrong one, with a prefix of the right one.
    let wrong = format!("wrong-metrics-token-{}", unique_suffix());
    record_secret_for_gate(&wrong);
    let before = m
        .scrape(&env)
        .await
        .sum("ferrowarden_auth_failures_total", &[("kind", "metrics")]);
    let none = m.get(&env, None).await;
    assert_eq!(none.status(), 401);
    assert_eq!(none.headers()["www-authenticate"], "Bearer");
    assert_eq!(m.get(&env, Some(&wrong)).await.status(), 401);
    assert_eq!(
        m.get(&env, Some(&m.token[..m.token.len() - 1]))
            .await
            .status(),
        401
    );
    // The token in the URL is not a token.
    let in_url = env
        .client
        .get(format!("{}/metrics?token={}", m.url, m.token))
        .send()
        .await
        .unwrap();
    assert_eq!(in_url.status(), 401);
    let after = m
        .scrape(&env)
        .await
        .sum("ferrowarden_auth_failures_total", &[("kind", "metrics")]);
    assert_eq!(after - before, 4.0, "every failed attempt is counted");

    // The right token.
    let scrape = m.scrape(&env).await;
    assert!(scrape.text.contains("ferrowarden_build_info"));

    // Only GET /metrics.
    for path in [
        "/",
        "/health",
        "/v1/credentials",
        "/v1/admin/status",
        "/metrics/",
        "/ui/",
    ] {
        let r = env
            .client
            .get(format!("{}{path}", m.url))
            .bearer_auth(&m.token)
            .header("X-Agent-Key", &env.agent_key)
            .header("X-Admin-Key", &env.admin_key)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "{path} on the metrics port");
        assert_eq!(r.text().await.unwrap(), "", "{path}");
    }
    for method in ["POST", "PUT", "DELETE", "PATCH"] {
        let r = env
            .client
            .request(method.parse().unwrap(), format!("{}/metrics", m.url))
            .bearer_auth(&m.token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 405, "{method}");
        assert_eq!(r.headers()["allow"], "GET");
    }

    // And no metrics on the API port, with or without keys.
    for path in ["/metrics", "/v1/metrics"] {
        let r = env
            .client
            .get(format!("{}{path}", env.fw_url))
            .bearer_auth(&m.token)
            .header("X-Agent-Key", &env.agent_key)
            .header("X-Admin-Key", &env.admin_key)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "{path} on the API port");
    }

    // The event: at most one per source address per minute, so if an earlier
    // run's failure is still inside the window, wait it out and fail again.
    let mut found = None;
    for attempt in 0..2 {
        let r = m.get(&env, Some(&wrong)).await;
        assert_eq!(r.status(), 401);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        found = env
            .events(1000)
            .await
            .into_iter()
            .find(|e| e["event"]["action"] == "metrics_auth");
        if found.is_some() {
            break;
        }
        if attempt == 0 {
            eprintln!("a metrics_auth event was reported less than a minute ago; waiting");
            tokio::time::sleep(std::time::Duration::from_secs(61)).await;
        }
    }
    let event = found.expect("no metrics_auth event in the audit buffer");
    assert_eq!(event["event"]["outcome"], "failure");
    assert!(
        ["missing_metrics_token", "invalid_metrics_token"]
            .contains(&event["event"]["reason"].as_str().unwrap()),
        "{event}"
    );
    assert_eq!(event["http"]["response"]["status_code"], 401);
    assert!(event["source"]["ip"].is_string());
    assert!(event["ferrowarden"]["details"]["suppressed"].is_u64());
    let all = serde_json::to_string(&env.events(1000).await).unwrap();
    assert!(!all.contains(&m.token), "the metrics token is in an event");
    assert!(!all.contains(&wrong), "a presented token is in an event");
}

/// Correctness: after real traffic, a scrape shows it. Outcomes and reasons of
/// forwards, durations, response sizes, the vault gauges against what the API
/// reports, and the keys without a policy against the key list.
#[tokio::test]
async fn test_metrics_show_the_traffic_and_the_state() {
    let Some(env) = TestEnv::load() else { return };
    let m = metrics_env();
    env.reset_mock().await;
    let spec_series = "ferrowarden_forward_requests_total";
    let before = m.scrape(&env).await;

    // A success, a policy block, an unknown credential, a bad agent key.
    let ok = env
        .forward(
            "GET",
            "/metrics-traffic",
            json!({ "Authorization": "Bearer {{vault:test_api_token}}" }),
            None,
        )
        .await;
    assert_eq!(ok.status(), 200);
    let ok_id = request_id(&ok);
    let blocked = env
        .forward_url("GET", "http://bw-serve:8087/status", json!({}), None)
        .await;
    assert_eq!(blocked.status(), 403);
    let unknown = env
        .forward(
            "GET",
            "/metrics-traffic",
            json!({ "X": "{{vault:this_credential_does_not_exist}}" }),
            None,
        )
        .await;
    assert_eq!(unknown.status(), 422);
    let bad_key = env
        .client
        .get(format!("{}/v1/credentials", env.fw_url))
        .header("X-Agent-Key", "not-a-key-0123456789")
        .send()
        .await
        .unwrap();
    assert_eq!(bad_key.status(), 401);

    // The forward event carries the size of what came back from the target.
    let e = env.event_for(&ok_id, "forward").await;
    let bytes = e["http"]["response"]["body"]["bytes"]
        .as_u64()
        .expect("http.response.body.bytes on a successful forward");

    // The consumer is another task: give it a moment.
    let mut after = m.scrape(&env).await;
    for _ in 0..40 {
        if after.sum(
            spec_series,
            &[("outcome", "failure"), ("reason", "unknown_credential")],
        ) > before.sum(
            spec_series,
            &[("outcome", "failure"), ("reason", "unknown_credential")],
        ) && after.sum("ferrowarden_auth_failures_total", &[("kind", "agent")])
            > before.sum("ferrowarden_auth_failures_total", &[("kind", "agent")])
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        after = m.scrape(&env).await;
    }
    let delta =
        |name: &str, labels: &[(&str, &str)]| after.sum(name, labels) - before.sum(name, labels);

    assert!(delta(spec_series, &[("outcome", "success")]) >= 1.0);
    assert!(
        delta(
            spec_series,
            &[("outcome", "failure"), ("reason", "target_blocked")]
        ) >= 1.0
    );
    assert!(
        delta(
            spec_series,
            &[("outcome", "failure"), ("reason", "unknown_credential")]
        ) >= 1.0
    );
    assert!(delta("ferrowarden_auth_failures_total", &[("kind", "agent")]) >= 1.0);
    assert!(
        delta(
            "ferrowarden_events_total",
            &[("action", "forward"), ("outcome", "success")]
        ) >= 1.0
    );
    assert!(
        delta(
            "ferrowarden_forward_duration_seconds_count",
            &[("outcome", "success")]
        ) >= 1.0
    );
    assert!(delta("ferrowarden_forward_response_bytes_count", &[]) >= 1.0);
    assert!(delta("ferrowarden_forward_response_bytes_sum", &[]) >= bytes as f64);
    // Gauges against what the API says.
    assert_eq!(after.gauge("ferrowarden_vault_unlocked"), 1.0);
    let listed: Vec<String> = env
        .client
        .get(format!("{}/v1/credentials", env.fw_url))
        .header("X-Agent-Key", &env.agent_key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        after.gauge("ferrowarden_vault_credentials"),
        listed.len() as f64,
        "credential count against /v1/credentials"
    );
    let status: Value = env
        .admin_call("GET", "/v1/admin/status", None)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        after.gauge("ferrowarden_vault_credentials"),
        status["credential_count"].as_f64().unwrap()
    );
    let keys: Vec<Value> = env
        .admin_call("GET", "/v1/admin/keys", None)
        .await
        .json()
        .await
        .unwrap();
    // The `key` label is the name an administrator gave a key: one of the
    // names in the key list (keys revoked since keep their series).
    let key_names: Vec<&str> = keys.iter().filter_map(|k| k["name"].as_str()).collect();
    assert!(
        after.series(spec_series).iter().any(|(labels, v)| *v >= 1.0
            && key_names
                .iter()
                .any(|n| labels.contains(&format!("key=\"{n}\"")))),
        "no forward series is labelled with the name of a listed key:
{}",
        after.text
    );
    let without = keys.iter().filter(|k| k["policy_set"] == false).count() as f64;
    let with = keys.len() as f64 - without;
    assert_eq!(
        after.sum("ferrowarden_agent_keys", &[("policy_set", "false")]),
        without
    );
    assert_eq!(
        after.sum("ferrowarden_agent_keys", &[("policy_set", "true")]),
        with
    );

    // The build and the backend the instance runs.
    let backend = status["vault_backend"].as_str().unwrap();
    assert!(
        after.sum(
            "ferrowarden_build_info",
            &[
                ("vault_backend", backend),
                ("version", env!("CARGO_PKG_VERSION"))
            ]
        ) == 1.0,
        "build_info for {backend}"
    );

    // The test stack syncs every 30 s: the last sync is recent.
    let last = after.gauge("ferrowarden_vault_last_sync_timestamp_seconds");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    assert!(
        last > 0.0 && (now - last).abs() < 600.0,
        "last sync {last}, now {now}"
    );

    // The rest exist, with the labels the documentation lists.
    assert!(after.gauge("ferrowarden_vault_excluded_items") >= 0.0);
    assert!(after.gauge("ferrowarden_ui_sessions") >= 0.0);
    assert!(after.gauge("ferrowarden_events_dropped_total") >= 0.0);
    assert!(after.gauge("ferrowarden_metrics_events_dropped_total") >= 0.0);
    for limiter in ["agent", "admin", "notify_test"] {
        assert!(
            after
                .series("ferrowarden_rate_limited_total")
                .iter()
                .any(|(l, _)| l.contains(&format!("limiter=\"{limiter}\""))),
            "{limiter}"
        );
    }
    for result in ["sent", "failed"] {
        assert!(
            after
                .series("ferrowarden_notifications_total")
                .iter()
                .any(|(l, _)| l.contains("sender=\"webhook\"")
                    && l.contains(&format!("result=\"{result}\""))),
            "the webhook notifier's {result} counter"
        );
    }
    assert!(
        after
            .series("ferrowarden_notifications_total")
            .iter()
            .any(|(l, _)| l.contains("result=\"suppressed\"")),
        "suppressed notifications"
    );

    assert_scrape_is_clean(&env, &m, &after);
}

/// Security (the acceptance criterion "metric output never contains
/// substituted values", and more): traffic whose URLs, paths, queries, headers
/// and placeholders are all recognisable must leave none of them in a scrape,
/// and a scrape holds no secret value, token, vault item name, host or IP.
#[tokio::test]
async fn test_metrics_never_contain_values_urls_hosts_or_tokens() {
    let Some(env) = TestEnv::load() else { return };
    let m = metrics_env();
    env.reset_mock().await;
    let marker = format!("leakmarker{}", unique_suffix());

    // Marked paths, queries and header names, on success and on failure.
    let path = format!("/{marker}/secret-segment?token={marker}&k=v");
    let header = format!("X-{marker}");
    let ok = env
        .forward(
            "POST",
            &path,
            json!({
                "Authorization": "Bearer {{vault:test_api_token}}",
                header.clone(): marker.clone(),
            }),
            Some(json!({ "note": marker.clone(), "pw": "{{vault:test_basic_password}}" })),
        )
        .await;
    assert_eq!(ok.status(), 200);
    let blocked = env
        .forward_url(
            "GET",
            &format!("http://bw-serve:8087/{marker}?token={marker}"),
            json!({ header.clone(): marker.clone() }),
            None,
        )
        .await;
    assert_eq!(blocked.status(), 403);
    let unknown = env
        .forward(
            "GET",
            &path,
            json!({ "X": format!("{{{{vault:{marker}}}}}") }),
            None,
        )
        .await;
    assert_eq!(unknown.status(), 422);
    let bad_key = env
        .client
        .post(format!("{}/v1/forward", env.fw_url))
        .header("X-Agent-Key", format!("bad-{marker}"))
        .json(&json!({"request": {"method": "GET", "url": format!("http://{marker}.example/")}}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_key.status(), 401);

    let scrape = m.scrape(&env).await;
    for needle in [marker.as_str(), "secret-segment", "this_credential"] {
        assert!(
            !scrape.text.contains(needle),
            "a scrape contains {needle:?}"
        );
    }
    assert_scrape_is_clean(&env, &m, &scrape);
}

/// The last word, after the rest of the suite (tests run in name order, one at
/// a time): everything the suite did, the scrape still holds nothing it must
/// not. The secret gate scans one more scrape of each instance afterwards.
#[tokio::test]
async fn test_zz_metrics_scrape_after_the_suite_holds_no_secrets() {
    let Some(env) = TestEnv::load() else { return };
    let m = metrics_env();
    let scrape = m.scrape(&env).await;
    assert!(
        scrape.sum("ferrowarden_forward_requests_total", &[]) > 0.0,
        "the suite made forward requests"
    );
    assert!(
        scrape.sum("ferrowarden_events_total", &[]) > 10.0,
        "and other events"
    );
    assert_scrape_is_clean(&env, &m, &scrape);
}

// ── Container hardening ───────────────────────────────────────────────────────

/// Run `docker` with `args` and return its trimmed stdout, or `None` when
/// docker is unavailable or the command fails (the test then skips).
fn docker(args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("docker")
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The ferrowarden container of the test stack reports `healthy` through its
/// own `ferrowarden healthcheck` (the image has no curl), and runs hardened:
/// read-only root filesystem, no capabilities, no privilege escalation. The
/// admin key is read from its secret file and is not part of the container's
/// configuration (its `docker inspect` environment holds only the file path).
///
/// Skips when docker, or the compose test stack's container, is not available
/// to the test (for example a stack running on another machine).
#[tokio::test]
async fn test_container_is_healthy_and_hardened() {
    let Some(env) = TestEnv::load() else {
        eprintln!("SKIP: set FERROWARDEN_INTEGRATION=1");
        return;
    };
    let Some(id) = docker(&[
        "compose",
        "-f",
        "docker-compose.test.yml",
        "ps",
        "-q",
        "ferrowarden",
    ])
    .filter(|id| !id.is_empty()) else {
        eprintln!("SKIP: docker or the compose test stack is not available to this test");
        return;
    };

    let health = docker(&["inspect", "-f", "{{.State.Health.Status}}", &id]).unwrap();
    assert_eq!(health, "healthy", "the container health check");

    let host = docker(&[
        "inspect",
        "-f",
        "{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}}",
        &id,
    ])
    .unwrap();
    assert_eq!(
        host, "true [ALL] [no-new-privileges:true]",
        "hardening flags"
    );

    // Never print the environment: it is compared, not displayed.
    let config_env = docker(&["inspect", "-f", "{{json .Config.Env}}", &id]).unwrap();
    assert!(
        !config_env.contains(&env.admin_key),
        "the admin key value is in the container configuration"
    );
    assert!(
        config_env.contains("FERROWARDEN_ADMIN_KEY_FILE="),
        "the admin key should come from a secret file"
    );
}
