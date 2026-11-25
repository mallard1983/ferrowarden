//! The MCP server driven end to end in one process: a mock Ferrowarden
//! (axum, on a loopback port) on one side, rmcp's own client over an
//! in-memory stream on the other.

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt};
use serde_json::{json, Value};

use super::client::FerroClient;
use super::config::Config;
use super::server::FerrowardenMcp;

const FAKE_KEY: &str = "fw_agent_FAKEKEY0123456789abcdef";
const FAKE_PREFIX: &str = "s3cr3tpr3fixq7";

// ── Mock Ferrowarden ──────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: String,
}

impl Reply {
    fn json(status: u16, body: Value) -> Self {
        Reply {
            status,
            headers: vec![
                ("content-type", "application/json".into()),
                (
                    "x-request-id",
                    "0191a2b3-0000-7000-8000-00000000abcd".into(),
                ),
            ],
            body: body.to_string(),
        }
    }
    fn error(status: u16, message: &str) -> Self {
        Reply::json(status, json!({ "error": message }))
    }
    fn with_header(mut self, name: &'static str, value: &str) -> Self {
        self.headers.push((name, value.into()));
        self
    }
}

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    query: String,
    key: Option<String>,
    content_type: Option<String>,
    body: String,
}

#[derive(Default)]
struct MockState {
    seen: Mutex<Vec<Seen>>,
    reply: Mutex<Option<Reply>>,
}

async fn mock_handler(
    State(state): State<Arc<MockState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let seen = Seen {
        method: method.to_string(),
        path: uri.path().to_string(),
        query: uri.query().unwrap_or_default().to_string(),
        key: header("x-agent-key"),
        content_type: header("content-type"),
        body: String::from_utf8_lossy(&body).into_owned(),
    };
    let path = seen.path.clone();
    let key_ok = seen.key.as_deref() == Some(FAKE_KEY);
    state.seen.lock().unwrap().push(seen);

    let reply = if !path.starts_with(&format!("/{FAKE_PREFIX}/")) {
        Reply::error(404, "not found")
    } else if !key_ok {
        Reply::error(401, "Invalid or missing agent key")
    } else if let Some(preset) = state.reply.lock().unwrap().clone() {
        preset
    } else if path.ends_with("/v1/credentials") {
        Reply::json(200, json!([credential_detail()]))
    } else if path.ends_with("/v1/forward") {
        Reply::json(200, proxy_response(200, "{\"ok\":true}"))
    } else {
        Reply::error(404, "not found")
    };

    let mut builder = Response::builder().status(StatusCode::from_u16(reply.status).unwrap());
    for (name, value) in &reply.headers {
        builder = builder.header(*name, value);
    }
    builder
        .body(axum::body::Body::from(reply.body))
        .unwrap()
        .into_response()
}

fn credential_detail() -> Value {
    json!({
        "name": "Example Service (prod)",
        "type": "login",
        "placeholder": "{{vault:'Example Service (prod)'}}",
        "username": "{{vault:'Example Service (prod)':username}}",
        "bound_to": ["https://api.example.com"]
    })
}

fn proxy_response(status: u16, body: &str) -> Value {
    json!({
        "status": status,
        "headers": { "content-type": "application/json" },
        "body": body,
        "body_encoding": "utf8"
    })
}

struct Harness {
    peer: RunningService<RoleClient, ()>,
    state: Arc<MockState>,
}

impl Harness {
    async fn start() -> Self {
        let state = Arc::new(MockState::default());
        let app = Router::new()
            .fallback(mock_handler)
            .with_state(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self::connect(port, FAKE_KEY, state).await
    }

    /// A server whose Ferrowarden is a closed port.
    async fn start_unreachable() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        Self::connect(port, FAKE_KEY, Arc::new(MockState::default())).await
    }

    async fn connect(port: u16, key: &str, state: Arc<MockState>) -> Self {
        let url = format!("http://127.0.0.1:{port}/{FAKE_PREFIX}");
        let config = Config::from_lookup(|name| {
            Ok(match name {
                "FERROWARDEN_URL" => Some(url.clone()),
                "FERROWARDEN_AGENT_KEY" => Some(key.to_string()),
                "FERROWARDEN_MCP_TIMEOUT_SECS" => Some("5".to_string()),
                _ => None,
            })
        })
        .unwrap();
        let client = Arc::new(FerroClient::new(&config).unwrap());
        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            let service = FerrowardenMcp::new(client).serve(server_io).await.unwrap();
            let _ = service.waiting().await;
        });
        let peer = ().serve(client_io).await.unwrap();
        Harness { peer, state }
    }

    fn reply_with(&self, reply: Reply) {
        *self.state.reply.lock().unwrap() = Some(reply);
    }

    fn seen(&self) -> Vec<Seen> {
        self.state.seen.lock().unwrap().clone()
    }

    async fn call(&self, name: &'static str, args: Value) -> CallToolResult {
        let mut params = CallToolRequestParams::new(name);
        if let Value::Object(map) = args {
            if !map.is_empty() {
                params = params.with_arguments(map);
            }
        }
        self.peer.call_tool(params).await.expect("protocol answer")
    }
}

fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Everything a client could see in a result, as one string.
fn everything(result: &CallToolResult) -> String {
    serde_json::to_string(result).unwrap()
}

fn assert_no_secrets(what: &str, shown: &str) {
    assert!(!shown.contains(FAKE_KEY), "{what}: the agent key is shown");
    assert!(
        !shown.contains(FAKE_PREFIX),
        "{what}: the base URL path is shown"
    );
}

fn get_args() -> Value {
    json!({ "method": "GET", "url": "https://api.example.com/v1/items",
            "headers": { "Authorization": "Bearer {{vault:example_api_token}}" } })
}

// ── Protocol ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn initialize_names_the_server_and_offers_tools() {
    let h = Harness::start().await;
    let info = h.peer.peer_info().expect("initialized");
    let server = info.server_info.as_ref().expect("server info");
    assert_eq!(server.name, "ferrowarden-mcp");
    assert_eq!(server.version, env!("CARGO_PKG_VERSION"));
    assert!(info.capabilities.tools.is_some());
    assert!(info.capabilities.resources.is_none());
    assert!(info.capabilities.prompts.is_none());
    let instructions = info.instructions.as_deref().unwrap_or_default();
    assert!(instructions.contains("403"));
}

#[tokio::test]
async fn tools_list_has_exactly_the_two_tools_with_strict_schemas() {
    let h = Harness::start().await;
    let tools = h.peer.list_all_tools().await.unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names, vec!["list_credentials", "http_request"]);
    for tool in &tools {
        let schema = Value::Object((*tool.input_schema).clone());
        assert_eq!(schema["type"], "object", "{}", tool.name);
        assert_eq!(
            schema["additionalProperties"],
            json!(false),
            "{}",
            tool.name
        );
    }
    let http = &tools[1];
    let schema = Value::Object((*http.input_schema).clone());
    assert_eq!(schema["required"], json!(["method", "url"]));
    assert_eq!(
        schema["properties"]["method"]["enum"],
        json!(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    );
    // What goes over the wire is what tools.rs defines (and what the
    // OpenAPI test there checks).
    assert_eq!(schema, Value::Object(super::tools::http_request_schema()));
}

#[tokio::test]
async fn unknown_tool_is_a_protocol_error() {
    let h = Harness::start().await;
    let err = h
        .peer
        .call_tool(CallToolRequestParams::new("ssh_exec"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unknown tool"));
}

// ── list_credentials ──────────────────────────────────────────────────────────

#[tokio::test]
async fn list_credentials_returns_structured_and_text() {
    let h = Harness::start().await;
    let r = h.call("list_credentials", json!({})).await;
    assert_eq!(r.is_error, Some(false));
    let structured = r.structured_content.clone().expect("structured content");
    assert_eq!(
        structured["credentials"][0]["placeholder"],
        "{{vault:'Example Service (prod)'}}"
    );
    let text = text_of(&r);
    assert!(text.contains("1 credential available"));
    assert!(text.contains("{{vault:'Example Service (prod)':username}}"));
    assert!(text.contains("bound to: https://api.example.com"));

    let seen = h.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].path, format!("/{FAKE_PREFIX}/v1/credentials"));
    assert_eq!(seen[0].query, "detail=true");
    assert_eq!(seen[0].key.as_deref(), Some(FAKE_KEY));
    assert_no_secrets("list_credentials", &everything(&r));
}

#[tokio::test]
async fn list_credentials_with_arguments_is_a_tool_error() {
    let h = Harness::start().await;
    let r = h.call("list_credentials", json!({"detail": false})).await;
    assert_eq!(r.is_error, Some(true));
    assert!(h.seen().is_empty());
}

// ── http_request ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn http_request_success_sends_the_documented_payload() {
    let h = Harness::start().await;
    let r = h
        .call(
            "http_request",
            json!({
                "method": "POST",
                "url": "https://api.example.com/v1/items",
                "headers": { "X-Api-Key": "{{vault:example_api_token}}" },
                "body": { "name": "example" }
            }),
        )
        .await;
    assert_eq!(r.is_error, Some(false));
    let structured = r.structured_content.clone().unwrap();
    assert_eq!(structured["status"], 200);
    assert_eq!(structured["body_encoding"], "utf8");
    assert!(text_of(&r).starts_with("HTTP 200"));
    assert!(text_of(&r).ends_with("{\"ok\":true}"));

    let seen = h.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, format!("/{FAKE_PREFIX}/v1/forward"));
    assert_eq!(seen[0].content_type.as_deref(), Some("application/json"));
    let sent: Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(
        sent,
        json!({"request": {
            "method": "POST",
            "url": "https://api.example.com/v1/items",
            "headers": { "X-Api-Key": "{{vault:example_api_token}}" },
            "body": { "name": "example" }
        }})
    );
    assert_no_secrets("http_request", &everything(&r));
}

#[tokio::test]
async fn a_string_body_is_sent_as_a_string() {
    let h = Harness::start().await;
    let mut args = get_args();
    args["method"] = json!("POST");
    args["body"] = json!("a=1&b={{vault:x}}");
    h.call("http_request", args).await;
    let sent: Value = serde_json::from_str(&h.seen()[0].body).unwrap();
    assert_eq!(sent["request"]["body"], "a=1&b={{vault:x}}");
}

/// A target's own 4xx or 5xx arrives inside a 200 from Ferrowarden. It is a
/// normal result with that status, not a tool error.
#[tokio::test]
async fn target_errors_are_normal_results() {
    for target_status in [400u16, 401, 403, 404, 429, 500, 502, 503] {
        let h = Harness::start().await;
        h.reply_with(Reply::json(
            200,
            proxy_response(target_status, "{\"error\":\"from the target\"}"),
        ));
        let r = h.call("http_request", get_args()).await;
        assert_eq!(r.is_error, Some(false), "target {target_status}");
        assert_eq!(
            r.structured_content.as_ref().unwrap()["status"],
            target_status
        );
        let text = text_of(&r);
        assert!(text.starts_with(&format!("HTTP {target_status} (the target's response")));
        assert!(!text.contains("Ferrowarden refused"));
    }
}

#[tokio::test]
async fn binary_bodies_are_summarised_in_text_and_complete_in_structure() {
    let h = Harness::start().await;
    h.reply_with(Reply::json(
        200,
        json!({"status": 200, "headers": {}, "body": "AJ+Slg==", "body_encoding": "base64"}),
    ));
    let r = h.call("http_request", get_args()).await;
    assert_eq!(r.is_error, Some(false));
    assert!(text_of(&r).contains("binary response body, 4 bytes"));
    assert!(!text_of(&r).contains("AJ+Slg=="));
    let structured = r.structured_content.unwrap();
    assert_eq!(structured["body"], "AJ+Slg==");
    assert_eq!(structured["body_encoding"], "base64");
}

#[tokio::test]
async fn large_bodies_are_cut_in_text_not_in_structure() {
    let h = Harness::start().await;
    let big = "y".repeat(300 * 1024);
    h.reply_with(Reply::json(200, proxy_response(200, &big)));
    let r = h.call("http_request", get_args()).await;
    let text = text_of(&r);
    assert!(text.len() < super::render::MAX_TEXT_BYTES + 400);
    assert!(text.contains("[truncated"));
    assert_eq!(
        r.structured_content.unwrap()["body"]
            .as_str()
            .unwrap()
            .len(),
        big.len()
    );
}

#[tokio::test]
async fn invalid_arguments_are_tool_errors_and_nothing_is_sent() {
    let h = Harness::start().await;
    for args in [
        json!({}),
        json!({"method": "GET"}),
        json!({"method": "GET", "url": "https://a.example", "extra": true}),
        json!({"method": "GET", "url": "https://a.example", "headers": {"A": 1}}),
    ] {
        let r = h.call("http_request", args).await;
        assert_eq!(r.is_error, Some(true));
        assert!(text_of(&r).contains("Invalid arguments"));
    }
    assert!(h.seen().is_empty());
}

// ── Ferrowarden's own errors ──────────────────────────────────────────────────

#[tokio::test]
async fn each_ferrowarden_error_status_is_a_tool_error_with_guidance() {
    let cases: [(u16, &str, &str); 10] = [
        (400, "Request body is not valid", "malformed"),
        (
            401,
            "Invalid or missing agent key",
            "missing, invalid or revoked",
        ),
        (
            403,
            "Credential example_api_token is not bound to this host",
            "Do not retry it with other credentials, hosts or methods",
        ),
        (
            404,
            "Credential not found in vault",
            "not found in the vault",
        ),
        (
            409,
            "Name matches more than one vault item",
            "more than one vault item",
        ),
        (422, "Unknown credential", "copy a ready-made placeholder"),
        (429, "Rate limit exceeded", "Wait 12 seconds"),
        (
            502,
            "Upstream request failed",
            "could not get an answer from the target",
        ),
        (503, "Vault is locked", "vault is locked"),
        (500, "Internal server error", "unexpected error"),
    ];
    for (status, message, guidance) in cases {
        for tool in ["list_credentials", "http_request"] {
            let h = Harness::start().await;
            let mut reply = Reply::error(status, message);
            if status == 429 {
                reply = reply.with_header("retry-after", "12");
            }
            h.reply_with(reply);
            let args = if tool == "http_request" {
                get_args()
            } else {
                json!({})
            };
            let r = h.call(tool, args).await;
            assert_eq!(r.is_error, Some(true), "{tool} {status}");
            let text = text_of(&r);
            assert!(text.contains(&format!("HTTP {status}")), "{text}");
            assert!(text.contains(&format!("Message: {message}")), "{text}");
            assert!(
                text.contains("Request ID: 0191a2b3-0000-7000-8000-00000000abcd"),
                "{text}"
            );
            assert!(text.contains(guidance), "{status}: {text}");
            let structured = r.structured_content.as_ref().unwrap();
            assert_eq!(structured["error_source"], "ferrowarden");
            assert_eq!(structured["status"], status);
            assert_no_secrets("error", &everything(&r));
        }
    }
}

#[tokio::test]
async fn a_wrong_key_gets_the_401_guidance() {
    let state = Arc::new(MockState::default());
    let app = Router::new()
        .fallback(mock_handler)
        .with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let wrong = "fw_agent_WRONGKEY9999999999999999";
    let h = Harness::connect(port, wrong, state).await;
    let r = h.call("list_credentials", json!({})).await;
    assert_eq!(r.is_error, Some(true));
    assert!(text_of(&r).contains("missing, invalid or revoked"));
    let shown = everything(&r);
    assert!(!shown.contains(wrong));
    assert_no_secrets("401", &shown);
}

/// Ferrowarden must never see its own secrets echoed back to the agent, even
/// if an error message from somewhere in the path contained them.
#[tokio::test]
async fn secrets_in_a_server_error_message_are_removed() {
    let h = Harness::start().await;
    h.reply_with(Reply::error(
        403,
        &format!("denied for {FAKE_KEY} at /{FAKE_PREFIX}/v1/forward"),
    ));
    let r = h.call("http_request", get_args()).await;
    assert_eq!(r.is_error, Some(true));
    assert_no_secrets("echoed error", &everything(&r));
    assert!(text_of(&r).contains("[agent key]"));
}

#[tokio::test]
async fn html_error_pages_are_not_echoed() {
    let h = Harness::start().await;
    h.reply_with(Reply {
        status: 502,
        headers: vec![("content-type", "text/html".into())],
        body: format!("<html>bad gateway /{FAKE_PREFIX}</html>"),
    });
    let r = h.call("http_request", get_args()).await;
    assert_eq!(r.is_error, Some(true));
    let text = text_of(&r);
    assert!(text.contains("Message: (none)"));
    assert!(!text.contains("<html>"));
    assert_no_secrets("html", &everything(&r));
}

#[tokio::test]
async fn redirects_are_not_followed_and_are_errors() {
    let h = Harness::start().await;
    h.reply_with(Reply::error(302, "moved").with_header("location", "https://elsewhere.example/"));
    let r = h.call("list_credentials", json!({})).await;
    assert_eq!(r.is_error, Some(true));
    assert!(text_of(&r).contains("redirect"));
    assert_eq!(h.seen().len(), 1, "the redirect must not be followed");
}

#[tokio::test]
async fn an_unexpected_success_body_is_an_error() {
    let h = Harness::start().await;
    h.reply_with(Reply {
        status: 200,
        headers: vec![("content-type", "text/html".into())],
        body: "<html>welcome</html>".into(),
    });
    for (tool, args) in [
        ("list_credentials", json!({})),
        ("http_request", get_args()),
    ] {
        let r = h.call(tool, args).await;
        assert_eq!(r.is_error, Some(true), "{tool}");
        assert!(text_of(&r).contains("FERROWARDEN_URL may point at the wrong address"));
    }
}

#[tokio::test]
async fn unreachable_ferrowarden_is_a_tool_error_without_the_url() {
    let h = Harness::start_unreachable().await;
    for (tool, args) in [
        ("list_credentials", json!({})),
        ("http_request", get_args()),
    ] {
        let r = h.call(tool, args).await;
        assert_eq!(r.is_error, Some(true), "{tool}");
        let text = text_of(&r);
        assert!(text.starts_with("Could not reach Ferrowarden"), "{text}");
        assert!(!text.contains("127.0.0.1"));
        assert!(!text.contains("http://"));
        assert_no_secrets("unreachable", &everything(&r));
    }
}

/// Every result from every path above, once more as a whole: the key and the
/// URL path appear in none of them.
#[tokio::test]
async fn no_output_contains_the_key_or_the_url_path() {
    let h = Harness::start().await;
    let mut shown = vec![
        everything(&h.call("list_credentials", json!({})).await),
        everything(&h.call("http_request", get_args()).await),
        everything(&h.call("http_request", json!({"method": "GET"})).await),
    ];
    for status in [401u16, 403, 422, 429, 502, 503] {
        h.reply_with(Reply::error(status, "refused"));
        shown.push(everything(&h.call("http_request", get_args()).await));
    }
    let tools = h.peer.list_all_tools().await.unwrap();
    shown.push(serde_json::to_string(&tools).unwrap());
    shown.push(serde_json::to_string(&h.peer.peer_info()).unwrap());
    for (i, s) in shown.iter().enumerate() {
        assert_no_secrets(&format!("output {i}"), s);
    }
}
