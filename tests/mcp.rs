//! Tests of the `ferrowarden-mcp` binary, run as a real process over stdio.
//!
//! Two groups:
//!
//! - Process behaviour that needs no Ferrowarden: `--help`, `--version`,
//!   unknown arguments, configuration errors (exit 2, nothing on stdout) and
//!   a session against a port where nothing listens (stdout carries only
//!   protocol messages; the key and the URL path appear nowhere).
//! - Tests against the running test stack, gated like `integration.rs` by
//!   `FERROWARDEN_INTEGRATION=1`: initialize, tools/list, list_credentials,
//!   http_request with substitution (seen at the mock API's capture
//!   endpoint) and scrubbing, and a refused request (403) with its guidance.
//!
//! ```sh
//! set -a; . ./.env.test; set +a
//! cargo test --test mcp -- --test-threads=1
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_ferrowarden-mcp");

/// The value of the seeded `test_api_token` (see integration.rs). Test data;
/// assertions on it never print it.
const TEST_API_TOKEN_VALUE: &str = "test-token-abc123def456";

const FAKE_KEY: &str = "fw_agent_NOTAREALKEY0123456789";
const FAKE_PREFIX: &str = "s3cr3tpr3fixq7";

fn command() -> Command {
    let mut cmd = Command::new(BIN);
    for name in [
        "FERROWARDEN_URL",
        "FERROWARDEN_AGENT_KEY",
        "FERROWARDEN_AGENT_KEY_FILE",
        "FERROWARDEN_CA_FILE",
        "FERROWARDEN_MCP_TIMEOUT_SECS",
        "FERROWARDEN_MCP_ALLOW_HTTP",
        "FERROWARDEN_MCP_LOG",
    ] {
        cmd.env_remove(name);
    }
    cmd
}

struct Output {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_to_end(mut cmd: Command) -> Output {
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .expect("ferrowarden-mcp starts");
    Output {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

// ── A client of the binary over stdio ─────────────────────────────────────────

struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    /// Every line the server wrote to stdout.
    stdout_log: Vec<String>,
    stderr: Receiver<String>,
    next_id: u64,
}

impl Session {
    fn start(mut cmd: Command) -> Self {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("ferrowarden-mcp starts");
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let (etx, stderr_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text);
            let _ = etx.send(text);
        });
        let stdin = child.stdin.take();
        Session {
            child,
            stdin,
            lines,
            stdout_log: Vec::new(),
            stderr: stderr_rx,
            next_id: 1,
        }
    }

    fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    fn notify(&mut self, method: &str) {
        self.send(&json!({"jsonrpc": "2.0", "method": method}));
    }

    /// Send a request and wait for its response. Every line the server
    /// writes must be a JSON-RPC message.
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(60))
                .expect("a response from ferrowarden-mcp within 60 s");
            self.stdout_log.push(line.clone());
            let message: Value = serde_json::from_str(&line)
                .unwrap_or_else(|_| panic!("stdout line is not JSON ({} bytes)", line.len()));
            assert_eq!(
                message["jsonrpc"], "2.0",
                "stdout carries only MCP messages"
            );
            if message["id"] == json!(id) {
                return message;
            }
        }
    }

    fn initialize(&mut self) -> Value {
        let reply = self.request(
            "initialize",
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "ferrowarden-mcp-test", "version": "0"}
            }),
        );
        self.notify("notifications/initialized");
        reply
    }

    fn call(&mut self, tool: &str, arguments: Value) -> Value {
        let reply = self.request("tools/call", json!({"name": tool, "arguments": arguments}));
        reply["result"].clone()
    }

    /// Close stdin, wait for exit, and return all of stdout and stderr.
    fn finish(mut self) -> (String, String) {
        drop(self.stdin.take());
        let status = {
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    break status;
                }
                if std::time::Instant::now() > deadline {
                    let _ = self.child.kill();
                    panic!("ferrowarden-mcp did not exit when stdin closed");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        };
        assert!(status.success(), "exit status {status:?}");
        while let Ok(line) = self.lines.try_recv() {
            self.stdout_log.push(line);
        }
        let stderr = self
            .stderr
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_default();
        (self.stdout_log.join("\n"), stderr)
    }
}

fn text_of(result: &Value) -> String {
    result["content"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|c| c["text"].as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

// ── No stack needed ───────────────────────────────────────────────────────────

#[test]
fn help_and_version_go_to_stdout_and_exit_zero() {
    let mut cmd = command();
    cmd.arg("--help");
    let out = run_to_end(cmd);
    assert_eq!(out.code, Some(0));
    assert!(out.stdout.starts_with(
        "ferrowarden-mcp \u{2014} MCP tools for calling APIs through Ferrowarden with named vault credentials."
    ));
    assert!(out.stdout.contains("FERROWARDEN_URL"));
    assert!(out.stderr.is_empty());

    let mut cmd = command();
    cmd.arg("--version");
    let out = run_to_end(cmd);
    assert_eq!(out.code, Some(0));
    assert_eq!(
        out.stdout.trim(),
        format!("ferrowarden-mcp {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn unknown_argument_prints_usage_on_stderr_and_exits_two() {
    let mut cmd = command();
    cmd.arg("serve");
    let out = run_to_end(cmd);
    assert_eq!(out.code, Some(2));
    assert!(out.stdout.is_empty());
    assert!(out.stderr.contains("unrecognized argument"));
    assert!(out.stderr.contains("Usage: ferrowarden-mcp"));
}

#[test]
fn configuration_errors_exit_two_with_nothing_on_stdout() {
    // (environment, text the message must contain)
    let url_with_prefix = format!("https://ferro.example.com/{FAKE_PREFIX}");
    let http_url = format!("http://ferro.lan:3000/{FAKE_PREFIX}");
    let cases: Vec<(Vec<(&str, String)>, &str)> = vec![
        (vec![], "FERROWARDEN_URL is required"),
        (
            vec![("FERROWARDEN_URL", url_with_prefix.clone())],
            "FERROWARDEN_AGENT_KEY",
        ),
        (
            vec![
                ("FERROWARDEN_URL", http_url.clone()),
                ("FERROWARDEN_AGENT_KEY", FAKE_KEY.to_string()),
            ],
            "must use https://",
        ),
        (
            vec![
                ("FERROWARDEN_URL", url_with_prefix.clone()),
                ("FERROWARDEN_AGENT_KEY", FAKE_KEY.to_string()),
                ("FERROWARDEN_AGENT_KEY_FILE", "somewhere".to_string()),
            ],
            "only one of",
        ),
        (
            vec![
                ("FERROWARDEN_URL", url_with_prefix.clone()),
                ("FERROWARDEN_AGENT_KEY", FAKE_KEY.to_string()),
                ("FERROWARDEN_MCP_TIMEOUT_SECS", "0".to_string()),
            ],
            "FERROWARDEN_MCP_TIMEOUT_SECS",
        ),
        (
            vec![
                ("FERROWARDEN_URL", url_with_prefix),
                ("FERROWARDEN_AGENT_KEY", FAKE_KEY.to_string()),
                ("FERROWARDEN_CA_FILE", "no-such-file.pem".to_string()),
            ],
            "FERROWARDEN_CA_FILE",
        ),
    ];
    for (env, needle) in cases {
        let mut cmd = command();
        cmd.envs(env);
        let out = run_to_end(cmd);
        assert_eq!(out.code, Some(2), "{needle}");
        assert!(out.stdout.is_empty(), "{needle}: stdout must stay empty");
        assert!(out.stderr.contains(needle), "{needle}: {}", out.stderr);
        assert!(!out.stderr.contains(FAKE_KEY), "{needle}");
        assert!(!out.stderr.contains(FAKE_PREFIX), "{needle}");
    }
}

/// Stdout holds protocol messages and nothing else, whatever the log level,
/// and neither the key nor the URL path is written anywhere, including stderr
/// at the most verbose level.
#[test]
fn stdout_is_protocol_only_and_secrets_stay_out_of_every_stream() {
    // A port where nothing listens: every call ends as "could not reach".
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut cmd = command();
    cmd.env(
        "FERROWARDEN_URL",
        format!("http://127.0.0.1:{port}/{FAKE_PREFIX}"),
    )
    .env("FERROWARDEN_AGENT_KEY", FAKE_KEY)
    .env("FERROWARDEN_MCP_LOG", "trace");
    let mut session = Session::start(cmd);
    let init = session.initialize();
    assert_eq!(init["result"]["serverInfo"]["name"], "ferrowarden-mcp");
    let tools = session.request("tools/list", json!({}));
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["list_credentials", "http_request"]);

    let listed = session.call("list_credentials", json!({}));
    assert_eq!(listed["isError"], true);
    assert!(text_of(&listed).starts_with("Could not reach Ferrowarden"));
    let forwarded = session.call(
        "http_request",
        json!({"method": "GET", "url": "https://api.example.com/x",
               "headers": {"Authorization": "Bearer {{vault:example}}"}}),
    );
    assert_eq!(forwarded["isError"], true);

    let (stdout, stderr) = session.finish();
    for (name, text) in [("stdout", &stdout), ("stderr", &stderr)] {
        assert!(!text.contains(FAKE_KEY), "{name} shows the agent key");
        assert!(!text.contains(FAKE_PREFIX), "{name} shows the URL path");
    }
    // The trace-level stderr has our own log lines (status and timing only).
    assert!(stderr.contains("could not reach Ferrowarden") || stderr.contains("starting"));
}

// ── Against the test stack ────────────────────────────────────────────────────

struct Stack {
    url: String,
    agent_key: String,
    mock_url: String,
    mock_internal: String,
}

impl Stack {
    fn load() -> Option<Self> {
        if std::env::var("FERROWARDEN_INTEGRATION").unwrap_or_default() != "1" {
            return None;
        }
        Some(Stack {
            url: std::env::var("FERROWARDEN_TEST_URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
            agent_key: std::env::var("FERROWARDEN_TEST_AGENT_KEY")
                .expect("FERROWARDEN_TEST_AGENT_KEY must be set when FERROWARDEN_INTEGRATION=1"),
            mock_url: std::env::var("MOCK_API_URL")
                .unwrap_or_else(|_| "http://localhost:7777".to_string()),
            mock_internal: std::env::var("MOCK_API_INTERNAL_URL")
                .unwrap_or_else(|_| "http://mock-api:7777".to_string()),
        })
    }

    fn session(&self) -> Session {
        let mut cmd = command();
        cmd.env("FERROWARDEN_URL", &self.url)
            .env("FERROWARDEN_AGENT_KEY", &self.agent_key)
            .env("FERROWARDEN_MCP_LOG", "info");
        Session::start(cmd)
    }

    async fn mock_get(&self, path: &str) -> Value {
        reqwest::get(format!("{}{path}", self.mock_url))
            .await
            .expect("mock API reachable")
            .json()
            .await
            .expect("mock API answered JSON")
    }

    async fn reset_mock(&self) {
        reqwest::Client::new()
            .post(format!("{}/__reset__", self.mock_url))
            .send()
            .await
            .expect("mock API reset");
    }
}

#[tokio::test]
async fn mcp_session_against_the_test_stack() {
    let Some(stack) = Stack::load() else { return };
    stack.reset_mock().await;
    let mut s = stack.session();

    // initialize, tools/list
    let init = s.initialize();
    assert_eq!(init["result"]["serverInfo"]["name"], "ferrowarden-mcp");
    let tools = s.request("tools/list", json!({}));
    let tools = tools["result"]["tools"].as_array().unwrap().clone();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["list_credentials", "http_request"]);
    for tool in &tools {
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
    }

    // list_credentials: ready-made placeholders, no values.
    let listed = s.call("list_credentials", json!({}));
    assert_eq!(listed["isError"], false, "{}", text_of(&listed));
    let credentials = listed["structuredContent"]["credentials"]
        .as_array()
        .expect("credential list");
    let token = credentials
        .iter()
        .find(|c| c["name"] == "test_api_token")
        .expect("test_api_token is listed for the test key");
    assert_eq!(token["placeholder"], "{{vault:test_api_token}}");
    assert!(token["bound_to"].as_array().is_some_and(|b| !b.is_empty()));
    assert!(text_of(&listed).contains("{{vault:test_api_token}}"));
    assert!(!listed.to_string().contains(TEST_API_TOKEN_VALUE));

    // http_request: the placeholder is substituted on the way out (seen at
    // the mock API) and the echoed value is scrubbed on the way back.
    let target = format!("{}/mock-api/api/echo", stack.mock_internal);
    let forwarded = s.call(
        "http_request",
        json!({
            "method": "GET",
            "url": target,
            "headers": { "X-Arbitrary-Name": "{{vault:test_api_token}}" }
        }),
    );
    assert_eq!(forwarded["isError"], false, "{}", text_of(&forwarded));
    assert_eq!(forwarded["structuredContent"]["status"], 200);
    let shown = forwarded.to_string();
    assert!(
        !shown.contains(TEST_API_TOKEN_VALUE),
        "the credential value reached the agent (result not printed)"
    );
    assert!(
        shown.contains("[REDACTED]"),
        "the echoed value was not scrubbed"
    );

    let captured = stack.mock_get("/__requests__/last").await;
    let sent = captured["headers"]
        .as_object()
        .and_then(|h| {
            h.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("x-arbitrary-name"))
        })
        .and_then(|(_, v)| v.as_str())
        .expect("the mock API captured the header");
    assert_eq!(
        sent, TEST_API_TOKEN_VALUE,
        "substitution did not reach the target (values not printed)"
    );

    // 403: the credential is bound to another host. Nothing is forwarded.
    stack.reset_mock().await;
    let refused = s.call(
        "http_request",
        json!({
            "method": "GET",
            "url": format!("{}/mock-api/api/unbound", stack.mock_internal),
            "headers": { "Authorization": "Bearer {{vault:test_unbound}}" }
        }),
    );
    assert_eq!(refused["isError"], true);
    let text = text_of(&refused);
    assert!(text.contains("HTTP 403"), "{text}");
    assert!(text.contains("Do not retry it with other credentials, hosts or methods"));
    assert_eq!(refused["structuredContent"]["error_source"], "ferrowarden");
    assert_eq!(refused["structuredContent"]["status"], 403);
    let captured = stack.mock_get("/__requests__").await;
    assert_eq!(
        captured,
        json!([]),
        "a refused request must not be forwarded"
    );

    // A placeholder for a credential that does not exist: 422 with guidance.
    let unknown = s.call(
        "http_request",
        json!({
            "method": "GET",
            "url": format!("{}/mock-api/api/x", stack.mock_internal),
            "headers": { "Authorization": "Bearer {{vault:no_such_credential_anywhere}}" }
        }),
    );
    assert_eq!(unknown["isError"], true);
    let status = unknown["structuredContent"]["status"].as_u64().unwrap();
    assert!(
        status == 403 || status == 422,
        "unknown or out-of-scope names are 403 or 422, got {status}"
    );

    let (stdout, stderr) = s.finish();
    for (name, text) in [("stdout", &stdout), ("stderr", &stderr)] {
        assert!(
            !text.contains(&stack.agent_key),
            "{name} shows the agent key"
        );
        assert!(
            !text.contains(TEST_API_TOKEN_VALUE),
            "{name} shows a credential value"
        );
    }
}

/// With nothing listening where `FERROWARDEN_URL` points, the call fails as a
/// tool error and the URL is not shown. (Always runs; needs no stack.)
#[test]
fn unreachable_ferrowarden_does_not_crash_the_server() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut cmd = command();
    cmd.env("FERROWARDEN_URL", format!("http://localhost:{port}"))
        .env("FERROWARDEN_AGENT_KEY", FAKE_KEY);
    let mut s = Session::start(cmd);
    s.initialize();
    let r = s.call("list_credentials", json!({}));
    assert_eq!(r["isError"], true);
    assert!(!text_of(&r).contains("localhost"));
    // Still alive and answering afterwards.
    let again = s.request("tools/list", json!({}));
    assert!(again["result"]["tools"].is_array());
    s.finish();
}
