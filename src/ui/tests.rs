//! End-to-end tests of the admin UI: the real router, driven with
//! `tower::ServiceExt::oneshot`, against a mock Vaultwarden (an axum server on
//! a loopback port that also plays `bw serve`).
//!
//! The mock's success body carries recognizable fake tokens and keys, and its
//! error messages are recognizable too. Every test that signs in checks that
//! none of them, nor the password or the derived hash, appears in any UI
//! response, any security event or any log line.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::config::{Config, UiConfig, UnlockMode};
use crate::events::EventLog;
use crate::state::{AgentKey, AppState};
use crate::ui::crypto::{self, Kdf};
use crate::ui::vw_login::Provider;
use crate::ui::{router, UiState};

const EMAIL: &str = "admin@example.test";
const PASSWORD: &str = "correct horse battery staple 7Q!";
const WRONG_PASSWORD: &str = "not-the-password-ZZ91";
const TOTP: &str = "123456";
const EMAIL_CODE: &str = "654321";
const YUBIKEY: &str = "ccccccdefghijklnrtuvccccccdefghijklnrtuvbbbb";
const KDF: Kdf = Kdf::Pbkdf2 { iterations: 5000 };

const FAKE_ACCESS_TOKEN: &str = "FAKE-ACCESS-TOKEN-7f3a9c41";
const FAKE_REFRESH_TOKEN: &str = "FAKE-REFRESH-TOKEN-b20e66d9";
const FAKE_VAULT_KEY: &str = "FAKE-ENCRYPTED-VAULT-KEY-55aa";
const FAKE_PRIVATE_KEY: &str = "FAKE-PRIVATE-KEY-9d8c";
const VW_MESSAGE: &str = "MOCK-VW-MESSAGE-do-not-leak";
const VW_TOTP_MESSAGE: &str = "Invalid TOTP code! Server time: MOCK-SERVER-TIME IP: MOCK-IP";

// ── Mock Vaultwarden / bw serve ───────────────────────────────────────────────

#[derive(Clone)]
struct TwoFa {
    providers: Vec<&'static str>,
    email_hint: Option<&'static str>,
}

impl TwoFa {
    fn totp() -> Self {
        Self {
            providers: vec!["0"],
            email_hint: None,
        }
    }
}

#[derive(Default)]
struct Inner {
    two_fa: Option<TwoFa>,
    expected_hash: String,
    /// Answer the token endpoint with this status and an empty object.
    token_status: Option<u16>,
    prelogin_body: Option<String>,
    token_calls: Vec<(HeaderMap, HashMap<String, String>)>,
    send_calls: Vec<String>,
    prelogin_calls: usize,
    status_calls: usize,
    bw_unauthenticated: bool,
}

struct Mock {
    inner: Mutex<Inner>,
}

impl Mock {
    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        f(&mut self.inner.lock().unwrap())
    }

    fn token_calls(&self) -> usize {
        self.with(|m| m.token_calls.len())
    }
}

fn json_response(status: u16, body: Value) -> Response {
    (
        StatusCode::from_u16(status).unwrap(),
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn mock_status(State(m): State<Arc<Mock>>) -> Response {
    let unauth = m.with(|i| {
        i.status_calls += 1;
        i.bw_unauthenticated
    });
    let template = if unauth {
        json!({"status": "unauthenticated"})
    } else {
        json!({
            "serverUrl": "https://vaultwarden",
            "lastSync": "2026-11-21T10:00:00.000Z",
            "userEmail": EMAIL,
            "userId": "00000000-0000-0000-0000-000000000000",
            "status": "unlocked"
        })
    };
    json_response(
        200,
        json!({"success": true, "data": {"object": "template", "template": template}}),
    )
}

async fn mock_prelogin(State(m): State<Arc<Mock>>) -> Response {
    let body = m.with(|i| {
        i.prelogin_calls += 1;
        i.prelogin_body.clone()
    });
    match body {
        Some(b) => (StatusCode::OK, [("content-type", "application/json")], b).into_response(),
        None => json_response(
            200,
            json!({"kdf": 0, "kdfIterations": 5000, "kdfMemory": null, "kdfParallelism": null}),
        ),
    }
}

fn two_factor_required(tf: &TwoFa) -> Response {
    let mut p2 = serde_json::Map::new();
    for id in &tf.providers {
        let v = match (*id, tf.email_hint) {
            ("1", Some(hint)) => json!({ "Email": hint }),
            _ => Value::Null,
        };
        p2.insert((*id).to_string(), v);
    }
    json_response(
        400,
        json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": tf.providers,
            "TwoFactorProviders2": p2,
            "message": VW_MESSAGE,
        }),
    )
}

async fn mock_token(State(m): State<Arc<Mock>>, headers: HeaderMap, body: String) -> Response {
    let form: HashMap<String, String> = form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    let mut g = m.inner.lock().unwrap();
    g.token_calls.push((headers, form.clone()));
    if let Some(status) = g.token_status {
        return json_response(status, json!({"message": VW_MESSAGE}));
    }
    if form.get("password") != Some(&g.expected_hash) {
        return json_response(400, json!({"error": "", "message": VW_MESSAGE}));
    }
    let ok = || {
        json_response(
            200,
            json!({
                "access_token": FAKE_ACCESS_TOKEN,
                "refresh_token": FAKE_REFRESH_TOKEN,
                "Key": FAKE_VAULT_KEY,
                "PrivateKey": FAKE_PRIVATE_KEY,
                "token_type": "Bearer",
            }),
        )
    };
    let Some(tf) = &g.two_fa else { return ok() };
    match (form.get("twoFactorProvider"), form.get("twoFactorToken")) {
        (Some(p), Some(t)) => {
            let valid = tf.providers.contains(&p.as_str())
                && match p.as_str() {
                    "0" => t == TOTP,
                    "1" => t == EMAIL_CODE,
                    "3" => t == YUBIKEY,
                    _ => false,
                };
            if valid {
                ok()
            } else {
                json_response(400, json!({"message": VW_TOTP_MESSAGE}))
            }
        }
        _ => two_factor_required(tf),
    }
}

async fn mock_send_email(State(m): State<Arc<Mock>>, body: String) -> Response {
    // Kept as the raw text the client sent; tests compare it verbatim.
    m.with(|i| i.send_calls.push(body));
    StatusCode::OK.into_response()
}

async fn start_mock(two_fa: Option<TwoFa>) -> (Arc<Mock>, String) {
    let expected = crypto::auth_hash(PASSWORD, EMAIL, KDF).unwrap();
    let mock = Arc::new(Mock {
        inner: Mutex::new(Inner {
            two_fa,
            expected_hash: expected.to_string(),
            ..Inner::default()
        }),
    });
    let app = Router::new()
        .route("/status", get(mock_status))
        .route("/identity/accounts/prelogin", post(mock_prelogin))
        .route("/identity/connect/token", post(mock_token))
        .route("/api/two-factor/send-email-login", post(mock_send_email))
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (mock, base)
}

// ── Log capture ───────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogBuf {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

// ── Harness ───────────────────────────────────────────────────────────────────

struct Opts {
    tls: bool,
    insecure_http: bool,
    trusted_proxies: &'static str,
    two_fa: Option<TwoFa>,
    keys_file: bool,
    /// Notifier settings (started against whatever URLs they name).
    notify: Option<crate::config::NotifyConfig>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            tls: true,
            insecure_http: false,
            trusted_proxies: "",
            two_fa: None,
            keys_file: false,
            notify: None,
        }
    }
}

struct Harness {
    router: Router,
    ui: Arc<UiState>,
    app: Arc<AppState>,
    mock: Arc<Mock>,
    logs: LogBuf,
    /// Every body, header block (without Set-Cookie) the UI returned.
    seen: Arc<Mutex<Vec<String>>>,
    keys_path: Option<std::path::PathBuf>,
    _dir: Option<tempfile::TempDir>,
    _guard: tracing::subscriber::DefaultGuard,
}

async fn harness(opts: Opts) -> Harness {
    let logs = LogBuf::default();
    let writer = logs.clone();
    let guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || writer.clone())
            .finish(),
    );

    let (mock, base) = start_mock(opts.two_fa).await;
    let dir = opts.keys_file.then(|| tempfile::tempdir().unwrap());
    let keys_path = dir.as_ref().map(|d| d.path().join("keys.json"));
    let config = Config {
        bind_addr: "127.0.0.1:3000".to_string(),
        bw_serve_url: base.clone(),
        unlock_mode: UnlockMode::Manual,
        unlock_file: None,
        admin_key: "a".repeat(32).into(),
        keys_file: keys_path.clone(),
        tls_enabled: opts.tls,
        tls_cert_file: None,
        tls_key_file: None,
        allow_private_targets: false,
        allowed_targets: String::new(),
        enforce_credential_hosts: true,
        refresh_interval_secs: 0,
        max_response_bytes: 1024,
        forward_timeout_secs: 5,
        trusted_proxies: opts.trusted_proxies.to_string(),
        api_prefix: String::new(),
        agent_rate_limit_per_minute: 120,
        agent_rate_limit_burst: 20,
        admin_rate_limit_per_minute: 30,
        admin_rate_limit_burst: 5,
        events: Default::default(),
        ui: UiConfig {
            bind: "127.0.0.1:3001".to_string(),
            vaultwarden_url: base,
            insecure_http: opts.insecure_http,
            ..UiConfig::default()
        },
        notify: opts.notify.clone().unwrap_or_default(),
        vault: Default::default(),
    };
    let events = Arc::new(EventLog::buffer_only(1000));
    let mut app = AppState::new(config.clone(), events.clone());
    if opts.notify.is_some() {
        app = app.with_notify(crate::notify::start(&config.notify, &events).unwrap());
    }
    let app = Arc::new(app);
    app.set_unlocked().await;
    let ui = UiState::new(app.clone()).unwrap();
    Harness {
        router: router(ui.clone()),
        ui,
        app,
        mock,
        logs,
        seen: Arc::new(Mutex::new(Vec::new())),
        keys_path,
        _dir: dir,
        _guard: guard,
    }
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
    /// The body as sent (static assets are binary).
    bytes: Vec<u8>,
}

impl Resp {
    fn location(&self) -> &str {
        self.headers
            .get("location")
            .map(|v| v.to_str().unwrap())
            .unwrap_or("")
    }

    fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    fn set_cookie(&self, name: &str) -> Option<String> {
        self.set_cookies()
            .into_iter()
            .find(|c| c.starts_with(&format!("{name}=")))
    }

    /// The single-use id in the create form's hidden field.
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

/// A browser: keeps cookies, sends the headers a browser would.
struct Browser {
    cookies: Vec<(String, String)>,
    /// Client address, sent as X-Forwarded-For (needs a trusted proxy).
    xff: Option<String>,
}

impl Browser {
    fn new() -> Self {
        Self {
            cookies: Vec::new(),
            xff: None,
        }
    }

    fn from(ip: &str) -> Self {
        Self {
            cookies: Vec::new(),
            xff: Some(ip.to_string()),
        }
    }

    fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn set_cookie_value(&mut self, name: &str, value: &str) {
        self.cookies.retain(|(n, _)| n != name);
        self.cookies.push((name.to_string(), value.to_string()));
    }

    async fn send(
        &mut self,
        h: &Harness,
        method: Method,
        path: &str,
        extra: &[(&str, &str)],
        body: Option<String>,
    ) -> Resp {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "admin.example.test");
        if !self.cookies.is_empty() {
            let cookie = self
                .cookies
                .iter()
                .map(|(n, v)| format!("{n}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            req = req.header("cookie", cookie);
        }
        if let Some(ip) = &self.xff {
            req = req.header("x-forwarded-for", ip);
        }
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        let req = req
            .body(match body {
                Some(b) => Body::from(b),
                None => Body::empty(),
            })
            .unwrap();
        let response = h.router.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes).into_owned();

        // Remember what the browser would keep.
        for value in headers.get_all("set-cookie") {
            let c = value.to_str().unwrap();
            let (pair, attrs) = c.split_once(';').unwrap_or((c, ""));
            let (name, val) = pair.split_once('=').unwrap();
            if attrs.contains("Max-Age=0") {
                self.cookies.retain(|(n, _)| n != name);
            } else {
                self.set_cookie_value(name, val);
            }
        }
        // For the leak checks: everything except cookies (which legitimately
        // carry the session id).
        let mut seen = body.clone();
        for (k, v) in headers.iter() {
            if k != "set-cookie" {
                seen.push_str(&format!("\n{k}: {}", v.to_str().unwrap_or("")));
            }
        }
        h.seen.lock().unwrap().push(seen);
        Resp {
            status,
            headers,
            body,
            bytes: bytes.to_vec(),
        }
    }

    async fn get(&mut self, h: &Harness, path: &str) -> Resp {
        self.send(h, Method::GET, path, &[], None).await
    }

    /// A same-origin form POST, as a browser sends it.
    async fn post(&mut self, h: &Harness, path: &str, fields: &[(&str, &str)]) -> Resp {
        self.post_with(h, path, fields, &[("sec-fetch-site", "same-origin")])
            .await
    }

    async fn post_with(
        &mut self,
        h: &Harness,
        path: &str,
        fields: &[(&str, &str)],
        headers: &[(&str, &str)],
    ) -> Resp {
        let mut ser = form_urlencoded::Serializer::new(String::new());
        for (k, v) in fields {
            ser.append_pair(k, v);
        }
        let mut all = vec![("content-type", "application/x-www-form-urlencoded")];
        all.extend_from_slice(headers);
        self.send(h, Method::POST, path, &all, Some(ser.finish()))
            .await
    }

    /// GET the login page, then POST the password with its CSRF token.
    async fn sign_in(&mut self, h: &Harness, password: &str) -> Resp {
        let page = self.get(h, "/ui/login").await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let csrf = page.csrf();
        self.post(h, "/ui/login", &[("csrf", &csrf), ("password", password)])
            .await
    }

    /// POST to the second-factor form (fetching its CSRF token first).
    async fn second_factor(
        &mut self,
        h: &Harness,
        provider: &str,
        action: &str,
        code: &str,
    ) -> Resp {
        let page = self
            .get(h, &format!("/ui/login/2fa?provider={provider}"))
            .await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let csrf = page.csrf();
        let mut fields = vec![
            ("csrf", csrf.as_str()),
            ("provider", provider),
            ("action", action),
        ];
        if action == "verify" {
            fields.push(("code", code));
        }
        self.post(h, "/ui/login/2fa", &fields).await
    }
}

impl Harness {
    fn events(&self) -> Vec<Value> {
        self.app
            .events
            .recent(1000)
            .iter()
            .map(|e| serde_json::to_value(&**e).unwrap())
            .collect()
    }

    /// Events of one action, newest first.
    fn events_of(&self, action: &str) -> Vec<Value> {
        self.events()
            .into_iter()
            .filter(|e| e["event"]["action"] == action)
            .collect()
    }

    fn last_login_event(&self) -> Value {
        self.events_of("ui_login")
            .into_iter()
            .next()
            .expect("a ui_login event")
    }

    /// These values may appear in pages (a CSRF token is rendered into its
    /// form) but never in an event or a log line.
    fn assert_not_logged(&self, secrets: &[&str]) {
        let events = serde_json::to_string(&self.events()).unwrap();
        let logs = self.logs.text();
        for secret in secrets {
            assert!(!events.contains(secret), "secret in an event");
            assert!(!logs.contains(secret), "secret in a log line");
        }
    }

    /// Nothing secret in any response, event or log line.
    fn assert_no_leaks(&self, extra: &[&str]) {
        let auth_hash = crypto::auth_hash(PASSWORD, EMAIL, KDF).unwrap();
        let mut secrets: Vec<String> = vec![
            PASSWORD.to_string(),
            WRONG_PASSWORD.to_string(),
            auth_hash.to_string(),
            FAKE_ACCESS_TOKEN.to_string(),
            FAKE_REFRESH_TOKEN.to_string(),
            FAKE_VAULT_KEY.to_string(),
            FAKE_PRIVATE_KEY.to_string(),
            TOTP.to_string(),
            EMAIL_CODE.to_string(),
            YUBIKEY.to_string(),
        ];
        secrets.extend(extra.iter().map(|s| s.to_string()));

        let responses = self.seen.lock().unwrap().join("\n");
        let events = serde_json::to_string(&self.events()).unwrap();
        let logs = self.logs.text();
        for secret in &secrets {
            assert!(!responses.contains(secret.as_str()), "secret in a response");
            assert!(!events.contains(secret.as_str()), "secret in an event");
            assert!(!logs.contains(secret.as_str()), "secret in a log line");
        }
        // Vaultwarden's own words: logs (debug) may have them, nothing else.
        for message in [VW_MESSAGE, "MOCK-SERVER-TIME", "MOCK-IP"] {
            assert!(
                !responses.contains(message),
                "Vaultwarden message in a response"
            );
            assert!(!events.contains(message), "Vaultwarden message in an event");
        }
    }
}

fn assert_security_headers(r: &Resp) {
    let h = &r.headers;
    assert_eq!(
        h["content-security-policy"],
        "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; \
form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    );
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert_eq!(h["x-frame-options"], "DENY");
    assert!(h.contains_key("permissions-policy"));
    assert_eq!(h["cross-origin-opener-policy"], "same-origin");
    assert_eq!(h["cross-origin-resource-policy"], "same-origin");
    assert!(h.contains_key("cache-control"));
    assert!(h.contains_key("x-request-id"));
}

// ── Sign-in: password only ────────────────────────────────────────────────────

#[tokio::test]
async fn password_sign_in_succeeds_and_shows_the_status_page() {
    let h = harness(Opts::default()).await;
    // One key without a policy, one with.
    {
        let mut keys = h.app.agent_keys.write().await;
        for (hash, id, policy_set) in [("h1", "k1", false), ("h2", "k2", true)] {
            keys.insert(
                hash.to_string(),
                AgentKey {
                    id: id.to_string(),
                    name: id.to_string(),
                    created_at: chrono::Utc::now(),
                    policy: Default::default(),
                    policy_set,
                },
            );
        }
    }
    let mut b = Browser::new();
    let r = b.sign_in(&h, PASSWORD).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/ui/");

    let cookie = r.set_cookie("__Host-fw_session").expect("session cookie");
    for attr in ["Path=/", "HttpOnly", "Secure", "SameSite=Strict"] {
        assert!(cookie.contains(attr), "{cookie}");
    }
    assert!(!cookie.contains("Max-Age") && !cookie.contains("Domain"));
    assert!(
        b.cookie("__Host-fw_login").is_none(),
        "login cookie cleared"
    );

    let status = b.get(&h, "/ui/").await;
    assert_eq!(status.status, StatusCode::OK);
    assert!(status.body.contains(EMAIL));
    assert!(status.body.contains("Unlocked"));
    assert!(
        status.body.contains("2026-11-21T10:00:00.000Z"),
        "last sync"
    );
    assert!(status.body.contains(env!("CARGO_PKG_VERSION")));
    assert!(status.body.contains("deny-all until a policy is set"));
    assert!(status.body.contains("Sign out"));
    assert_security_headers(&status);

    let e = h.last_login_event();
    assert_eq!(e["event"]["outcome"], "success");
    assert_eq!(
        e["event"]["category"],
        serde_json::json!(["authentication"])
    );
    assert!(e["ferrowarden"]["request_id"].is_string());
    assert!(e["source"]["ip"].is_string());
    assert!(e["event"].get("reason").is_none());

    h.assert_no_leaks(&[b.cookie("__Host-fw_session").unwrap()]);
    h.assert_not_logged(&[&status.csrf()]);
}

#[tokio::test]
async fn the_token_request_follows_the_verified_protocol() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    b.sign_in(&h, PASSWORD).await;

    let (headers, form) = h.mock.with(|m| m.token_calls[0].clone());
    assert_eq!(headers["device-type"], "22");
    assert_eq!(headers["content-type"], "application/x-www-form-urlencoded");
    assert_eq!(form["grant_type"], "password");
    assert_eq!(form["username"], EMAIL);
    assert_eq!(form["scope"], "api offline_access");
    assert_eq!(form["client_id"], "web");
    assert_eq!(form["deviceType"], "22");
    assert_eq!(form["deviceName"], "ferrowarden-admin-ui");
    assert_eq!(
        form["deviceIdentifier"],
        crate::ui::vw_login::device_identifier(EMAIL).to_string()
    );
    assert!(!form.contains_key("twoFactorProvider"));
    assert!(!form.contains_key("twoFactorRemember"));
    // The password itself is never sent; the hash is.
    assert_ne!(form["password"], PASSWORD);
    assert_eq!(
        form["password"],
        crypto::auth_hash(PASSWORD, EMAIL, KDF).unwrap().as_str()
    );
    assert_eq!(h.mock.with(|m| m.prelogin_calls), 1);
}

#[tokio::test]
async fn the_account_email_is_cached_after_the_first_lookup() {
    let h = harness(Opts::default()).await;
    Browser::new().sign_in(&h, PASSWORD).await;
    Browser::new().sign_in(&h, PASSWORD).await;
    assert_eq!(h.mock.with(|m| m.status_calls), 1);
}

#[tokio::test]
async fn a_concurrent_sign_in_is_refused_before_any_work() {
    let h = harness(Opts::default()).await;
    // Another verification is in flight.
    let held = h.ui.login_gate.try_acquire().expect("gate free");
    let mut b = Browser::new();
    let r = b.sign_in(&h, PASSWORD).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        h.mock.with(|m| m.prelogin_calls),
        0,
        "no prelogin while busy"
    );
    assert_eq!(h.mock.token_calls(), 0, "no token request while busy");
    drop(held);
    // Not counted as a failure: the next attempt goes through.
    let r = Browser::new().sign_in(&h, PASSWORD).await;
    assert_ne!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(h.mock.with(|m| m.prelogin_calls), 1);
}

#[tokio::test]
async fn an_unauthenticated_bw_serve_means_no_sign_in() {
    let h = harness(Opts::default()).await;
    h.mock.with(|m| m.bw_unauthenticated = true);
    let mut b = Browser::new();
    let r = b.sign_in(&h, PASSWORD).await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        h.mock.token_calls(),
        0,
        "no token request without an account"
    );
    assert_eq!(h.mock.with(|m| m.prelogin_calls), 0);
    assert_eq!(h.last_login_event()["event"]["reason"], "upstream_error");
}

#[tokio::test]
async fn the_login_form_has_no_email_field() {
    let h = harness(Opts::default()).await;
    let page = Browser::new().get(&h, "/ui/login").await;
    assert!(page.body.contains("name=\"password\""));
    assert!(page.body.contains("autocomplete=\"current-password\""));
    assert!(!page.body.to_lowercase().contains("email"));
    assert!(page.set_cookie("__Host-fw_login").is_some());
}

#[tokio::test]
async fn a_second_tab_keeps_the_same_login_token() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    let first = b.get(&h, "/ui/login").await;
    let second = b.get(&h, "/ui/login").await;
    assert_eq!(first.csrf(), second.csrf());
    // Either tab's form works.
    let r = b
        .post(
            &h,
            "/ui/login",
            &[("csrf", &first.csrf()), ("password", PASSWORD)],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn wrong_password_fails_with_a_generic_message() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    let r = b.sign_in(&h, WRONG_PASSWORD).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.body.contains("Invalid password or code."));
    assert!(b.cookie("__Host-fw_session").is_none());
    assert!(
        r.set_cookie("__Host-fw_login").is_some(),
        "fresh login token"
    );

    let e = h.last_login_event();
    assert_eq!(e["event"]["outcome"], "failure");
    assert_eq!(e["event"]["reason"], "invalid_credentials");
    assert_eq!(e["http"]["response"]["status_code"], 401);
    // The debug log is the only place Vaultwarden's own message may appear.
    assert!(h.logs.text().contains(VW_MESSAGE));
    h.assert_no_leaks(&[]);

    // And the protected page is still closed.
    assert_eq!(b.get(&h, "/ui/").await.location(), "/ui/login");
}

#[tokio::test]
async fn an_empty_password_is_refused_before_any_upstream_call() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    let r = b.sign_in(&h, "").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.mock.token_calls(), 0);
    assert_eq!(h.mock.with(|m| m.prelogin_calls), 0);
}

#[tokio::test]
async fn hostile_kdf_parameters_from_the_server_are_refused() {
    let h = harness(Opts::default()).await;
    for body in [
        r#"{"kdf":0,"kdfIterations":4294967295}"#,
        r#"{"kdf":1,"kdfIterations":3,"kdfMemory":4096,"kdfParallelism":4}"#,
        r#"{"kdf":0,"kdfIterations":10}"#,
    ] {
        h.mock.with(|m| m.prelogin_body = Some(body.to_string()));
        let mut b = Browser::new();
        let r = b.sign_in(&h, PASSWORD).await;
        assert_eq!(r.status, StatusCode::BAD_GATEWAY, "{body}");
    }
    assert_eq!(h.mock.token_calls(), 0, "the password was never derived");
}

#[tokio::test]
async fn upstream_rate_limit_and_errors_are_reported_without_counting() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();

    h.mock.with(|m| m.token_status = Some(429));
    let r = b.sign_in(&h, PASSWORD).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.body.contains("Too many attempts"));
    assert_eq!(
        h.last_login_event()["event"]["reason"],
        "upstream_rate_limited"
    );

    h.mock.with(|m| m.token_status = Some(500));
    let r = b.sign_in(&h, PASSWORD).await;
    assert_eq!(r.status, StatusCode::BAD_GATEWAY);
    assert_eq!(h.last_login_event()["event"]["reason"], "upstream_error");

    // Neither counts towards the lockouts: eight more would otherwise lock.
    h.mock.with(|m| m.token_status = None);
    for _ in 0..4 {
        let r = b.sign_in(&h, WRONG_PASSWORD).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    h.assert_no_leaks(&[]);
}

#[tokio::test]
async fn a_new_sign_in_rotates_the_session_and_ends_the_old_one() {
    let h = harness(Opts::default()).await;
    let mut first = Browser::new();
    first.sign_in(&h, PASSWORD).await;
    let old = first.cookie("__Host-fw_session").unwrap().to_string();
    assert_eq!(first.get(&h, "/ui/").await.status, StatusCode::OK);

    // A second browser fetches a login form, then presents the old session
    // cookie along with the password.
    let mut second = Browser::new();
    let csrf = second.get(&h, "/ui/login").await.csrf();
    second.set_cookie_value("__Host-fw_session", &old);
    let r = second
        .post(&h, "/ui/login", &[("csrf", &csrf), ("password", PASSWORD)])
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let new = second.cookie("__Host-fw_session").unwrap().to_string();
    assert_ne!(old, new, "a new id on every sign-in");
    assert_eq!(second.get(&h, "/ui/").await.status, StatusCode::OK);
    // The old id no longer works.
    assert_eq!(first.get(&h, "/ui/").await.location(), "/ui/login");
}

// ── Sign-in: second factor ────────────────────────────────────────────────────

async fn start_two_factor(h: &Harness, b: &mut Browser) -> Resp {
    let r = b.sign_in(h, PASSWORD).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(r.location(), "/ui/login/2fa");
    r
}

#[tokio::test]
async fn totp_second_factor_signs_in() {
    let h = harness(Opts {
        two_fa: Some(TwoFa::totp()),
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    let step1 = start_two_factor(&h, &mut b).await;

    let pending = step1.set_cookie("__Host-fw_pending").unwrap();
    for attr in [
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=180",
    ] {
        assert!(pending.contains(attr), "{pending}");
    }
    // Step one is "unknown", not a success.
    let e = h.last_login_event();
    assert_eq!(e["event"]["outcome"], "unknown");
    assert_eq!(e["event"]["reason"], "two_factor_required");
    assert!(b.cookie("__Host-fw_session").is_none());
    assert_eq!(b.get(&h, "/ui/").await.location(), "/ui/login");

    // The 2FA page: a one-time-code field, no email button.
    let page = b.get(&h, "/ui/login/2fa").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("autocomplete=\"one-time-code\""));
    assert!(page.body.contains("inputmode=\"numeric\""));
    assert!(!page.body.contains("Send code"));
    assert_security_headers(&page);

    let r = b.second_factor(&h, "0", "verify", TOTP).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/ui/");
    assert!(b.cookie("__Host-fw_session").is_some());
    assert!(
        b.cookie("__Host-fw_pending").is_none(),
        "pending cookie cleared"
    );
    assert!(h.ui.pending.lock().unwrap().is_empty());

    let e = h.last_login_event();
    assert_eq!(e["event"]["outcome"], "success");
    assert_eq!(e["ferrowarden"]["details"]["provider"], "authenticator");
    assert_eq!(b.get(&h, "/ui/").await.status, StatusCode::OK);

    // The second request carried the provider and token, and never "remember".
    let (_, form) = h.mock.with(|m| m.token_calls[1].clone());
    assert_eq!(form["twoFactorProvider"], "0");
    assert_eq!(form["twoFactorToken"], TOTP);
    assert!(!form.contains_key("twoFactorRemember"));
    h.assert_no_leaks(&[]);
}

#[tokio::test]
async fn a_totp_code_with_a_space_is_accepted() {
    let h = harness(Opts {
        two_fa: Some(TwoFa::totp()),
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    start_two_factor(&h, &mut b).await;
    let r = b.second_factor(&h, "0", "verify", "123 456").await;
    assert_eq!(r.location(), "/ui/");
}

#[tokio::test]
async fn wrong_codes_fail_and_the_third_ends_the_pending_login() {
    let h = harness(Opts {
        two_fa: Some(TwoFa::totp()),
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    start_two_factor(&h, &mut b).await;

    for n in 1..=2 {
        let r = b.second_factor(&h, "0", "verify", "000000").await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "attempt {n}");
        assert!(r.body.contains("Invalid password or code."));
        let e = h.last_login_event();
        assert_eq!(e["event"]["reason"], "two_factor_failed");
        assert_eq!(e["ferrowarden"]["details"]["provider"], "authenticator");
    }
    // The third wrong code removes the pending login.
    let r = b.second_factor(&h, "0", "verify", "000000").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/ui/login?m=failed");
    assert!(h.ui.pending.lock().unwrap().is_empty());
    assert!(b.cookie("__Host-fw_pending").is_none());

    // Even the right code is useless now.
    let page = b.get(&h, "/ui/login/2fa").await;
    assert_eq!(page.location(), "/ui/login?m=expired");
    assert!(b.cookie("__Host-fw_session").is_none());
    h.assert_no_leaks(&["000000"]);
}

#[tokio::test]
async fn malformed_codes_are_not_sent_upstream_or_counted() {
    let h = harness(Opts {
        two_fa: Some(TwoFa::totp()),
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    start_two_factor(&h, &mut b).await;
    let before = h.mock.token_calls();
    for bad in ["", "abc", "12345", "123456789", "12 34 5x"] {
        let r = b.second_factor(&h, "0", "verify", bad).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad:?}");
    }
    assert_eq!(h.mock.token_calls(), before);
    // Still three real attempts left.
    let r = b.second_factor(&h, "0", "verify", TOTP).await;
    assert_eq!(r.location(), "/ui/");
}

#[tokio::test]
async fn email_second_factor_sends_a_code_and_limits_resends() {
    let h = harness(Opts {
        two_fa: Some(TwoFa {
            providers: vec!["1"],
            email_hint: Some("a***@example.test"),
        }),
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    start_two_factor(&h, &mut b).await;

    let page = b.get(&h, "/ui/login/2fa").await;
    assert!(page.body.contains("Send code"));
    assert!(page.body.contains("a***@example.test"), "obscured address");

    let r = b.second_factor(&h, "1", "send_email", "").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("The code was sent"));
    let sent = h.mock.with(|m| m.send_calls.clone());
    assert_eq!(sent.len(), 1);
    // Compared as text against the exact serialization the client produces
    // (serde_json orders object keys), so the mock never has to parse it.
    let expected = json!({
        "email": EMAIL,
        "masterPasswordHash": crypto::auth_hash(PASSWORD, EMAIL, KDF).unwrap().as_str(),
        "deviceIdentifier": crate::ui::vw_login::device_identifier(EMAIL).to_string(),
    })
    .to_string();
    assert_eq!(sent[0], expected);
    let e = h.events_of("ui_two_factor_email_sent");
    assert_eq!(e.len(), 1);
    assert_eq!(e[0]["event"]["outcome"], "success");

    // A resend within a minute is refused without calling Vaultwarden.
    let r = b.second_factor(&h, "1", "send_email", "").await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(h.mock.with(|m| m.send_calls.len()), 1);
    // After a minute it works again.
    h.ui.advance(Duration::from_secs(61));
    let r = b.second_factor(&h, "1", "send_email", "").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(h.mock.with(|m| m.send_calls.len()), 2);

    let r = b.second_factor(&h, "1", "verify", EMAIL_CODE).await;
    assert_eq!(r.location(), "/ui/");
    let e = h.last_login_event();
    assert_eq!(e["ferrowarden"]["details"]["provider"], "email");
    h.assert_no_leaks(&[]);
}

#[tokio::test]
async fn the_email_button_is_only_for_accounts_with_email_two_factor() {
    let h = harness(Opts {
        two_fa: Some(TwoFa::totp()),
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    start_two_factor(&h, &mut b).await;
    let page = b.get(&h, "/ui/login/2fa").await;
    let csrf = page.csrf();
    // Forged: ask for an email code although the server did not offer it.
    let r = b
        .post(
            &h,
            "/ui/login/2fa",
            &[("csrf", &csrf), ("provider", "1"), ("action", "send_email")],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(h.mock.with(|m| m.send_calls.is_empty()));
}

#[tokio::test]
async fn yubikey_second_factor_signs_in() {
    let h = harness(Opts {
        two_fa: Some(TwoFa {
            providers: vec!["3"],
            email_hint: None,
        }),
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    start_two_factor(&h, &mut b).await;
    let page = b.get(&h, "/ui/login/2fa").await;
    assert!(page.body.contains("maxlength=\"44\""));
    let r = b.second_factor(&h, "3", "verify", YUBIKEY).await;
    assert_eq!(r.location(), "/ui/");
    assert_eq!(
        h.last_login_event()["ferrowarden"]["details"]["provider"],
        "yubikey"
    );
    h.assert_no_leaks(&[]);
}

#[tokio::test]
async fn several_providers_can_be_chosen_and_only_offered_ones_work() {
    let h = harness(Opts {
        two_fa: Some(TwoFa {
            providers: vec!["0", "3", "7", "2"],
            email_hint: None,
        }),
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    start_two_factor(&h, &mut b).await;
    let page = b.get(&h, "/ui/login/2fa").await;
    assert!(page.body.contains("Authenticator app"));
    assert!(page.body.contains("YubiKey"));
    assert!(!page.body.contains("WebAuthn") && !page.body.contains("Duo"));
    // Email (1) was not offered: forged provider is refused.
    let csrf = page.csrf();
    let r = b
        .post(
            &h,
            "/ui/login/2fa",
            &[
                ("csrf", &csrf),
                ("provider", "1"),
                ("action", "verify"),
                ("code", "654321"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // The selected provider is the one used.
    let r = b.second_factor(&h, "0", "verify", TOTP).await;
    assert_eq!(r.location(), "/ui/");
}

#[tokio::test]
async fn accounts_with_only_unsupported_providers_get_a_clear_message() {
    let h = harness(Opts {
        two_fa: Some(TwoFa {
            providers: vec!["7", "2"],
            email_hint: None,
        }),
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    let r = b.sign_in(&h, PASSWORD).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(r.body.contains("authenticator app"));
    assert!(r.body.contains("YubiKey"));
    assert!(b.cookie("__Host-fw_pending").is_none());
    assert!(h.ui.pending.lock().unwrap().is_empty(), "nothing is parked");
    let e = h.last_login_event();
    assert_eq!(e["event"]["outcome"], "failure");
    assert_eq!(e["event"]["reason"], "two_factor_required");
    h.assert_no_leaks(&[]);
}

#[tokio::test]
async fn a_pending_login_expires_after_three_minutes() {
    let h = harness(Opts {
        two_fa: Some(TwoFa::totp()),
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    start_two_factor(&h, &mut b).await;
    h.ui.advance(Duration::from_secs(181));
    let page = b.get(&h, "/ui/login/2fa").await;
    assert_eq!(page.location(), "/ui/login?m=expired");
    // The login page explains with a fixed text.
    let login = b.get(&h, page.location()).await;
    assert!(login.body.contains("expired or was cancelled"));
}

#[tokio::test]
async fn a_pending_login_is_bound_to_the_client_ip() {
    let h = harness(Opts {
        two_fa: Some(TwoFa::totp()),
        trusted_proxies: "127.0.0.1",
        ..Opts::default()
    })
    .await;
    let mut owner = Browser::from("198.51.100.10");
    start_two_factor(&h, &mut owner).await;

    // Somebody with the cookie but another address gets nowhere.
    let mut thief = Browser::from("203.0.113.66");
    thief.set_cookie_value(
        "__Host-fw_pending",
        owner.cookie("__Host-fw_pending").unwrap(),
    );
    let page = thief.get(&h, "/ui/login/2fa").await;
    assert_eq!(page.location(), "/ui/login?m=expired");
    // The owner is unaffected.
    let r = owner.second_factor(&h, "0", "verify", TOTP).await;
    assert_eq!(r.location(), "/ui/");
}

#[tokio::test]
async fn a_new_password_step_replaces_the_pending_login() {
    let h = harness(Opts {
        two_fa: Some(TwoFa::totp()),
        ..Opts::default()
    })
    .await;
    let mut first = Browser::new();
    start_two_factor(&h, &mut first).await;
    let mut second = Browser::new();
    start_two_factor(&h, &mut second).await;
    assert_eq!(
        first.get(&h, "/ui/login/2fa").await.location(),
        "/ui/login?m=expired"
    );
    assert_eq!(second.get(&h, "/ui/login/2fa").await.status, StatusCode::OK);
}

// ── Lockouts ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn five_wrong_passwords_lock_the_ip_before_any_upstream_call() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    for _ in 0..5 {
        assert_eq!(
            b.sign_in(&h, WRONG_PASSWORD).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
    let (token_calls, prelogins, statuses) = h
        .mock
        .with(|m| (m.token_calls.len(), m.prelogin_calls, m.status_calls));

    // Locked: even the right password is refused, and nothing is called.
    let r = b.sign_in(&h, PASSWORD).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.body.contains("Too many attempts"));
    assert!(
        !r.body.contains("password</label>"),
        "no form while locked out"
    );
    assert_eq!(
        h.mock
            .with(|m| (m.token_calls.len(), m.prelogin_calls, m.status_calls)),
        (token_calls, prelogins, statuses)
    );
    let e = h.last_login_event();
    assert_eq!(e["event"]["reason"], "login_locked_out");
    assert_eq!(e["ferrowarden"]["details"]["scope"], "ip");

    // Fifteen minutes later the lock is over.
    h.ui.advance(Duration::from_secs(15 * 60 + 1));
    let r = b.sign_in(&h, PASSWORD).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    h.assert_no_leaks(&[]);
}

#[tokio::test]
async fn ten_failures_across_ips_lock_every_password_submission() {
    let h = harness(Opts {
        trusted_proxies: "127.0.0.1",
        ..Opts::default()
    })
    .await;
    // Five addresses, two failures each: no single IP is locked.
    for n in 1..=5 {
        let mut b = Browser::from(&format!("198.51.100.{n}"));
        for _ in 0..2 {
            assert_eq!(
                b.sign_in(&h, WRONG_PASSWORD).await.status,
                StatusCode::UNAUTHORIZED
            );
        }
    }
    let calls = h.mock.token_calls();
    // A sixth, clean address is refused too.
    let mut fresh = Browser::from("203.0.113.9");
    let r = fresh.sign_in(&h, PASSWORD).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(h.mock.token_calls(), calls);
    assert_eq!(
        h.last_login_event()["ferrowarden"]["details"]["scope"],
        "global"
    );
}

#[tokio::test]
async fn wrong_codes_count_towards_the_lockouts() {
    let h = harness(Opts {
        two_fa: Some(TwoFa::totp()),
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    // Two pending logins of three wrong codes each: the 5th failure locks.
    start_two_factor(&h, &mut b).await;
    for _ in 0..3 {
        b.second_factor(&h, "0", "verify", "000000").await;
    }
    start_two_factor(&h, &mut b).await;
    for _ in 0..2 {
        b.second_factor(&h, "0", "verify", "000000").await;
    }
    let r = b.get(&h, "/ui/login/2fa").await;
    assert_eq!(r.status, StatusCode::OK);
    let calls = h.mock.token_calls();
    let r = b.second_factor(&h, "0", "verify", TOTP).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        h.mock.token_calls(),
        calls,
        "locked out before the upstream call"
    );
}

// ── CSRF and origin ───────────────────────────────────────────────────────────

#[tokio::test]
async fn login_post_needs_a_matching_csrf_token() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    let page = b.get(&h, "/ui/login").await;
    let csrf = page.csrf();

    // Missing, wrong and empty tokens.
    for fields in [
        vec![("password", PASSWORD)],
        vec![("csrf", "wrong-token"), ("password", PASSWORD)],
        vec![("csrf", ""), ("password", PASSWORD)],
    ] {
        let r = b.post(&h, "/ui/login", &fields).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{fields:?}");
    }
    // Right field, but no login cookie (an attacker's form cannot set it).
    let mut other = Browser::new();
    let r = other
        .post(&h, "/ui/login", &[("csrf", &csrf), ("password", PASSWORD)])
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Right field, other person's cookie.
    let mut mismatch = Browser::new();
    mismatch.get(&h, "/ui/login").await;
    let r = mismatch
        .post(&h, "/ui/login", &[("csrf", &csrf), ("password", PASSWORD)])
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    assert_eq!(h.mock.token_calls(), 0, "nothing reached Vaultwarden");
    assert!(h
        .events_of("request_rejected")
        .iter()
        .all(|e| e["http"]["response"]["status_code"] == 403));
    // The matching pair works.
    let r = b
        .post(&h, "/ui/login", &[("csrf", &csrf), ("password", PASSWORD)])
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn cross_site_and_headerless_posts_are_rejected() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    let csrf = b.get(&h, "/ui/login").await.csrf();
    let fields = [("csrf", csrf.as_str()), ("password", PASSWORD)];

    for headers in [
        vec![("sec-fetch-site", "cross-site")],
        vec![("sec-fetch-site", "same-site")],
        vec![("sec-fetch-site", "none")],
        vec![("origin", "https://evil.example")],
        vec![("origin", "null")],
        vec![("origin", "http://admin.example.test")], // wrong scheme
        vec![],                                        // neither header
    ] {
        let r = b.post_with(&h, "/ui/login", &fields, &headers).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{headers:?}");
    }
    assert_eq!(h.mock.token_calls(), 0);

    // An Origin that equals the request's own origin is fine.
    let r = b
        .post_with(
            &h,
            "/ui/login",
            &fields,
            &[("origin", "https://admin.example.test")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn forms_are_parsed_strictly() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    let csrf = b.get(&h, "/ui/login").await.csrf();

    let r = b
        .post(
            &h,
            "/ui/login",
            &[("csrf", &csrf), ("password", PASSWORD), ("email", "x@y.z")],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "unknown field");
    let r = b
        .post(
            &h,
            "/ui/login",
            &[
                ("csrf", &csrf),
                ("password", PASSWORD),
                ("password", "other"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "duplicate field");
    let r = b
        .send(
            &h,
            Method::POST,
            "/ui/login",
            &[
                ("sec-fetch-site", "same-origin"),
                ("content-type", "application/json"),
            ],
            Some(format!("{{\"csrf\":\"{csrf}\",\"password\":\"x\"}}")),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "not a form");
    let r = b
        .send(
            &h,
            Method::POST,
            "/ui/login",
            &[
                ("sec-fetch-site", "same-origin"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            Some(format!("csrf={csrf}&password=%zz")),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "bad escape");
    let r = b
        .send(
            &h,
            Method::POST,
            "/ui/login",
            &[
                ("sec-fetch-site", "same-origin"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            Some(format!("csrf={csrf}&password={}", "a".repeat(20_000))),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "too large");
    assert_eq!(h.mock.token_calls(), 0);
    h.assert_no_leaks(&[]);
}

// ── Sessions ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn logout_needs_the_session_csrf_token_and_destroys_the_session() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    b.sign_in(&h, PASSWORD).await;
    let csrf = b.get(&h, "/ui/").await.csrf();
    let session = b.cookie("__Host-fw_session").unwrap().to_string();

    // Wrong token, no token, the login-form token of someone else: 403.
    for fields in [vec![], vec![("csrf", "nope")], vec![("csrf", "")]] {
        let r = b.post(&h, "/ui/logout", &fields).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{fields:?}");
    }
    // Cross-site: 403 even with the right token.
    let r = b
        .post_with(
            &h,
            "/ui/logout",
            &[("csrf", &csrf)],
            &[("sec-fetch-site", "cross-site")],
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(
        b.get(&h, "/ui/").await.status,
        StatusCode::OK,
        "still signed in"
    );

    let r = b.post(&h, "/ui/logout", &[("csrf", &csrf)]).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/ui/login?m=logged_out");
    assert!(b.cookie("__Host-fw_session").is_none());
    assert!(r
        .set_cookies()
        .iter()
        .any(|c| c.starts_with("__Host-fw_session=;") && c.contains("Max-Age=0")));
    assert_eq!(h.events_of("ui_logout").len(), 1);

    // The old cookie is dead server-side.
    let mut replay = Browser::new();
    replay.set_cookie_value("__Host-fw_session", &session);
    assert_eq!(replay.get(&h, "/ui/").await.location(), "/ui/login");
    let login = b.get(&h, "/ui/login?m=logged_out").await;
    assert!(login.body.contains("signed out"));
    h.assert_no_leaks(&[&session]);
    h.assert_not_logged(&[&csrf]);
}

#[tokio::test]
async fn sessions_expire_when_idle_and_at_the_absolute_limit() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    b.sign_in(&h, PASSWORD).await;

    // Activity keeps it alive past the idle limit ...
    for _ in 0..3 {
        h.ui.advance(Duration::from_secs(10 * 60));
        assert_eq!(b.get(&h, "/ui/").await.status, StatusCode::OK);
    }
    // ... idleness does not.
    h.ui.advance(Duration::from_secs(15 * 60 + 1));
    let r = b.get(&h, "/ui/").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/ui/login?m=session");
    assert_eq!(h.events_of("ui_session_expired").len(), 1);
    assert_eq!(b.get(&h, "/ui/").await.location(), "/ui/login");

    // The absolute limit: 8 hours, however active.
    b.sign_in(&h, PASSWORD).await;
    let mut elapsed = Duration::ZERO;
    loop {
        h.ui.advance(Duration::from_secs(10 * 60));
        elapsed += Duration::from_secs(10 * 60);
        let r = b.get(&h, "/ui/").await;
        if r.status != StatusCode::OK {
            assert_eq!(r.location(), "/ui/login?m=session");
            assert!(elapsed >= Duration::from_secs(8 * 3600), "{elapsed:?}");
            assert_eq!(h.events_of("ui_session_expired").len(), 2);
            break;
        }
        assert!(
            elapsed < Duration::from_secs(9 * 3600),
            "outlived the limit"
        );
    }
}

#[tokio::test]
async fn at_most_eight_sessions_exist_at_once() {
    let h = harness(Opts::default()).await;
    let mut browsers = Vec::new();
    for _ in 0..9 {
        let mut b = Browser::new();
        assert_eq!(b.sign_in(&h, PASSWORD).await.status, StatusCode::SEE_OTHER);
        browsers.push(b);
    }
    // The oldest was evicted.
    assert_eq!(browsers[0].get(&h, "/ui/").await.location(), "/ui/login");
    assert_eq!(browsers[8].get(&h, "/ui/").await.status, StatusCode::OK);
}

// ── Routing, HTTPS rule, headers ──────────────────────────────────────────────

#[tokio::test]
async fn routes_redirect_and_unknown_paths_follow_the_session() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    assert_eq!(b.get(&h, "/").await.location(), "/ui/");
    assert_eq!(b.get(&h, "/ui").await.location(), "/ui/");
    assert_eq!(b.get(&h, "/ui/").await.location(), "/ui/login");
    for path in ["/ui/keys", "/ui/audit", "/ui/anything/else", "/ui/logout/x"] {
        assert_eq!(b.get(&h, path).await.location(), "/ui/login", "{path}");
    }
    // Outside /ui there is nothing.
    for path in ["/v1/credentials", "/v1/admin/keys", "/health", "/nope"] {
        assert_eq!(
            b.get(&h, path).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    b.sign_in(&h, PASSWORD).await;
    assert_eq!(
        b.get(&h, "/ui/nothing-here").await.status,
        StatusCode::NOT_FOUND
    );
    // The wrong method is refused, not served.
    let r = b.send(&h, Method::GET, "/ui/logout", &[], None).await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn every_response_carries_the_security_headers() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    let css_path = h.ui.css_path.clone();
    let mut responses = vec![
        b.get(&h, "/").await,
        b.get(&h, "/ui/").await,
        b.get(&h, "/ui/login").await,
        b.get(&h, "/ui/login/2fa").await,
        b.get(&h, "/nope").await,
        b.get(&h, "/ui/static/missing.css").await,
        b.post_with(&h, "/ui/login", &[], &[]).await, // 403
        b.get(&h, &css_path).await,
    ];
    b.sign_in(&h, PASSWORD).await;
    responses.push(b.get(&h, "/ui/").await);
    responses.push(b.get(&h, "/ui/nope").await);
    for r in &responses {
        assert_security_headers(r);
        // HTTPS: HSTS on every response.
        assert_eq!(r.headers["strict-transport-security"], "max-age=31536000");
        // No cookies without these attributes.
        for c in r.set_cookies() {
            assert!(
                c.contains("Secure") && c.contains("HttpOnly") && c.contains("SameSite=Strict")
            );
            assert!(c.starts_with("__Host-") && c.contains("Path=/") && !c.contains("Domain"));
        }
    }
    // Pages are never cached; the stylesheet is.
    assert_eq!(responses[2].headers["cache-control"], "no-store");
    let css = &responses[7];
    assert_eq!(css.status, StatusCode::OK);
    assert_eq!(css.headers["cache-control"], "public, max-age=86400");
    assert_eq!(css.headers["content-type"], "text/css; charset=utf-8");
    assert!(css_path.starts_with("/ui/static/app-") && css_path.ends_with(".css"));
    assert_eq!(responses[5].status, StatusCode::NOT_FOUND);
    // No scripts anywhere.
    for r in &responses {
        assert!(!r.body.to_lowercase().contains("<script"));
    }
}

#[tokio::test]
async fn plain_http_is_refused_without_the_form() {
    let h = harness(Opts {
        tls: false,
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    for path in ["/ui/login", "/ui/", "/", "/ui/login/2fa", "/anything"] {
        let r = b.get(&h, path).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{path}");
        assert!(r.body.contains("HTTPS is required"), "{path}");
        assert!(r.body.contains("trusted_proxies"));
        assert!(r.body.contains("insecure_http"));
        assert!(
            !r.body.contains("name=\"password\""),
            "form must not render"
        );
        assert!(r.set_cookies().is_empty());
        assert_security_headers(&r);
        assert!(!r.headers.contains_key("strict-transport-security"));
    }
    // A POST never reaches the handler either.
    let r = b
        .post(&h, "/ui/login", &[("csrf", "x"), ("password", PASSWORD)])
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.mock.token_calls(), 0);
    assert_eq!(h.mock.with(|m| m.status_calls), 0);

    // The stylesheet is exempt, so the explanation is readable.
    let css = h.ui.css_path.clone();
    assert_eq!(b.get(&h, &css).await.status, StatusCode::OK);

    // The refusal is an event, throttled.
    let e = h.events_of("ui_login");
    assert_eq!(e.len(), 1, "one event per interval");
    assert_eq!(e[0]["event"]["reason"], "insecure_transport");
    assert_eq!(e[0]["event"]["outcome"], "failure");
    assert!(e[0]["ferrowarden"]["request_id"].is_string());
    h.ui.advance(Duration::from_secs(31));
    b.get(&h, "/ui/login").await;
    let e = h.events_of("ui_login");
    assert_eq!(e.len(), 2);
    assert!(
        e[0]["ferrowarden"]["details"]["suppressed"]
            .as_u64()
            .unwrap()
            >= 5
    );
}

#[tokio::test]
async fn a_trusted_proxy_can_vouch_for_https() {
    let h = harness(Opts {
        tls: false,
        trusted_proxies: "127.0.0.1",
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    // Trusted peer + X-Forwarded-Proto: https -> served.
    let r = b
        .send(
            &h,
            Method::GET,
            "/ui/login",
            &[("x-forwarded-proto", "https")],
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("name=\"password\""));
    assert_eq!(r.headers["strict-transport-security"], "max-age=31536000");
    // The same proxy saying http -> refused.
    let r = b
        .send(
            &h,
            Method::GET,
            "/ui/login",
            &[("x-forwarded-proto", "http")],
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // No header at all -> refused.
    assert_eq!(b.get(&h, "/ui/login").await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn forwarded_proto_from_an_untrusted_peer_is_ignored() {
    // The test peer is 127.0.0.1, which is not in trusted_proxies here.
    let h = harness(Opts {
        tls: false,
        trusted_proxies: "10.0.0.0/8",
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    let r = b
        .send(
            &h,
            Method::GET,
            "/ui/login",
            &[("x-forwarded-proto", "https")],
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn behind_a_proxy_the_origin_is_the_forwarded_one() {
    let h = harness(Opts {
        tls: false,
        trusted_proxies: "127.0.0.1",
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    let proxy = [
        ("x-forwarded-proto", "https"),
        ("x-forwarded-host", "vault.example.test"),
    ];
    let csrf = {
        let r = b.send(&h, Method::GET, "/ui/login", &proxy, None).await;
        r.csrf()
    };
    let fields = [("csrf", csrf.as_str()), ("password", PASSWORD)];
    let mut headers = proxy.to_vec();
    // Origin of the public name: accepted.
    headers.push(("origin", "https://vault.example.test"));
    let r = b.post_with(&h, "/ui/login", &fields, &headers).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn insecure_http_serves_the_form_over_plain_http() {
    let h = harness(Opts {
        tls: false,
        insecure_http: true,
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    let r = b.sign_in(&h, PASSWORD).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let status = b.get(&h, "/ui/").await;
    assert_eq!(status.status, StatusCode::OK);
    assert!(status
        .body
        .contains("<span class=\"badge bad\">Plain HTTP</span>"));
    assert!(!status.headers.contains_key("strict-transport-security"));
    // Cookies stay Secure regardless.
    assert!(r
        .set_cookie("__Host-fw_session")
        .unwrap()
        .contains("Secure"));
    // And a POST's origin is http://host here.
    let csrf = b.get(&h, "/ui/").await.csrf();
    let r = b
        .post_with(
            &h,
            "/ui/logout",
            &[("csrf", &csrf)],
            &[("origin", "http://admin.example.test")],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn the_ui_router_does_not_serve_the_api() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    for (method, path) in [
        (Method::GET, "/v1/credentials"),
        (Method::POST, "/v1/forward"),
        (Method::GET, "/v1/admin/keys"),
        (Method::POST, "/v1/unlock"),
        (Method::GET, "/health"),
    ] {
        let r = b.send(&h, method, path, &[], None).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn the_status_page_counts_keys_and_dropped_events() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    b.sign_in(&h, PASSWORD).await;
    h.app.set_locked("test").await;
    let page = b.get(&h, "/ui/").await;
    assert!(page.body.contains("Locked"));
    assert!(page.body.contains("Security events dropped"));
    assert!(page.body.contains("Agent keys"));
    assert!(page.body.contains("<dd>0</dd>"));
}

#[test]
fn the_provider_enum_matches_the_documented_event_names() {
    assert_eq!(Provider::Authenticator.name(), "authenticator");
    assert_eq!(Provider::Email.name(), "email");
    assert_eq!(Provider::YubiKey.name(), "yubikey");
}

mod admin;
mod brand;
mod notify;
