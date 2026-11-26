use super::*;
use crate::config::{Config, MetricsToken, UnlockMode};
use crate::events::EventLog;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use std::time::Duration;
use tower::ServiceExt;
use zeroize::Zeroizing;

const TOKEN: &str = "s3cr3t-metrics-token-0123456789abcdef";

fn config(token: Option<&str>) -> Config {
    Config {
        bind_addr: "127.0.0.1:3000".to_string(),
        bw_serve_url: None,
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
        forward_timeout_secs: 5,
        trusted_proxies: String::new(),
        api_prefix: String::new(),
        agent_rate_limit_per_minute: 120,
        agent_rate_limit_burst: 20,
        admin_rate_limit_per_minute: 30,
        admin_rate_limit_burst: 5,
        events: Default::default(),
        ui: Default::default(),
        notify: Default::default(),
        vault: crate::config::VaultConfig::default(),
        metrics: MetricsConfig {
            bind: "127.0.0.1:9095".into(),
            token: MetricsToken(token.map(|t| Zeroizing::new(t.to_string()))),
            ..Default::default()
        },
        sessions: Default::default(),
        approval: Default::default(),
    }
}

struct Fixture {
    app: Router,
    state: Arc<AppState>,
    metrics: Arc<Metrics>,
}

fn fixture(token: Option<&str>) -> Fixture {
    let cfg = config(token);
    let state = Arc::new(AppState::new(
        cfg.clone(),
        Arc::new(EventLog::buffer_only(1000)),
    ));
    let metrics = Metrics::new("0.0.0", "native", false);
    let server = MetricsServer::new(state.clone(), metrics.clone(), &cfg.metrics, None);
    Fixture {
        app: router(server),
        state,
        metrics,
    }
}

async fn call(
    f: &Fixture,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    peer: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut req = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let mut req = req.body(Body::empty()).unwrap();
    if let Some(peer) = peer {
        let addr: SocketAddr = format!("{peer}:50000").parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
    }
    let resp = f.app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn bearer_header(token: &str) -> [(&'static str, String); 1] {
    [("authorization", format!("Bearer {token}"))]
}

async fn get_with(f: &Fixture, token: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let [(k, v)] = bearer_header(token);
    call(f, "GET", "/metrics", &[(k, &v)], None).await
}

fn metrics_auth_events(f: &Fixture) -> Vec<serde_json::Value> {
    f.state
        .events
        .recent(100)
        .iter()
        .filter(|e| e.event.action == Action::MetricsAuth)
        .map(|e| serde_json::to_value(&**e).unwrap())
        .collect()
}

// ── Without a token ───────────────────────────────────────────────────────────

#[tokio::test]
async fn without_a_token_a_scrape_is_served() {
    let f = fixture(None);
    let (status, headers, body) = call(&f, "GET", "/metrics", &[], None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], CONTENT_TYPE);
    assert!(body.contains("ferrowarden_vault_unlocked 0"));
    assert!(body.ends_with("# EOF\n"));
    assert!(metrics_auth_events(&f).is_empty());
}

// ── Bearer token ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_right_token_is_served() {
    let f = fixture(Some(TOKEN));
    let (status, headers, body) = get_with(&f, TOKEN).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], CONTENT_TYPE);
    assert!(body.contains("ferrowarden_build_info"));
    assert!(metrics_auth_events(&f).is_empty());
}

#[tokio::test]
async fn the_scheme_is_case_insensitive_the_token_is_not() {
    let f = fixture(Some(TOKEN));
    for scheme in ["bearer", "BEARER", "BeArEr"] {
        let h = format!("{scheme} {TOKEN}");
        let (status, _, _) = call(&f, "GET", "/metrics", &[("authorization", &h)], None).await;
        assert_eq!(status, StatusCode::OK, "{scheme}");
    }
    let (status, _, _) = get_with(&f, &TOKEN.to_uppercase()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_missing_or_wrong_token_is_a_401_with_a_challenge() {
    let f = fixture(Some(TOKEN));
    let wrong_tokens = [
        "wrong".to_string(),
        TOKEN[..TOKEN.len() - 1].to_string(),
        format!("{TOKEN}x"),
        TOKEN.replace('s', "S"),
    ];
    for wrong in &wrong_tokens {
        let (status, headers, body) = get_with(&f, wrong).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{wrong}");
        assert_eq!(headers["www-authenticate"], "Bearer");
        assert!(!body.contains("ferrowarden_"));
    }
    for headers in [
        vec![],
        vec![("authorization", "Basic dXNlcjpwYXNz")],
        vec![("authorization", "Bearer")],
        vec![("authorization", "Bearer ")],
        vec![("authorization", TOKEN)],
    ] {
        let (status, h, _) = call(&f, "GET", "/metrics", &headers, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{headers:?}");
        assert_eq!(h["www-authenticate"], "Bearer");
    }
    // The token in the URL is not a token.
    let (status, _, _) = call(&f, "GET", &format!("/metrics?token={TOKEN}"), &[], None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn failures_are_events_without_the_token_and_counted_every_time() {
    let f = fixture(Some(TOKEN));
    let presented = "presented-but-wrong-token-9999";
    let (status, _, _) = call(&f, "GET", "/metrics", &[], Some("192.0.2.10")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    for _ in 0..5 {
        let [(k, v)] = bearer_header(presented);
        call(&f, "GET", "/metrics", &[(k, &v)], Some("192.0.2.10")).await;
    }
    // Another address has its own budget.
    let [(k, v)] = bearer_header(presented);
    call(&f, "GET", "/metrics", &[(k, &v)], Some("192.0.2.11")).await;

    let events = metrics_auth_events(&f);
    assert_eq!(events.len(), 2, "one per source address per minute");
    let first = events
        .iter()
        .find(|e| e["source"]["ip"] == "192.0.2.10")
        .unwrap();
    assert_eq!(first["event"]["action"], "metrics_auth");
    assert_eq!(first["event"]["outcome"], "failure");
    assert_eq!(first["event"]["reason"], "missing_metrics_token");
    assert_eq!(first["http"]["response"]["status_code"], 401);
    assert_eq!(first["ferrowarden"]["details"]["suppressed"], 0);
    let other = events
        .iter()
        .find(|e| e["source"]["ip"] == "192.0.2.11")
        .unwrap();
    assert_eq!(other["event"]["reason"], "invalid_metrics_token");

    // No event holds either token.
    let all = serde_json::to_string(&events).unwrap();
    assert!(!all.contains(TOKEN));
    assert!(!all.contains(presented));

    // The counter has all of them, suppressed or not.
    let (_, _, body) = get_with(&f, TOKEN).await;
    assert!(
        body.contains("ferrowarden_auth_failures_total{kind=\"metrics\"} 7"),
        "{body}"
    );
    // And the scrape itself leaks neither.
    assert!(!body.contains(TOKEN));
    assert!(!body.contains(presented));
}

#[tokio::test]
async fn the_failure_event_reports_what_was_suppressed() {
    let f = fixture(Some(TOKEN));
    // The report table is the same one the rate limiter uses; drive it past
    // its window with the clock argument instead of sleeping.
    let ip: IpAddr = "192.0.2.50".parse().unwrap();
    let t0 = Instant::now();
    let server = MetricsServer::new(
        f.state.clone(),
        f.metrics.clone(),
        &config(Some(TOKEN)).metrics,
        None,
    );
    assert_eq!(server.reports.note(ip, t0), Some(0));
    assert_eq!(server.reports.note(ip, t0), None);
    assert_eq!(server.reports.note(ip, t0), None);
    assert_eq!(
        server.reports.note(ip, t0 + Duration::from_secs(61)),
        Some(2)
    );
}

// ── Routes ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn everything_but_metrics_is_a_404_with_or_without_a_token() {
    for token in [None, Some(TOKEN)] {
        let f = fixture(token);
        for path in [
            "/",
            "/health",
            "/v1/credentials",
            "/v1/forward",
            "/v1/admin/keys",
            "/metrics/",
            "/metrics/x",
            "/Metrics",
            "/ui/",
        ] {
            let (status, _, body) = call(&f, "GET", path, &[], None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            assert!(body.is_empty(), "{path}");
        }
        assert!(
            metrics_auth_events(&f).is_empty(),
            "a 404 is not an auth event"
        );
    }
}

#[tokio::test]
async fn every_method_but_get_is_a_405() {
    for token in [None, Some(TOKEN)] {
        let f = fixture(token);
        for method in ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
            let (status, headers, _) = call(&f, method, "/metrics", &[], None).await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
            assert_eq!(headers["allow"], "GET");
        }
    }
}

// ── Pieces ────────────────────────────────────────────────────────────────────

#[test]
fn bearer_parsing() {
    let h = |v: &str| {
        let mut m = HeaderMap::new();
        m.insert(header::AUTHORIZATION, HeaderValue::from_str(v).unwrap());
        m
    };
    assert_eq!(bearer(&h("Bearer abc")), Presented::Token("abc"));
    assert_eq!(bearer(&h("bearer   abc")), Presented::Token("abc"));
    assert_eq!(bearer(&h("Bearer")), Presented::Nothing);
    assert_eq!(bearer(&h("Bearer  ")), Presented::Nothing);
    assert_eq!(bearer(&h("Basic abc")), Presented::Nothing);
    assert_eq!(bearer(&HeaderMap::new()), Presented::Nothing);
}

#[test]
fn tokens_are_compared_as_digests() {
    let expected: [u8; 32] = Sha256::digest(TOKEN.as_bytes()).into();
    assert!(token_matches(&expected, TOKEN));
    // Different lengths, a prefix, an extension and a one-character change
    // all compare unequal the same way.
    for wrong in [
        "",
        "x",
        &TOKEN[..10],
        &format!("{TOKEN}0"),
        &TOKEN.replace('3', "4"),
    ] {
        assert!(!token_matches(&expected, wrong), "{wrong}");
    }
}

#[test]
fn the_token_is_kept_as_a_digest_only() {
    let cfg = config(Some(TOKEN));
    let state = Arc::new(AppState::new(
        cfg.clone(),
        Arc::new(EventLog::buffer_only(1)),
    ));
    let server = MetricsServer::new(
        state,
        Metrics::new("0", "native", false),
        &cfg.metrics,
        None,
    );
    let digest = server.token_digest.expect("a token is configured");
    assert_ne!(&digest[..], TOKEN.as_bytes());
    assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(TOKEN.as_bytes())));
    // The config prints without it.
    assert!(!format!("{:?}", cfg.metrics).contains(TOKEN));
}

#[tokio::test]
async fn scrapes_reflect_the_state() {
    let f = fixture(Some(TOKEN));
    f.state.set_unlocked().await;
    f.state.sync_stats.record_success(3);
    let (_, _, body) = get_with(&f, TOKEN).await;
    assert!(body.contains("ferrowarden_vault_unlocked 1"));
    assert!(body.contains("ferrowarden_vault_excluded_items 3"));
    assert!(!body.contains("ferrowarden_vault_last_sync_timestamp_seconds 0\n"));
}
