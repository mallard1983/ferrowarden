use super::*;
use crate::config::{Config, UnlockMode};

fn policy(allowed: &str) -> Arc<TargetPolicy> {
    Arc::new(TargetPolicy::from_config(&Config {
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
        allowed_targets: allowed.to_string(),
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
        metrics: Default::default(),
        sessions: Default::default(),
        approval: Default::default(),
    }))
}

fn limits() -> ForwardLimits {
    ForwardLimits {
        timeout: Duration::from_secs(5),
        max_response_bytes: 1024,
    }
}

async fn fwd(method: &str, url: &str, allowed: &str) -> FerroResult<ProxyResponse> {
    let up = send_request(
        method,
        &Url::parse(url).unwrap(),
        HashMap::new(),
        None,
        &policy(allowed),
        &limits(),
    )
    .await?;
    Ok(render_response(&up, &[]))
}

#[tokio::test]
async fn rejects_invalid_method() {
    let err = fwd("BAD METHOD", "http://localhost/", "localhost")
        .await
        .unwrap_err();
    assert!(matches!(err, FerroError::InvalidTargetUrl(_)));
}

#[tokio::test]
async fn blocks_internal_name_at_resolution() {
    let err = fwd("GET", "http://localhost:1/", "").await.unwrap_err();
    assert!(matches!(err, FerroError::TargetBlocked(_)), "{err:?}");
}

#[tokio::test]
async fn connection_error_never_contains_url_or_secret() {
    // Allowed internal target with nothing listening.
    let url = "http://localhost:1/path?key=SUPERSECRETVALUE";
    let err = fwd("GET", url, "localhost").await.unwrap_err();
    assert!(matches!(err, FerroError::ForwardFailed(_)), "{err:?}");
    let text = err.to_string();
    assert!(!text.contains("SUPERSECRETVALUE"), "{text}");
    assert!(!text.contains("localhost"), "{text}");
}

fn parse(json: &str) -> Result<ProxyRequest, String> {
    crate::api::strict_json::parse_strict(json.as_bytes())
}

#[test]
fn validate_rejects_case_insensitive_duplicate_headers() {
    let r = parse(
        r#"{"method":"GET","url":"http://x","headers":{"Authorization":"a","authorization":"b"}}"#,
    )
    .unwrap();
    let e = r.validate().unwrap_err().to_string();
    assert!(e.contains("more than once"), "{e}");

    let r = parse(r#"{"method":"GET","url":"http://x","headers":{"X-A":"1","x-a":"1","X-B":"2"}}"#)
        .unwrap();
    assert!(r.validate().is_err());
}

#[test]
fn validate_accepts_distinct_headers() {
    let r =
        parse(r#"{"method":"GET","url":"http://x","headers":{"Authorization":"a","X-Other":"a"}}"#)
            .unwrap();
    assert!(r.validate().is_ok());
    let r = parse(r#"{"method":"GET","url":"http://x"}"#).unwrap();
    assert!(r.validate().is_ok());
}

#[test]
fn proxy_request_rejects_unknown_fields_and_duplicate_keys() {
    let e = parse(r#"{"method":"GET","url":"http://x","extra":1}"#).unwrap_err();
    assert!(e.contains("unknown field `extra`"), "{e}");
    assert!(parse(r#"{"method":"GET","method":"POST","url":"http://x"}"#).is_err());
    assert!(parse(r#"{"method":"GET","url":"http://x","headers":{"a":"1","a":"2"}}"#).is_err());
    assert!(parse(r#"{"method":"GET","url":"http://x","body":{"k":{"a":1,"a":2}}}"#).is_err());
}

/// A server that answers every request with `body`, once per connection.
async fn body_server(body: Vec<u8>) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes()).await;
            let _ = s.write_all(&body).await;
        }
    });
    addr
}

#[tokio::test]
async fn the_upstream_body_size_is_recorded_but_never_sent_to_the_agent() {
    // Text: the size of the body as received, before scrubbing.
    let addr = body_server(vec![b'a'; 700]).await;
    let resp = fwd("GET", &format!("http://{addr}/"), "127.0.0.1")
        .await
        .unwrap();
    assert_eq!(resp.upstream_bytes, 700);
    assert_eq!(resp.body_encoding, "utf8");
    // Bytes that are not text: the size of the bytes, not of their base64.
    let addr = body_server(vec![0xff; 30]).await;
    let resp = fwd("GET", &format!("http://{addr}/"), "127.0.0.1")
        .await
        .unwrap();
    assert_eq!(resp.upstream_bytes, 30);
    assert_eq!(resp.body_encoding, "base64");
    assert!(resp.body.len() > 30);
    // It is bookkeeping for the event: the response the agent gets has no
    // such field (the API description does not list one).
    let json = serde_json::to_value(&resp).unwrap();
    assert!(json.get("upstream_bytes").is_none(), "{json}");
}
