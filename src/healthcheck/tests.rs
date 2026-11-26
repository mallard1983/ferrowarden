use super::*;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

const SERVER_CERT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/testdata/healthcheck-server.crt"
);
const SERVER_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/testdata/healthcheck-server.key"
);
const OTHER_CERT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/testdata/healthcheck-other.crt"
);

fn config(bind: &str, prefix: &str) -> Config {
    let mut cfg: Config = ::config::Config::builder()
        .add_source(::config::File::from_str(
            "unlock_mode = \"manual\"
",
            ::config::FileFormat::Toml,
        ))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    cfg.tls_enabled = false;
    cfg.bind_addr = bind.to_string();
    cfg.api_prefix = prefix.to_string();
    cfg
}

#[test]
fn wildcard_bind_addresses_are_reached_through_loopback() {
    let t = |bind: &str| target(&config(bind, "")).unwrap().addr.to_string();
    assert_eq!(t("0.0.0.0:3000"), "127.0.0.1:3000");
    assert_eq!(t("[::]:3000"), "[::1]:3000");
    assert_eq!(t("127.0.0.1:4000"), "127.0.0.1:4000");
    assert_eq!(t("10.1.2.3:3000"), "10.1.2.3:3000");
    assert_eq!(t("[fd00::5]:3000"), "[fd00::5]:3000");
    assert_eq!(t(" 0.0.0.0:3000 "), "127.0.0.1:3000");
    assert!(target(&config("not-an-address", "")).is_err());
}

#[test]
fn the_target_never_depends_on_the_api_prefix() {
    let with = target(&config("0.0.0.0:3000", "/k7f3q9")).unwrap();
    let without = target(&config("0.0.0.0:3000", "")).unwrap();
    assert_eq!(with, without);
    // The request path is a constant: /health, never prefixed.
    assert!(REQUEST.starts_with("GET /health HTTP/1.1\r\n"));
}

#[test]
fn tls_needs_a_certificate_file() {
    let mut cfg = config("0.0.0.0:3000", "");
    cfg.tls_enabled = true;
    cfg.tls_cert_file = None;
    assert!(target(&cfg).is_err());
    cfg.tls_cert_file = Some("/run/certs/server.crt".into());
    assert_eq!(
        target(&cfg).unwrap().tls_cert_file,
        Some("/run/certs/server.crt".into())
    );
    cfg.tls_enabled = false;
    assert_eq!(target(&cfg).unwrap().tls_cert_file, None);
}

#[test]
fn status_lines_are_parsed() {
    assert_eq!(parse_status_line(b"HTTP/1.1 200 OK"), Some(200));
    assert_eq!(
        parse_status_line(b"HTTP/1.0 503 Service Unavailable"),
        Some(503)
    );
    assert_eq!(parse_status_line(b"HTTP/2 200"), None);
    assert_eq!(parse_status_line(b"SSH-2.0-OpenSSH"), None);
    assert_eq!(parse_status_line(b""), None);
    assert_eq!(parse_status_line(b"HTTP/1.1 abc"), None);
}

#[test]
fn the_configured_certificate_is_loaded_as_the_only_trust() {
    assert!(load_server_cert(Path::new(SERVER_CERT)).is_ok());
    assert!(load_server_cert(Path::new("/nonexistent/server.crt")).is_err());
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty.crt");
    std::fs::write(&empty, "nothing here\n").unwrap();
    assert!(load_server_cert(&empty)
        .unwrap_err()
        .contains("no certificate"));
    assert!(tls_connector(Path::new(SERVER_CERT)).is_ok());
    assert!(tls_connector(&empty).is_err());
}

/// A one-shot server answering every connection with `status`.
async fn plain_server(status: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let mut buf = [0u8; 512];
            let _ = s.read(&mut buf).await;
            let _ = s
                .write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await;
        }
    });
    addr
}

/// A TLS server with `SERVER_KEY` and `cert_file` as its certificate.
async fn tls_server(cert_file: &str) -> SocketAddr {
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_file, SERVER_KEY)
        .await
        .unwrap();
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = std_listener.local_addr().unwrap();
    let app = axum::Router::new().route("/health", axum::routing::get(|| async { "ok" }));
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(std_listener, config)
            .unwrap()
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    addr
}

#[tokio::test]
async fn plain_http_200_is_healthy_and_anything_else_is_not() {
    let ok = Target {
        addr: plain_server("200 OK").await,
        tls_cert_file: None,
    };
    assert!(check(&ok).await.is_ok());
    let sick = Target {
        addr: plain_server("503 Service Unavailable").await,
        tls_cert_file: None,
    };
    let err = check(&sick).await.unwrap_err();
    assert!(err.contains("503"), "{err}");
}

#[tokio::test]
async fn a_closed_port_is_unhealthy() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let err = check(&Target {
        addr,
        tls_cert_file: None,
    })
    .await
    .unwrap_err();
    assert!(err.contains("cannot connect"), "{err}");
}

#[tokio::test]
async fn a_silent_server_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Accept and hold the connection open without answering.
        let (_s, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let started = std::time::Instant::now();
    let err = check(&Target {
        addr,
        tls_cert_file: None,
    })
    .await
    .unwrap_err();
    assert!(err.contains("no answer"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(6));
}

#[tokio::test]
async fn tls_is_verified_against_the_configured_certificate() {
    let addr = tls_server(SERVER_CERT).await;
    let target = Target {
        addr,
        tls_cert_file: Some(SERVER_CERT.into()),
    };
    check(&target)
        .await
        .expect("the server's own certificate is accepted");
}

#[tokio::test]
async fn a_different_certificate_is_rejected() {
    // The server presents SERVER_CERT; the configuration names another.
    let addr = tls_server(SERVER_CERT).await;
    let target = Target {
        addr,
        tls_cert_file: Some(OTHER_CERT.into()),
    };
    let err = check(&target).await.unwrap_err();
    assert!(err.contains("TLS handshake failed"), "{err}");
}

#[tokio::test]
async fn a_plain_http_port_fails_a_tls_check() {
    let addr = plain_server("200 OK").await;
    let target = Target {
        addr,
        tls_cert_file: Some(SERVER_CERT.into()),
    };
    assert!(check(&target).await.is_err());
}
