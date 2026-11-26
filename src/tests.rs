use super::*;

fn parse(args: &[&str]) -> Cli {
    parse_args(args.iter().map(|a| a.to_string()))
}

#[test]
fn no_arguments_runs() {
    assert_eq!(parse(&[]), Cli::Run);
}

#[test]
fn help_and_version_flags() {
    assert_eq!(parse(&["--help"]), Cli::Help);
    assert_eq!(parse(&["-h"]), Cli::Help);
    assert_eq!(parse(&["--version"]), Cli::Version);
    assert_eq!(parse(&["-V"]), Cli::Version);
}

#[test]
fn healthcheck_is_a_subcommand_without_arguments() {
    assert_eq!(parse(&["healthcheck"]), Cli::Healthcheck);
    assert_eq!(
        parse(&["healthcheck", "--insecure"]),
        Cli::Unknown("--insecure".into())
    );
    assert!(USAGE.contains("healthcheck"));
}

#[test]
fn anything_else_is_unknown() {
    assert_eq!(parse(&["serve"]), Cli::Unknown("serve".into()));
    assert_eq!(parse(&["-v"]), Cli::Unknown("-v".into()));
    assert_eq!(parse(&["--help2"]), Cli::Unknown("--help2".into()));
}

#[test]
fn usage_starts_with_the_description() {
    assert!(USAGE.starts_with(
            "Ferrowarden \u{2014} proxy authenticated API calls for agents using named vault credentials."
        ));
    assert!(USAGE.contains("docs/setup.md"));
}

// ── The metrics listener ──────────────────────────────────────────────────────

/// A server certificate for 127.0.0.1 / localhost, signed by `TEST_CA`.
const METRICS_CERT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/testdata/tls-test-server.crt"
);
const METRICS_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/testdata/tls-test-server.key"
);
/// The CA that signed `METRICS_CERT` (its private key was not kept).
const TEST_CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/testdata/tls-test-ca.crt");
/// An unrelated CA: a client that trusts only this one must refuse the server.
const OTHER_CA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/testdata/tls-test-other-ca.crt"
);
const METRICS_TEST_TOKEN: &str = "tls-test-metrics-token-0123456789";

/// A metrics router with a bearer token, over a minimal state.
fn metrics_router() -> axum::Router {
    let mut cfg: Config = ::config::Config::builder()
        .add_source(::config::File::from_str(
            "unlock_mode = \"manual\"\n[vault]\nbackend = \"bw-serve\"\n",
            ::config::FileFormat::Toml,
        ))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap();
    cfg.admin_key = "a".repeat(32).into();
    cfg.metrics.token = config::MetricsToken(Some(METRICS_TEST_TOKEN.to_string().into()));
    let events = Arc::new(EventLog::buffer_only(100));
    let state = Arc::new(AppState::new(cfg.clone(), events));
    let metrics = metrics::Metrics::new("0.0.0", "bw-serve", false);
    metrics::server::router(metrics::server::MetricsServer::new(
        state,
        metrics,
        &cfg.metrics,
        None,
    ))
}

fn free_port_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

async fn wait_until_listening(addr: SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("nothing listens on {addr}");
}

/// A client that fully verifies the server against `ca_file` only (no
/// built-in roots) and records the certificate it was shown.
fn verifying_client(ca_file: &str) -> reqwest::Client {
    let ca = reqwest::Certificate::from_pem(&std::fs::read(ca_file).unwrap()).unwrap();
    reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .tls_info(true)
        .build()
        .unwrap()
}

/// The DER bytes of the first certificate in a PEM file.
fn der_of(cert_file: &str) -> Vec<u8> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    CertificateDer::from_pem_file(cert_file).unwrap().to_vec()
}

/// The DER of the certificate the server presented for `response`.
fn presented(response: &reqwest::Response) -> Vec<u8> {
    response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|t| t.peer_certificate())
        .expect("TLS info")
        .to_vec()
}

#[tokio::test]
async fn the_metrics_listener_serves_tls_with_the_configured_certificate() {
    let addr = free_port_addr();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(METRICS_CERT, METRICS_KEY)
        .await
        .unwrap();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(serve(
        "Metrics listening",
        metrics_router(),
        addr,
        Some(tls),
        stop_rx,
    ));
    wait_until_listening(addr).await;
    let url = format!("https://{addr}/metrics");

    // A client that trusts the test CA verifies the server in full (chain,
    // name 127.0.0.1, validity) and is shown the configured certificate; the
    // token still decides.
    let client = verifying_client(TEST_CA);
    let ok = client
        .get(&url)
        .bearer_auth(METRICS_TEST_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(presented(&ok), der_of(METRICS_CERT));
    assert_eq!(
        ok.headers()["content-type"],
        "application/openmetrics-text; version=1.0.0; charset=utf-8"
    );
    assert!(ok.text().await.unwrap().contains("ferrowarden_build_info"));
    let denied = client.get(&url).send().await.unwrap();
    assert_eq!(denied.status(), 401);
    assert_eq!(denied.headers()["www-authenticate"], "Bearer");

    // A client that trusts only an unrelated CA refuses the server, and so
    // does one using the system roots; plain HTTP to the TLS port gets
    // nothing.
    assert!(verifying_client(OTHER_CA)
        .get(&url)
        .bearer_auth(METRICS_TEST_TOKEN)
        .send()
        .await
        .is_err());
    assert!(reqwest::Client::new()
        .get(&url)
        .bearer_auth(METRICS_TEST_TOKEN)
        .send()
        .await
        .is_err());
    assert!(reqwest::Client::new()
        .get(format!("http://{addr}/metrics"))
        .bearer_auth(METRICS_TEST_TOKEN)
        .send()
        .await
        .is_err());

    // The same graceful stop as the other listeners.
    stop_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(15), server)
        .await
        .expect("the listener stops on the shared signal")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn the_metrics_listener_without_tls_is_plain_http_and_stops_gracefully() {
    let addr = free_port_addr();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(serve(
        "Metrics listening",
        metrics_router(),
        addr,
        None,
        stop_rx,
    ));
    wait_until_listening(addr).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/metrics");
    let ok = client
        .get(&url)
        .bearer_auth(METRICS_TEST_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(
        client
            .get(&url)
            .bearer_auth("wrong-token-0123456789abcdef")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    // Nothing of the API is on this port.
    for path in ["/health", "/v1/credentials", "/v1/forward"] {
        let r = client
            .get(format!("http://{addr}{path}"))
            .bearer_auth(METRICS_TEST_TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "{path}");
    }
    stop_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(15), server)
        .await
        .expect("the listener stops on the shared signal")
        .unwrap()
        .unwrap();
}
