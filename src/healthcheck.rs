//! `ferrowarden healthcheck`: the container health check.
//!
//! The runtime image has no shell and no `curl`, so the binary checks itself:
//! it loads the same settings as the server (no secrets are needed), connects
//! to the port the server listens on, sends `GET /health` and exits 0 on an
//! HTTP 200, 1 otherwise, with one short line on stderr on failure.
//!
//! `/health` is never under `api_prefix`, so the prefix is ignored.
//!
//! With TLS on, the check **verifies the server's certificate**. The server
//! is addressed as `127.0.0.1`, which a certificate for `agents.example.com`
//! does not cover, so the name cannot be what is verified. Instead the check
//! pins the certificate: the one the server was configured with
//! (`tls_cert_file`, the first certificate in the file) is the only
//! certificate accepted, and the handshake signature must verify against it,
//! so the peer has to hold the matching private key. Chain building and name
//! matching are replaced by that exact match; nothing is skipped or accepted
//! on failure. Expiry is not judged here: a liveness check should not fail
//! the container the day a certificate lapses (the clients will say so).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::Config;

/// The whole check (connect, handshake, request, status line) must finish in
/// this long.
pub const TIMEOUT: Duration = Duration::from_secs(3);

/// The request sent. `/health` is public and never prefixed.
const REQUEST: &str = "GET /health HTTP/1.1\r\nHost: localhost\r\nUser-Agent: ferrowarden-healthcheck\r\nConnection: close\r\n\r\n";

/// Where to connect and, with TLS, which certificate to expect.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub addr: SocketAddr,
    /// The server's configured certificate file; `None` means plain HTTP.
    pub tls_cert_file: Option<PathBuf>,
}

/// Work out the target from the configuration. A wildcard bind address
/// (`0.0.0.0`, `::`) is reached through loopback; anything else as written.
pub fn target(config: &Config) -> Result<Target, String> {
    let bind: SocketAddr = config
        .bind_addr
        .trim()
        .parse()
        .map_err(|_| "bind_addr is not a valid socket address".to_string())?;
    let ip = match bind.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    let tls_cert_file = if config.tls_enabled {
        Some(
            config
                .tls_cert_file
                .clone()
                .ok_or_else(|| "tls_enabled is set but tls_cert_file is not".to_string())?,
        )
    } else {
        None
    };
    Ok(Target {
        addr: SocketAddr::new(ip, bind.port()),
        tls_cert_file,
    })
}

/// The HTTP status code on the first line of a response, if it is one.
pub fn parse_status_line(line: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    parts.next()?.parse().ok()
}

/// Accepts exactly one certificate, the server's own, and checks that the
/// peer can sign with its key. See the module documentation.
#[derive(Debug)]
struct PinnedCertVerifier {
    expected: CertificateDer<'static>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "the server presented a certificate other than tls_cert_file".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The first certificate in a PEM file: the server's own, as served.
fn load_server_cert(path: &Path) -> Result<CertificateDer<'static>, String> {
    CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("cannot read tls_cert_file: {e}"))?
        .next()
        .ok_or_else(|| "tls_cert_file contains no certificate".to_string())?
        .map_err(|e| format!("tls_cert_file is not a valid PEM certificate: {e}"))
}

/// A TLS client that trusts only the server's own configured certificate.
fn tls_connector(cert_file: &Path) -> Result<TlsConnector, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = PinnedCertVerifier {
        expected: load_server_cert(cert_file)?,
        provider: provider.clone(),
    };
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS setup failed: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Send the request on an open stream and return the response's status code.
async fn get_health<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<u16, String> {
    stream
        .write_all(REQUEST.as_bytes())
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    // Only the status line is needed.
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    while !buf.windows(2).any(|w| w == b"\r\n") && buf.len() < 1024 {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("response failed: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let line = buf.split(|b| *b == b'\r').next().unwrap_or_default();
    parse_status_line(line).ok_or_else(|| "response is not HTTP".to_string())
}

/// Run the check against `target`, within [`TIMEOUT`]. `Ok` means HTTP 200.
pub async fn check(target: &Target) -> Result<(), String> {
    let work = async {
        let tls = target.tls_cert_file.as_deref().map(tls_connector);
        let mut tcp = TcpStream::connect(target.addr)
            .await
            .map_err(|e| format!("cannot connect to {}: {e}", target.addr))?;
        let status = match tls {
            None => get_health(&mut tcp).await?,
            Some(connector) => {
                let name = ServerName::try_from("localhost").expect("a valid name");
                let mut stream = connector?
                    .connect(name, tcp)
                    .await
                    .map_err(|e| format!("TLS handshake failed: {e}"))?;
                get_health(&mut stream).await?
            }
        };
        if status == 200 {
            Ok(())
        } else {
            Err(format!("GET /health returned HTTP {status}"))
        }
    };
    tokio::time::timeout(TIMEOUT, work)
        .await
        .unwrap_or_else(|_| Err(format!("no answer within {} s", TIMEOUT.as_secs())))
}

/// Entry point: the process exit code (0 healthy, 1 not), with one line on
/// stderr when not.
pub async fn run() -> i32 {
    let result = match Config::load_for_healthcheck() {
        Ok(config) => match target(&config) {
            Ok(target) => check(&target).await,
            Err(e) => Err(e),
        },
        Err(e) => Err(format!("cannot load the configuration: {e}")),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("ferrowarden healthcheck: unhealthy: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests;
