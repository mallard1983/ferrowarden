//! The metrics listener's router: `GET /metrics` and nothing else.
//!
//! It is a server of its own (never merged into the API or UI router), so the
//! agent and admin API cannot be reached on the metrics port, nor the metrics
//! on theirs. Every path but `/metrics` is a 404 and every method but GET a
//! 405, both without authentication and without an event: they reveal nothing.
//!
//! With a token configured, `GET /metrics` needs `Authorization: Bearer
//! <token>`. The token is read once at startup ([`crate::config::MetricsToken`]),
//! kept only as a SHA-256 digest and compared in constant time (the digests of
//! both sides, so the length of the token cannot be learned either). A missing
//! or wrong token is a 401 with `WWW-Authenticate: Bearer`, counted in
//! `ferrowarden_auth_failures_total{kind="metrics"}` every time and reported as
//! a `metrics_auth` event at most once per client address per minute (with the
//! number suppressed since), like `rate_limited`. Neither the presented nor
//! the configured token is ever logged, put in an event or echoed.

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use subtle::ConstantTimeEq;

use super::{Metrics, Snapshot, CONTENT_TYPE};
use crate::config::MetricsConfig;
use crate::events::{Action, Reason, SecurityEvent};
use crate::middleware::rate_limit::RateLimitReports;
use crate::middleware::request_context::RequestContext;
use crate::state::AppState;
use crate::ui::UiState;

/// The one path served.
pub const PATH: &str = "/metrics";

/// Everything the handler needs.
pub struct MetricsServer {
    app: Arc<AppState>,
    metrics: Arc<Metrics>,
    /// SHA-256 of the bearer token; `None` serves without authentication.
    token_digest: Option<[u8; 32]>,
    ui: Option<Arc<UiState>>,
    reports: RateLimitReports,
    /// One scrape at a time: the gauges are written into the registry just
    /// before it is encoded, and two scrapes must not interleave.
    scrape: tokio::sync::Mutex<()>,
}

impl MetricsServer {
    pub fn new(
        app: Arc<AppState>,
        metrics: Arc<Metrics>,
        cfg: &MetricsConfig,
        ui: Option<Arc<UiState>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            app,
            metrics,
            token_digest: cfg
                .token
                .0
                .as_ref()
                .map(|t| Sha256::digest(t.as_bytes()).into()),
            ui,
            reports: RateLimitReports::default(),
            scrape: tokio::sync::Mutex::new(()),
        })
    }
}

/// The router of the metrics listener.
pub fn router(server: Arc<MetricsServer>) -> Router {
    Router::new().fallback(handle).with_state(server)
}

/// Whether `presented` is the token whose SHA-256 is `expected`. Compares the
/// digests in constant time.
pub fn token_matches(expected: &[u8; 32], presented: &str) -> bool {
    let got = Sha256::digest(presented.as_bytes());
    bool::from(expected.as_slice().ct_eq(got.as_slice()))
}

/// What the `Authorization` header holds.
#[derive(Debug, PartialEq, Eq)]
pub enum Presented<'a> {
    /// No header, or one that is not `Bearer <something>`.
    Nothing,
    Token(&'a str),
}

/// Read a bearer token from the headers. The scheme is case-insensitive.
pub fn bearer(headers: &HeaderMap) -> Presented<'_> {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return Presented::Nothing;
    };
    let Some((scheme, rest)) = value.split_once(' ') else {
        return Presented::Nothing;
    };
    let token = rest.trim_start();
    if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
        Presented::Token(token)
    } else {
        Presented::Nothing
    }
}

async fn handle(State(server): State<Arc<MetricsServer>>, request: Request) -> Response {
    if request.uri().path() != PATH {
        return StatusCode::NOT_FOUND.into_response();
    }
    if request.method() != Method::GET {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, HeaderValue::from_static("GET"))],
        )
            .into_response();
    }

    if let Some(expected) = &server.token_digest {
        let reason = match bearer(request.headers()) {
            Presented::Nothing => Some(Reason::MissingMetricsToken),
            Presented::Token(t) if token_matches(expected, t) => None,
            Presented::Token(_) => Some(Reason::InvalidMetricsToken),
        };
        if let Some(reason) = reason {
            return unauthorized(&server, &request, reason);
        }
    }

    let _one_at_a_time = server.scrape.lock().await;
    let ui_sessions = server.ui.as_ref().map(|ui| ui.live_sessions());
    let snapshot = Snapshot::gather(&server.app, ui_sessions).await;
    match server.metrics.render(&snapshot) {
        Ok(body) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, CONTENT_TYPE),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// The TCP peer. The metrics listener does not look at `X-Forwarded-For`: a
/// scraper connects directly.
fn peer_ip(request: &Request) -> IpAddr {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]))
}

fn unauthorized(server: &MetricsServer, request: &Request, reason: Reason) -> Response {
    server.metrics.count_metrics_auth_failure();
    let ip = peer_ip(request);
    if let Some(suppressed) = server.reports.note(ip, Instant::now()) {
        server.app.events.emit(
            SecurityEvent::new(Action::MetricsAuth)
                .request(&RequestContext::new(ip))
                .reason(reason)
                .status(StatusCode::UNAUTHORIZED.as_u16())
                .detail("suppressed", suppressed),
        );
    }
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::WWW_AUTHENTICATE, "Bearer"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        "unauthorized\n",
    )
        .into_response()
}

#[cfg(test)]
mod tests;
