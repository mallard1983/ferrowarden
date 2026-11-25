//! Per-request context: request ID and client IP, computed once.
//!
//! This is the outermost layer, so every response — including 404s, 429s and
//! `/health` — carries an `X-Request-Id` header, and every security event for
//! the request can be correlated by that ID.

use axum::{
    extract::{ConnectInfo, FromRequestParts, Request},
    http::{request::Parts, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};
use uuid::Uuid;

use crate::net::{client_ip, Cidr};

/// Name of the response header carrying the request ID.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Reverse proxies whose `X-Forwarded-For` header is trusted when working out
/// the client IP.
#[derive(Clone)]
pub struct TrustedProxies(pub Arc<Vec<Cidr>>);

/// What every handler and middleware needs to know about the current request.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// UUID v7, always generated here — an incoming `X-Request-Id` is ignored.
    pub request_id: String,
    pub client_ip: IpAddr,
    /// The TCP peer itself (the reverse proxy, when there is one). Only the
    /// admin UI needs it, to decide whether `X-Forwarded-Proto` is trusted.
    pub peer_ip: IpAddr,
    pub started: Instant,
}

impl RequestContext {
    pub fn new(client_ip: IpAddr) -> Self {
        Self {
            request_id: Uuid::now_v7().to_string(),
            client_ip,
            peer_ip: client_ip,
            started: Instant::now(),
        }
    }

    /// Context for code paths that run without the middleware (unit tests).
    fn detached() -> Self {
        Self::new(IpAddr::from([127, 0, 0, 1]))
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequestContext {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Infallible> {
        Ok(parts
            .extensions
            .get::<RequestContext>()
            .cloned()
            .unwrap_or_else(RequestContext::detached))
    }
}

/// The TCP peer address; 127.0.0.1 when ConnectInfo is absent (unit tests,
/// manual serve).
fn peer_ip(request: &Request) -> IpAddr {
    // Read ConnectInfo from extensions rather than using it as a function-level
    // extractor: the Option<ConnectInfo<_>> extractor has trait bound
    // complications in Axum 0.8; reading extensions directly is more reliable.
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]))
}

/// The client IP: the TCP peer address, or — when the peer is a trusted proxy
/// — the rightmost untrusted address in `X-Forwarded-For`. Falls back to
/// 127.0.0.1 when ConnectInfo is absent (unit tests, manual serve).
fn resolve_client_ip(request: &Request, peer: IpAddr, trusted: &[Cidr]) -> IpAddr {
    if trusted.is_empty() {
        return peer;
    }
    let xff = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    client_ip(peer, xff, trusted)
}

/// Axum middleware: attach a [`RequestContext`] and set `X-Request-Id`.
pub async fn request_context(
    axum::extract::State(TrustedProxies(trusted)): axum::extract::State<TrustedProxies>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = peer_ip(&request);
    let mut ctx = RequestContext::new(resolve_client_ip(&request, peer, &trusted));
    ctx.peer_ip = peer;
    let request_id = ctx.request_id.clone();
    request.extensions_mut().insert(ctx);

    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

#[cfg(test)]
mod tests;
