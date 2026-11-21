use axum::extract::Request;
use axum::{
    extract::ConnectInfo,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Extension,
};
use governor::{
    clock::{Clock, DefaultClock},
    state::keyed::DefaultKeyedStateStore,
    Quota, RateLimiter,
};
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

use crate::net::{client_ip, Cidr};

pub type IpRateLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// Reverse proxies whose `X-Forwarded-For` header is trusted for rate limiting.
#[derive(Clone)]
pub struct TrustedProxies(pub Arc<Vec<Cidr>>);

/// Creates a per-IP token bucket rate limiter.
///
/// Token bucket semantics: each request consumes one token. Tokens refill at
/// `requests_per_minute / 60` per second up to `burst`. When the bucket is
/// empty the request is rejected with 429 and a `Retry-After` header.
///
/// Progressive back-off emerges naturally: sustained overconsumption grows
/// the token deficit linearly, increasing the `Retry-After` delay each time.
pub fn new_limiter(requests_per_minute: u32, burst: u32) -> Arc<IpRateLimiter> {
    let limiter = Arc::new(RateLimiter::keyed(
        Quota::per_minute(
            NonZeroU32::new(requests_per_minute).expect("requests_per_minute must be > 0"),
        )
        .allow_burst(NonZeroU32::new(burst).expect("burst must be > 0")),
    ));

    // The keyed store holds one entry per client IP ever seen. Periodically
    // drop entries whose buckets are full again so memory stays bounded.
    // Only spawn when a Tokio runtime is available (always true in the server).
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let weak = Arc::downgrade(&limiter);
        handle.spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            loop {
                ticker.tick().await;
                let Some(limiter) = weak.upgrade() else { break };
                limiter.retain_recent();
                limiter.shrink_to_fit();
            }
        });
    }

    limiter
}

/// Axum middleware: rate-limit requests per client IP address.
///
/// Requires the limiter and [`TrustedProxies`] to be injected via
/// Extension before this middleware runs. Apply layers in this order (Axum
/// runs the last-added layer first):
///
/// ```rust,ignore
/// .layer(middleware::from_fn(rate_limit))  // added first → inner → runs second
/// .layer(Extension(limiter))               // added second → outer → runs first
/// ```
///
/// The client IP is the TCP peer address, or — when the peer is a trusted
/// proxy — the rightmost untrusted address in `X-Forwarded-For`.
/// Falls back to 127.0.0.1 when ConnectInfo is absent (unit tests, manual serve).
pub async fn rate_limit(
    Extension(limiter): Extension<Arc<IpRateLimiter>>,
    Extension(TrustedProxies(trusted)): Extension<TrustedProxies>,
    request: Request,
    next: Next,
) -> Response {
    // Read ConnectInfo from extensions rather than using it as a function-level
    // extractor. The extractor pattern for Option<ConnectInfo<_>> has trait bound
    // complications in Axum 0.8; reading extensions directly is more reliable.
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));

    let ip = if trusted.is_empty() {
        peer
    } else {
        let xff = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok());
        client_ip(peer, xff, &trusted)
    };

    match limiter.check_key(&ip) {
        Ok(_) => next.run(request).await,
        Err(not_until) => {
            let wait_secs = not_until
                .wait_time_from(DefaultClock::default().now())
                .as_secs()
                .max(1);

            (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, wait_secs.to_string())],
                "Rate limit exceeded. See the Retry-After header.",
            )
                .into_response()
        }
    }
}
