use axum::extract::Request;
use axum::{
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
    collections::HashMap,
    net::IpAddr,
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::events::{Action, EventLog, Outcome, Reason, SecurityEvent};
use crate::middleware::request_context::RequestContext;

pub type IpRateLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// At most one `rate_limited` event per client IP per window and limiter, so a
/// flood of 429s cannot flood the event stream.
const REPORT_WINDOW: Duration = Duration::from_secs(60);
/// Prune the per-IP report table beyond this many entries.
const REPORT_TABLE_SOFT_CAP: usize = 10_000;

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

/// Aggregates 429s per client IP: tells the caller when an event is due and
/// how many 429s were suppressed since the previous event for that IP.
#[derive(Default)]
pub struct RateLimitReports {
    table: Mutex<HashMap<IpAddr, Report>>,
}

struct Report {
    last_event: Instant,
    suppressed: u64,
}

impl RateLimitReports {
    /// Record one 429 for `ip` at `now`. Returns `Some(suppressed)` when an
    /// event should be emitted now, `None` when this 429 is folded into the
    /// next event.
    pub fn note(&self, ip: IpAddr, now: Instant) -> Option<u64> {
        let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
        if table.len() > REPORT_TABLE_SOFT_CAP {
            table.retain(|_, r| now.duration_since(r.last_event) < REPORT_WINDOW);
        }
        match table.get_mut(&ip) {
            Some(report) if now.duration_since(report.last_event) < REPORT_WINDOW => {
                report.suppressed += 1;
                None
            }
            Some(report) => {
                let suppressed = std::mem::take(&mut report.suppressed);
                report.last_event = now;
                Some(suppressed)
            }
            None => {
                table.insert(
                    ip,
                    Report {
                        last_event: now,
                        suppressed: 0,
                    },
                );
                Some(0)
            }
        }
    }
}

/// Everything the rate-limit middleware needs for one limiter.
#[derive(Clone)]
pub struct LimitState {
    limiter: Arc<IpRateLimiter>,
    /// `"agent"` or `"admin"`, recorded in the event.
    name: &'static str,
    reports: Arc<RateLimitReports>,
    events: Arc<EventLog>,
}

impl LimitState {
    pub fn new(
        name: &'static str,
        requests_per_minute: u32,
        burst: u32,
        events: Arc<EventLog>,
    ) -> Self {
        Self {
            limiter: new_limiter(requests_per_minute, burst),
            name,
            reports: Arc::new(RateLimitReports::default()),
            events,
        }
    }
}

/// Axum middleware: rate-limit requests per client IP address.
///
/// Requires a [`LimitState`] injected via Extension and the outer
/// request-context middleware (for the client IP). Apply layers in this order
/// (Axum runs the last-added layer first):
///
/// ```rust,ignore
/// .layer(middleware::from_fn(rate_limit))  // added first → inner → runs second
/// .layer(Extension(limit_state))           // added second → outer → runs first
/// ```
///
/// The client IP comes from [`RequestContext`]: the TCP peer address, or —
/// when the peer is a trusted proxy — the rightmost untrusted address in
/// `X-Forwarded-For`.
pub async fn rate_limit(
    Extension(state): Extension<LimitState>,
    request: Request,
    next: Next,
) -> Response {
    let ctx = request.extensions().get::<RequestContext>().cloned();
    let ip = ctx
        .as_ref()
        .map(|c| c.client_ip)
        .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));

    match state.limiter.check_key(&ip) {
        Ok(_) => next.run(request).await,
        Err(not_until) => {
            let wait_secs = not_until
                .wait_time_from(DefaultClock::default().now())
                .as_secs()
                .max(1);

            if let Some(suppressed) = state.reports.note(ip, Instant::now()) {
                let mut event = SecurityEvent::new(Action::RateLimited)
                    .outcome(Outcome::Failure)
                    .reason(Reason::RateLimited)
                    .status(StatusCode::TOO_MANY_REQUESTS.as_u16())
                    .detail("limiter", state.name)
                    .detail("suppressed", suppressed);
                if let Some(ctx) = &ctx {
                    event = event.request(ctx);
                }
                state.events.emit(event);
            }

            (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, wait_secs.to_string())],
                "Rate limit exceeded. See the Retry-After header.",
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests;
