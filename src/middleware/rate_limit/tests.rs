
use super::*;

fn ip(last: u8) -> IpAddr {
    IpAddr::from([10, 0, 0, last])
}

#[test]
fn first_429_emits_then_the_window_aggregates() {
    let reports = RateLimitReports::default();
    let t0 = Instant::now();

    assert_eq!(
        reports.note(ip(1), t0),
        Some(0),
        "first event, nothing suppressed"
    );
    for i in 1..=5 {
        assert_eq!(
            reports.note(ip(1), t0 + Duration::from_secs(i)),
            None,
            "folded into the next event"
        );
    }
    // A different IP has its own window.
    assert_eq!(reports.note(ip(2), t0 + Duration::from_secs(2)), Some(0));

    // Window over: next event reports the 5 suppressed 429s, then resets.
    assert_eq!(reports.note(ip(1), t0 + Duration::from_secs(61)), Some(5));
    assert_eq!(reports.note(ip(1), t0 + Duration::from_secs(62)), None);
    assert_eq!(reports.note(ip(1), t0 + Duration::from_secs(125)), Some(1));
}

#[test]
fn flood_produces_one_event_per_window() {
    let reports = RateLimitReports::default();
    let t0 = Instant::now();
    let emitted = (0..10_000)
        .filter(|i| {
            reports
                .note(ip(9), t0 + Duration::from_millis(*i as u64))
                .is_some()
        })
        .count();
    assert_eq!(emitted, 1);
}

#[test]
fn stale_entries_are_pruned_when_the_table_grows() {
    let reports = RateLimitReports::default();
    let t0 = Instant::now();
    for i in 0..(REPORT_TABLE_SOFT_CAP as u32 + 5) {
        let a = IpAddr::from(i.to_be_bytes());
        reports.note(a, t0);
    }
    // Far in the future every entry is stale; the next call prunes.
    reports.note(ip(250), t0 + Duration::from_secs(3600));
    assert!(reports.table.lock().unwrap().len() < 10);
}

#[tokio::test]
async fn middleware_emits_one_aggregated_event_for_a_burst_of_429s() {
    use axum::{body::Body, http::Request as HttpRequest, middleware, routing::get, Router};
    use tower::ServiceExt;

    let events = Arc::new(EventLog::buffer_only(100));
    // burst 1, very slow refill: every request after the first is a 429.
    let state = LimitState::new("agent", 1, 1, events.clone());
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(middleware::from_fn(rate_limit))
        .layer(Extension(state));

    let mut statuses = Vec::new();
    for _ in 0..6 {
        let resp = app
            .clone()
            .oneshot(HttpRequest::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        statuses.push(resp.status());
    }
    assert_eq!(statuses[0], StatusCode::OK);
    assert!(statuses[1..]
        .iter()
        .all(|s| *s == StatusCode::TOO_MANY_REQUESTS));

    let recent = events.recent(10);
    assert_eq!(recent.len(), 1, "five 429s, one event");
    let v = serde_json::to_value(&*recent[0]).unwrap();
    assert_eq!(v["event"]["action"], "rate_limited");
    assert_eq!(v["event"]["reason"], "rate_limited");
    assert_eq!(v["http"]["response"]["status_code"], 429);
    assert_eq!(v["ferrowarden"]["details"]["limiter"], "agent");
    assert_eq!(v["ferrowarden"]["details"]["suppressed"], 0);
}
