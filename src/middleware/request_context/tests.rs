
use super::*;
use axum::{body::Body, http::Request as HttpRequest, middleware, routing::get, Router};
use tower::ServiceExt;

fn app(trusted: Vec<Cidr>) -> Router {
    Router::new()
        .route(
            "/ip",
            get(|ctx: RequestContext| async move { ctx.client_ip.to_string() }),
        )
        .layer(middleware::from_fn_with_state(
            TrustedProxies(Arc::new(trusted)),
            request_context,
        ))
}

#[tokio::test]
async fn sets_a_fresh_uuid_v7_and_ignores_incoming_header() {
    let resp = app(vec![])
        .oneshot(
            HttpRequest::get("/ip")
                .header("x-request-id", "attacker-chosen")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let id = resp.headers()["x-request-id"].to_str().unwrap();
    assert_ne!(id, "attacker-chosen");
    let parsed = Uuid::parse_str(id).unwrap();
    assert_eq!(parsed.get_version_num(), 7);
}

#[tokio::test]
async fn header_is_set_even_on_404() {
    let resp = app(vec![])
        .oneshot(HttpRequest::get("/nope").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert!(resp.headers().contains_key("x-request-id"));
}

#[tokio::test]
async fn client_ip_uses_xff_only_from_trusted_peer() {
    // No ConnectInfo → peer 127.0.0.1.
    let untrusted = app(vec![])
        .oneshot(
            HttpRequest::get("/ip")
                .header("x-forwarded-for", "9.9.9.9")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(untrusted.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], b"127.0.0.1");

    let trusted = app(vec![Cidr::parse("127.0.0.1").unwrap()])
        .oneshot(
            HttpRequest::get("/ip")
                .header("x-forwarded-for", "9.9.9.9")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(trusted.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], b"9.9.9.9");
}
