use axum::http::StatusCode;

/// Public health check endpoint — no authentication required.
/// Returns 200 OK when the HTTP server is accepting connections.
/// Used by Docker health checks and load balancers.
pub async fn health() -> StatusCode {
    StatusCode::OK
}
