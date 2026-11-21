pub mod admin;
pub mod credentials;
pub mod forward;
pub mod health;
pub mod unlock;

use axum::{
    middleware,
    routing::{delete, get, post},
    Extension, Router,
};
use std::sync::Arc;

use crate::middleware::rate_limit::{new_limiter, rate_limit};
use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    // Agent endpoints: 120 requests/min sustained, burst of 20.
    // Sized for high-frequency automation — a single agent making one call per
    // second (60/min) fits within the sustained rate with headroom.
    let agent_limiter = new_limiter(120, 20);

    // Admin endpoints: 30 requests/min sustained, burst of 5.
    // Admin actions (key management, audit queries) are infrequent by design.
    // Stricter limits reduce the blast radius if the admin key is compromised.
    let admin_limiter = new_limiter(30, 5);

    // Layer ordering: Axum runs the last-added layer first.
    // Extension (outer, added second) adds the limiter to request extensions.
    // rate_limit middleware (inner, added first) reads it from extensions.
    let agent_routes = Router::new()
        .route("/v1/forward", post(forward::forward))
        .route("/v1/credentials", get(credentials::list_credentials))
        .route("/v1/unlock", post(unlock::unlock))
        .layer(middleware::from_fn(rate_limit))
        .layer(Extension(agent_limiter));

    let admin_routes = Router::new()
        .route("/v1/admin/keys", post(admin::create_key))
        .route("/v1/admin/keys", get(admin::list_keys))
        .route("/v1/admin/keys/{id}", delete(admin::revoke_key))
        .route("/v1/admin/audit", get(admin::get_audit))
        .route("/v1/admin/status", get(admin::get_status))
        .layer(middleware::from_fn(rate_limit))
        .layer(Extension(admin_limiter));

    Router::new()
        // Health check: public, no auth, no rate limit.
        // Used by Docker healthcheck and reverse proxies.
        .route("/health", get(health::health))
        .merge(agent_routes)
        .merge(admin_routes)
        .with_state(state)
}
