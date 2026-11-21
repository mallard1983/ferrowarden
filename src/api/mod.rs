pub mod admin;
pub mod credentials;
pub mod forward;
pub mod unlock;

use axum::{
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;

use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        // Agent endpoints
        .route("/v1/forward", post(forward::forward))
        .route("/v1/credentials", get(credentials::list_credentials))
        .route("/v1/unlock", post(unlock::unlock))
        // Admin endpoints
        .route("/v1/admin/keys", post(admin::create_key))
        .route("/v1/admin/keys", get(admin::list_keys))
        .route("/v1/admin/keys/{id}", delete(admin::revoke_key))
        .route("/v1/admin/audit", get(admin::get_audit))
        .route("/v1/admin/status", get(admin::get_status))
        .with_state(state)
}
