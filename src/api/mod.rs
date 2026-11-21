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

use crate::config::split_list;
use crate::middleware::rate_limit::{new_limiter, rate_limit, TrustedProxies};
use crate::net::Cidr;
use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    // Agent endpoints: configurable, default 120 requests/min sustained with a
    // burst of 20 — a single agent making one call per second (60/min) fits
    // with headroom. Validated > 0 in Config::validate.
    let agent_limiter = new_limiter(
        state.config.agent_rate_limit_per_minute,
        state.config.agent_rate_limit_burst,
    );

    // Admin endpoints: 30 requests/min sustained, burst of 5.
    // Admin actions (unlock, key management, audit queries) are infrequent by
    // design. Stricter limits reduce the blast radius if the admin key is
    // compromised and slow down guessing.
    let admin_limiter = new_limiter(30, 5);

    // Validated in Config::validate, so every entry parses.
    let trusted = TrustedProxies(Arc::new(
        split_list(&state.config.trusted_proxies)
            .iter()
            .filter_map(|e| Cidr::parse(e))
            .collect(),
    ));

    // Layer ordering: Axum runs the last-added layer first.
    // Extension (outer, added second) adds the limiter to request extensions.
    // rate_limit middleware (inner, added first) reads it from extensions.
    let agent_routes = Router::new()
        .route("/v1/forward", post(forward::forward))
        .route("/v1/credentials", get(credentials::list_credentials))
        .layer(middleware::from_fn(rate_limit))
        .layer(Extension(agent_limiter))
        .layer(Extension(trusted.clone()));

    let admin_routes = Router::new()
        .route("/v1/unlock", post(unlock::unlock))
        .route("/v1/admin/keys", post(admin::create_key))
        .route("/v1/admin/keys", get(admin::list_keys))
        .route("/v1/admin/keys/{id}", delete(admin::revoke_key))
        .route("/v1/admin/audit", get(admin::get_audit))
        .route("/v1/admin/status", get(admin::get_status))
        .layer(middleware::from_fn(rate_limit))
        .layer(Extension(admin_limiter))
        .layer(Extension(trusted));

    let api = agent_routes.merge(admin_routes);
    let prefix = state.config.api_prefix.clone();

    // Health check: public, no auth, no rate limit, never prefixed.
    // Used by Docker healthcheck and reverse proxies.
    let router = Router::new().route("/health", get(health::health));
    let router = if prefix.is_empty() {
        router.merge(api)
    } else {
        // Config::load normalizes the prefix to "/seg[/seg...]".
        router.nest(&prefix, api)
    };
    router.with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;
    use crate::config::{Config, UnlockMode};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn app(prefix: &str) -> Router {
        let cfg = Config {
            bind_addr: "127.0.0.1:3000".to_string(),
            bw_serve_url: "http://127.0.0.1:8087".to_string(),
            unlock_mode: UnlockMode::Manual,
            unlock_file: None,
            admin_key: "a".repeat(32),
            keys_file: None,
            tls_enabled: false,
            tls_cert_file: None,
            tls_key_file: None,
            allow_private_targets: false,
            allowed_targets: String::new(),
            enforce_credential_hosts: true,
            refresh_interval_secs: 0,
            max_response_bytes: 1024,
            forward_timeout_secs: 5,
            trusted_proxies: String::new(),
            api_prefix: prefix.to_string(),
            agent_rate_limit_per_minute: 120,
            agent_rate_limit_burst: 20,
        };
        router(Arc::new(AppState::new_with_audit(cfg, Arc::new(AuditLog::new(10)))))
    }

    async fn status(app: Router, path: &str) -> StatusCode {
        app.oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn default_routes_have_no_prefix() {
        assert_eq!(status(app(""), "/health").await, StatusCode::OK);
        // Reaches the handler: rejected for the missing agent key, not 404.
        assert_eq!(status(app(""), "/v1/credentials").await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn prefix_moves_api_but_not_health() {
        assert_eq!(status(app("/k7f3q9"), "/k7f3q9/v1/credentials").await, StatusCode::UNAUTHORIZED);
        assert_eq!(status(app("/k7f3q9"), "/k7f3q9/v1/admin/status").await, StatusCode::UNAUTHORIZED);
        assert_eq!(status(app("/k7f3q9"), "/v1/credentials").await, StatusCode::NOT_FOUND);
        assert_eq!(status(app("/k7f3q9"), "/health").await, StatusCode::OK);
        assert_eq!(status(app("/k7f3q9"), "/k7f3q9/health").await, StatusCode::NOT_FOUND);
    }
}
