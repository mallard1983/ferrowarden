pub mod admin;
pub mod credentials;
pub mod forward;
pub mod health;
pub mod key_service;
pub mod openapi;
pub mod strict_json;
pub mod unlock;

use axum::{
    middleware,
    routing::{on, MethodFilter, MethodRouter},
    Extension, Router,
};
use std::sync::Arc;

use crate::config::split_list;
use crate::middleware::rate_limit::{rate_limit, LimitState};
use crate::middleware::request_context::{request_context, TrustedProxies};
use crate::net::Cidr;
use crate::state::AppState;

/// Who calls a route, which decides its rate limiter and whether it moves
/// under `api_prefix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// Public, no authentication, no rate limit, never prefixed.
    Public,
    /// Agent endpoints (and the OpenAPI document): the agent rate limiter.
    Agent,
    /// Operator endpoints: the admin rate limiter.
    Admin,
}

/// The handler behind a route. [`handler`] maps each one to its axum handler
/// with an exhaustive `match`, so a route cannot be listed without one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Health,
    OpenApi,
    ListCredentials,
    Forward,
    Unlock,
    ListKeys,
    CreateKey,
    UpdateKeyPolicy,
    RevokeKey,
    PreviewKeyPolicy,
    ListAuditEvents,
    GetStatus,
    SendTestNotification,
}

/// One route of the HTTP API.
#[derive(Debug, Clone, Copy)]
pub struct Route {
    /// Upper-case HTTP method.
    pub method: &'static str,
    /// Path template in the form OpenAPI and axum share (`{id}`), without
    /// `api_prefix`.
    pub path: &'static str,
    pub group: Group,
    op: Op,
}

/// Every route Ferrowarden serves, declared once. [`router`] builds the axum
/// router from this table, and a unit test compares it with `docs/openapi.yaml`,
/// so a route cannot be added without being described there.
#[rustfmt::skip]
pub const ROUTES: [Route; 13] = [
    Route { method: "GET", path: "/health", group: Group::Public, op: Op::Health },
    Route { method: "GET", path: "/v1/openapi.json", group: Group::Agent, op: Op::OpenApi },
    Route { method: "GET", path: "/v1/credentials", group: Group::Agent, op: Op::ListCredentials },
    Route { method: "POST", path: "/v1/forward", group: Group::Agent, op: Op::Forward },
    Route { method: "POST", path: "/v1/unlock", group: Group::Admin, op: Op::Unlock },
    Route { method: "GET", path: "/v1/admin/keys", group: Group::Admin, op: Op::ListKeys },
    Route { method: "POST", path: "/v1/admin/keys", group: Group::Admin, op: Op::CreateKey },
    Route { method: "PATCH", path: "/v1/admin/keys/{id}", group: Group::Admin, op: Op::UpdateKeyPolicy },
    Route { method: "DELETE", path: "/v1/admin/keys/{id}", group: Group::Admin, op: Op::RevokeKey },
    Route { method: "POST", path: "/v1/admin/keys/{id}/preview", group: Group::Admin, op: Op::PreviewKeyPolicy },
    Route { method: "GET", path: "/v1/admin/audit", group: Group::Admin, op: Op::ListAuditEvents },
    Route { method: "GET", path: "/v1/admin/status", group: Group::Admin, op: Op::GetStatus },
    Route { method: "POST", path: "/v1/admin/notify/test", group: Group::Admin, op: Op::SendTestNotification },
];

/// The axum method filter for a table entry's method.
fn filter(method: &str) -> MethodFilter {
    match method {
        "GET" => MethodFilter::GET,
        "POST" => MethodFilter::POST,
        "PATCH" => MethodFilter::PATCH,
        "DELETE" => MethodFilter::DELETE,
        other => panic!("route table lists unsupported method {other}"),
    }
}

/// The axum handler for a route, bound to the method the table gives it.
fn handler(route: &Route) -> MethodRouter<Arc<AppState>> {
    let f = filter(route.method);
    match route.op {
        Op::Health => on(f, health::health),
        Op::OpenApi => on(f, openapi::get_openapi),
        Op::ListCredentials => on(f, credentials::list_credentials),
        Op::Forward => on(f, forward::forward),
        Op::Unlock => on(f, unlock::unlock),
        Op::ListKeys => on(f, admin::list_keys),
        Op::CreateKey => on(f, admin::create_key),
        Op::UpdateKeyPolicy => on(f, admin::patch_key),
        Op::RevokeKey => on(f, admin::revoke_key),
        Op::PreviewKeyPolicy => on(f, admin::preview_key),
        Op::ListAuditEvents => on(f, admin::get_audit),
        Op::GetStatus => on(f, admin::get_status),
        Op::SendTestNotification => on(f, admin::send_test_notification),
    }
}

/// The routes of one group as a router. Routes that share a path (the method
/// routers are merged by axum) end up on one path entry.
fn group_router(group: Group) -> Router<Arc<AppState>> {
    ROUTES
        .iter()
        .filter(|r| r.group == group)
        .fold(Router::new(), |router, r| router.route(r.path, handler(r)))
}

pub fn router(state: Arc<AppState>) -> Router {
    // Agent endpoints: configurable, default 120 requests/min sustained with a
    // burst of 20 — a single agent making one call per second (60/min) fits
    // with headroom. Validated > 0 in Config::validate.
    let agent_limiter = LimitState::new(
        "agent",
        state.config.agent_rate_limit_per_minute,
        state.config.agent_rate_limit_burst,
        state.events.clone(),
    );

    // Admin endpoints: configurable, default 30 requests/min sustained with a
    // burst of 5. Admin actions (unlock, key management, audit queries) are
    // infrequent by design; stricter limits slow down admin key guessing.
    let admin_limiter = LimitState::new(
        "admin",
        state.config.admin_rate_limit_per_minute,
        state.config.admin_rate_limit_burst,
        state.events.clone(),
    );

    // Validated in Config::validate, so every entry parses.
    let trusted = TrustedProxies(Arc::new(
        split_list(&state.config.trusted_proxies)
            .iter()
            .filter_map(|e| Cidr::parse(e))
            .collect(),
    ));

    let prefix = state.config.api_prefix.clone();

    // The OpenAPI document is parsed once, here. The YAML is part of the
    // binary, so a failure is a bug and must stop startup, not leave the
    // endpoint broken (a unit test keeps it from shipping).
    let openapi_docs = Arc::new(
        openapi::OpenApiDocs::build(&prefix)
            .unwrap_or_else(|e| panic!("embedded OpenAPI document is invalid: {e}")),
    );

    // Layer ordering: Axum runs the last-added layer first.
    // Extension (outer, added second) adds the limiter to request extensions.
    // rate_limit middleware (inner, added first) reads it from extensions.
    // The client IP it keys on comes from the request-context middleware,
    // which wraps the whole router (see the end of this function).
    //
    // The OpenAPI document counts against the agent limiter, also when it is
    // fetched with the admin key.
    let agent_routes = group_router(Group::Agent)
        .layer(middleware::from_fn(rate_limit))
        .layer(Extension(agent_limiter))
        .layer(Extension(openapi_docs));

    let admin_routes = group_router(Group::Admin)
        .layer(middleware::from_fn(rate_limit))
        .layer(Extension(admin_limiter));

    let api = agent_routes.merge(admin_routes);

    // Health check: public, no auth, no rate limit, never prefixed.
    // Used by Docker healthcheck and reverse proxies.
    let router = group_router(Group::Public);
    let router = if prefix.is_empty() {
        router.merge(api)
    } else {
        // Config::load normalizes the prefix to "/seg[/seg...]".
        router.nest(&prefix, api)
    };
    // Outermost layer, added last: every response (including /health, 404s and
    // 429s) gets an X-Request-Id, and the client IP is computed exactly once.
    router
        .with_state(state)
        .layer(middleware::from_fn_with_state(trusted, request_context))
}

#[cfg(test)]
mod tests;
