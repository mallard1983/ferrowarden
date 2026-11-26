//! `GET /v1/sessions` and `DELETE /v1/sessions/{name}`: the agent's view of
//! the sessions it has captured (docs/sessions.md). Names and expiry only,
//! never a value. Both use the agent key and the agent rate limiter, like
//! `/v1/credentials`.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::Utc;
use std::sync::Arc;

use crate::api::credentials::authenticate_agent;
use crate::error::{FerroError, FerroResult};
use crate::events::{truncate, Action, SecurityEvent};
use crate::middleware::request_context::RequestContext;
use crate::sessions::{DeleteCause, SessionInfo};
use crate::state::AppState;

/// GET /v1/sessions
///
/// The live captured sessions of the calling key: name, the host they are
/// bound to and when they expire.
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
) -> FerroResult<Json<Vec<SessionInfo>>> {
    const ENDPOINT: &str = "/v1/sessions";
    let agent = authenticate_agent(&state, &ctx, &headers, ENDPOINT).await?;
    Ok(Json(state.sessions.list(&agent.id, Utc::now())))
}

/// DELETE /v1/sessions/{name}
///
/// Forget one captured session. A name that is absent, expired or another
/// key's is the same `unknown_session` error.
pub async fn delete_session(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> FerroResult<StatusCode> {
    const ENDPOINT: &str = "/v1/sessions/{name}";
    let agent = authenticate_agent(&state, &ctx, &headers, ENDPOINT).await?;
    if !state.sessions.remove(&agent.id, &name, Utc::now()) {
        return Err(FerroError::UnknownSession(truncate(&name, 64)));
    }
    state.events.emit(
        SecurityEvent::new(Action::SessionDelete)
            .request(&ctx)
            .key(&agent)
            .status(StatusCode::NO_CONTENT.as_u16())
            .detail_str("session", &name)
            .detail("cause", DeleteCause::Agent.as_str()),
    );
    Ok(StatusCode::NO_CONTENT)
}
