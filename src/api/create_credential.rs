//! `POST /v1/credentials`: ask Ferrowarden to create a credential
//! (docs/managed-credentials.md).
//!
//! The handler authenticates the agent key, reads the strict body, validates
//! every field and the URIs against the outbound target policy, and hands the
//! request to [`crate::create::run`], which checks the key's `create`
//! patterns, finds the managed collection, checks the name against a fresh
//! sync, gets a human's approval and only then generates and writes. Whatever
//! happens, one `credential_create` event records the outcome (names and
//! codes, never a value), and the response never carries the value.

use axum::{extract::State, http::HeaderMap, http::StatusCode, Json};
use std::sync::Arc;

use crate::api::credentials::authenticate_agent;
use crate::api::strict_json::StrictJson;
use crate::create::{self, CreatePayload, Created, Progress};
use crate::error::{FerroError, FerroResult};
use crate::events::{emit_rejected, Action, SecurityEvent};
use crate::middleware::request_context::RequestContext;
use crate::state::AppState;

/// POST /v1/credentials
///
/// Create a credential in the managed collection with a generated password.
/// The agent key's `create` patterns must match the name, a human must
/// approve this one operation (the request is held for up to
/// `approval.wait_secs`, then answered `approval_pending` for the agent to
/// retry the identical request), and the name must be free. The answer is the
/// name and its placeholder; **never the value**.
pub async fn create_credential(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    body: Result<StrictJson<CreatePayload>, FerroError>,
) -> FerroResult<(StatusCode, Json<Created>)> {
    const ENDPOINT: &str = "/v1/credentials";
    // The agent first, before the body is looked at.
    let agent = authenticate_agent(&state, &ctx, &headers, ENDPOINT).await?;
    let payload = match body {
        Ok(StrictJson(payload)) => payload,
        Err(e) => {
            emit_rejected(&state.events, &ctx, Some(&agent), ENDPOINT, &e);
            return Err(e);
        }
    };
    let (req, urls) = match payload.validate() {
        Ok(ok) => ok,
        Err(e) => {
            emit_rejected(&state.events, &ctx, Some(&agent), ENDPOINT, &e);
            return Err(e);
        }
    };

    let mut progress = Progress::default();
    // A credential can only be made for places Ferrowarden may reach anyway:
    // each URI passes the outbound target policy (IP literals are checked
    // here; a name is checked again when a request is forwarded to it).
    // One check per distinct scheme, host and port (the policy looks at
    // nothing else).
    let mut checked = std::collections::HashSet::new();
    let mut result = Ok(());
    for url in &urls {
        let target = (
            url.scheme().to_string(),
            url.host_str().map(str::to_ascii_lowercase),
            url.port_or_known_default(),
        );
        if !checked.insert(target) {
            continue;
        }
        if let Err(e) = state.target_policy.check_url(url).await {
            result = Err(e);
            break;
        }
    }
    let result = match result {
        Ok(()) => create::run(&state, &agent, &ctx, &req, &mut progress).await,
        Err(e) => Err(e),
    };

    let mut event = SecurityEvent::new(Action::CredentialCreate)
        .request(&ctx)
        .key(&agent)
        .credentials([req.name.as_str()])
        .duration(ctx.started.elapsed());
    if let Some(id) = &progress.collection_id {
        event = event.detail("collection_id", id.as_str());
    }
    match &result {
        Ok(created) => state.events.emit(
            event
                .detail("cache_refreshed", created.cache_refreshed)
                .status(StatusCode::CREATED.as_u16()),
        ),
        Err(e) => state
            .events
            .emit(event.failed_with(e).status(e.status_code().as_u16())),
    }
    result.map(|created| (StatusCode::CREATED, Json(created)))
}
