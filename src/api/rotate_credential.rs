//! `POST /v1/credentials/{name}/rotate`, `.../rotate/commit` and
//! `.../rotate/abort`: rotate a credential's password in two phases
//! (docs/managed-credentials.md), and the operator's
//! `POST /v1/admin/credentials/{name}/rotate/abort`.
//!
//! The handlers authenticate the agent key, read the strict body and hand the
//! request to [`crate::rotate`], which checks the key's `rotate` patterns and
//! the item, gets a human's approval for a **start** (a commit or an abort
//! needs none: the start's approval covered the rotation), and writes.
//! Whatever happens, one `credential_rotate_start`, `_commit` or `_abort`
//! event records the outcome (names and codes, never a value), and no response
//! carries a value.
//!
//! `{name}` is the credential's name, URL-encoded in the path: every
//! character that is not a letter, digit or one of `-` `_` `.` `~` is written
//! as `%XX` (a space is `%20`, a `/` is `%2F`). It is decoded once, before
//! it is compared with the vault's names.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::api::admin::authenticate_admin;
use crate::api::credentials::authenticate_agent;
use crate::api::key_service::{Caller, Via};
use crate::api::strict_json::{OptionalStrictJson, StrictJson};
use crate::create::MAX_NAME_CHARS;
use crate::error::{FerroError, FerroResult};
use crate::events::{emit_rejected, Action, SecurityEvent};
use crate::middleware::request_context::RequestContext;
use crate::rotate::{self, Finish, FinishPayload, Finished, Progress, RotatePayload, Started, Who};
use crate::state::{AgentKey, AppState};

/// The recorded `by` of an event: who asked.
const BY_AGENT: &str = "agent";
const BY_ADMIN: &str = "admin";

fn check_name(name: &str) -> FerroResult<()> {
    let chars = name.chars().count();
    if chars == 0 || chars > MAX_NAME_CHARS {
        return Err(FerroError::InvalidRequest(format!(
            "the credential name must be 1-{MAX_NAME_CHARS} characters"
        )));
    }
    Ok(())
}

/// One event for the end of a rotation request.
fn emit_outcome<T>(
    state: &AppState,
    event: SecurityEvent,
    progress: &Progress,
    result: &FerroResult<T>,
) {
    let mut event = event;
    if let Some(id) = &progress.collection_id {
        event = event.detail("collection_id", id.as_str());
    }
    if let Some(id) = &progress.item_id {
        event = event.detail("item_id", id.as_str());
    }
    match result {
        Ok(_) => {
            if let Some(refreshed) = progress.cache_refreshed {
                event = event.detail("cache_refreshed", refreshed);
            }
            state.events.emit(event)
        }
        Err(e) => state
            .events
            .emit(event.failed_with(e).status(e.status_code().as_u16())),
    }
}

fn agent_event(
    action: Action,
    ctx: &RequestContext,
    agent: &AgentKey,
    name: &str,
) -> SecurityEvent {
    SecurityEvent::new(action)
        .request(ctx)
        .key(agent)
        .credentials([name])
        .detail("by", BY_AGENT)
        .duration(ctx.started.elapsed())
}

/// POST /v1/credentials/{name}/rotate
///
/// Start rotating the password of a credential in the managed collection. The
/// agent key's `rotate` patterns must match the name, a human must approve
/// this one operation (the request is held for up to `approval.wait_secs`,
/// then answered `approval_pending` for the agent to retry the identical
/// request), and no rotation may be pending on the item. The answer is the
/// two placeholders, `{{vault:NAME}}` (the current password) and
/// `{{vault:NAME:next}}` (the new one); **never a value**.
pub async fn rotate_start(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Result<OptionalStrictJson<RotatePayload>, FerroError>,
) -> FerroResult<(StatusCode, Json<Started>)> {
    const ENDPOINT: &str = "/v1/credentials/{name}/rotate";
    let agent = authenticate_agent(&state, &ctx, &headers, ENDPOINT).await?;
    let req = check_name(&name)
        .and(body)
        .and_then(|OptionalStrictJson(payload)| payload.validate());
    let req = match req {
        Ok(req) => req,
        Err(e) => {
            emit_rejected(&state.events, &ctx, Some(&agent), ENDPOINT, &e);
            return Err(e);
        }
    };

    let mut progress = Progress::default();
    let result = rotate::start(&state, &agent, &ctx, &name, &req, &mut progress).await;
    let event = agent_event(Action::CredentialRotateStart, &ctx, &agent, &name)
        .detail("charset", req.charset.as_str())
        .detail("length", req.length);
    emit_outcome(
        &state,
        event.status(StatusCode::ACCEPTED.as_u16()),
        &progress,
        &result,
    );
    result.map(|started| (StatusCode::ACCEPTED, Json(started)))
}

async fn agent_finish(
    state: Arc<AppState>,
    ctx: RequestContext,
    headers: HeaderMap,
    name: String,
    body: Result<StrictJson<FinishPayload>, FerroError>,
    how: Finish,
) -> FerroResult<Json<Finished>> {
    let (endpoint, action) = match how {
        Finish::Commit => (
            "/v1/credentials/{name}/rotate/commit",
            Action::CredentialRotateCommit,
        ),
        Finish::Abort => (
            "/v1/credentials/{name}/rotate/abort",
            Action::CredentialRotateAbort,
        ),
    };
    let agent = authenticate_agent(&state, &ctx, &headers, endpoint).await?;
    let rotation_id = match check_name(&name)
        .and(body)
        .and_then(|StrictJson(payload)| payload.validate())
    {
        Ok(id) => id,
        Err(e) => {
            emit_rejected(&state.events, &ctx, Some(&agent), endpoint, &e);
            return Err(e);
        }
    };

    let mut progress = Progress::default();
    let result = rotate::finish(
        &state,
        Who::Agent(&agent),
        &name,
        how,
        &rotation_id,
        &mut progress,
    )
    .await;
    let event = agent_event(action, &ctx, &agent, &name).status(200);
    emit_outcome(&state, event, &progress, &result);
    result.map(Json)
}

/// POST /v1/credentials/{name}/rotate/commit
///
/// Make the pending new password the password; the old one goes to the item's
/// password history. The body names the rotation (`{ "rotation_id": ... }`,
/// from the start or the detailed listing): `409 rotation_mismatch` when the
/// pending value is another one. No approval: the start was approved. `409
/// no_rotation_pending` when none is pending; `409 vault_conflict` when
/// someone changed the item in the meantime (nothing is overwritten: read the
/// credential again and retry).
pub async fn rotate_commit(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Result<StrictJson<FinishPayload>, FerroError>,
) -> FerroResult<Json<Finished>> {
    agent_finish(state, ctx, headers, name, body, Finish::Commit).await
}

/// POST /v1/credentials/{name}/rotate/abort
///
/// Throw the pending new password away; the password is unchanged, and the
/// discarded value goes to the item's password history. The body names the
/// rotation, like a commit's. No approval.
pub async fn rotate_abort(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Result<StrictJson<FinishPayload>, FerroError>,
) -> FerroResult<Json<Finished>> {
    agent_finish(state, ctx, headers, name, body, Finish::Abort).await
}

/// Abort the pending rotation `rotation_id` names, of `name`, for an operator
/// (the admin API or the admin UI call this one function). Only the managed
/// collection is checked: an operator is not an agent key. Emits
/// `credential_rotate_abort` with `by` `admin`.
pub async fn admin_abort(
    state: &Arc<AppState>,
    caller: Caller<'_>,
    name: &str,
    rotation_id: &str,
    approver: &str,
) -> FerroResult<Finished> {
    let mut progress = Progress::default();
    let result = match check_name(name) {
        Ok(()) => {
            rotate::finish(
                state,
                Who::Admin,
                name,
                Finish::Abort,
                rotation_id,
                &mut progress,
            )
            .await
        }
        Err(e) => Err(e),
    };
    let event = caller
        .event(Action::CredentialRotateAbort)
        .credentials([name])
        .detail("by", BY_ADMIN)
        .detail_str("approver", approver)
        .duration(caller.ctx.started.elapsed())
        .status(200);
    emit_outcome(state, event, &progress, &result);
    result
}

/// POST /v1/admin/credentials/{name}/rotate/abort
///
/// Clear a stuck rotation: remove the pending new password of a credential in
/// the managed collection (its value goes to the item's password history).
/// Admin auth required; the body names the rotation (`{ "rotation_id": ... }`,
/// from the detailed listing).
pub async fn admin_abort_route(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Result<StrictJson<FinishPayload>, FerroError>,
) -> FerroResult<Json<Value>> {
    const ENDPOINT: &str = "/v1/admin/credentials/{name}/rotate/abort";
    authenticate_admin(&state, &ctx, &headers, ENDPOINT)?;
    let rotation_id = match body.and_then(|StrictJson(payload)| payload.validate()) {
        Ok(id) => id,
        Err(e) => {
            emit_rejected(&state.events, &ctx, None, ENDPOINT, &e);
            return Err(e);
        }
    };
    let caller = Caller {
        ctx: &ctx,
        via: Via::Api,
    };
    admin_abort(
        &state,
        caller,
        &name,
        &rotation_id,
        crate::api::approval_service::API_APPROVER,
    )
    .await?;
    Ok(Json(json!({ "status": "aborted", "name": name })))
}
