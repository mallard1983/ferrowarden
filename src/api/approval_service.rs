//! Deciding approvals: approve, deny, and end a grant early.
//!
//! The admin API handlers below and the admin web UI call the same three
//! functions, so validation, the one-decision-wins rule and the events behave
//! identically whichever door the operator came through. They are the **only**
//! code that decides, and no agent route reaches them: the agent API has no
//! decision route, the admin routes need the admin key (which an agent key is
//! not), and the UI needs a signed-in session and a recent sign-in.
//!
//! Nothing here reads a credential value. Events carry the key, the
//! credential names, the host, the approver and the ids.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use chrono::{SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

use crate::api::admin::authenticate_admin;
use crate::api::key_service::{Caller, Via};
use crate::api::strict_json::OptionalStrictJson;
use crate::approvals::{self, GrantView, PendingView};
use crate::error::{FerroError, FerroResult};
use crate::events::{emit_rejected, Action};
use crate::middleware::request_context::RequestContext;
use crate::state::AppState;

/// The approver recorded for a decision made with the admin key.
pub const API_APPROVER: &str = "admin_api";

fn rfc3339(t: chrono::DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Check the length of a grant: 1 to `max` (`approval.max_grant_minutes`)
/// minutes.
pub fn check_minutes(max: u32, minutes: u64) -> FerroResult<u32> {
    match u32::try_from(minutes) {
        Ok(m) if (1..=max).contains(&m) => Ok(m),
        _ => Err(FerroError::InvalidRequest(format!(
            "`minutes` must be a whole number from 1 to {max}"
        ))),
    }
}

// ── The decisions ─────────────────────────────────────────────────────────────

/// Approve the pending approval `id` for `minutes` (already checked with
/// [`check_minutes`]). Creates the grant, wakes the held requests and emits
/// `approval_granted`. A second decision on the same approval is
/// [`FerroError::ApprovalNotPending`] and changes nothing.
pub fn approve(
    state: &AppState,
    caller: Caller<'_>,
    id: &str,
    minutes: u32,
    approver: &str,
) -> FerroResult<(PendingView, GrantView)> {
    let result = approve_inner(state, id, minutes, approver);
    match &result {
        Ok((pending, grant)) => state.events.emit(
            caller
                .event(Action::ApprovalGranted)
                .status(200)
                .key_named(&pending.key_id, &pending.key_name)
                .credentials(pending.item_names())
                .detail("kind", pending.kind.as_str())
                .detail("approval_id", pending.id.as_str())
                .detail("grant_id", grant.id.as_str())
                .detail("host", pending.host.as_str())
                .detail_str("approver", approver)
                .detail("minutes", minutes)
                .detail("grant_expires_at", rfc3339(grant.expires)),
        ),
        Err(e) => state.events.emit(
            caller
                .event(Action::ApprovalGranted)
                .failed_with(e)
                .status(e.status_code().as_u16())
                .detail_str("approver", approver),
        ),
    }
    result
}

fn approve_inner(
    state: &AppState,
    id: &str,
    minutes: u32,
    approver: &str,
) -> FerroResult<(PendingView, GrantView)> {
    if !approvals::valid_id(id) {
        return Err(FerroError::ApprovalNotPending);
    }
    let grant_id = approvals::new_id()
        .ok_or_else(|| FerroError::Internal("no random id for a grant".to_string()))?;
    state
        .approvals
        .approve(id, grant_id, minutes, approver, Utc::now())
        .map_err(|_| FerroError::ApprovalNotPending)
}

/// Approve the pending **create** or **rotate** approval `id`: exactly one
/// operation, the one it was opened for, may proceed. There is no duration and no grant: the
/// approval is used up by the first request that matches it (the held one, or
/// a retry within `approval.pending_ttl_secs`). Wakes the held requests and
/// emits `approval_granted` with `kind` `create` or `rotate`.
pub fn approve_create(
    state: &AppState,
    caller: Caller<'_>,
    id: &str,
    approver: &str,
) -> FerroResult<PendingView> {
    let ttl = Duration::from_secs(state.config.approval.pending_ttl_secs);
    let result = if approvals::valid_id(id) {
        state
            .approvals
            .approve_create(id, ttl, Utc::now())
            .map_err(|_| FerroError::ApprovalNotPending)
    } else {
        Err(FerroError::ApprovalNotPending)
    };
    match &result {
        Ok(pending) => state.events.emit(
            caller
                .event(Action::ApprovalGranted)
                .status(200)
                .key_named(&pending.key_id, &pending.key_name)
                .credentials(pending.item_names())
                .detail("kind", pending.kind.as_str())
                .detail("approval_id", pending.id.as_str())
                .detail_str("approver", approver),
        ),
        Err(e) => state.events.emit(
            caller
                .event(Action::ApprovalGranted)
                .failed_with(e)
                .status(e.status_code().as_u16())
                .detail_str("approver", approver),
        ),
    }
    result
}

/// Deny the pending approval `id`: its credentials are refused for the key
/// and origin for `approval.pending_ttl_secs` (a create: that one operation).
/// Emits `approval_denied`.
pub fn deny(
    state: &AppState,
    caller: Caller<'_>,
    id: &str,
    approver: &str,
) -> FerroResult<PendingView> {
    let ttl = Duration::from_secs(state.config.approval.pending_ttl_secs);
    let result = if approvals::valid_id(id) {
        state
            .approvals
            .deny(id, ttl, Utc::now())
            .map_err(|_| FerroError::ApprovalNotPending)
    } else {
        Err(FerroError::ApprovalNotPending)
    };
    match &result {
        Ok(pending) => state.events.emit(
            caller
                .event(Action::ApprovalDenied)
                .status(200)
                .key_named(&pending.key_id, &pending.key_name)
                .credentials(pending.item_names())
                .detail("kind", pending.kind.as_str())
                .detail("approval_id", pending.id.as_str())
                .detail("host", pending.host.as_str())
                .detail_str("approver", approver),
        ),
        Err(e) => state.events.emit(
            caller
                .event(Action::ApprovalDenied)
                .failed_with(e)
                .status(e.status_code().as_u16())
                .detail_str("approver", approver),
        ),
    }
    result
}

/// End a live grant early. Emits `grant_revoked`. The next request that needs
/// the credential asks again.
pub fn revoke_grant(
    state: &AppState,
    caller: Caller<'_>,
    id: &str,
    approver: &str,
) -> FerroResult<GrantView> {
    let result = if approvals::valid_id(id) {
        state
            .approvals
            .revoke_grant(id, Utc::now())
            .map_err(|_| FerroError::GrantNotFound)
    } else {
        Err(FerroError::GrantNotFound)
    };
    match &result {
        Ok(grant) => state.events.emit(
            caller
                .event(Action::GrantRevoked)
                .status(200)
                .key_named(&grant.key_id, &grant.key_name)
                .credentials(&grant.items)
                .detail("grant_id", grant.id.as_str())
                .detail("approval_id", grant.approval_id.as_str())
                .detail("host", grant.host.as_str())
                .detail_str("approver", approver),
        ),
        Err(e) => state.events.emit(
            caller
                .event(Action::GrantRevoked)
                .failed_with(e)
                .status(e.status_code().as_u16())
                .detail_str("approver", approver),
        ),
    }
    result
}

// ── The admin API ─────────────────────────────────────────────────────────────

/// The body of `POST /v1/admin/approvals/{id}/approve`: a JSON object, or no
/// body. `minutes` is required to approve a **forward** (it is the length of
/// the grant) and refused for a **create** or **rotate**, which allow one
/// operation once and have no duration. `null` is refused, like everywhere in
/// the API.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveBody {
    #[serde(default, deserialize_with = "crate::policy::some_not_null")]
    pub minutes: Option<u64>,
}

/// GET /v1/admin/approvals
///
/// The pending approvals and the live grants. Admin auth required.
pub async fn list_approvals(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
) -> FerroResult<Json<Value>> {
    authenticate_admin(&state, &ctx, &headers, "/v1/admin/approvals")?;
    let (pending, grants) = state.approvals.list(Utc::now());
    Ok(Json(json!({
        "pending": pending.iter().map(PendingView::to_json).collect::<Vec<_>>(),
        "grants": grants.iter().map(GrantView::to_json).collect::<Vec<_>>(),
    })))
}

/// POST /v1/admin/approvals/{id}/approve
///
/// Approve a pending approval. The body depends on its `kind`:
///
/// * `forward`: `{ "minutes": N }`. Creates a grant for `minutes`; held
///   requests proceed at once, and a request retried within the grant passes.
///   The answer is `{ "status": "approved", "kind": "forward", "grant": {...} }`.
/// * `create` and `rotate`: **no body** (an empty body or `{}`). Allows
///   exactly one operation, once; there is no duration, and a `minutes` is
///   refused (`400`). The answer is `{ "status": "approved", "kind": "create" }`
///   (or `"rotate"`).
///
/// Admin auth required.
pub async fn approve_approval(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<OptionalStrictJson<ApproveBody>, FerroError>,
) -> FerroResult<Json<Value>> {
    const ENDPOINT: &str = "/v1/admin/approvals/{id}/approve";
    authenticate_admin(&state, &ctx, &headers, ENDPOINT)?;
    let caller = Caller {
        ctx: &ctx,
        via: Via::Api,
    };
    // The kind decides what the body may be. An approval that is not open
    // takes the ordinary 409 path below, whatever was sent.
    let kind = if approvals::valid_id(&id) {
        state.approvals.kind_of(&id, Utc::now())
    } else {
        None
    };
    let reject = |e: FerroError| {
        emit_rejected(&state.events, &ctx, None, ENDPOINT, &e);
        e
    };
    let OptionalStrictJson(body) = body.map_err(reject)?;
    match kind {
        Some(one_shot @ (approvals::ApprovalKind::Create | approvals::ApprovalKind::Rotate)) => {
            if body.minutes.is_some() {
                return Err(reject(FerroError::InvalidRequest(format!(
                    "an approval to {} a credential has no duration: send no body, or {{}}",
                    one_shot.as_str()
                ))));
            }
            approve_create(&state, caller, &id, API_APPROVER)?;
            Ok(Json(
                json!({ "status": "approved", "kind": one_shot.as_str() }),
            ))
        }
        Some(approvals::ApprovalKind::Forward) | None => {
            let minutes = if kind.is_some() {
                let minutes = body.minutes.ok_or_else(|| {
                    reject(FerroError::InvalidRequest(
                        "`minutes` is required to approve a forward".to_string(),
                    ))
                })?;
                check_minutes(state.config.approval.max_grant_minutes, minutes).map_err(reject)?
            } else {
                // Not open: the decision fails as not pending.
                1
            };
            let (_, grant) = approve(&state, caller, &id, minutes, API_APPROVER)?;
            Ok(Json(json!({
                "status": "approved",
                "kind": "forward",
                "grant": grant.to_json(),
            })))
        }
    }
}

/// POST /v1/admin/approvals/{id}/deny
///
/// Deny a pending approval. Held requests are answered `approval_denied`, and
/// so is a retry for `approval.pending_ttl_secs`. Admin auth required.
pub async fn deny_approval(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> FerroResult<Json<Value>> {
    authenticate_admin(&state, &ctx, &headers, "/v1/admin/approvals/{id}/deny")?;
    let caller = Caller {
        ctx: &ctx,
        via: Via::Api,
    };
    deny(&state, caller, &id, API_APPROVER)?;
    Ok(Json(json!({ "status": "denied", "id": id })))
}

/// DELETE /v1/admin/grants/{id}
///
/// End a grant early. Admin auth required.
pub async fn revoke_grant_route(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> FerroResult<Json<Value>> {
    authenticate_admin(&state, &ctx, &headers, "/v1/admin/grants/{id}")?;
    let caller = Caller {
        ctx: &ctx,
        via: Via::Api,
    };
    revoke_grant(&state, caller, &id, API_APPROVER)?;
    Ok(Json(json!({ "status": "revoked", "id": id })))
}

#[cfg(test)]
mod tests;
