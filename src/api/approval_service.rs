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
use crate::api::strict_json::StrictJson;
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

/// Deny the pending approval `id`: its credentials are refused for the key
/// and origin for `approval.pending_ttl_secs`. Emits `approval_denied`.
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

/// `POST /v1/admin/approvals/{id}/approve`: `minutes` is required, there is
/// no default and no other field, and the body is a JSON object (serde would
/// also read a struct from an array, which is not what an approval takes).
#[derive(Debug)]
pub struct ApproveRequest {
    pub minutes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveFields {
    minutes: u64,
}

impl<'de> Deserialize<'de> for ApproveRequest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Object;
        impl<'de> serde::de::Visitor<'de> for Object {
            type Value = ApproveFields;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object with `minutes`")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<ApproveFields, A::Error> {
                ApproveFields::deserialize(serde::de::value::MapAccessDeserializer::new(map))
            }
        }
        d.deserialize_map(Object)
            .map(|f| ApproveRequest { minutes: f.minutes })
    }
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
/// Approve a pending approval for `minutes`. Held requests proceed at once;
/// a request retried within the grant passes. Admin auth required.
pub async fn approve_approval(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<StrictJson<ApproveRequest>, FerroError>,
) -> FerroResult<Json<Value>> {
    const ENDPOINT: &str = "/v1/admin/approvals/{id}/approve";
    authenticate_admin(&state, &ctx, &headers, ENDPOINT)?;
    let req = match body {
        Ok(StrictJson(req)) => req,
        Err(e) => {
            emit_rejected(&state.events, &ctx, None, ENDPOINT, &e);
            return Err(e);
        }
    };
    let caller = Caller {
        ctx: &ctx,
        via: Via::Api,
    };
    let minutes = match check_minutes(state.config.approval.max_grant_minutes, req.minutes) {
        Ok(m) => m,
        Err(e) => {
            emit_rejected(&state.events, &ctx, None, ENDPOINT, &e);
            return Err(e);
        }
    };
    let (_, grant) = approve(&state, caller, &id, minutes, API_APPROVER)?;
    Ok(Json(
        json!({ "status": "approved", "grant": grant.to_json() }),
    ))
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
