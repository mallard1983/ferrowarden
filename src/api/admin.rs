use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::api::key_service::{self, AuditFilter, Caller, CreateKeyResponse, KeySummary, Via};
use crate::api::strict_json::StrictJson;
use crate::error::{FerroError, FerroResult};
use crate::events::{emit_rejected, truncate, Action, Outcome, Reason, SecurityEvent};
use crate::middleware::request_context::RequestContext;
use crate::policy::{self, Patch};
use crate::proxy::forward::ProxyRequest;
use crate::state::AppState;
use crate::vault::Vault;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateKeyRequest {
    /// Human-readable name for this agent (e.g. "homelab-claude")
    pub name: String,
    /// Credential name patterns (`*` wildcard). Required: `["*"]` for every
    /// credential, `[]` for none. `null` is rejected.
    #[serde(deserialize_with = "policy::required_credentials")]
    pub credentials: Vec<String>,
    /// Allowed HTTP methods. Required: `["*"]` for all, `[]` for none.
    #[serde(deserialize_with = "policy::required_methods")]
    pub methods: Vec<String>,
}

/// `PATCH /v1/admin/keys/{id}`: a field that is left out is unchanged, one that
/// is present replaces the old value, `null` is rejected.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchKeyRequest {
    #[serde(default, deserialize_with = "policy::patch_credentials")]
    pub credentials: Patch<Vec<String>>,
    #[serde(default, deserialize_with = "policy::patch_methods")]
    pub methods: Patch<Vec<String>>,
}

/// `POST /v1/admin/keys/{id}/preview`
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewRequest {
    /// Draft credential patterns; absent = the saved value.
    #[serde(default, deserialize_with = "policy::patch_credentials")]
    pub credentials: Patch<Vec<String>>,
    /// Draft methods; absent = the saved value.
    #[serde(default, deserialize_with = "policy::patch_methods")]
    pub methods: Patch<Vec<String>>,
    /// A request to check against the draft policy (same shape as `/v1/forward`).
    #[serde(default, deserialize_with = "policy::some_not_null")]
    pub request: Option<ProxyRequest>,
}

/// POST /v1/admin/keys
///
/// Create a new agent API key. Returns the token once — only its SHA-256 hash
/// is stored (in memory and optionally on disk). Admin auth required.
pub async fn create_key(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    body: Result<StrictJson<CreateKeyRequest>, FerroError>,
) -> FerroResult<(StatusCode, Json<CreateKeyResponse>)> {
    const ENDPOINT: &str = "/v1/admin/keys";
    // Authenticate before looking at the body, so an unauthenticated caller
    // learns nothing from parse errors.
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
    let created =
        key_service::create_key(&state, caller, &req.name, req.credentials, req.methods).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

/// GET /v1/admin/keys
///
/// List all agent keys by id, name and policy. Token values are never returned.
/// Admin auth required.
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
) -> FerroResult<Json<Vec<KeySummary>>> {
    authenticate_admin(&state, &ctx, &headers, "/v1/admin/keys")?;
    let caller = Caller {
        ctx: &ctx,
        via: Via::Api,
    };
    Ok(Json(key_service::list_keys(&state, caller).await))
}

/// DELETE /v1/admin/keys/{id}
///
/// Revoke an agent key by id. Removes from in-memory map and rewrites the
/// key file without the revoked entry. Admin auth required.
pub async fn revoke_key(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> FerroResult<Json<serde_json::Value>> {
    authenticate_admin(&state, &ctx, &headers, "/v1/admin/keys/{id}")?;
    let caller = Caller {
        ctx: &ctx,
        via: Via::Api,
    };
    key_service::revoke_key(&state, caller, &id).await?;
    Ok(Json(serde_json::json!({ "status": "revoked", "id": id })))
}

/// PATCH /v1/admin/keys/{id}
///
/// Replace the policy fields that are present in the body; fields left out are
/// unchanged. `null` and an empty body are rejected. Takes effect for the very
/// next request. Admin auth required.
pub async fn patch_key(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<StrictJson<PatchKeyRequest>, FerroError>,
) -> FerroResult<Json<KeySummary>> {
    const ENDPOINT: &str = "/v1/admin/keys/{id}";
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
    let change = key_service::patch_key(&state, caller, &id, req.credentials, req.methods).await?;
    Ok(Json(change.summary))
}

/// POST /v1/admin/keys/{id}/preview
///
/// Show what a draft policy would allow, without saving anything, reading any
/// credential value or sending anything: the credentials it reaches, what it
/// gains and loses against the saved policy, and optionally whether one
/// request would be allowed. Admin auth required.
pub async fn preview_key(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<StrictJson<PreviewRequest>, FerroError>,
) -> FerroResult<Json<serde_json::Value>> {
    const ENDPOINT: &str = "/v1/admin/keys/{id}/preview";
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
    let preview = key_service::preview_key(
        &state,
        caller,
        &id,
        req.credentials,
        req.methods,
        req.request.as_ref(),
    )
    .await?;
    Ok(Json(preview.to_json()))
}

/// Default number of events returned by `GET /v1/admin/audit`.
const DEFAULT_AUDIT_LIMIT: usize = 100;

/// Query parameters of `GET /v1/admin/audit`: only `limit`, at most once, an
/// integer from 1 to the ring buffer size. Unknown or repeated parameters are
/// rejected rather than resolved first-wins or last-wins.
fn parse_limit(params: &[(String, String)], max: usize) -> FerroResult<usize> {
    let mut limit = None;
    for (k, v) in params {
        if k != "limit" {
            return Err(FerroError::InvalidRequest(format!(
                "unknown query parameter {:?}; only `limit` is allowed",
                truncate(k, 64)
            )));
        }
        if limit.replace(v).is_some() {
            return Err(FerroError::InvalidRequest(
                "query parameter `limit` may be given only once".to_string(),
            ));
        }
    }
    match limit {
        None => Ok(DEFAULT_AUDIT_LIMIT.min(max)),
        Some(v) => match v.parse::<usize>() {
            Ok(n) if (1..=max).contains(&n) => Ok(n),
            _ => Err(FerroError::InvalidRequest(format!(
                "`limit` must be an integer from 1 to {max}"
            ))),
        },
    }
}

/// GET /v1/admin/audit
///
/// Return the newest security events (newest first), up to `?limit=` (default
/// 100, at most the ring buffer size). Admin auth required.
pub async fn get_audit(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Query(params): Query<Vec<(String, String)>>,
) -> FerroResult<Json<Vec<serde_json::Value>>> {
    const ENDPOINT: &str = "/v1/admin/audit";
    authenticate_admin(&state, &ctx, &headers, ENDPOINT)?;
    let limit = match parse_limit(&params, state.events.capacity()) {
        Ok(limit) => limit,
        Err(e) => {
            emit_rejected(&state.events, &ctx, None, ENDPOINT, &e);
            return Err(e);
        }
    };

    let caller = Caller {
        ctx: &ctx,
        via: Via::Api,
    };
    let events: Vec<serde_json::Value> =
        key_service::read_audit(&state, caller, limit, &AuditFilter::default())
            .iter()
            .map(|e| serde_json::to_value(&**e))
            .collect::<Result<_, _>>()
            .map_err(|e| FerroError::Internal(e.to_string()))?;
    Ok(Json(events))
}

/// GET /v1/admin/status
///
/// Return vault lock state, the vault backend and the credential count.
/// Admin auth required.
pub async fn get_status(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
) -> FerroResult<Json<serde_json::Value>> {
    authenticate_admin(&state, &ctx, &headers, "/v1/admin/status")?;

    let locked = state.is_locked().await;
    let credential_count = state.credentials.read().await.len();
    let key_count = state.agent_keys.read().await.len();

    state.events.emit(
        SecurityEvent::new(Action::StatusRead)
            .request(&ctx)
            .status(200),
    );

    Ok(Json(serde_json::json!({
        "locked": locked,
        "vault_backend": state.vault.name(),
        "credential_count": credential_count,
        "agent_key_count": key_count,
    })))
}

/// POST /v1/admin/notify/test
///
/// Send one test notification to every enabled sender and report each result.
/// Admin auth required; at most one test every ten seconds.
pub async fn send_test_notification(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
) -> FerroResult<Response> {
    authenticate_admin(&state, &ctx, &headers, "/v1/admin/notify/test")?;
    Ok(match run_notify_test(&state, &ctx, "api").await {
        Ok(results) => Json(serde_json::json!({ "results": results })).into_response(),
        Err(wait) => notify_test_too_soon(wait),
    })
}

/// Send the test notification and record `notify_test`. `Err(seconds)`: one
/// was sent less than ten seconds ago. Shared by the API and the admin UI.
pub(crate) async fn run_notify_test(
    state: &AppState,
    ctx: &RequestContext,
    via: &'static str,
) -> Result<Vec<crate::notify::TestResult>, u64> {
    let results = match state.notify.send_test().await {
        Ok(results) => results,
        Err(wait) => {
            state.events.emit(
                SecurityEvent::new(Action::RateLimited)
                    .request(ctx)
                    .status(StatusCode::TOO_MANY_REQUESTS.as_u16())
                    .detail("limiter", "notify_test"),
            );
            return Err(wait);
        }
    };
    let failed = results.iter().filter(|r| !r.ok).count();
    let mut event = SecurityEvent::new(Action::NotifyTest)
        .request(ctx)
        .status(StatusCode::OK.as_u16())
        .detail("via", via)
        .detail("senders", results.len())
        .detail("failed", failed);
    if failed > 0 {
        event = event
            .outcome(Outcome::Failure)
            .reason(Reason::UpstreamError);
    }
    state.events.emit(event);
    Ok(results)
}

/// The 429 for a second test within ten seconds: the same plain-text answer
/// and `Retry-After` as the rate limiters.
fn notify_test_too_soon(wait: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, wait.max(1).to_string())],
        "Rate limit exceeded. See the Retry-After header.",
    )
        .into_response()
}

/// Check the admin key. Accepts `X-Admin-Key: <key>` (documented) and, for
/// backward compatibility with earlier releases of `/v1/unlock`,
/// `Authorization: Bearer <key>`. A failure is recorded as an `admin_auth`
/// event (reason `missing_admin_key` or `invalid_admin_key`), never with the
/// presented value. `endpoint` is the route template, not the raw path.
pub(crate) fn authenticate_admin(
    state: &AppState,
    ctx: &RequestContext,
    headers: &HeaderMap,
    endpoint: &'static str,
) -> FerroResult<()> {
    // `Some(None)`: a header is present but unusable (not UTF-8, or an
    // Authorization header that is not a Bearer token).
    let presented = headers
        .get("x-admin-key")
        .map(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("authorization")
                .map(|v| v.to_str().ok().and_then(|v| v.strip_prefix("Bearer ")))
        });

    let reason = match presented {
        None => Reason::MissingAdminKey,
        Some(Some(token)) if state.authenticate_admin(token) => return Ok(()),
        Some(_) => Reason::InvalidAdminKey,
    };
    state.events.emit(
        SecurityEvent::new(Action::AdminAuth)
            .request(ctx)
            .reason(reason)
            .status(401)
            .detail("endpoint", endpoint),
    );
    Err(FerroError::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn limit_defaults_to_100_capped_by_the_buffer() {
        assert_eq!(parse_limit(&[], 1000).unwrap(), 100);
        assert_eq!(parse_limit(&[], 50).unwrap(), 50);
    }

    #[test]
    fn limit_accepts_one_to_buffer_size() {
        assert_eq!(parse_limit(&q(&[("limit", "1")]), 1000).unwrap(), 1);
        assert_eq!(parse_limit(&q(&[("limit", "1000")]), 1000).unwrap(), 1000);
        for bad in ["0", "1001", "-1", "abc", "", "1.5", " 5"] {
            assert!(parse_limit(&q(&[("limit", bad)]), 1000).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn limit_rejects_unknown_and_repeated_parameters() {
        assert!(parse_limit(&q(&[("lmit", "5")]), 1000).is_err());
        assert!(parse_limit(&q(&[("limit", "5"), ("x", "1")]), 1000).is_err());
        assert!(parse_limit(&q(&[("limit", "5"), ("limit", "5")]), 1000).is_err());
        assert!(parse_limit(&q(&[("Limit", "5")]), 1000).is_err());
    }
}
