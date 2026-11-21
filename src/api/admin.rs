use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::Utc;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::api::strict_json::StrictJson;
use crate::error::{FerroError, FerroResult};
use crate::events::{emit_rejected, truncate, Action, Reason, SecurityEvent};
use crate::keys::{hash_token, load, save, StoredKey};
use crate::middleware::request_context::RequestContext;
use crate::state::{AgentKey, AppState};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateKeyRequest {
    /// Human-readable name for this agent (e.g. "homelab-claude")
    pub name: String,
}

#[derive(Serialize)]
pub struct CreateKeyResponse {
    pub id: String,
    pub name: String,
    /// The token value — shown only once at creation, never stored in plaintext.
    pub token: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub struct KeySummary {
    pub id: String,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
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

    match create_key_inner(&state, req).await {
        Ok(created) => {
            // The token itself never leaves the response body: only id + name.
            state.events.emit(
                SecurityEvent::new(Action::KeyCreate)
                    .request(&ctx)
                    .status(StatusCode::CREATED.as_u16())
                    .detail("key_id", created.id.as_str())
                    .detail_str("key_name", &created.name),
            );
            Ok((StatusCode::CREATED, Json(created)))
        }
        Err(e) => {
            state.events.emit(
                SecurityEvent::new(Action::KeyCreate)
                    .request(&ctx)
                    .failed_with(&e)
                    .status(e.status_code().as_u16()),
            );
            Err(e)
        }
    }
}

async fn create_key_inner(
    state: &Arc<AppState>,
    req: CreateKeyRequest,
) -> FerroResult<CreateKeyResponse> {
    let id = Uuid::new_v4().to_string();
    let token = generate_token();
    let token_hash = hash_token(&token);
    let now = Utc::now();

    let name = req.name.trim().to_string();
    if name.is_empty() || name.len() > 128 {
        return Err(FerroError::InvalidRequest(
            "name must be 1-128 characters".to_string(),
        ));
    }

    // Serialize key-file updates: without this, two concurrent creates (or a
    // create and a revoke) can each read the old file and drop the other's change.
    let _guard = state.keys_file_lock.lock().await;

    // Persist first. If the write fails, the key is never activated, so the
    // caller is not left with an error response for a token that still works.
    if let Some(ref path) = state.config.keys_file {
        let mut stored = load(path)
            .map_err(|e| FerroError::Internal(format!("Failed to read key file: {e}")))?;
        stored.push(StoredKey {
            id: id.clone(),
            name: name.clone(),
            token_hash: token_hash.clone(),
            created_at: now,
        });
        save(path, &stored)
            .map_err(|e| FerroError::Internal(format!("Failed to write key file: {e}")))?;
    }

    // Insert into in-memory map keyed by hash — plaintext never stored
    state.agent_keys.write().await.insert(
        token_hash,
        AgentKey {
            id: id.clone(),
            name: name.clone(),
            created_at: now,
        },
    );

    tracing::info!(agent_id = %id, agent_name = %name, "Agent key created");

    Ok(CreateKeyResponse {
        id,
        name,
        // Return the raw token once — the caller must store it
        token,
        created_at: now,
    })
}

/// GET /v1/admin/keys
///
/// List all agent keys by id and name. Token values are never returned.
/// Admin auth required.
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
) -> FerroResult<Json<Vec<KeySummary>>> {
    authenticate_admin(&state, &ctx, &headers, "/v1/admin/keys")?;

    let keys = state.agent_keys.read().await;
    let summaries: Vec<KeySummary> = keys
        .values()
        .map(|k| KeySummary {
            id: k.id.clone(),
            name: k.name.clone(),
            created_at: k.created_at,
        })
        .collect();

    state.events.emit(
        SecurityEvent::new(Action::KeyList)
            .request(&ctx)
            .status(200)
            .detail("count", summaries.len()),
    );
    Ok(Json(summaries))
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

    match revoke_key_inner(&state, &id).await {
        Ok(name) => {
            state.events.emit(
                SecurityEvent::new(Action::KeyRevoke)
                    .request(&ctx)
                    .status(200)
                    .detail_str("key_id", &id)
                    .detail_str("key_name", &name),
            );
            Ok(Json(serde_json::json!({ "status": "revoked", "id": id })))
        }
        Err(e) => {
            state.events.emit(
                SecurityEvent::new(Action::KeyRevoke)
                    .request(&ctx)
                    // AgentKeyNotFound maps to reason `key_not_found`.
                    .failed_with(&e)
                    .status(e.status_code().as_u16())
                    .detail_str("key_id", &id),
            );
            Err(e)
        }
    }
}

/// Revoke the key; returns its name.
async fn revoke_key_inner(state: &Arc<AppState>, id: &str) -> FerroResult<String> {
    let _guard = state.keys_file_lock.lock().await;

    let name = state
        .agent_keys
        .read()
        .await
        .values()
        .find(|k| k.id == id)
        .map(|k| k.name.clone())
        .ok_or(FerroError::AgentKeyNotFound)?;

    // Rewrite the key file without the revoked entry first, so a failed write
    // is reported before the in-memory state diverges from disk.
    if let Some(ref path) = state.config.keys_file {
        let stored = load(path)
            .map_err(|e| FerroError::Internal(format!("Failed to read key file: {e}")))?;
        let remaining: Vec<_> = stored.into_iter().filter(|k| k.id != id).collect();
        save(path, &remaining)
            .map_err(|e| FerroError::Internal(format!("Failed to write key file: {e}")))?;
    }

    // Revoke in memory — takes effect for the very next request.
    state.agent_keys.write().await.retain(|_, k| k.id != id);

    tracing::info!(agent_id = %id, "Agent key revoked");

    Ok(name)
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

    let events: Vec<serde_json::Value> = state
        .events
        .recent(limit)
        .iter()
        .map(|e| serde_json::to_value(&**e))
        .collect::<Result<_, _>>()
        .map_err(|e| FerroError::Internal(e.to_string()))?;

    // Emitted after the snapshot, so a read does not list itself.
    state.events.emit(
        SecurityEvent::new(Action::AuditRead)
            .request(&ctx)
            .status(200)
            .detail("limit", limit)
            .detail("count", events.len()),
    );
    Ok(Json(events))
}

/// GET /v1/admin/status
///
/// Return vault lock state and credential count. Admin auth required.
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
        "credential_count": credential_count,
        "agent_key_count": key_count,
    })))
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

/// Generate a cryptographically random 48-character alphanumeric token.
fn generate_token() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..48)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
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
