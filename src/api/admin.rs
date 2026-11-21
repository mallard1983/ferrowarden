use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::error::{FerroError, FerroResult};
use crate::keys::{hash_token, load, save, StoredKey};
use crate::state::{AgentKey, AppState};

#[derive(Deserialize)]
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
    headers: HeaderMap,
    Json(req): Json<CreateKeyRequest>,
) -> FerroResult<(StatusCode, Json<CreateKeyResponse>)> {
    authenticate_admin(&state, &headers)?;

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

    Ok((
        StatusCode::CREATED,
        Json(CreateKeyResponse {
            id,
            name,
            // Return the raw token once — the caller must store it
            token,
            created_at: now,
        }),
    ))
}

/// GET /v1/admin/keys
///
/// List all agent keys by id and name. Token values are never returned.
/// Admin auth required.
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> FerroResult<Json<Vec<KeySummary>>> {
    authenticate_admin(&state, &headers)?;

    let keys = state.agent_keys.read().await;
    let summaries = keys
        .values()
        .map(|k| KeySummary {
            id: k.id.clone(),
            name: k.name.clone(),
            created_at: k.created_at,
        })
        .collect();

    Ok(Json(summaries))
}

/// DELETE /v1/admin/keys/{id}
///
/// Revoke an agent key by id. Removes from in-memory map and rewrites the
/// key file without the revoked entry. Admin auth required.
pub async fn revoke_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> FerroResult<Json<serde_json::Value>> {
    authenticate_admin(&state, &headers)?;

    let _guard = state.keys_file_lock.lock().await;

    if !state.agent_keys.read().await.values().any(|k| k.id == id) {
        return Err(FerroError::AgentKeyNotFound);
    }

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

    Ok(Json(serde_json::json!({ "status": "revoked", "id": id })))
}

/// GET /v1/admin/audit
///
/// Return recent audit log entries. Admin auth required.
pub async fn get_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> FerroResult<Json<Vec<crate::audit::AuditEntry>>> {
    authenticate_admin(&state, &headers)?;

    let entries = state.audit.recent(100).await;
    Ok(Json(entries))
}

/// GET /v1/admin/status
///
/// Return vault lock state and credential count. Admin auth required.
pub async fn get_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> FerroResult<Json<serde_json::Value>> {
    authenticate_admin(&state, &headers)?;

    let locked = state.is_locked().await;
    let credential_count = state.credentials.read().await.len();
    let key_count = state.agent_keys.read().await.len();

    Ok(Json(serde_json::json!({
        "locked": locked,
        "credential_count": credential_count,
        "agent_key_count": key_count,
    })))
}

/// Check the admin key. Accepts `X-Admin-Key: <key>` (documented) and, for
/// backward compatibility with earlier releases of `/v1/unlock`,
/// `Authorization: Bearer <key>`.
pub(crate) fn authenticate_admin(state: &AppState, headers: &HeaderMap) -> FerroResult<()> {
    let token = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        })
        .ok_or(FerroError::Unauthorized)?;

    if !state.authenticate_admin(token) {
        return Err(FerroError::Unauthorized);
    }

    Ok(())
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
