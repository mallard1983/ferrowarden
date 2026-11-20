use axum::{extract::{Path, State}, http::HeaderMap, Json};
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{FerroError, FerroResult};
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
    /// The token value — shown only once at creation, never again.
    pub token: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub struct KeySummary {
    pub id: String,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub struct AuditResponse {
    pub entries: Vec<crate::audit::AuditEntry>,
}

/// POST /v1/admin/keys
///
/// Create a new agent API key. Returns the token once — it is not stored in
/// plaintext and cannot be retrieved again. Admin auth required.
pub async fn create_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateKeyRequest>,
) -> FerroResult<Json<CreateKeyResponse>> {
    authenticate_admin(&state, &headers)?;

    let id = Uuid::new_v4().to_string();
    let token = generate_token();
    let now = Utc::now();

    let key = AgentKey {
        id: id.clone(),
        name: req.name.clone(),
        token: Zeroizing::new(token.clone()),
        created_at: now,
    };

    state.agent_keys.write().await.insert(token.clone(), key);

    tracing::info!(agent_id = %id, agent_name = %req.name, "Agent key created");

    Ok(Json(CreateKeyResponse {
        id,
        name: req.name,
        // Return the raw token once — the caller must store it
        token,
        created_at: now,
    }))
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

/// DELETE /v1/admin/keys/:id
///
/// Revoke an agent key by id. The Zeroizing token is wiped from memory on
/// removal from the HashMap. Admin auth required.
pub async fn revoke_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> FerroResult<Json<serde_json::Value>> {
    authenticate_admin(&state, &headers)?;

    let mut keys = state.agent_keys.write().await;

    // Find the key by id (the HashMap is keyed by token for O(1) auth lookup)
    let token = keys
        .iter()
        .find(|(_, k)| k.id == id)
        .map(|(t, _)| t.clone())
        .ok_or(FerroError::AgentKeyNotFound)?;

    // Removing from the HashMap drops the AgentKey — Zeroizing token is wiped
    keys.remove(&token);

    tracing::info!(agent_id = %id, "Agent key revoked");

    Ok(Json(serde_json::json!({ "status": "revoked", "id": id })))
}

/// GET /v1/admin/audit
///
/// Return recent audit log entries. Admin auth required.
pub async fn get_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> FerroResult<Json<AuditResponse>> {
    authenticate_admin(&state, &headers)?;

    let entries = state.audit.recent(100).await;
    Ok(Json(AuditResponse { entries }))
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
    let credential_count = state.credential_names.read().await.len();
    let key_count = state.agent_keys.read().await.len();

    Ok(Json(serde_json::json!({
        "vault_locked": locked,
        "credential_count": credential_count,
        "agent_key_count": key_count,
    })))
}

fn authenticate_admin(state: &Arc<AppState>, headers: &HeaderMap) -> FerroResult<()> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
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
