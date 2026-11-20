use axum::{extract::State, http::HeaderMap, Json};
use serde::Serialize;
use std::sync::Arc;

use crate::error::{FerroError, FerroResult};
use crate::state::AppState;

#[derive(Serialize)]
pub struct CredentialsResponse {
    pub credentials: Vec<String>,
}

/// GET /v1/credentials
///
/// Returns the list of credential names available in the vault.
/// Names only — values are never returned through this endpoint.
/// Requires a valid agent bearer token.
pub async fn list_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> FerroResult<Json<CredentialsResponse>> {
    authenticate_agent(&state, &headers).await?;

    if state.is_locked().await {
        return Err(FerroError::VaultLocked);
    }

    let names = state.credential_names.read().await.clone();

    Ok(Json(CredentialsResponse { credentials: names }))
}

/// Extract and validate the bearer token from the Authorization header.
pub async fn authenticate_agent(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> FerroResult<crate::state::AgentKey> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(FerroError::Unauthorized)?;

    state
        .authenticate(token)
        .await
        .ok_or(FerroError::Unauthorized)
}
