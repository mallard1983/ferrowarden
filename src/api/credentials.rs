use axum::{extract::State, http::HeaderMap, Json};
use std::sync::Arc;

use crate::error::{FerroError, FerroResult};
use crate::state::AppState;

/// GET /v1/credentials
///
/// Returns the list of credential names available in the vault.
/// Names only — values are never returned through this endpoint.
/// Requires a valid agent key in the X-Agent-Key header.
pub async fn list_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> FerroResult<Json<Vec<String>>> {
    authenticate_agent(&state, &headers).await?;

    // In file mode, try to unlock again right away (e.g. after a bw serve
    // restart) instead of failing until the next refresh.
    if state.is_locked().await && !crate::vault::refresh::reunlock_if_possible(&state).await {
        return Err(FerroError::VaultLocked);
    }

    // BTreeMap keys: sorted, de-duplicated names. Values (ids, URIs) are not exposed.
    let names = state.credentials.read().await.keys().cloned().collect();

    Ok(Json(names))
}

/// Extract and validate the agent key from the X-Agent-Key header.
pub async fn authenticate_agent(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> FerroResult<crate::state::AgentKey> {
    let token = headers
        .get("x-agent-key")
        .and_then(|v| v.to_str().ok())
        .ok_or(FerroError::Unauthorized)?;

    state
        .authenticate(token)
        .await
        .ok_or(FerroError::Unauthorized)
}
