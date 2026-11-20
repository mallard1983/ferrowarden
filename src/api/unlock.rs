use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::config::UnlockMode;
use crate::error::{FerroError, FerroResult};
use crate::state::AppState;
use crate::vault::{unlock_vault, VaultClient};

#[derive(Deserialize)]
pub struct UnlockPayload {
    /// The vault master password. Consumed and zeroed immediately after use.
    pub password: String,
}

/// POST /v1/unlock
///
/// Manual unlock mode only. The operator POSTs the master password once after
/// boot. The password is zeroed immediately after bw serve confirms unlock.
/// Returns 404 in file unlock mode — the endpoint does not exist.
pub async fn unlock(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<UnlockPayload>,
) -> FerroResult<Json<serde_json::Value>> {
    // Only the admin can call this endpoint
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(FerroError::Unauthorized)?;

    if !state.authenticate_admin(token) {
        return Err(FerroError::Unauthorized);
    }

    // Endpoint disabled in file mode
    if state.config.unlock_mode == UnlockMode::File {
        return Err(FerroError::UnlockEndpointDisabled);
    }

    // Wrap the password in Zeroizing immediately so it's wiped even if we
    // return early due to an error
    let password = Zeroizing::new(payload.password);

    unlock_vault(&state.config.bw_serve_url, password).await?;

    // Refresh credential name cache now that the vault is unlocked
    let vault = VaultClient::new(state.config.bw_serve_url.clone());
    let names = vault.list_item_names().await?;
    *state.credential_names.write().await = names;

    state.set_unlocked().await;

    tracing::info!("Vault unlocked via manual endpoint");

    Ok(Json(serde_json::json!({ "status": "unlocked" })))
}
