use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::api::admin::authenticate_admin;
use crate::config::UnlockMode;
use crate::error::{FerroError, FerroResult};
use crate::state::AppState;
use crate::vault::refresh::refresh_credentials;
use crate::vault::unlock_vault;

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
    // Wrap the password in Zeroizing immediately so it's wiped even if we
    // return early due to an error
    let password = Zeroizing::new(payload.password);

    // Only the admin can call this endpoint
    authenticate_admin(&state, &headers)?;

    // Endpoint disabled in file mode
    if state.config.unlock_mode == UnlockMode::File {
        return Err(FerroError::UnlockEndpointDisabled);
    }

    unlock_vault(&state.config.bw_serve_url, password).await?;

    // Sync and refresh the credential cache now that the vault is unlocked
    refresh_credentials(&state).await?;

    state.set_unlocked().await;

    tracing::info!("Vault unlocked via manual endpoint");

    Ok(Json(serde_json::json!({ "status": "unlocked" })))
}
