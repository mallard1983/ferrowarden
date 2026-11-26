use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::api::admin::authenticate_admin;
use crate::api::strict_json::StrictJson;
use crate::config::UnlockMode;
use crate::error::{FerroError, FerroResult};
use crate::events::{emit_rejected, Action, Outcome, Reason, SecurityEvent};
use crate::middleware::request_context::RequestContext;
use crate::state::AppState;
use crate::vault::refresh::refresh_credentials;
use crate::vault::Vault;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlockPayload {
    /// The vault master password. Consumed and zeroed immediately after use.
    pub password: String,
}

/// POST /v1/unlock
///
/// Manual unlock mode only. The operator POSTs the master password once after
/// boot. The password is zeroed immediately after the vault confirms unlock.
/// Returns 404 in file unlock mode — the endpoint does not exist.
pub async fn unlock(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    body: Result<StrictJson<UnlockPayload>, FerroError>,
) -> FerroResult<Json<serde_json::Value>> {
    const ENDPOINT: &str = "/v1/unlock";

    // Wrap the password in Zeroizing immediately so it's wiped even if we
    // return early (including when authentication fails below).
    let body = body.map(|StrictJson(payload)| Zeroizing::new(payload.password));

    // Only the admin can call this endpoint — and only after that is the body
    // looked at, so an unauthenticated caller learns nothing from parse errors.
    authenticate_admin(&state, &ctx, &headers, ENDPOINT)?;
    let password = match body {
        Ok(password) => password,
        Err(e) => {
            emit_rejected(&state.events, &ctx, None, ENDPOINT, &e);
            return Err(e);
        }
    };

    let event = SecurityEvent::new(Action::VaultUnlock)
        .request(&ctx)
        .detail("mode", "manual");

    // Endpoint disabled in file mode
    if state.config.unlock_mode == UnlockMode::File {
        let e = FerroError::UnlockEndpointDisabled;
        state
            .events
            .emit(event.failed_with(&e).status(e.status_code().as_u16()));
        return Err(e);
    }

    let result = async {
        state.vault.unlock(password).await?;
        // Sync and refresh the credential cache now that the vault is unlocked
        refresh_credentials(&state).await
    }
    .await;

    match result {
        Ok(()) => {
            state.set_unlocked().await;
            tracing::info!("Vault unlocked via manual endpoint");
            state.events.emit(event.status(200));
            Ok(Json(serde_json::json!({ "status": "unlocked" })))
        }
        Err(e) => {
            state.events.emit(
                event
                    .outcome(Outcome::Failure)
                    .reason(Reason::UnlockFailed)
                    .status(e.status_code().as_u16()),
            );
            Err(e)
        }
    }
}
