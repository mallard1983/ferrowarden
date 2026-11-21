//! Credential cache refresh and lock-state tracking.
//!
//! bw serve keeps a local copy of the vault that is only updated by
//! `POST /sync`, and it can lock or restart independently of ferrowarden.
//! The refresher periodically syncs, reloads the credential cache and keeps
//! ferrowarden's lock state honest. In file unlock mode it also re-unlocks
//! bw serve after a restart by re-reading the password file.

use std::sync::Arc;
use std::time::Duration;

use crate::config::UnlockMode;
use crate::error::{FerroError, FerroResult};
use crate::state::AppState;
use crate::vault::{read_password_file, unlock_vault, VaultClient};

/// Sync bw serve with Vaultwarden and reload the credential cache.
/// A failed sync (e.g. Vaultwarden briefly down) is logged and the cached
/// copy in bw serve is used instead. Marks the state locked if bw serve
/// reports the vault locked.
pub async fn refresh_credentials(state: &AppState) -> FerroResult<()> {
    let vault = VaultClient::new(state.config.bw_serve_url.clone());

    if let Err(e) = vault.sync().await {
        if matches!(e, FerroError::VaultLocked) {
            state.set_locked().await;
            return Err(e);
        }
        tracing::warn!(error = %e, "bw serve sync failed; using its cached vault copy");
    }

    // The first list after a fresh login/unlock can fail transiently while the
    // CLI finishes one-time state migrations (observed once with CLI
    // 2026.11.0 as a 500). Retry once before reporting an error.
    let listed = match vault.list_credentials().await {
        Err(FerroError::Internal(msg)) => {
            tracing::warn!(error = %msg, "Listing vault items failed; retrying once");
            tokio::time::sleep(Duration::from_secs(2)).await;
            vault.list_credentials().await
        }
        other => other,
    };

    match listed {
        Ok(map) => {
            let count = map.len();
            *state.credentials.write().await = map;
            tracing::debug!(credential_count = count, "Credential cache refreshed");
            Ok(())
        }
        Err(e) => {
            if matches!(e, FerroError::VaultLocked) {
                state.set_locked().await;
            }
            Err(e)
        }
    }
}

/// Unlock bw serve using the configured password file (file mode only),
/// then refresh the cache and mark the state unlocked.
pub async fn unlock_from_file(state: &AppState) -> FerroResult<()> {
    let path = state
        .config
        .unlock_file
        .as_ref()
        .ok_or_else(|| FerroError::Config("unlock_file is not set".to_string()))?;
    let password = read_password_file(path)?;
    unlock_vault(&state.config.bw_serve_url, password).await?;
    refresh_credentials(state).await?;
    state.set_unlocked().await;
    Ok(())
}

/// Spawn the periodic refresher. Does nothing when the interval is 0.
pub fn spawn_refresher(state: Arc<AppState>) {
    let secs = state.config.refresh_interval_secs;
    if secs == 0 {
        tracing::info!("Credential refresh disabled (refresh_interval_secs = 0)");
        return;
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(secs));
        ticker.tick().await; // first tick fires immediately; startup already refreshed
        loop {
            ticker.tick().await;
            if state.is_locked().await {
                if state.config.unlock_mode == UnlockMode::File {
                    match unlock_from_file(&state).await {
                        Ok(()) => tracing::info!("Vault re-unlocked from password file"),
                        Err(e) => tracing::warn!(error = %e, "Vault re-unlock failed"),
                    }
                }
                continue;
            }
            match refresh_credentials(&state).await {
                Ok(()) => {}
                Err(FerroError::VaultLocked) => {
                    tracing::warn!("bw serve reports the vault is locked; marking locked");
                    if state.config.unlock_mode == UnlockMode::File {
                        if let Err(e) = unlock_from_file(&state).await {
                            tracing::warn!(error = %e, "Vault re-unlock failed");
                        } else {
                            tracing::info!("Vault re-unlocked from password file");
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "Credential refresh failed"),
            }
        }
    });
}
