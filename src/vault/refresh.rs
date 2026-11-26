//! Credential cache refresh and lock-state tracking.
//!
//! The native backend holds its own copy of the vault and locks itself when
//! the account's key changes. The refresher periodically syncs, reloads the
//! credential cache and keeps ferrowarden's lock state honest. In file unlock
//! mode it also re-unlocks the vault after it was locked by re-reading the
//! password file.

use std::sync::Arc;
use std::time::Duration;

use crate::config::UnlockMode;
use crate::error::{FerroError, FerroResult};
use crate::events::{Action, Outcome, Reason, SecurityEvent};
use crate::state::AppState;
use crate::vault::{read_password_file, Vault};

/// Sync the vault backend with Vaultwarden and reload the credential cache.
/// A failed sync (e.g. Vaultwarden briefly down) is logged and the backend's
/// cached copy is used instead. Marks the state locked if the backend reports
/// the vault locked.
///
/// Emits `vault_sync`: always on failure, and on success when the credential
/// count changed or the sync left items out (the native backend, with counts
/// by reason).
pub async fn refresh_credentials(state: &AppState) -> FerroResult<()> {
    let vault = &*state.vault;

    let mut synced = true;
    if let Err(e) = vault.sync().await {
        if matches!(e, FerroError::VaultLocked) {
            state.set_locked(vault.lock_cause()).await;
            return Err(e);
        }
        synced = false;
        tracing::warn!(error = %e, backend = vault.name(), "Vault sync failed; using the cached vault copy");
        emit_sync_failed(state, "sync");
    }

    let listed = vault.list_credentials().await;

    match listed {
        Ok(listing) => {
            // "Last successful sync" for the metrics: the sync and the listing
            // both worked, so the cache is as fresh as the server.
            if synced {
                state.sync_stats.record_success(listing.excluded_count);
            }
            let map = listing.map;
            let count = map.len();
            let previous = std::mem::replace(&mut *state.credentials.write().await, map).len();
            tracing::debug!(credential_count = count, "Credential cache refreshed");
            let excluded = listing.excluded.filter(|r| !r.is_empty());
            if count != previous || excluded.is_some() {
                let mut event = SecurityEvent::new(Action::VaultSync)
                    .detail("credential_count", count)
                    .detail("previous", previous);
                if let Some(report) = &excluded {
                    // Counts by reason and the (random) ids of the items; never
                    // names or values.
                    tracing::warn!(
                        excluded = report.total(),
                        "Vault items were left out (not readable safely, or their collection hides the password)"
                    );
                    event = event
                        .detail("excluded", report.total())
                        .detail("excluded_reasons", serde_json::json!(report.counts))
                        .detail("excluded_ids", serde_json::json!(report.ids));
                }
                state.events.emit(event);
            }
            Ok(())
        }
        Err(e) => {
            if matches!(e, FerroError::VaultLocked) {
                state.set_locked(vault.lock_cause()).await;
            } else {
                emit_sync_failed(state, "list");
            }
            Err(e)
        }
    }
}

fn emit_sync_failed(state: &AppState, stage: &'static str) {
    state.events.emit(
        SecurityEvent::new(Action::VaultSync)
            .outcome(Outcome::Failure)
            .reason(Reason::SyncFailed)
            .detail("stage", stage),
    );
}

/// Unlock the vault using the configured password file (file mode only),
/// then refresh the cache and mark the state unlocked. Emits `vault_unlock`
/// with the given `mode` (`"file"` at startup, `"reunlock"` afterwards).
pub async fn unlock_from_file(state: &AppState, mode: &'static str) -> FerroResult<()> {
    let result = unlock_from_file_inner(state).await;
    let event = SecurityEvent::new(Action::VaultUnlock).detail("mode", mode);
    state.events.emit(match &result {
        Ok(()) => event,
        Err(_) => event.outcome(Outcome::Failure).reason(Reason::UnlockFailed),
    });
    result
}

async fn unlock_from_file_inner(state: &AppState) -> FerroResult<()> {
    let path = state
        .config
        .unlock_file
        .as_ref()
        .ok_or_else(|| FerroError::Config("unlock_file is not set".to_string()))?;
    let password = read_password_file(path)?;
    state.vault.unlock(password).await?;
    refresh_credentials(state).await?;
    state.set_unlocked().await;
    Ok(())
}

/// File mode only: unlock the vault again right away, instead of waiting for
/// the next refresh — e.g. when a request finds the vault locked. Attempts
/// are serialized, and a caller that waited while another task re-unlocked
/// simply sees the vault unlocked. Returns true when the vault is unlocked
/// afterwards.
pub async fn reunlock_if_possible(state: &AppState) -> bool {
    if state.config.unlock_mode != UnlockMode::File {
        return false;
    }
    let _guard = state.unlock_lock.lock().await;
    if !state.is_locked().await {
        return true;
    }
    match unlock_from_file(state, "reunlock").await {
        Ok(()) => {
            tracing::info!("Vault re-unlocked from password file");
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, "Vault re-unlock failed");
            false
        }
    }
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
                reunlock_if_possible(&state).await;
                continue;
            }
            match refresh_credentials(&state).await {
                Ok(()) => {}
                Err(FerroError::VaultLocked) => {
                    tracing::warn!(
                        backend = state.vault.name(),
                        "The vault is locked; marking it locked"
                    );
                    reunlock_if_possible(&state).await;
                }
                Err(e) => tracing::warn!(error = %e, "Credential refresh failed"),
            }
        }
    });
}
