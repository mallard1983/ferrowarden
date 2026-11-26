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
use crate::vault::model::ManagedState;
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
            // Items whose `ferrowarden_approval` value is not `required`
            // still need approval (fail closed). A warning, reported when the
            // number changes, so the operator can fix the spelling.
            let approval_invalid = map
                .values()
                .flatten()
                .filter(|e| e.approval_field_invalid)
                .count();
            let warn_approval = state.sync_stats.swap_approval_invalid(approval_invalid)
                != approval_invalid as u64
                && approval_invalid > 0;
            let previous = std::mem::replace(&mut *state.credentials.write().await, map).len();
            report_managed(state).await;
            tracing::debug!(credential_count = count, "Credential cache refreshed");
            let excluded = listing.excluded.filter(|r| !r.is_empty());
            if count != previous || excluded.is_some() || warn_approval {
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
                if warn_approval {
                    tracing::warn!(
                        items = approval_invalid,
                        "Vault items have a ferrowarden_approval field whose value is not \"required\"; they still need approval"
                    );
                    event = event.detail(
                        "warnings",
                        serde_json::json!({ "approval_field_invalid": approval_invalid }),
                    );
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

/// Where the managed collection stands after this sync. When it has become
/// unusable (or its problem changed) say so once: a log line and a `vault_sync`
/// event with a warning, so the operator hears about it before an agent's
/// create request is refused. Creating never falls back to anything else.
async fn report_managed(state: &AppState) {
    let problem = match state.vault.managed_collection().await {
        Ok(ManagedState::Unavailable { problem, .. }) => Some(problem),
        Ok(_) => None,
        // Locked: nothing to say about it.
        Err(_) => return,
    };
    let previous = state
        .sync_stats
        .swap_managed_problem(problem.map(|p| p.code()));
    match problem {
        Some(p) if previous != Some(p.code()) => {
            tracing::warn!(
                reason = p.code(),
                "The managed collection cannot be written to: {}; creating credentials is refused until it is fixed",
                p.describe()
            );
            state
                .events
                .emit(SecurityEvent::new(Action::VaultSync).detail(
                    "warnings",
                    serde_json::json!({ "managed_collection": p.code() }),
                ));
        }
        None if previous.is_some() => {
            tracing::info!("The managed collection can be written to again");
        }
        _ => {}
    }
}

/// The startup rule for the managed collection: when one is configured, it
/// has to be usable, or Ferrowarden does not start (fail closed). `Ok` when
/// none is configured.
pub fn check_managed_at_startup(managed: &ManagedState) -> Result<(), String> {
    match managed {
        ManagedState::Off | ManagedState::Usable(_) => Ok(()),
        ManagedState::Unavailable { problem, .. } => Err(format!(
            "vault.managed.collection is set, but {}. Fix the collection or the account's access              to it in Vaultwarden, or unset vault.managed.collection to switch creating off",
            problem.describe()
        )),
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

#[cfg(test)]
mod tests;
