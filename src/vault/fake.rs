//! An in-memory [`Vault`] for unit tests: the stand-in for a Vaultwarden
//! that tests which only need an `AppState` do not want to run.
//!
//! Compiled for `cargo test` only (`#[cfg(test)]` in `vault/mod.rs`) and not
//! reachable from configuration: `vault.backend` has one value, `native`,
//! and [`super::ActiveVault::from_config`] never builds this. A release
//! binary cannot contain it.
//!
//! It holds no secrets. It reports the account email it was given (and a
//! fixed last-sync time) as its status, counts those lookups, and fails every value read, so a test that
//! reaches for a credential value without arranging one fails loudly.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use zeroize::Zeroizing;

use super::model::{Builtin, Listing, VaultStatus};
use super::Vault;
use crate::error::{FerroError, FerroResult};

/// The last-sync time the fake reports for a signed-in account.
pub const LAST_SYNC: &str = "2026-11-21T10:00:00Z";

#[derive(Default)]
pub struct FakeVault {
    /// The logged-in account; `None` reports the vault as unauthenticated.
    email: Mutex<Option<String>>,
    status_calls: AtomicUsize,
}

impl FakeVault {
    /// Make `status` report this account (or none).
    pub fn set_email(&self, email: Option<&str>) {
        *self.email.lock().unwrap() = email.map(str::to_string);
    }

    /// How many times `status` was asked for.
    pub fn status_calls(&self) -> usize {
        self.status_calls.load(Ordering::SeqCst)
    }
}

impl Vault for FakeVault {
    fn name(&self) -> &'static str {
        "native"
    }

    fn lock_cause(&self) -> &'static str {
        "vault_locked"
    }

    async fn status(&self) -> FerroResult<VaultStatus> {
        self.status_calls.fetch_add(1, Ordering::SeqCst);
        let email = self.email.lock().unwrap().clone();
        Ok(VaultStatus {
            user_email: email.clone(),
            status: if email.is_some() {
                "unlocked"
            } else {
                "unauthenticated"
            }
            .to_string(),
            last_sync: email.is_some().then(|| LAST_SYNC.to_string()),
        })
    }

    async fn unlock(&self, _password: Zeroizing<String>) -> FerroResult<()> {
        Ok(())
    }

    async fn lock(&self) {}

    async fn sync(&self) -> FerroResult<()> {
        Ok(())
    }

    async fn list_credentials(&self) -> FerroResult<Listing> {
        Ok(Listing::default())
    }

    async fn get_value(&self, _: Builtin, _: &str, _: &str) -> FerroResult<Zeroizing<String>> {
        Err(FerroError::VaultUnavailable)
    }

    async fn get_field(&self, _: &str, _: &str, _: &str) -> FerroResult<Zeroizing<String>> {
        Err(FerroError::VaultUnavailable)
    }
}
