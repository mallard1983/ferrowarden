//! An in-memory [`Vault`] for unit tests: the stand-in for a Vaultwarden
//! that tests which only need an `AppState` do not want to run.
//!
//! Compiled for `cargo test` only (`#[cfg(test)]` in `vault/mod.rs`) and not
//! reachable from configuration: `vault.backend` has one value, `native`,
//! and [`super::ActiveVault::from_config`] never builds this. A release
//! binary cannot contain it.
//!
//! It holds no secrets. It reports the account email it was given (and a
//! fixed last-sync time) as its status, counts those lookups, and fails every
//! value read unless the test arranged one with [`FakeVault::set_value`], so a
//! test that reaches for a credential value without arranging one fails
//! loudly. [`FakeVault::value_reads`] counts the reads, which is how a test
//! shows that a value was never fetched.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use zeroize::Zeroizing;

use super::model::{
    Builtin, CredentialEntry, CredentialMap, Listing, ManagedState, NewLogin, VaultStatus,
};
use super::Vault;
use crate::error::{FerroError, FerroResult};

/// The last-sync time the fake reports for a signed-in account.
pub const LAST_SYNC: &str = "2026-11-21T10:00:00Z";

#[derive(Default)]
pub struct FakeVault {
    /// The logged-in account; `None` reports the vault as unauthenticated.
    email: Mutex<Option<String>>,
    status_calls: AtomicUsize,
    /// Values a test arranged, by item id and built-in.
    values: Mutex<HashMap<(String, &'static str), String>>,
    value_reads: AtomicUsize,
    /// The vault reports itself locked (sync, listing and writes refuse).
    locked: AtomicBool,
    /// What `managed_collection` answers (default: not configured).
    managed: Mutex<ManagedState>,
    /// The items a listing shows: the ones a test added and the ones created.
    items: Mutex<CredentialMap>,
    /// What `create_login` was asked to write, without the value.
    created: Mutex<Vec<CreatedItem>>,
    /// The next writes fail.
    fail_writes: AtomicBool,
    create_calls: AtomicUsize,
}

/// One item `create_login` wrote (the value is kept apart, in `values`, and
/// only readable through [`FakeVault::password_of`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedItem {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub uris: Vec<String>,
    pub created_by: String,
    pub approval_required: bool,
    /// The managed collection it went to.
    pub collection_id: String,
}

impl FakeVault {
    /// Make `status` report this account (or none).
    pub fn set_email(&self, email: Option<&str>) {
        *self.email.lock().unwrap() = email.map(str::to_string);
    }

    /// Arrange the password of item `id` (a test value).
    pub fn set_password(&self, id: &str, value: &str) {
        self.values
            .lock()
            .unwrap()
            .insert((id.to_string(), "password"), value.to_string());
    }

    /// Make `managed_collection` answer `state`.
    pub fn set_managed(&self, state: ManagedState) {
        *self.managed.lock().unwrap() = state;
    }

    /// Report the vault locked (or unlocked again).
    pub fn set_locked(&self, locked: bool) {
        self.locked.store(locked, Ordering::SeqCst);
    }

    /// Show an item with this name (and these URIs) in listings.
    pub fn add_item(&self, name: &str, uris: &[&str]) {
        let id = format!("seed-{}", self.items.lock().unwrap().len());
        self.items
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default()
            .push(CredentialEntry::login(&id, uris));
    }

    /// Make the next writes fail (or work again).
    pub fn fail_writes(&self, fail: bool) {
        self.fail_writes.store(fail, Ordering::SeqCst);
    }

    /// The items `create_login` wrote.
    pub fn created(&self) -> Vec<CreatedItem> {
        self.created.lock().unwrap().clone()
    }

    /// How many times `create_login` was called (writes that failed included).
    pub fn create_calls(&self) -> usize {
        self.create_calls.load(Ordering::SeqCst)
    }

    /// The password written for item `id`, for a test that compares it with
    /// what must never leave Ferrowarden.
    pub fn password_of(&self, id: &str) -> Option<String> {
        self.values
            .lock()
            .unwrap()
            .get(&(id.to_string(), "password"))
            .cloned()
    }

    /// How many times a value (built-in or field) was asked for, found or not.
    pub fn value_reads(&self) -> usize {
        self.value_reads.load(Ordering::SeqCst)
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
        if self.locked.load(Ordering::SeqCst) {
            return Err(FerroError::VaultLocked);
        }
        Ok(())
    }

    async fn list_credentials(&self) -> FerroResult<Listing> {
        if self.locked.load(Ordering::SeqCst) {
            return Err(FerroError::VaultLocked);
        }
        Ok(Listing {
            map: self.items.lock().unwrap().clone(),
            ..Listing::default()
        })
    }

    async fn get_value(&self, which: Builtin, id: &str, _: &str) -> FerroResult<Zeroizing<String>> {
        self.value_reads.fetch_add(1, Ordering::SeqCst);
        let key = match which {
            Builtin::Password => "password",
            Builtin::Username => "username",
            Builtin::Totp => "totp",
            Builtin::Notes => "notes",
        };
        self.values
            .lock()
            .unwrap()
            .get(&(id.to_string(), key))
            .map(|v| Zeroizing::new(v.clone()))
            .ok_or(FerroError::VaultUnavailable)
    }

    async fn get_field(&self, _: &str, _: &str, _: &str) -> FerroResult<Zeroizing<String>> {
        self.value_reads.fetch_add(1, Ordering::SeqCst);
        Err(FerroError::VaultUnavailable)
    }

    async fn managed_collection(&self) -> FerroResult<ManagedState> {
        if self.locked.load(Ordering::SeqCst) {
            return Err(FerroError::VaultLocked);
        }
        Ok(self.managed.lock().unwrap().clone())
    }

    async fn create_login(&self, new: NewLogin) -> FerroResult<String> {
        self.create_calls.fetch_add(1, Ordering::SeqCst);
        if self.locked.load(Ordering::SeqCst) {
            return Err(FerroError::VaultLocked);
        }
        // Like the real backend: only into the usable managed collection.
        let collection = match self.managed.lock().unwrap().clone() {
            ManagedState::Usable(c) => c,
            ManagedState::Unavailable { problem, .. } => {
                return Err(FerroError::ManagedCollectionUnavailable(problem))
            }
            ManagedState::Off => return Err(FerroError::CredentialCreateDisabled),
        };
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(FerroError::VaultWriteFailed);
        }
        let id = format!("fake-{}", self.created.lock().unwrap().len());
        self.values
            .lock()
            .unwrap()
            .insert((id.clone(), "password"), new.password.to_string());
        let mut entry = CredentialEntry::login(
            &id,
            &new.uris.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        entry.has_username = new.username.is_some();
        entry.approval_required = new.approval_required;
        self.items
            .lock()
            .unwrap()
            .entry(new.name.clone())
            .or_default()
            .push(entry);
        self.created.lock().unwrap().push(CreatedItem {
            id: id.clone(),
            name: new.name.clone(),
            username: new.username.clone(),
            uris: new.uris.clone(),
            created_by: new.created_by.clone(),
            approval_required: new.approval_required,
            collection_id: collection.id,
        });
        Ok(id)
    }
}
