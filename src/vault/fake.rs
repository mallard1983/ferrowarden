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
    /// What the rotation calls were asked to do: `start:<id>`, `commit:<id>`,
    /// `abort:<id>`, in order (refused calls included).
    rotate_calls: Mutex<Vec<String>>,
    /// The next rotation write answers `VaultConflict` (a person edited the
    /// item), once.
    conflict_once: AtomicBool,
    /// How many times a rotation moved a password to the item's history.
    history: Mutex<HashMap<String, usize>>,
    /// The rotation id of each pending value, by item id.
    rotation_ids: Mutex<HashMap<String, String>>,
    /// The next write fails with an unknown outcome (a timeout), once.
    unknown_once: AtomicBool,
    /// Items whose password a person changed after the rotation started.
    password_changed: Mutex<std::collections::HashSet<String>>,
    /// Where every id this fake issues comes from: one monotonic counter, so
    /// two items never share an id, whatever their names.
    next_id: AtomicUsize,
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

    /// Show a login in the managed collection (the one `set_managed` made
    /// usable) with a password, and return its id. Change its entry with
    /// [`FakeVault::edit_item`].
    pub fn add_managed_item(&self, name: &str, uris: &[&str], password: &str) -> String {
        let collection = match &*self.managed.lock().unwrap() {
            ManagedState::Usable(c) => c.id.clone(),
            _ => "unset".to_string(),
        };
        let id = format!("managed-{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        let mut entry = CredentialEntry::login(&id, uris);
        entry.collection_ids = vec![collection];
        self.items
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default()
            .push(entry);
        self.set_password(&id, password);
        id
    }

    /// Change the entry of item `id` as shown in listings.
    pub fn edit_item(&self, id: &str, change: impl FnOnce(&mut CredentialEntry)) {
        let mut items = self.items.lock().unwrap();
        let entry = items
            .values_mut()
            .flatten()
            .find(|e| e.id == id)
            .expect("no such item");
        change(entry);
    }

    /// Arrange the pending value of item `id` (a test value), with a new
    /// rotation id, as a person replacing the pending field in the vault
    /// would. Returns the rotation id.
    pub fn set_next(&self, id: &str, value: &str) -> String {
        self.values
            .lock()
            .unwrap()
            .insert((id.to_string(), "next"), value.to_string());
        let rotation_id = format!("rotation-{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        self.rotation_ids
            .lock()
            .unwrap()
            .insert(id.to_string(), rotation_id.clone());
        let shown = rotation_id.clone();
        // An item that is not listed (a test of the substitution alone) has no
        // entry to mark.
        if let Some(entry) = self
            .items
            .lock()
            .unwrap()
            .values_mut()
            .flatten()
            .find(|e| e.id == id)
        {
            entry.has_next = true;
            entry.rotation_id = Some(shown);
        }
        rotation_id
    }

    /// The rotation id of the pending value of item `id`, if there is one.
    pub fn rotation_id_of(&self, id: &str) -> Option<String> {
        self.rotation_ids.lock().unwrap().get(id).cloned()
    }

    /// Replace the item called `name` by another one with the same name and
    /// password, in the same collection and with a new id (a person deleted
    /// it and made a new one). Returns the new id.
    pub fn swap_item(&self, name: &str) -> String {
        let (old, collection, password) = {
            let items = self.items.lock().unwrap();
            let entry = &items[name][0];
            (
                entry.id.clone(),
                entry.collection_ids.clone(),
                self.password_of(&entry.id).unwrap_or_default(),
            )
        };
        let id = format!("managed-{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        let mut entry = CredentialEntry::login(&id, &[]);
        entry.collection_ids = collection;
        self.items
            .lock()
            .unwrap()
            .insert(name.to_string(), vec![entry]);
        self.values.lock().unwrap().remove(&(old, "password"));
        self.set_password(&id, &password);
        id
    }

    /// A person changes the password of item `id` (to `value`) while a rotation
    /// is pending: a commit is then refused, an abort is not.
    pub fn person_changes_password(&self, id: &str, value: &str) {
        self.set_password(id, value);
        self.password_changed.lock().unwrap().insert(id.to_string());
    }

    /// The next write fails with an unknown outcome (the write may have been
    /// applied), once.
    pub fn unknown_next_write(&self) {
        self.unknown_once.store(true, Ordering::SeqCst);
    }

    /// The rotation calls so far (see the field).
    pub fn rotate_calls(&self) -> Vec<String> {
        self.rotate_calls.lock().unwrap().clone()
    }

    /// The pending value of item `id`, if a rotation is pending.
    pub fn next_of(&self, id: &str) -> Option<String> {
        self.values
            .lock()
            .unwrap()
            .get(&(id.to_string(), "next"))
            .cloned()
    }

    /// How many passwords the item's history holds.
    pub fn history_len(&self, id: &str) -> usize {
        self.history.lock().unwrap().get(id).copied().unwrap_or(0)
    }

    /// The next rotation write fails with a conflict, once.
    pub fn conflict_next_write(&self) {
        self.conflict_once.store(true, Ordering::SeqCst);
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
        let id = format!("seed-{}", self.next_id.fetch_add(1, Ordering::SeqCst));
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
            Builtin::Next => "next",
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

    async fn rotate_start(
        &self,
        id: &str,
        label: &str,
        next: Zeroizing<String>,
    ) -> FerroResult<String> {
        self.rotate_calls
            .lock()
            .unwrap()
            .push(format!("start:{id}"));
        self.rotate_checks(id, label)?;
        if self
            .values
            .lock()
            .unwrap()
            .contains_key(&(id.to_string(), "next"))
        {
            return Err(FerroError::RotationInProgress(label.to_string()));
        }
        Ok(self.set_next(id, &next))
    }

    async fn rotate_commit(&self, id: &str, label: &str, rotation_id: &str) -> FerroResult<()> {
        self.rotate_calls
            .lock()
            .unwrap()
            .push(format!("commit:{id}"));
        self.rotate_checks(id, label)?;
        self.check_rotation_id(id, label, rotation_id)?;
        if self.password_changed.lock().unwrap().contains(id) {
            return Err(FerroError::VaultPasswordChanged);
        }
        let mut values = self.values.lock().unwrap();
        let next = values.remove(&(id.to_string(), "next")).unwrap_or_default();
        values.insert((id.to_string(), "password"), next);
        drop(values);
        self.finish_pending(id);
        Ok(())
    }

    async fn rotate_abort(&self, id: &str, label: &str, rotation_id: &str) -> FerroResult<()> {
        self.rotate_calls
            .lock()
            .unwrap()
            .push(format!("abort:{id}"));
        self.rotate_checks(id, label)?;
        self.check_rotation_id(id, label, rotation_id)?;
        self.values
            .lock()
            .unwrap()
            .remove(&(id.to_string(), "next"));
        self.finish_pending(id);
        Ok(())
    }

    async fn create_login(&self, new: NewLogin) -> FerroResult<Option<String>> {
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
        if self.unknown_once.swap(false, Ordering::SeqCst) {
            return Err(FerroError::VaultWriteUnknown);
        }
        let id = format!("fake-{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        self.values
            .lock()
            .unwrap()
            .insert((id.clone(), "password"), new.password.to_string());
        let mut entry = CredentialEntry::login(
            &id,
            &new.uris.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        entry.collection_ids = vec![collection.id.clone()];
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
        Ok(Some(id))
    }
}

impl FakeVault {
    /// What a finish checks, like the real backend: a rotation is pending, and
    /// it is the one `rotation_id` names.
    fn check_rotation_id(&self, id: &str, label: &str, rotation_id: &str) -> FerroResult<()> {
        match self.rotation_ids.lock().unwrap().get(id) {
            None => Err(FerroError::NoRotationPending(label.to_string())),
            Some(pending) if pending != rotation_id => {
                Err(FerroError::RotationMismatch(label.to_string()))
            }
            Some(_) => Ok(()),
        }
    }

    /// A rotation ended (committed or aborted): the value went to the history.
    fn finish_pending(&self, id: &str) {
        self.password_changed.lock().unwrap().remove(id);
        self.rotation_ids.lock().unwrap().remove(id);
        *self
            .history
            .lock()
            .unwrap()
            .entry(id.to_string())
            .or_default() += 1;
        self.edit_item(id, |e| {
            e.has_next = false;
            e.rotation_id = None;
        });
    }

    /// What every rotation write checks, like the real backend: unlocked, the
    /// managed collection usable, the item in it, no conflict.
    fn rotate_checks(&self, id: &str, label: &str) -> FerroResult<()> {
        if self.locked.load(Ordering::SeqCst) {
            return Err(FerroError::VaultLocked);
        }
        let collection = match self.managed.lock().unwrap().clone() {
            ManagedState::Usable(c) => c,
            ManagedState::Unavailable { problem, .. } => {
                return Err(FerroError::ManagedCollectionUnavailable(problem))
            }
            ManagedState::Off => return Err(FerroError::CredentialCreateDisabled),
        };
        let in_collection = self
            .items
            .lock()
            .unwrap()
            .values()
            .flatten()
            .any(|e| e.id == id && e.collection_ids.contains(&collection.id));
        if !in_collection {
            return Err(FerroError::CredentialNotManaged(label.to_string()));
        }
        if self.conflict_once.swap(false, Ordering::SeqCst) {
            return Err(FerroError::VaultConflict);
        }
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(FerroError::VaultWriteFailed);
        }
        if self.unknown_once.swap(false, Ordering::SeqCst) {
            return Err(FerroError::VaultWriteUnknown);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
