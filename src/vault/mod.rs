//! The vault Ferrowarden reads credentials from.
//!
//! The [`Vault`] trait is what the rest of Ferrowarden sees. Its one
//! production implementation is [`native::NativeVault`]: the Bitwarden client
//! protocol and cryptography implemented in Rust directly against Vaultwarden
//! (docs/native-vault.md). The trait stays so that another backend can be
//! added later without touching its callers.
//!
//! Everything else (the proxy, the refresher, the unlock endpoint, the admin
//! UI, events) talks to [`ActiveVault`]. The surface: lock and unlock, sync
//! into the credential map (names, bindings, field names, which values exist,
//! never a value), status, and one secret value at a time.

#[cfg(test)]
pub mod fake;
pub mod model;
pub mod native;
pub mod refresh;
pub mod unlock;

use zeroize::Zeroizing;

use crate::config::{Config, VaultBackend};
use crate::error::FerroResult;

pub use model::{Builtin, CredentialMap, Listing, ManagedState, NewLogin, VaultStatus};
pub use unlock::read_password_file;

/// What a vault backend offers the rest of Ferrowarden.
#[allow(async_fn_in_trait)] // only used inside this binary, through `ActiveVault`
pub trait Vault: Send + Sync {
    /// `native`, as reported in events and on the status page.
    fn name(&self) -> &'static str;

    /// The `cause` of the `vault_lock` event when this backend reports the
    /// vault locked behind Ferrowarden's back.
    fn lock_cause(&self) -> &'static str;

    /// Session state and account email, without secrets.
    async fn status(&self) -> FerroResult<VaultStatus>;

    /// Unlock with the master password. The password is consumed and wiped.
    async fn unlock(&self, password: Zeroizing<String>) -> FerroResult<()>;

    /// Drop everything the backend holds that could decrypt the vault.
    async fn lock(&self);

    /// Bring the backend's copy of the vault up to date with the server.
    /// `Err(VaultLocked)` when the vault is (now) locked.
    async fn sync(&self) -> FerroResult<()>;

    /// Metadata of every supported item, never a value.
    async fn list_credentials(&self) -> FerroResult<Listing>;

    /// One built-in value of an item, by id. `label` (the placeholder text)
    /// is only used in error messages.
    async fn get_value(
        &self,
        value: Builtin,
        id: &str,
        label: &str,
    ) -> FerroResult<Zeroizing<String>>;

    /// One custom field of an item, by name. Linked fields resolve to the
    /// login username or password they point at.
    async fn get_field(&self, id: &str, field: &str, label: &str)
        -> FerroResult<Zeroizing<String>>;

    /// Where `vault.managed.collection` stands as of the last sync: off,
    /// writable, or unavailable with the reason. `Err(VaultLocked)` when the
    /// vault is locked.
    async fn managed_collection(&self) -> FerroResult<ManagedState>;

    /// Create one login item in the managed collection and return the id the
    /// server gave it (`None` when the server created it but its answer could
    /// not be read: the item exists all the same). Refuses (without writing)
    /// when the vault is locked or the managed collection is not usable: it
    /// never falls back to another collection or the personal vault. A write
    /// the server refused is `VaultWriteFailed` (nothing was created); one
    /// whose outcome is unknown (a timeout, a server error) is
    /// `VaultWriteUnknown`. The caller syncs afterwards.
    async fn create_login(&self, new: NewLogin) -> FerroResult<Option<String>>;

    /// Start rotating the password of item `id` (in the managed collection):
    /// store `next` on the item as its pending value, in the reserved hidden
    /// field `ferrowarden_next`, and change nothing else. Refuses (without
    /// writing) when the vault is locked, the managed collection is not
    /// usable, the item is not in it, or a rotation is already pending
    /// (`RotationInProgress`). A change made to the item by someone else in
    /// the meantime is `VaultConflict`: it is never overwritten. Returns the
    /// rotation id of the pending value (an opaque identifier of exactly this
    /// value: a digest of its ciphertext). The caller syncs afterwards. `label`
    /// (the credential's name) is only used in error messages.
    async fn rotate_start(
        &self,
        id: &str,
        label: &str,
        next: Zeroizing<String>,
    ) -> FerroResult<String>;

    /// Make the pending value the password: the old password goes to the
    /// item's password history and the pending field is removed. Refuses like
    /// [`rotate_start`](Self::rotate_start); `NoRotationPending` when there is
    /// none, and `RotationMismatch` (nothing written) when the pending value
    /// is not the one `rotation_id` names.
    async fn rotate_commit(&self, id: &str, label: &str, rotation_id: &str) -> FerroResult<()>;

    /// Throw the pending value away: the field is removed and its value goes
    /// to the front of the item's password history, so that nothing is ever
    /// lost. Refuses like [`rotate_commit`](Self::rotate_commit).
    async fn rotate_abort(&self, id: &str, label: &str, rotation_id: &str) -> FerroResult<()>;
}

/// The backend chosen at startup by `vault.backend`.
pub enum ActiveVault {
    Native(Box<native::NativeVault>),
    /// An in-memory stand-in for tests that need an `AppState` without a
    /// Vaultwarden. Compiled only into the test build; no configuration value
    /// selects it, and [`ActiveVault::from_config`] never builds it.
    #[cfg(test)]
    Fake(Box<fake::FakeVault>),
}

impl ActiveVault {
    /// Build the configured backend. Fails when its settings cannot be used
    /// (unreadable CA file, missing API key).
    pub fn from_config(config: &Config) -> FerroResult<Self> {
        Ok(match config.vault.backend {
            VaultBackend::Native => {
                ActiveVault::Native(Box::new(native::NativeVault::new(config)?))
            }
        })
    }
}

macro_rules! delegate {
    ($self:ident, $v:ident => $call:expr) => {
        match $self {
            ActiveVault::Native(boxed) => {
                let $v: &native::NativeVault = boxed;
                $call
            }
            #[cfg(test)]
            ActiveVault::Fake(boxed) => {
                let $v: &fake::FakeVault = boxed;
                $call
            }
        }
    };
}

impl Vault for ActiveVault {
    fn name(&self) -> &'static str {
        delegate!(self, v => Vault::name(v))
    }

    fn lock_cause(&self) -> &'static str {
        delegate!(self, v => Vault::lock_cause(v))
    }

    async fn status(&self) -> FerroResult<VaultStatus> {
        delegate!(self, v => Vault::status(v).await)
    }

    async fn unlock(&self, password: Zeroizing<String>) -> FerroResult<()> {
        delegate!(self, v => Vault::unlock(v, password).await)
    }

    async fn lock(&self) {
        delegate!(self, v => Vault::lock(v).await)
    }

    async fn sync(&self) -> FerroResult<()> {
        delegate!(self, v => Vault::sync(v).await)
    }

    async fn list_credentials(&self) -> FerroResult<Listing> {
        delegate!(self, v => Vault::list_credentials(v).await)
    }

    async fn get_value(
        &self,
        value: Builtin,
        id: &str,
        label: &str,
    ) -> FerroResult<Zeroizing<String>> {
        delegate!(self, v => Vault::get_value(v, value, id, label).await)
    }

    async fn get_field(
        &self,
        id: &str,
        field: &str,
        label: &str,
    ) -> FerroResult<Zeroizing<String>> {
        delegate!(self, v => Vault::get_field(v, id, field, label).await)
    }

    async fn managed_collection(&self) -> FerroResult<ManagedState> {
        delegate!(self, v => Vault::managed_collection(v).await)
    }

    async fn create_login(&self, new: NewLogin) -> FerroResult<Option<String>> {
        delegate!(self, v => Vault::create_login(v, new).await)
    }

    async fn rotate_start(
        &self,
        id: &str,
        label: &str,
        next: Zeroizing<String>,
    ) -> FerroResult<String> {
        delegate!(self, v => Vault::rotate_start(v, id, label, next).await)
    }

    async fn rotate_commit(&self, id: &str, label: &str, rotation_id: &str) -> FerroResult<()> {
        delegate!(self, v => Vault::rotate_commit(v, id, label, rotation_id).await)
    }

    async fn rotate_abort(&self, id: &str, label: &str, rotation_id: &str) -> FerroResult<()> {
        delegate!(self, v => Vault::rotate_abort(v, id, label, rotation_id).await)
    }
}
