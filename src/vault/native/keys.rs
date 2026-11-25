//! The key hierarchy of a Bitwarden account, and nothing else.
//!
//! 1. The master key comes from the master password with the account's KDF
//!    (PBKDF2 or Argon2id, bounded: `ui::crypto`).
//! 2. HKDF-Expand turns it into the stretched `enc` and `mac` keys.
//! 3. Those decrypt the user key (`profile.key`), which must be exactly 64
//!    bytes.
//! 4. The user key decrypts the PKCS#8 RSA private key (`profile.privateKey`).
//! 5. The private key unwraps each organisation key (RSA-OAEP, 64 bytes).
//! 6. A per-item key (`cipher.key`) is wrapped by the user key or by the
//!    item's organisation key, and must be 64 bytes too.
//!
//! Every key is a [`SymKey`] or [`RsaKey`]: wiped on drop, never printed.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::enc::{EncError, EncString, RsaKey, SymKey};
use crate::ui::crypto::{master_key, Kdf, KdfError};

/// Why unlocking failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockError {
    /// The KDF parameters are out of bounds or the KDF failed.
    Kdf(KdfError),
    /// The user key did not verify: the master password is wrong, or the key
    /// was altered.
    BadPasswordOrKey,
    /// The user key or the private key is in a format Ferrowarden refuses
    /// (not type 2, not 64 bytes, not PKCS#8 RSA).
    Unsupported(EncError),
}

impl std::fmt::Display for UnlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnlockError::Kdf(_) => {
                f.write_str("the account's key derivation settings are not acceptable")
            }
            UnlockError::BadPasswordOrKey => f.write_str(
                "the master password is wrong, or the vault key failed its integrity check",
            ),
            UnlockError::Unsupported(e) => write!(f, "the vault key format is not supported ({e})"),
        }
    }
}

/// HKDF-Expand (SHA-256) of `prk` with `info` into `out`.
pub(crate) fn hkdf_expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), EncError> {
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| EncError::KeyLength)?;
    hk.expand(info, out).map_err(|_| EncError::KeyLength)
}

/// Stretch a 32-byte master key into the 64-byte key that wraps the user key:
/// `enc = HKDF-Expand(master, "enc", 32)`, `mac = HKDF-Expand(master, "mac", 32)`.
pub fn stretch(master: &[u8; 32]) -> Result<SymKey, EncError> {
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut mac = Zeroizing::new([0u8; 32]);
    hkdf_expand(master, b"enc", &mut *enc)?;
    hkdf_expand(master, b"mac", &mut *mac)?;
    Ok(SymKey::from_parts(enc, mac))
}

/// Derive the user key from the master password: KDF, stretch, then decrypt
/// `enc_user_key` (`profile.key`). CPU- and memory-heavy: call it from
/// `spawn_blocking`.
///
/// A MAC failure here means the password is wrong (or the key was altered);
/// that is an unlock failure, not an item to skip.
pub fn derive_user_key(
    password: &str,
    email: &str,
    kdf: Kdf,
    enc_user_key: &str,
) -> Result<SymKey, UnlockError> {
    let master = master_key(password.as_bytes(), email, kdf).map_err(UnlockError::Kdf)?;
    let stretched = stretch(&master).map_err(UnlockError::Unsupported)?;
    drop(master);
    unwrap_sym_key(&stretched, enc_user_key).map_err(|e| match e {
        EncError::MacFailure => UnlockError::BadPasswordOrKey,
        other => UnlockError::Unsupported(other),
    })
}

/// Decrypt a wrapped 64-byte symmetric key (a user key, or a per-item key)
/// with `wrapping`. Only type 2 strings are accepted, and only 64-byte
/// results.
pub fn unwrap_sym_key(wrapping: &SymKey, enc: &str) -> Result<SymKey, EncError> {
    let bytes = EncString::parse(enc)?.decrypt(wrapping)?;
    SymKey::from_slice(&bytes)
}

/// Decrypt `profile.privateKey` (a type 2 string under the user key) into an
/// RSA key.
pub fn load_rsa_key(user_key: &SymKey, enc_private_key: &str) -> Result<RsaKey, EncError> {
    let der = EncString::parse(enc_private_key)?.decrypt(user_key)?;
    RsaKey::from_pkcs8_der(&der)
}

/// Unwrap an organisation key: RSA-OAEP (type 3 or 4), 64 bytes.
pub fn unwrap_org_key(rsa: &RsaKey, enc: &str) -> Result<SymKey, EncError> {
    let bytes = EncString::parse(enc)?.decrypt_rsa(rsa)?;
    SymKey::from_slice(&bytes)
}

#[cfg(test)]
mod tests;
