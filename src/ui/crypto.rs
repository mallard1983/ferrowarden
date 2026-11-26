//! Master-password key derivation for the Vaultwarden sign-in.
//!
//! Bitwarden clients never send the master password. They derive a 32-byte
//! master key from it with the account's KDF, then send
//! `base64(PBKDF2-HMAC-SHA256(masterKey, password, 1 iteration))` — the
//! "master password hash" — to prove knowledge of it. This module computes
//! that hash and nothing else: the master key is never used for decryption
//! here and is wiped as soon as the hash exists.
//!
//! Every intermediate lives in a [`Zeroizing`] buffer. The KDF parameters come
//! from the server (prelogin), so they are bounded before any work is done: a
//! hostile or compromised server must not be able to make us burn minutes of
//! CPU or gigabytes of memory.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::Hmac;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// PBKDF2 iteration range accepted from the server. The lower bound is the
/// Bitwarden client minimum, the upper bound is generous (the Bitwarden
/// default is 600 000) but keeps a derivation within a few seconds.
pub const PBKDF2_ITERATIONS: std::ops::RangeInclusive<u32> = 5_000..=2_000_000;
/// Argon2id memory in MiB (client minimum 16, ceiling 1 GiB).
pub const ARGON2_MEMORY_MIB: std::ops::RangeInclusive<u32> = 16..=1024;
pub const ARGON2_ITERATIONS: std::ops::RangeInclusive<u32> = 2..=10;
pub const ARGON2_PARALLELISM: std::ops::RangeInclusive<u32> = 1..=16;

/// The account's key-derivation settings, as reported by `prelogin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    Pbkdf2 {
        iterations: u32,
    },
    Argon2id {
        memory_mib: u32,
        iterations: u32,
        parallelism: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfError {
    /// Parameters outside the accepted range (too weak or too expensive).
    OutOfBounds,
    /// The KDF failed (cannot happen for validated parameters).
    Failed,
}

impl Kdf {
    /// Reject parameters below the client minimums or above the ceilings.
    pub fn validate(&self) -> Result<(), KdfError> {
        let ok = match *self {
            Kdf::Pbkdf2 { iterations } => PBKDF2_ITERATIONS.contains(&iterations),
            Kdf::Argon2id {
                memory_mib,
                iterations,
                parallelism,
            } => {
                ARGON2_MEMORY_MIB.contains(&memory_mib)
                    && ARGON2_ITERATIONS.contains(&iterations)
                    && ARGON2_PARALLELISM.contains(&parallelism)
            }
        };
        if ok {
            Ok(())
        } else {
            Err(KdfError::OutOfBounds)
        }
    }
}

/// How Bitwarden normalizes the account email before using it as the salt.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Derive the master key from the password.
pub(crate) fn master_key(
    password: &[u8],
    email: &str,
    kdf: Kdf,
) -> Result<Zeroizing<[u8; 32]>, KdfError> {
    kdf.validate()?;
    let salt_str = normalize_email(email);
    let mut key = Zeroizing::new([0u8; 32]);
    match kdf {
        Kdf::Pbkdf2 { iterations } => {
            pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt_str.as_bytes(), iterations, &mut *key)
                .map_err(|_| KdfError::Failed)?;
        }
        Kdf::Argon2id {
            memory_mib,
            iterations,
            parallelism,
        } => {
            // Bitwarden hashes the salt first: Argon2 wants a salt of at
            // least 8 bytes, and an email can be shorter.
            let salt = Sha256::digest(salt_str.as_bytes());
            // memory_mib is at most 1024, so the KiB value cannot overflow.
            let params = Params::new(memory_mib * 1024, iterations, parallelism, Some(32))
                .map_err(|_| KdfError::Failed)?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(password, &salt, &mut *key)
                .map_err(|_| KdfError::Failed)?;
        }
    }
    Ok(key)
}

/// The master password hash Vaultwarden expects as the OAuth `password`:
/// standard padded base64 of PBKDF2-HMAC-SHA256(masterKey, password, 1).
///
/// CPU- and memory-heavy: call it from `spawn_blocking`. The caller wipes its
/// copy of the password afterwards.
pub fn auth_hash(password: &str, email: &str, kdf: Kdf) -> Result<Zeroizing<String>, KdfError> {
    let key = master_key(password.as_bytes(), email, kdf)?;
    let mut hash = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2::<Hmac<Sha256>>(&*key, password.as_bytes(), 1, &mut *hash)
        .map_err(|_| KdfError::Failed)?;
    let mut out = Zeroizing::new(String::with_capacity(44));
    STANDARD.encode_string(*hash, &mut out);
    Ok(out)
}

#[cfg(test)]
mod tests;
