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
mod tests {
    use super::*;

    // Known-answer vectors. The master keys are the Bitwarden SDK's own test
    // vectors (bitwarden/sdk-internal, crates/bitwarden-crypto/src/keys/kdf.rs:
    // `test_master_key_derive_pbkdf2` and `test_master_key_derive_argon2`;
    // password "67t9b5g67$%Dh89n", email "test_key"). The same PBKDF2 value
    // reproduces with Python:
    //   hashlib.pbkdf2_hmac("sha256", b"67t9b5g67$%Dh89n", b"test_key", 10000, 32)
    // and the authentication hashes with
    //   base64.b64encode(hashlib.pbkdf2_hmac("sha256", master_key, password, 1, 32))
    const PASSWORD: &str = "67t9b5g67$%Dh89n";

    const PBKDF2_MASTER_KEY: [u8; 32] = [
        31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167, 69, 167,
        254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75,
    ];
    const PBKDF2_AUTH_HASH: &str = "XLXIhqgTBvhKS2cbb99YpUf9wEUFtMBwX1Ht2HCA0tA=";

    const ARGON2_MASTER_KEY: [u8; 32] = [
        207, 240, 225, 177, 162, 19, 163, 76, 98, 106, 179, 175, 224, 9, 17, 240, 20, 147, 237, 47,
        246, 150, 141, 184, 62, 225, 131, 242, 51, 53, 225, 242,
    ];
    const ARGON2_AUTH_HASH: &str = "r3Eince9qETXVbhwh9B2OSVoJZLxvqHS2ig2kCocNrg=";

    const PBKDF2: Kdf = Kdf::Pbkdf2 { iterations: 10_000 };
    const ARGON2: Kdf = Kdf::Argon2id {
        memory_mib: 32,
        iterations: 4,
        parallelism: 2,
    };

    #[test]
    fn pbkdf2_master_key_matches_the_bitwarden_sdk_vector() {
        let key = master_key(PASSWORD.as_bytes(), "test_key", PBKDF2).unwrap();
        assert_eq!(*key, PBKDF2_MASTER_KEY);
    }

    #[test]
    fn argon2id_master_key_matches_the_bitwarden_sdk_vector() {
        let key = master_key(PASSWORD.as_bytes(), "test_key", ARGON2).unwrap();
        assert_eq!(*key, ARGON2_MASTER_KEY);
    }

    #[test]
    fn auth_hash_vectors() {
        assert_eq!(
            auth_hash(PASSWORD, "test_key", PBKDF2).unwrap().as_str(),
            PBKDF2_AUTH_HASH
        );
        assert_eq!(
            auth_hash(PASSWORD, "test_key", ARGON2).unwrap().as_str(),
            ARGON2_AUTH_HASH
        );
    }

    #[test]
    fn email_is_trimmed_and_lowercased_before_it_is_the_salt() {
        // Python: pbkdf2_hmac("sha256", b"correct horse", b"admin@example.test", 5000, 32)
        //   = ce28e87b...5c5214; hash = URqPLtU4ohPhnugxqAsDs0iNyCsRm+fx8NqH8whV9o8=
        let kdf = Kdf::Pbkdf2 { iterations: 5000 };
        for email in ["admin@example.test", "  Admin@Example.TEST \n"] {
            assert_eq!(
                auth_hash("correct horse", email, kdf).unwrap().as_str(),
                "URqPLtU4ohPhnugxqAsDs0iNyCsRm+fx8NqH8whV9o8="
            );
        }
    }

    #[test]
    fn hash_is_44_chars_of_padded_standard_base64() {
        let h = auth_hash("pw", "a@b.test", Kdf::Pbkdf2 { iterations: 5000 }).unwrap();
        assert_eq!(h.len(), 44);
        assert!(h.ends_with('='));
        assert_eq!(STANDARD.decode(h.as_bytes()).unwrap().len(), 32);
    }

    #[test]
    fn kdf_bounds() {
        let p = |iterations| Kdf::Pbkdf2 { iterations };
        assert_eq!(p(4_999).validate(), Err(KdfError::OutOfBounds));
        assert_eq!(p(5_000).validate(), Ok(()));
        assert_eq!(p(2_000_000).validate(), Ok(()));
        assert_eq!(p(2_000_001).validate(), Err(KdfError::OutOfBounds));
        assert_eq!(p(0).validate(), Err(KdfError::OutOfBounds));
        assert_eq!(p(u32::MAX).validate(), Err(KdfError::OutOfBounds));

        let a = |memory_mib, iterations, parallelism| Kdf::Argon2id {
            memory_mib,
            iterations,
            parallelism,
        };
        assert_eq!(a(16, 2, 1).validate(), Ok(()));
        assert_eq!(a(1024, 10, 16).validate(), Ok(()));
        assert_eq!(a(15, 2, 1).validate(), Err(KdfError::OutOfBounds));
        assert_eq!(a(16, 1, 1).validate(), Err(KdfError::OutOfBounds));
        assert_eq!(a(16, 2, 0).validate(), Err(KdfError::OutOfBounds));
        assert_eq!(a(1025, 2, 1).validate(), Err(KdfError::OutOfBounds));
        assert_eq!(a(16, 11, 1).validate(), Err(KdfError::OutOfBounds));
        assert_eq!(a(16, 2, 17).validate(), Err(KdfError::OutOfBounds));
        assert_eq!(a(u32::MAX, 2, 1).validate(), Err(KdfError::OutOfBounds));
    }

    #[test]
    fn out_of_bounds_parameters_do_no_work() {
        // Would take hours / gigabytes if it ran; it must be refused up front.
        let expensive = Kdf::Argon2id {
            memory_mib: u32::MAX,
            iterations: u32::MAX,
            parallelism: u32::MAX,
        };
        assert_eq!(
            auth_hash("pw", "a@b.test", expensive).err(),
            Some(KdfError::OutOfBounds)
        );
        let huge = Kdf::Pbkdf2 {
            iterations: u32::MAX,
        };
        assert_eq!(
            auth_hash("pw", "a@b.test", huge).err(),
            Some(KdfError::OutOfBounds)
        );
    }
}
