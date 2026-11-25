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
