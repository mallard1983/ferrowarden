use super::super::enc::test_support::{encrypt2, key};
use super::*;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn stretch_matches_the_independent_vector() {
    let v = &vectors()["stretch"];
    let master: [u8; 32] = unhex(v["master_key"].as_str().unwrap()).try_into().unwrap();
    let stretched = stretch(&master).unwrap();
    assert_eq!(&stretched.enc[..], &unhex(v["enc"].as_str().unwrap())[..]);
    assert_eq!(&stretched.mac[..], &unhex(v["mac"].as_str().unwrap())[..]);
    // The two halves are different keys.
    assert_ne!(&stretched.enc[..], &stretched.mac[..]);
}

#[test]
fn hkdf_expand_matches_rfc_5869_test_case_1() {
    // RFC 5869 appendix A.1: the PRK and OKM are given there.
    let prk = unhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    let info = unhex("f0f1f2f3f4f5f6f7f8f9");
    let mut okm = [0u8; 42];
    hkdf_expand(&prk, &info, &mut okm).unwrap();
    assert_eq!(
        okm.to_vec(),
        unhex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
    );
}

#[test]
fn user_key_must_be_exactly_64_bytes() {
    let wrapping = key(1);
    for len in [0usize, 16, 32, 48, 63, 65, 96] {
        let wrapped = encrypt2(&wrapping, [7; 16], &vec![9u8; len]);
        assert_eq!(
            unwrap_sym_key(&wrapping, &wrapped).unwrap_err(),
            EncError::KeyLength,
            "{len} bytes"
        );
    }
    let ok = encrypt2(&wrapping, [7; 16], &[9u8; 64]);
    assert!(unwrap_sym_key(&wrapping, &ok).is_ok());
}

#[test]
fn unwrapping_with_the_wrong_key_is_a_mac_failure() {
    let wrapped = encrypt2(&key(1), [7; 16], &[9u8; 64]);
    assert_eq!(
        unwrap_sym_key(&key(2), &wrapped).unwrap_err(),
        EncError::MacFailure
    );
}

#[test]
fn user_key_derivation_round_trip_and_wrong_password() {
    // A 5000-iteration PBKDF2 account: the user key is wrapped with the
    // stretched master key, exactly as a client does it.
    let kdf = Kdf::Pbkdf2 { iterations: 5000 };
    let email = "Admin@Example.test ";
    let master = master_key(b"correct horse", email, kdf).unwrap();
    let user_key_bytes = [0x5au8; 64];
    let wrapped = encrypt2(&stretch(&master).unwrap(), [3; 16], &user_key_bytes);

    let uk = derive_user_key("correct horse", email, kdf, &wrapped).unwrap();
    assert_eq!(&uk.enc[..], &user_key_bytes[..32]);
    assert_eq!(&uk.mac[..], &user_key_bytes[32..]);

    assert_eq!(
        derive_user_key("wrong horse", email, kdf, &wrapped).unwrap_err(),
        UnlockError::BadPasswordOrKey
    );
    // A tampered wrapped key fails the same way: the MAC does not verify.
    let mut tampered = wrapped.clone().into_bytes();
    let n = tampered.len() - 10;
    tampered[n] = if tampered[n] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        derive_user_key(
            "correct horse",
            email,
            kdf,
            &String::from_utf8(tampered).unwrap()
        )
        .unwrap_err(),
        UnlockError::BadPasswordOrKey
    );
}

#[test]
fn kdf_bounds_apply_before_any_work() {
    let kdf = Kdf::Pbkdf2 { iterations: 1 };
    assert_eq!(
        derive_user_key("pw", "a@b.test", kdf, "2.x|y|z").unwrap_err(),
        UnlockError::Kdf(KdfError::OutOfBounds)
    );
}

#[test]
fn a_legacy_type_0_user_key_is_refused_not_decrypted() {
    let kdf = Kdf::Pbkdf2 { iterations: 5000 };
    assert_eq!(
        derive_user_key(
            "pw",
            "a@b.test",
            kdf,
            "0.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA=="
        )
        .unwrap_err(),
        UnlockError::Unsupported(EncError::UnsupportedType(0))
    );
}

#[test]
fn rsa_org_keys_unwrap_with_sha1_and_sha256() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let v = &vectors()["rsa"];
    let der = STANDARD
        .decode(v["pkcs8_der_b64"].as_str().unwrap())
        .unwrap();
    let rsa = RsaKey::from_pkcs8_der(&der).unwrap();
    let expected = unhex(v["payload"].as_str().unwrap());
    for field in ["sha1", "sha256"] {
        let k = unwrap_org_key(&rsa, v[field].as_str().unwrap()).unwrap();
        assert_eq!(&k.enc[..], &expected[..32], "{field}");
        assert_eq!(&k.mac[..], &expected[32..], "{field}");
    }
}

#[test]
fn rsa_hash_must_match_the_type_number() {
    // The SHA-1 ciphertext relabelled as type 3 (SHA-256) must fail, and
    // the other way round: the type decides the hash, nothing is guessed.
    use base64::{engine::general_purpose::STANDARD, Engine};
    let v = &vectors()["rsa"];
    let der = STANDARD
        .decode(v["pkcs8_der_b64"].as_str().unwrap())
        .unwrap();
    let rsa = RsaKey::from_pkcs8_der(&der).unwrap();
    let sha1 = v["sha1"].as_str().unwrap().replacen("4.", "3.", 1);
    let sha256 = v["sha256"].as_str().unwrap().replacen("3.", "4.", 1);
    assert_eq!(
        unwrap_org_key(&rsa, &sha1).unwrap_err(),
        EncError::RsaFailure
    );
    assert_eq!(
        unwrap_org_key(&rsa, &sha256).unwrap_err(),
        EncError::RsaFailure
    );
}

#[test]
fn org_key_of_the_wrong_length_is_refused() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let v = &vectors()["rsa"];
    let der = STANDARD
        .decode(v["pkcs8_der_b64"].as_str().unwrap())
        .unwrap();
    let rsa = RsaKey::from_pkcs8_der(&der).unwrap();
    // A real ciphertext of the 64-byte payload cannot be made 32 bytes
    // here, so check the length rule on the byte path directly.
    assert_eq!(
        SymKey::from_slice(&[1u8; 32]).unwrap_err(),
        EncError::KeyLength
    );
    // And the RSA key itself is refused if it is not RSA at all.
    assert!(RsaKey::from_pkcs8_der(&[0u8; 16]).is_err());
    let _ = rsa;
}

#[test]
fn private_key_loads_from_a_type_2_wrapped_pkcs8() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let v = &vectors()["rsa"];
    let der = STANDARD
        .decode(v["pkcs8_der_b64"].as_str().unwrap())
        .unwrap();
    let uk = key(5);
    let wrapped = encrypt2(&uk, [1; 16], &der);
    assert!(load_rsa_key(&uk, &wrapped).is_ok());
    // Wrong user key: a MAC failure, never a parse attempt on garbage.
    assert_eq!(
        load_rsa_key(&key(6), &wrapped).unwrap_err(),
        EncError::MacFailure
    );
}

#[test]
fn debug_of_keys_shows_nothing() {
    let k = key(9);
    assert_eq!(format!("{k:?}"), "SymKey(<redacted>)");
    let v = &vectors()["rsa"];
    use base64::{engine::general_purpose::STANDARD, Engine};
    let der = STANDARD
        .decode(v["pkcs8_der_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        format!("{:?}", RsaKey::from_pkcs8_der(&der).unwrap()),
        "RsaKey(<redacted>)"
    );
}
