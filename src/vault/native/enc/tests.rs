use super::test_support::{encrypt2, key};
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

fn valid() -> String {
    encrypt2(&key(1), [7; 16], b"hello")
}

#[test]
fn known_answer_vectors_from_an_independent_implementation() {
    // Generated with Node's crypto module (tests/native-vectors/gen.js):
    // the strings decrypt to the stated plaintext, and our own
    // encryption reproduces them byte for byte.
    let v = &vectors()["type2"];
    let k = SymKey::from_slice(&unhex(v["key"].as_str().unwrap())).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 7);
    for case in cases {
        let enc = case["enc"].as_str().unwrap();
        let plain = case["plain_utf8"].as_str().unwrap();
        let got = EncString::parse(enc).unwrap().decrypt_string(&k).unwrap();
        assert_eq!(got.as_str(), plain);
        let iv: [u8; 16] = unhex(case["iv"].as_str().unwrap()).try_into().unwrap();
        assert_eq!(encrypt2(&k, iv, plain.as_bytes()), enc);
    }
}

#[test]
fn only_the_allow_listed_types_parse() {
    // Allowed shapes.
    assert!(matches!(
        EncString::parse(&valid()).unwrap(),
        EncString::Aes256CbcHmac { .. }
    ));
    let rsa = vectors()["rsa"].clone();
    assert!(matches!(
        EncString::parse(rsa["sha1"].as_str().unwrap()).unwrap(),
        EncString::RsaOaepSha1(_)
    ));
    assert!(matches!(
        EncString::parse(rsa["sha256"].as_str().unwrap()).unwrap(),
        EncString::RsaOaepSha256(_)
    ));
    // Every other type number is refused with the number, whatever follows.
    let body = valid().split_once('.').unwrap().1.to_string();
    for t in (0..=255u16).filter(|t| ![2, 3, 4].contains(t)) {
        assert_eq!(
            EncString::parse(&format!("{t}.{body}")).unwrap_err(),
            EncError::UnsupportedType(t as u8),
            "type {t}"
        );
    }
    // Not a number a type can be.
    for bad in ["256", "-1", "+2", "02x", " 2", "2 ", "", "\u{662}"] {
        assert_eq!(
            EncString::parse(&format!("{bad}.{body}")).unwrap_err(),
            EncError::Malformed,
            "{bad:?}"
        );
    }
}

#[test]
fn type_0_is_never_decrypted() {
    // A type 0 string is refused before its payload is even decoded, so
    // there is no MAC-less path to decrypt anything.
    for s in [
            "0.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==",
            "0.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "0.!!!",
            "0.",
        ] {
            assert_eq!(
                EncString::parse(s).unwrap_err(),
                EncError::UnsupportedType(0)
            );
        }
}

#[test]
fn malformed_layouts_are_rejected() {
    let ok = valid();
    let parts: Vec<&str> = ok.split_once('.').unwrap().1.split('|').collect();
    let (iv, ct, mac) = (parts[0], parts[1], parts[2]);
    let b = |n: usize| STANDARD.encode(vec![0u8; n]);
    let cases: Vec<(String, EncError)> = vec![
        ("no dot".into(), EncError::Malformed),
        (format!("2.{iv}|{ct}"), EncError::Malformed),
        (format!("2.{iv}|{ct}|{mac}|{mac}"), EncError::Malformed),
        (format!("2.{iv}|{ct}|{mac}|"), EncError::Malformed),
        (format!("2.|{ct}|{mac}"), EncError::BadLength),
        (format!("2.{iv}||{mac}"), EncError::BadLength),
        (format!("2.{}|{ct}|{mac}", b(15)), EncError::BadLength),
        (format!("2.{}|{ct}|{mac}", b(17)), EncError::BadLength),
        (format!("2.{iv}|{ct}|{}", b(31)), EncError::BadLength),
        (format!("2.{iv}|{ct}|{}", b(33)), EncError::BadLength),
        (format!("2.{iv}|{}|{mac}", b(15)), EncError::BadLength),
        (format!("2.{iv}|{}|{mac}", b(17)), EncError::BadLength),
        (
            format!("2.{iv}|{ct}|{}", mac.trim_end_matches('=')),
            EncError::BadBase64,
        ),
        (format!("2.{iv}|{ct}!|{mac}"), EncError::BadBase64),
        (format!("2.{iv}|{ct} |{mac}"), EncError::BadBase64),
        (
            format!("2.{iv}|{}|{mac}", ct.replace('=', "")),
            EncError::BadBase64,
        ),
        (format!("3.{}", b(100)), EncError::BadLength),
        (format!("4.{}|{}", b(256), b(32)), EncError::Malformed),
        ("4.".into(), EncError::BadLength),
        (
            format!("3.{}", "A".repeat(MAX_ENC_STRING_LEN + 1)),
            EncError::Malformed,
        ),
    ];
    for (s, want) in cases {
        assert_eq!(EncString::parse(&s).unwrap_err(), want, "{:.60}", s);
    }
}

#[test]
fn decrypt_round_trips_and_checks_the_key_kind() {
    let k = key(1);
    for plain in [
        &b""[..],
        b"a",
        &[0u8; 15],
        &[1u8; 16],
        &[2u8; 17],
        "p\u{e4}ss".as_bytes(),
    ] {
        let s = encrypt2(&k, [3; 16], plain);
        let out = EncString::parse(&s).unwrap().decrypt(&k).unwrap();
        assert_eq!(&out[..], plain);
    }
    // A type 2 string is not an RSA ciphertext, and vice versa.
    let der = STANDARD
        .decode(vectors()["rsa"]["pkcs8_der_b64"].as_str().unwrap())
        .unwrap();
    let rsa_key = RsaKey::from_pkcs8_der(&der).unwrap();
    assert_eq!(
        EncString::parse(&valid())
            .unwrap()
            .decrypt_rsa(&rsa_key)
            .unwrap_err(),
        EncError::WrongKind
    );
    let rsa_enc = EncString::parse(vectors()["rsa"]["sha1"].as_str().unwrap()).unwrap();
    assert_eq!(rsa_enc.decrypt(&k).unwrap_err(), EncError::WrongKind);
}

#[test]
fn the_mac_is_verified_before_the_cipher_runs() {
    // A ciphertext whose padding is invalid after decryption: with a
    // correct MAC the failure is BadPadding (the cipher ran) ...
    let k = key(1);
    let iv = [7u8; 16];
    let ct = vec![0x42u8; 16];
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&*k.mac).unwrap();
    mac.update(&iv);
    mac.update(&ct);
    let good_mac = mac.finalize().into_bytes();
    let enc = |mac: &[u8]| {
        format!(
            "2.{}|{}|{}",
            STANDARD.encode(iv),
            STANDARD.encode(&ct),
            STANDARD.encode(mac)
        )
    };
    assert_eq!(
        EncString::parse(&enc(&good_mac))
            .unwrap()
            .decrypt(&k)
            .unwrap_err(),
        EncError::BadPadding
    );
    // ... and with a MAC that is wrong in any single bit it is MacFailure,
    // so the cipher never saw the data.
    for bit in 0..256 {
        let mut bad = good_mac.to_vec();
        bad[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(
            EncString::parse(&enc(&bad))
                .unwrap()
                .decrypt(&k)
                .unwrap_err(),
            EncError::MacFailure,
            "bit {bit}"
        );
    }
}

#[test]
fn any_tampered_byte_fails_the_mac() {
    let k = key(1);
    let s = EncString::parse(&encrypt2(&k, [1; 16], b"a secret value that spans blocks")).unwrap();
    let EncString::Aes256CbcHmac { iv, ct, mac } = &s else {
        unreachable!()
    };
    for i in 0..iv.len() {
        let mut t = *iv;
        t[i] ^= 1;
        let e = EncString::Aes256CbcHmac {
            iv: t,
            ct: ct.clone(),
            mac: *mac,
        };
        assert_eq!(e.decrypt(&k).unwrap_err(), EncError::MacFailure, "iv {i}");
    }
    for i in 0..ct.len() {
        let mut t = ct.clone();
        t[i] ^= 0x80;
        let e = EncString::Aes256CbcHmac {
            iv: *iv,
            ct: t,
            mac: *mac,
        };
        assert_eq!(e.decrypt(&k).unwrap_err(), EncError::MacFailure, "ct {i}");
    }
    // The wrong key is the same failure.
    assert_eq!(s.decrypt(&key(2)).unwrap_err(), EncError::MacFailure);
}

#[test]
fn keys_must_be_exactly_64_bytes() {
    for len in [0usize, 1, 31, 32, 33, 48, 63, 65, 128] {
        assert_eq!(
            SymKey::from_slice(&vec![1u8; len]).unwrap_err(),
            EncError::KeyLength,
            "{len}"
        );
    }
    assert!(SymKey::from_slice(&[1u8; 64]).is_ok());
}

#[test]
fn invalid_utf8_is_an_error() {
    assert_eq!(
        utf8(Zeroizing::new(vec![0xff, 0xfe])).unwrap_err(),
        EncError::NotUtf8
    );
    assert_eq!(utf8(Zeroizing::new(b"ok".to_vec())).unwrap().as_str(), "ok");
}

#[test]
fn debug_never_shows_key_or_ciphertext() {
    let k = key(1);
    assert_eq!(format!("{k:?}"), "SymKey(<redacted>)");
    let s = valid();
    let dbg = format!("{:?}", EncString::parse(&s).unwrap());
    assert_eq!(dbg, "EncString(type 2)");
    assert!(!dbg.contains(&s[2..10]));
}

#[test]
fn error_codes_are_fixed_labels() {
    for (e, code) in [
        (EncError::Malformed, "malformed_encstring"),
        (EncError::UnsupportedType(9), "unsupported_encstring_type"),
        (EncError::KeyLength, "bad_key_length"),
        (EncError::MacFailure, "mac_failure"),
        (EncError::NotUtf8, "invalid_utf8"),
    ] {
        assert_eq!(e.code(), code);
    }
    assert_eq!(
        EncError::UnsupportedType(7).to_string(),
        "unsupported EncString type 7"
    );
}
