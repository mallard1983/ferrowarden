//! EncString: the text form Bitwarden clients use for every encrypted value,
//! `<type>.<base64 part>|<base64 part>|...`.
//!
//! Only the formats Ferrowarden implements are accepted, by an explicit
//! allow-list, and everything else is refused with a typed error. There is
//! no "try to guess" path: in particular type 0 (AES-CBC without a MAC) is
//! never decrypted, because an unauthenticated ciphertext can be altered by
//! whoever controls the server.
//!
//! | type | meaning                           | accepted                        |
//! |------|-----------------------------------|---------------------------------|
//! | 2    | AES-256-CBC + HMAC-SHA256         | yes, symmetric keys             |
//! | 3    | RSA-2048 OAEP, SHA-256            | yes, RSA keys                   |
//! | 4    | RSA-2048 OAEP, SHA-1              | yes, RSA keys                   |
//! | 0, 1, 5, 6, 7, others | legacy, deprecated or not implemented | refused, never decrypted |
//!
//! For type 2 the MAC (HMAC-SHA256 over `iv || ciphertext`) is verified in
//! constant time **before** the cipher sees a single byte of ciphertext.
//!
//! Implemented from the published description of the format and from what
//! Vaultwarden sends; no Bitwarden SDK code is used (docs/native-vault.md).

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD, Engine};
use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use rsa::{Oaep, PrivateKey};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Longest EncString text accepted. A note is limited to 10 000 characters by
/// the clients, which is about 14 KiB encrypted; anything near this limit is
/// not something a Bitwarden client wrote.
pub const MAX_ENC_STRING_LEN: usize = 256 * 1024;

const AES_BLOCK: usize = 16;
const IV_LEN: usize = 16;
const MAC_LEN: usize = 32;

/// Why an EncString or a key was refused. Carries no data from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncError {
    /// Not of the form `<digits>.<payload>`, or too long.
    Malformed,
    /// Type 0 (no MAC), 1, 5, 6, 7 or a type number we do not know. Never
    /// decrypted.
    UnsupportedType(u8),
    /// The type is allowed, but not for this key: a symmetric key was given a
    /// type 3/4 string, or an RSA key a type 2 string.
    WrongKind,
    /// Base64 that is not canonical standard base64.
    BadBase64,
    /// An IV, MAC or ciphertext of an impossible length.
    BadLength,
    /// A symmetric key that is not exactly 64 bytes (32 AES + 32 HMAC), or an
    /// RSA key outside 2048..=4096 bits.
    KeyLength,
    /// MAC mismatch: wrong key or altered data.
    MacFailure,
    /// The MAC was fine but the padding was not.
    BadPadding,
    /// RSA decryption failed.
    RsaFailure,
    /// The decrypted bytes are not valid UTF-8.
    NotUtf8,
}

impl EncError {
    /// A fixed label for events and counters.
    pub fn code(self) -> &'static str {
        match self {
            EncError::Malformed | EncError::BadBase64 | EncError::BadLength => {
                "malformed_encstring"
            }
            EncError::UnsupportedType(_) | EncError::WrongKind => "unsupported_encstring_type",
            EncError::KeyLength => "bad_key_length",
            EncError::MacFailure => "mac_failure",
            EncError::BadPadding | EncError::RsaFailure => "decrypt_failure",
            EncError::NotUtf8 => "invalid_utf8",
        }
    }
}

impl std::fmt::Display for EncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncError::UnsupportedType(t) => write!(f, "unsupported EncString type {t}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for EncError {}

/// A 64-byte symmetric key: 32 bytes for AES-256, 32 for HMAC-SHA256. Both
/// halves are wiped on drop, and `Debug` shows nothing. Deliberately not
/// `Clone`: key material is moved or borrowed, never duplicated.
pub struct SymKey {
    pub(super) enc: Zeroizing<[u8; 32]>,
    pub(super) mac: Zeroizing<[u8; 32]>,
}

impl SymKey {
    /// Build a key from exactly 64 bytes. Any other length (32-byte legacy
    /// keys included) is refused.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, EncError> {
        if bytes.len() != 64 {
            return Err(EncError::KeyLength);
        }
        let mut enc = Zeroizing::new([0u8; 32]);
        let mut mac = Zeroizing::new([0u8; 32]);
        enc.copy_from_slice(&bytes[..32]);
        mac.copy_from_slice(&bytes[32..]);
        Ok(Self { enc, mac })
    }

    /// Build a key from the two halves.
    pub fn from_parts(enc: Zeroizing<[u8; 32]>, mac: Zeroizing<[u8; 32]>) -> Self {
        Self { enc, mac }
    }
}

impl std::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SymKey(<redacted>)")
    }
}

/// An RSA private key (PKCS#8, 2048 to 4096 bits). Wiped on drop by the `rsa`
/// crate; `Debug` shows nothing.
pub struct RsaKey(PrivateKey);

impl RsaKey {
    /// Parse a PKCS#8 DER private key. Sizes outside 2048..=4096 bits are
    /// refused.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, EncError> {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::PublicKeyParts;
        let key = PrivateKey::from_pkcs8_der(der).map_err(|_| EncError::RsaFailure)?;
        if !(2048..=4096).contains(&key.n().bit_width()) {
            return Err(EncError::KeyLength);
        }
        Ok(Self(key))
    }
}

impl std::fmt::Debug for RsaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RsaKey(<redacted>)")
    }
}

/// A parsed EncString. Holds ciphertext only.
#[derive(Clone, PartialEq, Eq)]
pub enum EncString {
    /// Type 2.
    Aes256CbcHmac {
        iv: [u8; IV_LEN],
        ct: Vec<u8>,
        mac: [u8; MAC_LEN],
    },
    /// Type 3.
    RsaOaepSha256(Vec<u8>),
    /// Type 4.
    RsaOaepSha1(Vec<u8>),
}

impl std::fmt::Debug for EncString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let t = match self {
            EncString::Aes256CbcHmac { .. } => 2,
            EncString::RsaOaepSha256(_) => 3,
            EncString::RsaOaepSha1(_) => 4,
        };
        write!(f, "EncString(type {t})")
    }
}

fn b64(part: &str) -> Result<Vec<u8>, EncError> {
    // Standard alphabet, padding required, trailing bits must be zero: the
    // same bytes always have the same text.
    STANDARD.decode(part).map_err(|_| EncError::BadBase64)
}

impl EncString {
    /// Parse the text form. The type number is read first and checked against
    /// the allow-list before any payload is looked at.
    pub fn parse(s: &str) -> Result<Self, EncError> {
        if s.len() > MAX_ENC_STRING_LEN {
            return Err(EncError::Malformed);
        }
        let (ty, payload) = s.split_once('.').ok_or(EncError::Malformed)?;
        // One to three plain ASCII digits: no sign, no whitespace.
        if ty.is_empty() || ty.len() > 3 || !ty.bytes().all(|b| b.is_ascii_digit()) {
            return Err(EncError::Malformed);
        }
        let ty: u8 = ty.parse().map_err(|_| EncError::Malformed)?;
        match ty {
            2 => {
                let mut parts = payload.split('|');
                let (Some(iv), Some(ct), Some(mac), None) =
                    (parts.next(), parts.next(), parts.next(), parts.next())
                else {
                    return Err(EncError::Malformed);
                };
                let iv: [u8; IV_LEN] = b64(iv)?.try_into().map_err(|_| EncError::BadLength)?;
                let mac: [u8; MAC_LEN] = b64(mac)?.try_into().map_err(|_| EncError::BadLength)?;
                let ct = b64(ct)?;
                if ct.is_empty() || ct.len() % AES_BLOCK != 0 {
                    return Err(EncError::BadLength);
                }
                Ok(EncString::Aes256CbcHmac { iv, ct, mac })
            }
            3 | 4 => {
                if payload.contains('|') {
                    return Err(EncError::Malformed);
                }
                let data = b64(payload)?;
                // RSA-2048 to RSA-4096 ciphertexts are 256 to 512 bytes.
                if !(256..=512).contains(&data.len()) {
                    return Err(EncError::BadLength);
                }
                Ok(if ty == 3 {
                    EncString::RsaOaepSha256(data)
                } else {
                    EncString::RsaOaepSha1(data)
                })
            }
            other => Err(EncError::UnsupportedType(other)),
        }
    }

    /// Decrypt a type 2 string with a symmetric key. The MAC is checked first,
    /// in constant time; on a mismatch nothing is decrypted.
    pub fn decrypt(&self, key: &SymKey) -> Result<Zeroizing<Vec<u8>>, EncError> {
        let EncString::Aes256CbcHmac { iv, ct, mac } = self else {
            return Err(EncError::WrongKind);
        };
        let mut hmac = <Hmac<Sha256> as KeyInit>::new_from_slice(&*key.mac)
            .map_err(|_| EncError::KeyLength)?;
        hmac.update(iv);
        hmac.update(ct);
        // `verify_slice` compares in constant time.
        hmac.verify_slice(mac).map_err(|_| EncError::MacFailure)?;

        // Decrypt in place in a buffer that is wiped when dropped.
        let mut buf = Zeroizing::new(ct.clone());
        let cipher = cbc::Decryptor::<Aes256>::new(&(*key.enc).into(), iv.into());
        let len = cipher
            .decrypt_padded::<Pkcs7>(&mut buf)
            .map_err(|_| EncError::BadPadding)?
            .len();
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypt a type 2 string to UTF-8 text.
    pub fn decrypt_string(&self, key: &SymKey) -> Result<Zeroizing<String>, EncError> {
        utf8(self.decrypt(key)?)
    }

    /// Decrypt a type 3 or 4 string with an RSA private key (RSA-OAEP with
    /// SHA-256 or SHA-1, matching the type).
    pub fn decrypt_rsa(&self, key: &RsaKey) -> Result<Zeroizing<Vec<u8>>, EncError> {
        let out = match self {
            EncString::RsaOaepSha256(data) => key.0.decrypt(Oaep::<Sha256>::new(), data),
            EncString::RsaOaepSha1(data) => key.0.decrypt(Oaep::<sha1::Sha1>::new(), data),
            EncString::Aes256CbcHmac { .. } => return Err(EncError::WrongKind),
        };
        out.map(Zeroizing::new).map_err(|_| EncError::RsaFailure)
    }
}

/// Convert decrypted bytes to text without leaving a copy behind.
pub fn utf8(mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, EncError> {
    // Validate, then move the allocation into a String: no second copy.
    std::str::from_utf8(&bytes).map_err(|_| EncError::NotUtf8)?;
    String::from_utf8(std::mem::take(&mut *bytes))
        .map(Zeroizing::new)
        .map_err(|_| EncError::NotUtf8)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Encryption for tests only: the production binary never encrypts.
    use super::*;
    use cbc::cipher::BlockModeEncrypt;

    pub fn encrypt2(key: &SymKey, iv: [u8; 16], plain: &[u8]) -> String {
        let mut ct = plain.to_vec();
        ct.resize(plain.len() + AES_BLOCK, 0);
        let len = cbc::Encryptor::<Aes256>::new(&(*key.enc).into(), &iv.into())
            .encrypt_padded::<Pkcs7>(&mut ct, plain.len())
            .unwrap()
            .len();
        ct.truncate(len);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&*key.mac).unwrap();
        mac.update(&iv);
        mac.update(&ct);
        let mac = mac.finalize().into_bytes();
        format!(
            "2.{}|{}|{}",
            STANDARD.encode(iv),
            STANDARD.encode(ct),
            STANDARD.encode(mac)
        )
    }

    pub fn key(seed: u8) -> SymKey {
        let bytes: Vec<u8> = (0..64u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(seed))
            .collect();
        SymKey::from_slice(&bytes).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{encrypt2, key};
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("testdata/vectors.json")).unwrap()
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
        let s =
            EncString::parse(&encrypt2(&k, [1; 16], b"a secret value that spans blocks")).unwrap();
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
}
