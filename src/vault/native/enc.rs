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
pub(crate) mod test_support;

#[cfg(test)]
mod tests;
