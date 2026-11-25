//! One-time codes from a stored TOTP secret (RFC 6238, HOTP of RFC 4226).
//!
//! What a Bitwarden item can hold in its TOTP field:
//! - a bare base32 secret (case-insensitive; spaces, dashes and `=` ignored),
//! - an `otpauth://totp/...?secret=...` URI with the optional parameters
//!   `algorithm` (SHA1, SHA256, SHA512), `digits` (1 to 10) and `period`
//!   (more than 0 seconds),
//! - `steam://<base32 secret>`: Steam Guard's five-character code.
//!
//! Anything else (bad base32, an unknown algorithm, digits or period out of
//! range, no secret) yields `None`. The secret and every intermediate value
//! are wiped when dropped.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// Decode RFC 4648 base32. Case-insensitive; whitespace, `-` and `=` are
/// skipped. `None` for any other character or for an empty secret.
fn base32_decode(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() * 5 / 8));
    let mut bits: u32 = 0;
    let mut have = 0u32;
    for c in s.chars() {
        if c.is_whitespace() || c == '=' || c == '-' {
            continue;
        }
        let v = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return None,
        };
        bits = (bits << 5) | v;
        have += 5;
        if have >= 8 {
            have -= 8;
            out.push((bits >> have) as u8);
            bits &= (1 << have) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

/// HOTP's 31-bit dynamic truncation of HMAC(`key`, `counter`).
fn hotp_truncated(alg: Algorithm, key: &[u8], counter: u64) -> Option<u32> {
    fn truncate(digest: &[u8]) -> u32 {
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ])
    }
    let msg = counter.to_be_bytes();
    match alg {
        Algorithm::Sha1 => {
            let mut m = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(key).ok()?;
            m.update(&msg);
            Some(truncate(&m.finalize().into_bytes()))
        }
        Algorithm::Sha256 => {
            let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).ok()?;
            m.update(&msg);
            Some(truncate(&m.finalize().into_bytes()))
        }
        Algorithm::Sha512 => {
            let mut m = <Hmac<Sha512> as KeyInit>::new_from_slice(key).ok()?;
            m.update(&msg);
            Some(truncate(&m.finalize().into_bytes()))
        }
    }
}

struct Spec {
    secret: Zeroizing<Vec<u8>>,
    alg: Algorithm,
    digits: u32,
    period: u64,
    steam: bool,
}

fn parse(spec: &str) -> Option<Spec> {
    let spec = spec.trim();
    if let Some(rest) = spec.strip_prefix("steam://") {
        return Some(Spec {
            secret: base32_decode(rest)?,
            alg: Algorithm::Sha1,
            digits: 5,
            period: 30,
            steam: true,
        });
    }
    if spec.len() >= 10 && spec[..10].eq_ignore_ascii_case("otpauth://") {
        let query = spec.split_once('?')?.1;
        let query = query.split_once('#').map_or(query, |(q, _)| q);
        let mut secret = None;
        let (mut alg, mut digits, mut period) = (Algorithm::Sha1, 6u32, 30u64);
        for pair in query.split('&') {
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            let v = urlencoding::decode(v).ok()?;
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(Zeroizing::new(v.into_owned())),
                "algorithm" => {
                    alg = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return None,
                    }
                }
                "digits" => digits = v.parse().ok()?,
                "period" => period = v.parse().ok()?,
                _ => {}
            }
        }
        if !(1..=10).contains(&digits) || period == 0 {
            return None;
        }
        return Some(Spec {
            secret: base32_decode(&secret?)?,
            alg,
            digits,
            period,
            steam: false,
        });
    }
    // A bare secret.
    Some(Spec {
        secret: base32_decode(spec)?,
        alg: Algorithm::Sha1,
        digits: 6,
        period: 30,
        steam: false,
    })
}

/// The code for `spec` at `unix_time` (seconds), or `None` if `spec` is not a
/// usable TOTP specification.
pub fn code(spec: &str, unix_time: u64) -> Option<Zeroizing<String>> {
    let s = parse(spec)?;
    let n = hotp_truncated(s.alg, &s.secret, unix_time / s.period)?;
    if s.steam {
        let mut n = n;
        let mut out = Zeroizing::new(String::with_capacity(5));
        for _ in 0..5 {
            out.push(STEAM_ALPHABET[(n % 26) as usize] as char);
            n /= 26;
        }
        return Some(out);
    }
    let modulus = 10u64.pow(s.digits);
    Some(Zeroizing::new(format!(
        "{:0width$}",
        u64::from(n) % modulus,
        width = s.digits as usize
    )))
}

#[cfg(test)]
mod tests;
