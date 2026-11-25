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
mod tests {
    use super::*;

    // RFC 6238 appendix B: the shared secrets are the ASCII strings
    // "12345678901234567890" (SHA1), "...890123456789012" (SHA256, 32 bytes) and
    // "...1234" (SHA512, 64 bytes); the codes are the 8-digit values listed
    // there, T0 = 0 and a 30 second step.
    fn b32(bytes: &[u8]) -> String {
        const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let (mut out, mut bits, mut have) = (String::new(), 0u32, 0u32);
        for &b in bytes {
            bits = (bits << 8) | u32::from(b);
            have += 8;
            while have >= 5 {
                have -= 5;
                out.push(A[((bits >> have) & 31) as usize] as char);
            }
        }
        if have > 0 {
            out.push(A[((bits << (5 - have)) & 31) as usize] as char);
        }
        out
    }

    const SEED1: &[u8] = b"12345678901234567890";
    const SEED256: &[u8] = b"12345678901234567890123456789012";
    const SEED512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn rfc_6238_appendix_b() {
        let cases: [(&str, &[u8], u64, &str); 18] = [
            ("SHA1", SEED1, 59, "94287082"),
            ("SHA256", SEED256, 59, "46119246"),
            ("SHA512", SEED512, 59, "90693936"),
            ("SHA1", SEED1, 1111111109, "07081804"),
            ("SHA256", SEED256, 1111111109, "68084774"),
            ("SHA512", SEED512, 1111111109, "25091201"),
            ("SHA1", SEED1, 1111111111, "14050471"),
            ("SHA256", SEED256, 1111111111, "67062674"),
            ("SHA512", SEED512, 1111111111, "99943326"),
            ("SHA1", SEED1, 1234567890, "89005924"),
            ("SHA256", SEED256, 1234567890, "91819424"),
            ("SHA512", SEED512, 1234567890, "93441116"),
            ("SHA1", SEED1, 2000000000, "69279037"),
            ("SHA256", SEED256, 2000000000, "90698825"),
            ("SHA512", SEED512, 2000000000, "38618901"),
            ("SHA1", SEED1, 20000000000, "65353130"),
            ("SHA256", SEED256, 20000000000, "77737706"),
            ("SHA512", SEED512, 20000000000, "47863826"),
        ];
        for (alg, seed, t, want) in cases {
            let uri = format!(
                "otpauth://totp/x?secret={}&algorithm={alg}&digits=8",
                b32(seed)
            );
            assert_eq!(code(&uri, t).unwrap().as_str(), want, "{alg} at {t}");
        }
    }

    #[test]
    fn bare_secret_is_sha1_six_digits_and_forgiving() {
        // Same secret as RFC 6238 SHA1 at T=59: the 6-digit code is the last
        // six digits of 94287082.
        let s = b32(SEED1);
        assert_eq!(code(&s, 59).unwrap().as_str(), "287082");
        let spaced = format!("{} {}", s[..8].to_lowercase(), &s[8..]);
        assert_eq!(code(&spaced, 59).unwrap().as_str(), "287082");
        assert_eq!(code(&format!("{s}===="), 59).unwrap().as_str(), "287082");
    }

    #[test]
    fn otpauth_parameters_and_defaults() {
        let s = b32(SEED1);
        let plain = format!("otpauth://totp/Issuer:me?secret={s}&issuer=Issuer");
        assert_eq!(code(&plain, 59).unwrap().as_str(), "287082");
        // Period 60: the step changes every minute, so T=59 and T=0 share a code.
        let p60 = format!("otpauth://totp/x?secret={s}&period=60");
        assert_eq!(code(&p60, 59), code(&p60, 0));
        assert_ne!(code(&p60, 59), code(&p60, 60));
        // Parameter names are case-insensitive; values are percent-decoded.
        let odd = format!("OTPAUTH://totp/x?SECRET={}&Digits=7", s.replace('A', "%41"));
        assert_eq!(code(&odd, 59).unwrap().len(), 7);
    }

    #[test]
    fn invalid_specifications_yield_none() {
        let s = b32(SEED1);
        for bad in [
            "".to_string(),
            "not base32 !".to_string(),
            "1".to_string(),
            format!("otpauth://totp/x?secret={s}&digits=0"),
            format!("otpauth://totp/x?secret={s}&digits=11"),
            format!("otpauth://totp/x?secret={s}&digits=six"),
            format!("otpauth://totp/x?secret={s}&period=0"),
            format!("otpauth://totp/x?secret={s}&algorithm=MD5"),
            "otpauth://totp/x?issuer=nosecret".to_string(),
            "otpauth://totp/x".to_string(),
            "steam://".to_string(),
            "steam://0189".to_string(),
        ] {
            assert!(code(&bad, 59).is_none(), "{bad}");
        }
    }

    #[test]
    fn steam_codes_are_five_characters_of_the_steam_alphabet() {
        // 1_699_999_980 is the start of a 30 second window.
        let c = code("steam://JBSWY3DPEHPK3PXP", 1_699_999_980).unwrap();
        assert_eq!(c.len(), 5);
        assert!(c.bytes().all(|b| STEAM_ALPHABET.contains(&b)));
        // Same window, same code; next window differs (with overwhelming
        // probability for this fixed secret; checked once here).
        assert_eq!(
            c,
            code("steam://JBSWY3DPEHPK3PXP", 1_699_999_980 + 29).unwrap()
        );
        assert_ne!(
            c,
            code("steam://JBSWY3DPEHPK3PXP", 1_699_999_980 + 30).unwrap()
        );
    }
}
