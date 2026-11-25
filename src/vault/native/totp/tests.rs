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
