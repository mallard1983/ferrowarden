//! Generating a credential's value (docs/managed-credentials.md).
//!
//! The value comes from the operating system's random generator
//! (`getrandom`) and is picked **uniformly** from the character set by
//! rejection sampling: a random byte is used only when it falls below the
//! largest multiple of the set's size that fits in 256, so no character is
//! more likely than another (a plain `byte % size` would favour the first
//! `256 % size` characters).
//!
//! The result is a [`Zeroizing`] string, and so is every buffer of random
//! bytes on the way to it. A generated value is never logged, never put in an
//! event and never returned to the agent: it goes from here to the vault
//! (`vault::native`, encrypted) and nowhere else.

use zeroize::Zeroizing;

use crate::error::{FerroError, FerroResult};

/// The shortest generated value.
pub const MIN_LENGTH: u32 = 16;
/// The longest generated value.
pub const MAX_LENGTH: u32 = 128;
/// The length used when a request leaves it out.
pub const DEFAULT_LENGTH: u32 = 32;

const ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// Letters, digits and the symbols `-_.~!@#%^*+=:,`: none of the characters
/// that most often break a shell command, a URL or a JSON string (no quotes,
/// backslash, `$`, backtick, space, `&`, `;`, `|`, `<` or `>`). A few of the
/// symbols still mean something in some places (`*` and `!` in a shell, `#`
/// and `%` in a URL), so the value is quoted or encoded where that matters.
const ASCII: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~!@#%^*+=:,";
const HEX: &[u8] = b"0123456789abcdef";
const BASE64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The character set of a generated value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Charset {
    /// `A-Z a-z 0-9` (62 characters). The default.
    #[default]
    Alphanumeric,
    /// Letters, digits and `-_.~!@#%^*+=:,` (76 characters).
    Ascii,
    /// `0-9 a-f` (16 characters).
    Hex,
    /// The URL-safe base64 alphabet, `A-Z a-z 0-9 - _` (64 characters), without
    /// padding.
    Base64Url,
}

impl Charset {
    pub const ALL: [Charset; 4] = [
        Charset::Alphanumeric,
        Charset::Ascii,
        Charset::Hex,
        Charset::Base64Url,
    ];

    /// The name used in requests, approvals and events.
    pub fn as_str(self) -> &'static str {
        match self {
            Charset::Alphanumeric => "alphanumeric",
            Charset::Ascii => "ascii",
            Charset::Hex => "hex",
            Charset::Base64Url => "base64url",
        }
    }

    pub fn parse(name: &str) -> Option<Charset> {
        Charset::ALL.into_iter().find(|c| c.as_str() == name)
    }

    /// The characters of the set, in a fixed order.
    pub fn alphabet(self) -> &'static [u8] {
        match self {
            Charset::Alphanumeric => ALPHANUMERIC,
            Charset::Ascii => ASCII,
            Charset::Hex => HEX,
            Charset::Base64Url => BASE64URL,
        }
    }
}

/// `length` is within [`MIN_LENGTH`], [`MAX_LENGTH`].
pub fn check_length(length: u32) -> FerroResult<u32> {
    if (MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        Ok(length)
    } else {
        Err(FerroError::InvalidRequest(format!(
            "`generate.length` must be a whole number from {MIN_LENGTH} to {MAX_LENGTH}"
        )))
    }
}

/// A random value of `length` characters from `charset`, from the operating
/// system's random generator.
pub fn generate(charset: Charset, length: u32) -> FerroResult<Zeroizing<String>> {
    generate_with(charset, length, |buf| getrandom::fill(buf).is_ok())
}

/// [`generate`] with the source of random bytes given: it fills the buffer and
/// answers whether it could. Tests use it to feed fixed bytes and to check the
/// rejection rule deterministically.
pub fn generate_with(
    charset: Charset,
    length: u32,
    mut fill: impl FnMut(&mut [u8]) -> bool,
) -> FerroResult<Zeroizing<String>> {
    let length = check_length(length)?;
    let alphabet = charset.alphabet();
    let size = alphabet.len();
    // Bytes at or above this limit would make the low characters likelier.
    let limit = 256 - (256 % size);
    let wanted = length as usize;
    let mut out = Zeroizing::new(String::with_capacity(wanted));
    let mut bytes = Zeroizing::new(vec![0u8; wanted * 2]);
    // A source that keeps producing rejected bytes cannot hold a request
    // forever: bounded, and then an error (the odds of reaching the bound
    // with a real generator are nil).
    for _ in 0..64 {
        if !fill(&mut bytes) {
            return Err(FerroError::Internal(
                "the random generator failed".to_string(),
            ));
        }
        for &b in bytes.iter() {
            if usize::from(b) < limit {
                out.push(char::from(alphabet[usize::from(b) % size]));
                if out.len() == wanted {
                    return Ok(out);
                }
            }
        }
    }
    Err(FerroError::Internal(
        "the random generator did not produce enough usable bytes".to_string(),
    ))
}

#[cfg(test)]
mod tests;
