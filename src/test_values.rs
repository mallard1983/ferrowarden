//! Stand-in secret values for unit tests (test builds only).
//!
//! A test that needs a password or a token gets one here, made at run time
//! from the operating system's random generator. No part of it is a literal:
//! a fixed string in a test would read as a hard-coded credential, and a fixed
//! prefix copied into the value would too. Two calls never return the same
//! value, so tests that need distinct values just call this twice.

/// 32 lowercase hex characters (128 random bits).
pub fn random_secret() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the OS random generator failed in a test");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests;
