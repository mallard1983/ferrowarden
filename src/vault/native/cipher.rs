//! From encrypted vault items to what Ferrowarden needs, and nothing more.
//!
//! Two jobs, kept apart on purpose:
//!
//! - [`build_metadata`] runs at unlock and sync. It decrypts only what a
//!   [`CredentialEntry`] holds: the name, the URIs that bind the item to
//!   hosts, custom field names, and the value of the reserved
//!   `ferrowarden_uris` field. Which secrets exist (password, username, TOTP,
//!   notes) is read from the presence of the ciphertext; the secrets
//!   themselves are not touched.
//! - [`builtin_value`] and [`field_value`] run per request. They decrypt one
//!   value into a [`Zeroizing`] string and return it; nothing is cached.
//!
//! Fail closed, per item: if anything needed for an item cannot be read
//! safely (an EncString type outside the allow-list, a key of the wrong
//! length, bad base64, a MAC that does not verify, a missing or undecryptable
//! organisation or per-item key, text that is not UTF-8), the item is left
//! out and the reason is counted ([`ExclusionReport`]). There is no fallback
//! to a weaker format.

use std::collections::HashMap;
use std::ops::Deref;

use zeroize::Zeroizing;

use super::api::{RawCipher, RawField};
use super::enc::{EncError, EncString, RsaKey, SymKey};
use super::keys::unwrap_sym_key;
use super::totp;
use crate::error::{FerroError, FerroResult};
use crate::vault::model::{
    match_type_is_binding, split_uris, Builtin, CredentialEntry, FieldInfo, FieldKind, ItemKind,
    BINDINGS_FIELD,
};

/// Every key needed to read the vault. Wiped on drop; never printed.
pub struct KeyRing {
    pub user: SymKey,
    /// Kept for organisations that appear in a later sync.
    pub rsa: Option<RsaKey>,
    /// Organisation id -> organisation key. An organisation whose key could
    /// not be unwrapped is absent, and its items are excluded.
    pub org: HashMap<String, SymKey>,
}

impl KeyRing {
    pub fn view(&self) -> Keys<'_> {
        Keys {
            user: &self.user,
            org: &self.org,
        }
    }
}

/// Borrowed view of the keys, so a sync can decrypt with the keys of the old
/// state and the organisation keys of the new one without copying a key.
pub struct Keys<'a> {
    pub user: &'a SymKey,
    pub org: &'a HashMap<String, SymKey>,
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("organizations", &self.org.len())
            .finish_non_exhaustive()
    }
}

/// The key that decrypts one item's fields: the user or organisation key, or
/// the item's own key.
enum ItemKey<'a> {
    Shared(&'a SymKey),
    Own(SymKey),
}

impl Deref for ItemKey<'_> {
    type Target = SymKey;
    fn deref(&self) -> &SymKey {
        match self {
            ItemKey::Shared(k) => k,
            ItemKey::Own(k) => k,
        }
    }
}

/// Reason codes for excluded items (events carry these, never names).
pub mod reason {
    pub const MISSING_ORG_KEY: &str = "missing_org_key";
    pub const ITEM_KEY: &str = "item_key_undecryptable";
    pub const MISSING_NAME: &str = "missing_name";
    /// The item's collection hides passwords from this account
    /// (`viewPassword: false`) and `vault.allow_hidden_passwords` is off.
    pub const HIDDEN_PASSWORD: &str = "hidden_password";
}

/// Whether the server marks this item's password as hidden from the account
/// (a collection with "Hide passwords"). Only an explicit `false` counts.
pub fn is_password_hidden(c: &RawCipher) -> bool {
    c.view_password == Some(false)
}

/// Items of the supported kinds: login and secure note.
pub fn is_supported_kind(c: &RawCipher) -> bool {
    u8::try_from(c.item_type)
        .ok()
        .and_then(ItemKind::from_type)
        .is_some()
}

fn item_key<'a>(keys: &Keys<'a>, c: &RawCipher) -> Result<ItemKey<'a>, &'static str> {
    let base: &'a SymKey = match &c.organization_id {
        Some(org) => keys.org.get(org).ok_or(reason::MISSING_ORG_KEY)?,
        None => keys.user,
    };
    match c.key.as_deref().filter(|k| !k.is_empty()) {
        None => Ok(ItemKey::Shared(base)),
        Some(wrapped) => unwrap_sym_key(base, wrapped)
            .map(ItemKey::Own)
            .map_err(|e| match e {
                // A wrong length or format is reported as such; a failed MAC
                // or padding is "this item's key cannot be read".
                EncError::KeyLength | EncError::UnsupportedType(_) | EncError::Malformed => {
                    e.code()
                }
                _ => reason::ITEM_KEY,
            }),
    }
}

/// Decrypt one EncString field to text.
fn dec(key: &SymKey, s: &str) -> Result<Zeroizing<String>, &'static str> {
    EncString::parse(s)
        .and_then(|e| e.decrypt_string(key))
        .map_err(EncError::code)
}

/// Whether a ciphertext field holds a value: present and not empty.
fn present(s: &Option<String>) -> bool {
    s.as_deref().is_some_and(|v| !v.is_empty())
}

/// What an item contributes to the credential map, or why it cannot.
/// Only call this for supported kinds ([`is_supported_kind`]).
pub fn build_metadata(
    keys: &Keys<'_>,
    c: &RawCipher,
) -> Result<(String, CredentialEntry), &'static str> {
    let kind = u8::try_from(c.item_type)
        .ok()
        .and_then(ItemKind::from_type)
        .ok_or("unsupported_item_type")?;
    let key = item_key(keys, c)?;

    let name = match c.name.as_deref() {
        Some(n) if !n.is_empty() => dec(&key, n)?,
        _ => return Err(reason::MISSING_NAME),
    };

    // Custom fields: names and kinds, plus the reserved bindings field's value.
    let mut bindings_override = None;
    let mut fields = Vec::new();
    for f in c.fields.as_deref().unwrap_or_default() {
        let Some(enc_name) = f.name.as_deref().filter(|n| !n.is_empty()) else {
            continue;
        };
        let field_name = dec(&key, enc_name)?;
        if field_name.as_str() == BINDINGS_FIELD {
            if let Some(v) = f.value.as_deref().filter(|v| !v.is_empty()) {
                bindings_override = Some(split_uris(&dec(&key, v)?));
            }
            continue;
        }
        let kind = u8::try_from(f.field_type)
            .ok()
            .and_then(|t| FieldKind::from_wire(t, f.linked_id));
        let Some(kind) = kind else { continue };
        fields.push(FieldInfo {
            name: field_name.as_str().to_string(),
            kind,
        });
    }

    // Login URIs. Regular-expression and "never" matches are not host
    // bindings, so they are not even decrypted.
    let login = c.login.as_ref();
    let mut login_uris = Vec::new();
    for u in login.and_then(|l| l.uris.as_deref()).unwrap_or_default() {
        let match_type = u.match_type.and_then(|m| u8::try_from(m).ok());
        if u.match_type.is_some() && match_type.is_none() {
            // A match type that does not fit the format: not understood.
            return Err("malformed_item");
        }
        if !match_type_is_binding(match_type) {
            continue;
        }
        let Some(enc_uri) = u.uri.as_deref().filter(|u| !u.is_empty()) else {
            continue;
        };
        let uri = dec(&key, enc_uri)?;
        if !uri.trim().is_empty() {
            login_uris.push(uri.as_str().to_string());
        }
    }

    let entry = CredentialEntry {
        id: c.id.clone(),
        kind,
        uris: bindings_override.unwrap_or(login_uris),
        has_username: login.is_some_and(|l| present(&l.username)),
        has_password: login.is_some_and(|l| present(&l.password)),
        has_totp: login.is_some_and(|l| present(&l.totp)),
        has_notes: present(&c.notes),
        fields,
        reprompt: c.reprompt != 0,
    };
    Ok((name.as_str().to_string(), entry))
}

fn not_found(label: &str) -> FerroError {
    FerroError::CredentialNotFound(label.to_string())
}

/// A failure while decrypting a requested value. The reason is not shown to
/// the agent (the same generic error bw serve gives); the log gets the fixed
/// code, never the item's name or any data.
fn unreadable(code: &'static str) -> FerroError {
    tracing::warn!(reason = code, "A vault value could not be decrypted");
    FerroError::Internal("vault returned an error".to_string())
}

fn dec_value(key: &SymKey, s: &str) -> FerroResult<Zeroizing<String>> {
    dec(key, s).map_err(unreadable)
}

/// One built-in value: decrypted now, returned, not kept.
pub fn builtin_value(
    keys: &Keys<'_>,
    c: &RawCipher,
    which: Builtin,
    unix_time: u64,
    label: &str,
) -> FerroResult<Zeroizing<String>> {
    let key = item_key(keys, c).map_err(unreadable)?;
    // The ciphertext to read, or "not found" when the item has no such value.
    let login = if c.item_type == 1 {
        c.login.as_ref()
    } else {
        None
    };
    let ciphertext: Option<&str> = match which {
        Builtin::Password => login.and_then(|l| l.password.as_deref()),
        Builtin::Username => login.and_then(|l| l.username.as_deref()),
        Builtin::Totp => login.and_then(|l| l.totp.as_deref()),
        Builtin::Notes => c.notes.as_deref(),
    };
    let ciphertext = ciphertext
        .filter(|s| !s.is_empty())
        .ok_or_else(|| not_found(label))?;
    let plain = dec_value(&key, ciphertext)?;
    // Like the Bitwarden CLI, a value that is only whitespace counts as none.
    if plain.trim().is_empty() {
        return Err(not_found(label));
    }
    if which == Builtin::Totp {
        // The code, never the stored secret. A specification that cannot
        // produce a code is the same as no TOTP.
        return totp::code(&plain, unix_time).ok_or_else(|| not_found(label));
    }
    Ok(plain)
}

/// One custom field's value, by name. Linked fields resolve to the login
/// username or password. More than one field with the name is ambiguous.
pub fn field_value(
    keys: &Keys<'_>,
    c: &RawCipher,
    field: &str,
    label: &str,
) -> FerroResult<Zeroizing<String>> {
    let key = item_key(keys, c).map_err(unreadable)?;
    let mut matches: Vec<&RawField> = Vec::new();
    for f in c.fields.as_deref().unwrap_or_default() {
        let Some(enc_name) = f.name.as_deref().filter(|n| !n.is_empty()) else {
            continue;
        };
        let name = dec_value(&key, enc_name)?;
        if name.as_str() == field {
            matches.push(f);
        }
    }
    let found = match matches.as_slice() {
        [one] => *one,
        [] => return Err(not_found(label)),
        _ => {
            return Err(FerroError::AmbiguousField {
                item: label.to_string(),
                field: field.to_string(),
            })
        }
    };
    let ciphertext = if found.field_type == 3 {
        let login = c.login.as_ref();
        match found.linked_id {
            Some(100) => login.and_then(|l| l.username.as_deref()),
            Some(101) => login.and_then(|l| l.password.as_deref()),
            _ => return Err(not_found(label)),
        }
    } else {
        found.value.as_deref()
    };
    match ciphertext.filter(|s| !s.is_empty()) {
        Some(s) => dec_value(&key, s),
        None => Err(not_found(label)),
    }
}

#[cfg(test)]
mod tests;
