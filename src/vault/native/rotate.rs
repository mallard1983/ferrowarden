//! Editing an existing item for a rotation (docs/managed-credentials.md).
//!
//! Written from the item format and the way the server accepts an edit, with
//! the primitives of [`super::enc`]. No Bitwarden client or SDK code is used
//! (docs/native-vault.md, "Provenance and licence").
//!
//! [`start`], [`commit`] and [`abort`] edit an item the server already holds,
//! as a [`serde_json::Value`] **round-trip**: the item is read
//! (`GET /api/ciphers/{id}`), only the members named below are changed, and
//! every other member (unknown ones included) is sent back as it came, with
//! `lastKnownRevisionDate` set to the revision that was read, so that the
//! server refuses the write if anyone changed the item in between. Fields
//! Ferrowarden does not change keep their existing ciphertext; only the new
//! values are encrypted.
//!
//! What a `PUT /api/ciphers/{id}` is sent, member by member (checked against
//! Vaultwarden 1.36.0 and 1.37.5):
//!
//! * **dropped**, because they are the server's own bookkeeping and the PUT
//!   body does not read them ([`RESPONSE_ONLY`] and `data`): `object`, `id`
//!   (it is in the URL), `creationDate`, `revisionDate` (replaced by
//!   `lastKnownRevisionDate`), `deletedDate`, `archivedDate`, `attachments`
//!   (attachments are separate rows the update leaves alone), `collectionIds`
//!   (an edit does not change collections: the item stays where it is),
//!   `edit`, `viewPassword`, `permissions`, `organizationUseTotp` and `data`
//!   (a legacy copy of the type's members);
//! * **sent back unchanged**: everything else, notably `type`, `name`,
//!   `notes`, `key` (the item's own wrapped key), `organizationId`,
//!   `folderId`, `favorite`, `reprompt`, `secureNote`, `card`, `identity`,
//!   `sshKey`, the whole of `login` (URIs and their checksums, the TOTP
//!   secret, any FIDO2 credentials, unknown members) and `fields`, apart from
//!   what each operation changes below.
//!
//! One member is **added** by the caller (`NativeVault::rotate`), not here:
//! `encryptedFor`, the account's own id, which Vaultwarden 1.37 requires in a
//! `PUT` (as in a create) and a `GET` does not return.
//!
//! The operations change **only** these members:
//!
//! * [`start`]: appends a hidden (type 1) custom field `ferrowarden_next`
//!   whose value is the new password, encrypted with the item's key.
//! * [`commit`]: `login.password` becomes the pending field's ciphertext **as
//!   it is** (same key, nothing decrypted and re-encrypted for it; it is first
//!   checked to decrypt under the item's key, and the commit fails closed if
//!   not), the old `login.password` ciphertext goes to the front of
//!   `passwordHistory` as `{ password, lastUsedDate }` (newest first, at most
//!   five entries kept, the way the Bitwarden clients keep it),
//!   `login.passwordRevisionDate` is set to now, and the pending field is
//!   removed.
//! * [`abort`]: the pending field is removed.
//!
//! The item's encryption key is its own key (`key`, unwrapped with the
//! organisation key) if it has one, else the organisation key.
//!
//! Nothing here touches the network or logs anything.

use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use super::enc::{encrypt_str, EncError, EncString, SymKey};
use super::keys::unwrap_sym_key;
use crate::vault::model::{is_next_field_name, NEXT_FIELD};

/// The members of an item's JSON that are the server's own and are not sent
/// back in a `PUT` (see the module documentation for why each is dropped; the
/// legacy `data` member is dropped as well).
pub const RESPONSE_ONLY: [&str; 12] = [
    "object",
    "id",
    "creationDate",
    "revisionDate",
    "deletedDate",
    "archivedDate",
    "attachments",
    "collectionIds",
    "edit",
    "viewPassword",
    "permissions",
    "organizationUseTotp",
];
/// The legacy copy of the type's members, also dropped.
const LEGACY_MEMBER: &str = "data";

/// Most password-history entries kept on an item (the clients' limit).
pub const MAX_PASSWORD_HISTORY: usize = 5;

/// Why an item could not be edited. Carries nothing from the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotateError {
    /// Encrypting or decrypting failed, or a field name could not be read.
    Crypto(EncError),
    /// Not a login, or not the shape of one, or without a password.
    NotRotatable,
    /// A rotation is already pending on the item (start).
    AlreadyPending,
    /// No rotation is pending on the item (commit, abort).
    NoPending,
    /// More than one `ferrowarden_next` field: a person has to fix the item.
    DuplicatePending,
    /// The pending value does not decrypt under the item's key.
    CorruptPending,
}

impl From<EncError> for RotateError {
    fn from(e: EncError) -> Self {
        RotateError::Crypto(e)
    }
}

/// The key an item's fields are encrypted with.
enum ItemKey<'a> {
    Org(&'a SymKey),
    Own(SymKey),
}

impl ItemKey<'_> {
    fn key(&self) -> &SymKey {
        match self {
            ItemKey::Org(k) => k,
            ItemKey::Own(k) => k,
        }
    }
}

/// The item's own key (`key`, unwrapped with the organisation key) if it has
/// one, else the organisation key.
fn item_key<'a>(org_key: &'a SymKey, item: &Value) -> Result<ItemKey<'a>, RotateError> {
    match item
        .get("key")
        .and_then(Value::as_str)
        .filter(|k| !k.is_empty())
    {
        None => Ok(ItemKey::Org(org_key)),
        Some(wrapped) => Ok(ItemKey::Own(unwrap_sym_key(org_key, wrapped)?)),
    }
}

/// The index of the item's `ferrowarden_next` field. `Ok(None)` when there is
/// none; an error when there is more than one, or when a field's name cannot
/// be read (it could be ours).
fn find_next(key: &SymKey, item: &Value) -> Result<Option<usize>, RotateError> {
    let Some(fields) = item.get("fields").and_then(Value::as_array) else {
        return Ok(None);
    };
    let mut found = None;
    for (i, f) in fields.iter().enumerate() {
        let Some(enc_name) = f
            .get("name")
            .and_then(Value::as_str)
            .filter(|n| !n.is_empty())
        else {
            continue;
        };
        let name = EncString::parse(enc_name)?.decrypt_string(key)?;
        if is_next_field_name(&name) && found.replace(i).is_some() {
            return Err(RotateError::DuplicatePending);
        }
    }
    Ok(found)
}

/// The item must be a login with a password.
fn check_login(item: &Value) -> Result<&Map<String, Value>, RotateError> {
    if item.get("type").and_then(Value::as_i64) != Some(1) {
        return Err(RotateError::NotRotatable);
    }
    let login = item
        .get("login")
        .and_then(Value::as_object)
        .ok_or(RotateError::NotRotatable)?;
    match login.get("password").and_then(Value::as_str) {
        Some(p) if !p.is_empty() => Ok(login),
        _ => Err(RotateError::NotRotatable),
    }
}

/// The body of the `PUT`: the item as read, without the server's own members
/// and with `lastKnownRevisionDate` set to the revision that was read.
fn put_body(mut item: Value, revision: &str) -> Result<Value, RotateError> {
    let Some(map) = item.as_object_mut() else {
        return Err(RotateError::NotRotatable);
    };
    for member in RESPONSE_ONLY {
        map.remove(member);
    }
    map.remove(LEGACY_MEMBER);
    map.insert("lastKnownRevisionDate".to_string(), json!(revision));
    Ok(item)
}

/// `fields` after the one at `index` has been removed: `null` when none is
/// left (an item that had no custom fields before the rotation has none
/// after it).
fn without_field(body: &Value, index: usize) -> Value {
    let mut fields = body
        .get("fields")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    fields.remove(index);
    if fields.is_empty() {
        Value::Null
    } else {
        Value::Array(fields)
    }
}

/// Start: add the hidden `ferrowarden_next` field holding `next`, encrypted
/// with the item's key. Nothing else changes. `revision` is the item's
/// `revisionDate` as it was read.
pub fn start(
    item: &Value,
    org_key: &SymKey,
    revision: &str,
    next: &str,
) -> Result<Value, RotateError> {
    check_login(item)?;
    let key = item_key(org_key, item)?;
    if find_next(key.key(), item)?.is_some() {
        return Err(RotateError::AlreadyPending);
    }
    let field = json!({
        "type": 1,
        "name": encrypt_str(key.key(), NEXT_FIELD)?,
        "value": encrypt_str(key.key(), next)?,
        "linkedId": null,
    });
    let mut body = put_body(item.clone(), revision)?;
    match body.get_mut("fields") {
        Some(Value::Array(fields)) => fields.push(field),
        _ => body["fields"] = json!([field]),
    }
    Ok(body)
}

/// Commit: the pending value becomes the password. See the module
/// documentation for exactly what changes. `now` is an RFC 3339 time.
pub fn commit(
    item: &Value,
    org_key: &SymKey,
    revision: &str,
    now: &str,
) -> Result<Value, RotateError> {
    let login = check_login(item)?;
    let key = item_key(org_key, item)?;
    let index = find_next(key.key(), item)?.ok_or(RotateError::NoPending)?;
    let pending = item["fields"][index]
        .get("value")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or(RotateError::CorruptPending)?
        .to_string();
    // Fail closed: the pending value must be a readable password under this
    // item's key, or it never becomes the password.
    let readable: Result<Zeroizing<String>, EncError> =
        EncString::parse(&pending).and_then(|e| e.decrypt_string(key.key()));
    match readable {
        Ok(text) if !text.is_empty() => {}
        _ => return Err(RotateError::CorruptPending),
    }
    let old = login
        .get("password")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let mut body = put_body(item.clone(), revision)?;
    body["login"]["password"] = json!(pending);
    body["login"]["passwordRevisionDate"] = json!(now);

    let mut history = vec![json!({ "password": old, "lastUsedDate": now })];
    if let Some(existing) = body.get("passwordHistory").and_then(Value::as_array) {
        history.extend(existing.iter().cloned());
    }
    history.truncate(MAX_PASSWORD_HISTORY);
    body["passwordHistory"] = Value::Array(history);

    body["fields"] = without_field(&body, index);
    Ok(body)
}

/// Abort: remove the pending field. Nothing else changes.
pub fn abort(item: &Value, org_key: &SymKey, revision: &str) -> Result<Value, RotateError> {
    check_login(item)?;
    let key = item_key(org_key, item)?;
    let index = find_next(key.key(), item)?.ok_or(RotateError::NoPending)?;
    let mut body = put_body(item.clone(), revision)?;
    body["fields"] = without_field(&body, index);
    Ok(body)
}

#[cfg(test)]
mod tests;
