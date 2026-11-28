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
//! * [`start`]: appends two hidden (type 1) custom fields, both encrypted
//!   with the item's key: `ferrowarden_next`, whose value is the new
//!   password, and `ferrowarden_rotation`, the rotation record
//!   ([`RotationRecord`]): a random rotation id, the **ciphertext text** of
//!   the password the rotation starts from, and the ciphertext text of the
//!   pending field. Nothing is hashed. The record lets a commit notice,
//!   durably (it lives on the item, so it survives a restart), that a person
//!   changed the password or replaced the pending value since.
//! * [`commit`]: `login.password` becomes the pending field's ciphertext **as
//!   it is** (same key, nothing decrypted and re-encrypted for it; it is first
//!   checked to decrypt under the item's key, and the commit fails closed if
//!   not), the old `login.password` ciphertext goes to the front of
//!   `passwordHistory` as `{ password, lastUsedDate }` (newest first, at most
//!   five entries kept, the way the Bitwarden clients keep it),
//!   `login.passwordRevisionDate` is set to now, and both reserved fields are
//!   removed. The commit first checks the record: its id is the one named and
//!   the pending field is still the text the record holds
//!   ([`RotateError::RotationMismatch`] otherwise: another rotation, or a
//!   person replaced the pending value), and the password is still the one the
//!   record names ([`RotateError::PasswordChanged`]). Nothing is written in any
//!   of those cases; a missing, repeated or unreadable record is
//!   [`RotateError::CorruptPending`]. Every other member, a person's edit of
//!   the notes, URIs or other fields included, is kept as read.
//! * [`abort`]: both reserved fields are removed (only the id is checked, not
//!   the password or the pending value: a person can always abort), and the
//!   pending value's ciphertext **as it is** goes to the front of
//!   `passwordHistory` (`{ password, lastUsedDate }`, at most five entries): if
//!   the service had in fact already switched to the pending password, a
//!   person can still recover it from the item's password history. Nothing is
//!   ever lost from the vault.
//!
//! [`commit`] and [`abort`] each name the **rotation id** the caller means (the
//! record's random `id`): if the record on the item now is another one (it was
//! finished and another started), nothing is written
//! ([`RotateError::RotationMismatch`]).
//!
//! The item's encryption key is its own key (`key`, unwrapped with the
//! organisation key) if it has one, else the organisation key.
//!
//! Nothing here touches the network or logs anything.

use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use super::enc::{encrypt_str, EncError, EncString, SymKey};
use super::keys::unwrap_sym_key;
use crate::vault::model::{
    is_next_field_name, is_rotation_field_name, RotationRecord, NEXT_FIELD, ROTATION_FIELD,
};

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
    /// The pending value is missing, empty, or does not decrypt under the
    /// item's key to a password.
    CorruptPending,
    /// The pending value on the item is not the one the caller named.
    RotationMismatch,
    /// The item's password is not the one the rotation started from: a person
    /// changed it (commit only).
    PasswordChanged,
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

/// Where the rotation's reserved fields are on an item.
struct Reserved {
    /// The `ferrowarden_next` field.
    next: Option<usize>,
    /// Every `ferrowarden_rotation` field (one is right).
    records: Vec<usize>,
}

/// The indices of the item's `ferrowarden_next` and `ferrowarden_rotation`
/// fields. An error when there is more than one `ferrowarden_next`, or when a
/// field's name cannot be read (it could be ours).
fn find_reserved(key: &SymKey, item: &Value) -> Result<Reserved, RotateError> {
    let mut found = Reserved {
        next: None,
        records: Vec::new(),
    };
    let Some(fields) = item.get("fields").and_then(Value::as_array) else {
        return Ok(found);
    };
    for (i, f) in fields.iter().enumerate() {
        let Some(enc_name) = f
            .get("name")
            .and_then(Value::as_str)
            .filter(|n| !n.is_empty())
        else {
            continue;
        };
        let name = EncString::parse(enc_name)?.decrypt_string(key)?;
        if is_next_field_name(&name) && found.next.replace(i).is_some() {
            return Err(RotateError::DuplicatePending);
        }
        if is_rotation_field_name(&name) {
            found.records.push(i);
        }
    }
    Ok(found)
}

/// The item must be a login with a password.
fn check_login(item: &Value) -> Result<&Map<String, Value>, RotateError> {
    if item.get("type").and_then(Value::as_i64) != Some(1) {
        return Err(RotateError::NotRotatable);
    }
    // Master password re-prompt, on the item as it is read now: never rotated.
    if item.get("reprompt").and_then(Value::as_i64).unwrap_or(0) != 0 {
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

/// `fields` after the ones at `indices` have been removed: `null` when none is
/// left (an item that had no custom fields before the rotation has none
/// after it).
fn without_fields(body: &Value, indices: &[usize]) -> Value {
    let mut fields = body
        .get("fields")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut sorted = indices.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    sorted.dedup();
    for index in sorted {
        fields.remove(index);
    }
    if fields.is_empty() {
        Value::Null
    } else {
        Value::Array(fields)
    }
}

/// The item's rotation record: there must be exactly one `ferrowarden_rotation`
/// field, readable under the item's key, a strict JSON object of the record's
/// three members. Anything else is [`RotateError::CorruptPending`].
fn read_record(
    key: &SymKey,
    item: &Value,
    reserved: &Reserved,
) -> Result<RotationRecord, RotateError> {
    let [index] = reserved.records[..] else {
        return Err(RotateError::CorruptPending);
    };
    let text: Zeroizing<String> = item["fields"][index]
        .get("value")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or(RotateError::CorruptPending)
        .and_then(|v| {
            EncString::parse(v)
                .and_then(|e| e.decrypt_string(key))
                .map_err(|_| RotateError::CorruptPending)
        })?;
    RotationRecord::parse(&text).ok_or(RotateError::CorruptPending)
}

/// Start: add the hidden `ferrowarden_next` field holding `next`, encrypted
/// with the item's key, and the hidden `ferrowarden_rotation` field holding the
/// rotation record (a random id, the ciphertext of the password the rotation
/// starts from, the ciphertext of the pending field). A stray record of an
/// earlier rotation is dropped. Nothing else changes. `revision` is the item's
/// `revisionDate` as it was read. Returns the body and the rotation id.
pub fn start(
    item: &Value,
    org_key: &SymKey,
    revision: &str,
    next: &str,
) -> Result<(Value, String), RotateError> {
    let login = check_login(item)?;
    let key = item_key(org_key, item)?;
    let reserved = find_reserved(key.key(), item)?;
    if reserved.next.is_some() {
        return Err(RotateError::AlreadyPending);
    }
    let current_password = login
        .get("password")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let pending_ciphertext = encrypt_str(key.key(), next)?;
    let record = RotationRecord::new(current_password, &pending_ciphertext)
        .ok_or(RotateError::Crypto(EncError::Random))?;
    let record_field = json!({
        "type": 1,
        "name": encrypt_str(key.key(), ROTATION_FIELD)?,
        "value": encrypt_str(key.key(), &record.to_text())?,
        "linkedId": null,
    });
    let field = json!({
        "type": 1,
        "name": encrypt_str(key.key(), NEXT_FIELD)?,
        "value": pending_ciphertext,
        "linkedId": null,
    });
    let mut body = put_body(item.clone(), revision)?;
    if !reserved.records.is_empty() {
        body["fields"] = without_fields(&body, &reserved.records);
    }
    match body.get_mut("fields") {
        Some(Value::Array(fields)) => {
            fields.push(field);
            fields.push(record_field);
        }
        _ => body["fields"] = json!([field, record_field]),
    }
    Ok((body, record.id))
}

/// The pending field's ciphertext, which must have a value.
fn pending_ciphertext(item: &Value, index: usize) -> Result<&str, RotateError> {
    item["fields"][index]
        .get("value")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or(RotateError::CorruptPending)
}

/// `passwordHistory` with `ciphertext` in front (newest first, at most
/// [`MAX_PASSWORD_HISTORY`] kept).
fn with_history_entry(body: &mut Value, ciphertext: &str, now: &str) {
    let mut history = vec![json!({ "password": ciphertext, "lastUsedDate": now })];
    if let Some(existing) = body.get("passwordHistory").and_then(Value::as_array) {
        history.extend(existing.iter().cloned());
    }
    history.truncate(MAX_PASSWORD_HISTORY);
    body["passwordHistory"] = Value::Array(history);
}

/// Commit: the pending value `rotation_id` names becomes the password. See the
/// module documentation for exactly what changes. `now` is an RFC 3339 time.
pub fn commit(
    item: &Value,
    org_key: &SymKey,
    revision: &str,
    now: &str,
    rotation_id: &str,
) -> Result<Value, RotateError> {
    let login = check_login(item)?;
    let key = item_key(org_key, item)?;
    let reserved = find_reserved(key.key(), item)?;
    let index = reserved.next.ok_or(RotateError::NoPending)?;
    let pending = pending_ciphertext(item, index)?.to_string();
    let record = read_record(key.key(), item, &reserved)?;
    // Not secrets: plain equality of ciphertext texts is enough. Another
    // rotation, or a person replaced the pending value.
    if record.id != rotation_id || record.next != pending {
        return Err(RotateError::RotationMismatch);
    }
    // The password must still be the one the rotation started from; otherwise
    // a person changed it and the commit would replace their change.
    let old = login
        .get("password")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if record.from != old {
        return Err(RotateError::PasswordChanged);
    }
    // Fail closed: the pending value must be a readable password under this
    // item's key, or it never becomes the password. Empty or whitespace-only
    // is no password, like the one it replaces.
    let readable: Result<Zeroizing<String>, EncError> =
        EncString::parse(&pending).and_then(|e| e.decrypt_string(key.key()));
    match readable {
        Ok(text) if !text.trim().is_empty() => {}
        _ => return Err(RotateError::CorruptPending),
    }
    let mut body = put_body(item.clone(), revision)?;
    body["login"]["password"] = json!(pending);
    body["login"]["passwordRevisionDate"] = json!(now);
    with_history_entry(&mut body, &old, now);
    let mut gone = reserved.records.clone();
    gone.push(index);
    body["fields"] = without_fields(&body, &gone);
    Ok(body)
}

/// Abort: remove the pending field and the record `rotation_id` names, and keep
/// the pending value in the front of the password history. Only the id is
/// checked, not the password or the pending value: a person can always abort.
/// Nothing else changes.
pub fn abort(
    item: &Value,
    org_key: &SymKey,
    revision: &str,
    now: &str,
    rotation_id: &str,
) -> Result<Value, RotateError> {
    check_login(item)?;
    let key = item_key(org_key, item)?;
    let reserved = find_reserved(key.key(), item)?;
    let index = reserved.next.ok_or(RotateError::NoPending)?;
    let discarded = pending_ciphertext(item, index)?.to_string();
    let record = read_record(key.key(), item, &reserved)?;
    if record.id != rotation_id {
        return Err(RotateError::RotationMismatch);
    }
    let mut body = put_body(item.clone(), revision)?;
    with_history_entry(&mut body, &discarded, now);
    let mut gone = reserved.records.clone();
    gone.push(index);
    body["fields"] = without_fields(&body, &gone);
    Ok(body)
}

#[cfg(test)]
mod tests;
