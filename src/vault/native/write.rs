//! The write path: what Ferrowarden sends to create one login item.
//!
//! Written from the item format (the fields the server stores and the way
//! clients encrypt them), with the primitives of [`super::enc`]. No Bitwarden
//! client or SDK code is used (docs/native-vault.md, "Provenance and
//! licence"), and `docker/bw-lib.js` + `docker/bw-seed.js`, which write the
//! same format from Node, are what it is cross-checked against
//! (`scripts/read-item.js` reads an item back with Node's `crypto`).
//!
//! A new item gets its **own 64-byte key**. Every encrypted field of the item
//! (name, username, password, each URI and its checksum, each custom field's
//! name and value) is encrypted under that item key, and the item key itself
//! is wrapped (type 2) under the **organisation key** of the managed
//! collection, so every member of the organisation can open the item.
//!
//! Nothing here touches the network. The body names exactly one collection;
//! [`NativeVault::create_login`](super::NativeVault) takes it from the evaluated
//! managed-collection state and from nowhere else.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::enc::{encrypt_str, EncError, SymKey};
use crate::vault::model::{NewLogin, APPROVAL_FIELD, CREATED_BY_FIELD};

/// What an item is written into: the managed collection and its organisation's
/// key.
pub struct Target<'a> {
    pub organization_id: &'a str,
    pub collection_id: &'a str,
    pub organization_key: &'a SymKey,
    /// The account's id, sent as `encryptedFor` (the seeder and current
    /// clients send it; the server ignores it when it does not know it).
    pub user_id: Option<&'a str>,
}

/// `base64(SHA-256(uri))`, which clients store (encrypted, like the URI) as
/// the URI's checksum.
pub fn uri_checksum(uri: &str) -> String {
    STANDARD.encode(Sha256::digest(uri.as_bytes()))
}

/// The body of `POST /api/ciphers/create`: `{ cipher, collectionIds }`.
pub fn create_body(target: &Target<'_>, login: &NewLogin) -> Result<Value, EncError> {
    let item_key = SymKey::generate()?;
    let enc = |s: &str| encrypt_str(&item_key, s);
    let enc_opt = |s: Option<&str>| s.map(enc).transpose();

    let uris = login
        .uris
        .iter()
        .map(|uri| {
            Ok(json!({
                "uri": enc(uri)?,
                "match": null,
                "uriChecksum": enc(&uri_checksum(uri))?,
            }))
        })
        .collect::<Result<Vec<_>, EncError>>()?;

    let mut fields = vec![json!({
        "type": 0,
        "name": enc(CREATED_BY_FIELD)?,
        "value": enc(&login.created_by)?,
        "linkedId": null,
    })];
    if login.approval_required {
        fields.push(json!({
            "type": 0,
            "name": enc(APPROVAL_FIELD)?,
            "value": enc("required")?,
            "linkedId": null,
        }));
    }

    let mut cipher = json!({
        "type": 1,
        "organizationId": target.organization_id,
        "name": enc(&login.name)?,
        "notes": null,
        "favorite": false,
        "reprompt": 0,
        // The item key, wrapped under the organisation key.
        "key": super::enc::encrypt(target.organization_key, &item_key.to_bytes()[..])?,
        "login": {
            "username": enc_opt(login.username.as_deref())?,
            "password": enc(login.password.as_str())?,
            "totp": null,
            "uris": uris,
            "passwordRevisionDate": null,
            "autofillOnPageLoad": null,
        },
        "fields": fields,
    });
    if let Some(user) = target.user_id {
        cipher["encryptedFor"] = json!(user);
    }
    Ok(json!({
        "cipher": cipher,
        "collectionIds": [target.collection_id],
    }))
}

#[cfg(test)]
mod tests;
