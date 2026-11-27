use std::collections::HashMap;

use zeroize::Zeroizing;

use super::super::api::RawCipher;
use super::super::cipher::{self, Keys};
use super::super::enc::test_support::key;
use super::super::enc::EncString;
use super::super::keys::unwrap_sym_key;
use super::*;
use crate::vault::model::{Builtin, ItemKind};

const ORG_ID: &str = "11111111-2222-3333-4444-555555555555";
const COLLECTION: &str = "66666666-7777-8888-9999-000000000000";
const USER_ID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const PASSWORD: &str = "Zx9-correct-horse-battery-STAPLE-0042";

fn login() -> NewLogin {
    NewLogin {
        name: "agent_keycloak_admin".into(),
        username: Some("admin".into()),
        uris: vec![
            "https://keycloak.example.com".into(),
            "https://sso.example.com:8443/auth".into(),
        ],
        password: Zeroizing::new(PASSWORD.to_string()),
        created_by: "homelab-claude".into(),
        approval_required: false,
    }
}

fn body_for(login: &NewLogin, org_key: &SymKey) -> Value {
    create_body(
        &Target {
            organization_id: ORG_ID,
            collection_id: COLLECTION,
            organization_key: org_key,
            user_id: Some(USER_ID),
        },
        login,
    )
    .unwrap()
}

fn dec(k: &SymKey, v: &Value) -> String {
    EncString::parse(v.as_str().expect("an EncString"))
        .unwrap()
        .decrypt_string(k)
        .unwrap()
        .as_str()
        .to_string()
}

#[test]
fn the_body_names_exactly_the_managed_collection_and_organisation() {
    let org_key = key(40);
    let body = body_for(&login(), &org_key);
    assert_eq!(body["collectionIds"], json!([COLLECTION]));
    assert_eq!(body["cipher"]["organizationId"], ORG_ID);
    assert_eq!(body["cipher"]["encryptedFor"], USER_ID);
    // The whole body has these two keys and nothing else.
    let keys: Vec<&String> = body.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 2, "{keys:?}");
}

#[test]
fn the_cipher_has_the_documented_shape() {
    let c = body_for(&login(), &key(40))["cipher"].clone();
    assert_eq!(c["type"], 1);
    assert_eq!(c["notes"], Value::Null);
    assert_eq!(c["favorite"], false);
    assert_eq!(c["reprompt"], 0);
    assert!(c["key"].is_string());
    assert_eq!(c["login"]["totp"], Value::Null);
    assert_eq!(c["login"]["passwordRevisionDate"], Value::Null);
    let uris = c["login"]["uris"].as_array().unwrap();
    assert_eq!(uris.len(), 2);
    for u in uris {
        assert_eq!(u["match"], Value::Null);
        assert!(u["uri"].is_string() && u["uriChecksum"].is_string());
    }
    // The created-by field only: no approval field unless asked.
    assert_eq!(c["fields"].as_array().unwrap().len(), 1);
    assert_eq!(c["fields"][0]["type"], 0);
}

#[test]
fn the_item_key_is_wrapped_under_the_organisation_key_and_encrypts_every_field() {
    let org_key = key(40);
    let new = login();
    let c = body_for(&new, &org_key)["cipher"].clone();

    // The item key opens with the organisation key, is 64 bytes, and is not
    // the organisation key.
    let item_key = unwrap_sym_key(&org_key, c["key"].as_str().unwrap()).unwrap();
    assert_ne!(&item_key.to_bytes()[..], &org_key.to_bytes()[..]);

    // Every encrypted field opens with the item key and with nothing else.
    let mut all: Vec<&Value> = vec![&c["name"], &c["login"]["username"], &c["login"]["password"]];
    for u in c["login"]["uris"].as_array().unwrap() {
        all.push(&u["uri"]);
        all.push(&u["uriChecksum"]);
    }
    for f in c["fields"].as_array().unwrap() {
        all.push(&f["name"]);
        all.push(&f["value"]);
    }
    for v in all {
        let s = v.as_str().expect("every field is an EncString");
        assert!(s.starts_with("2."), "type 2: {s}");
        let parsed = EncString::parse(s).unwrap();
        assert!(parsed.decrypt(&item_key).is_ok());
        assert!(parsed.decrypt(&org_key).is_err(), "not under the org key");
    }

    assert_eq!(dec(&item_key, &c["name"]), new.name);
    assert_eq!(dec(&item_key, &c["login"]["username"]), "admin");
    assert_eq!(dec(&item_key, &c["login"]["password"]), PASSWORD);
    assert_eq!(
        dec(&item_key, &c["fields"][0]["name"]),
        "ferrowarden_created_by"
    );
    assert_eq!(dec(&item_key, &c["fields"][0]["value"]), "homelab-claude");
}

#[test]
fn uri_checksums_are_the_encrypted_base64_sha256_of_the_uri() {
    let org_key = key(40);
    let new = login();
    let c = body_for(&new, &org_key)["cipher"].clone();
    let item_key = unwrap_sym_key(&org_key, c["key"].as_str().unwrap()).unwrap();
    for (u, want) in c["login"]["uris"].as_array().unwrap().iter().zip(&new.uris) {
        assert_eq!(&dec(&item_key, &u["uri"]), want);
        let sum = dec(&item_key, &u["uriChecksum"]);
        assert_eq!(sum, uri_checksum(want));
        // Independent of the helper: base64 of the 32-byte SHA-256 digest.
        let raw = STANDARD.decode(&sum).unwrap();
        assert_eq!(raw.len(), 32);
        assert_eq!(&raw[..], &Sha256::digest(want.as_bytes())[..]);
    }
    // A known value: SHA-256("abc") is ba7816bf...15ad.
    assert_eq!(
        uri_checksum("abc"),
        "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
}

#[test]
fn nothing_readable_is_in_the_body() {
    let new = login();
    let text = serde_json::to_string(&body_for(&new, &key(40))).unwrap();
    for plain in [
        PASSWORD,
        "agent_keycloak_admin",
        "admin",
        "keycloak.example.com",
        "sso.example.com",
        "ferrowarden_created_by",
        "homelab-claude",
    ] {
        // "admin" is also a substring of nothing structural: the keys are
        // camelCase words such as `organizationId`.
        assert!(!text.contains(plain), "{plain} appears in the body");
    }
}

#[test]
fn a_missing_username_is_null_and_the_approval_flag_adds_a_field() {
    let org_key = key(40);
    let new = NewLogin {
        username: None,
        approval_required: true,
        ..login()
    };
    let c = body_for(&new, &org_key)["cipher"].clone();
    assert_eq!(c["login"]["username"], Value::Null);
    let item_key = unwrap_sym_key(&org_key, c["key"].as_str().unwrap()).unwrap();
    let fields = c["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 2);
    assert_eq!(dec(&item_key, &fields[1]["name"]), "ferrowarden_approval");
    assert_eq!(dec(&item_key, &fields[1]["value"]), "required");
    assert_eq!(fields[1]["type"], 0);
}

#[test]
fn encrypted_for_is_left_out_when_the_account_id_is_unknown() {
    let org_key = key(40);
    let body = create_body(
        &Target {
            organization_id: ORG_ID,
            collection_id: COLLECTION,
            organization_key: &org_key,
            user_id: None,
        },
        &login(),
    )
    .unwrap();
    assert!(body["cipher"].get("encryptedFor").is_none());
}

#[test]
fn every_item_gets_its_own_key_and_fresh_ivs() {
    let org_key = key(40);
    let a = body_for(&login(), &org_key);
    let b = body_for(&login(), &org_key);
    assert_ne!(a["cipher"]["key"], b["cipher"]["key"]);
    assert_ne!(
        a["cipher"]["login"]["password"],
        b["cipher"]["login"]["password"]
    );
    let ka = unwrap_sym_key(&org_key, a["cipher"]["key"].as_str().unwrap()).unwrap();
    let kb = unwrap_sym_key(&org_key, b["cipher"]["key"].as_str().unwrap()).unwrap();
    assert_ne!(&ka.to_bytes()[..], &kb.to_bytes()[..]);
}

/// The reader that Ferrowarden itself uses reads the item back: the same
/// functions that serve a placeholder at forward time.
#[test]
fn the_reader_of_the_native_backend_reads_a_written_item_back() {
    let org_key = key(40);
    let new = NewLogin {
        approval_required: true,
        ..login()
    };
    let mut cipher_json = body_for(&new, &org_key)["cipher"].clone();
    cipher_json["id"] = json!("item-1");
    let raw: RawCipher = serde_json::from_value(cipher_json).unwrap();

    let user = key(1);
    let orgs = HashMap::from([(ORG_ID.to_string(), key(40))]);
    let keys = Keys {
        user: &user,
        org: &orgs,
    };
    let (name, entry) = cipher::build_metadata(&keys, &raw).unwrap();
    assert_eq!(name, "agent_keycloak_admin");
    assert_eq!(entry.kind, ItemKind::Login);
    assert_eq!(entry.uris, login().uris);
    assert!(entry.has_username && entry.has_password && !entry.has_totp && !entry.has_notes);
    assert!(entry.approval_required, "the approval field is read");
    assert!(
        !entry.approval_field_invalid,
        "`required` is the clean spelling"
    );
    // The created-by field is Ferrowarden's own: not offered as a field.
    assert!(entry.fields.is_empty(), "{:?}", entry.fields);

    let password = cipher::builtin_value(&keys, &raw, Builtin::Password, 0, "x").unwrap();
    assert_eq!(password.as_str(), PASSWORD);
    let username = cipher::builtin_value(&keys, &raw, Builtin::Username, 0, "x").unwrap();
    assert_eq!(username.as_str(), "admin");
    // And the field value can be read by name.
    let by = cipher::field_value(&keys, &raw, "ferrowarden_created_by", "x").unwrap();
    assert_eq!(by.as_str(), "homelab-claude");
}
