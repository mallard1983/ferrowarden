use serde_json::{json, Value};

use super::super::enc::test_support::key;
use super::super::enc::{encrypt, encrypt_str, EncString, SymKey};
use super::*;

const REVISION: &str = "2026-11-26T10:00:00.123456Z";
const NOW: &str = "2026-11-26T12:30:00.000Z";
const NEXT: &str = "NEXT-VALUE-0123456789-abcdef";
const OLD: &str = "OLD-VALUE-0123456789-abcdef";

fn org_key() -> SymKey {
    key(40)
}

fn open(k: &SymKey, v: &Value) -> String {
    EncString::parse(v.as_str().expect("an EncString"))
        .unwrap()
        .decrypt_string(k)
        .unwrap()
        .as_str()
        .to_string()
}

/// An item as `GET /api/ciphers/{id}` returns it. With `own_key` the fields
/// are encrypted with the item's own key (wrapped under the organisation
/// key); without, with the organisation key.
fn item(own_key: bool) -> (Value, SymKey) {
    let org = org_key();
    let (wrapped, k) = if own_key {
        let bytes: Vec<u8> = (0..64u8)
            .map(|i| i.wrapping_mul(5).wrapping_add(3))
            .collect();
        (
            json!(encrypt(&org, &bytes).unwrap()),
            SymKey::from_slice(&bytes).unwrap(),
        )
    } else {
        (Value::Null, key(40))
    };
    let enc = |s: &str| json!(encrypt(&k, s.as_bytes()).unwrap());
    let v = json!({
        "object": "cipherDetails",
        "id": "11111111-2222-3333-4444-555555555555",
        "organizationId": "org1",
        "folderId": "folder-1",
        "type": 1,
        "creationDate": "2026-01-01T00:00:00.000000Z",
        "revisionDate": REVISION,
        "deletedDate": null,
        "archivedDate": null,
        "collectionIds": ["coll-managed"],
        "attachments": [{"id": "a1", "fileName": "2.x|y|z"}],
        "organizationUseTotp": true,
        "edit": true,
        "viewPassword": true,
        "permissions": {"delete": true, "restore": true},
        "data": {"legacy": true},
        "favorite": true,
        "reprompt": 0,
        "key": wrapped,
        "name": enc("agent_service"),
        "notes": enc("a human wrote this"),
        "login": {
            "username": enc("svc"),
            "password": enc(OLD),
            "totp": enc("JBSWY3DPEHPK3PXP"),
            "uris": [{"uri": enc("https://a.example"), "uriChecksum": enc("checksum"), "match": null}],
            "passwordRevisionDate": "2026-02-02T00:00:00.000Z",
            "fido2Credentials": [{"credentialId": "kept"}],
            "someFutureMember": {"nested": [1, 2, 3]},
        },
        "fields": [
            {"name": enc("ferrowarden_created_by"), "value": enc("homelab"), "type": 0, "linkedId": null},
            {"name": enc("api key"), "value": enc("FIELD-VALUE"), "type": 1, "linkedId": null},
        ],
        "passwordHistory": null,
        "secureNote": null,
        "card": null,
        "identity": null,
        "sshKey": null,
        "aMemberNobodyKnowsYet": "kept as it is",
    });
    (v, k)
}

/// The body of a start of `item`.
fn start_body(item: &Value) -> Value {
    start(item, &org_key(), REVISION, NEXT).unwrap().0
}

/// The rotation id of the pending value, which these tests find in the
/// second-to-last field of the item (the base field is the last).
fn rid(item: &Value) -> String {
    let fields = item["fields"].as_array().unwrap();
    // A pending value that is missing or not text names nothing: any id.
    rotation_id_of_ciphertext(
        fields[fields.len() - 2]["value"]
            .as_str()
            .unwrap_or_default(),
    )
}

fn started(own_key: bool) -> (Value, SymKey) {
    let (item, k) = item(own_key);
    let body = start_body(&item);
    // What the server answers after the write: the body, plus its own members.
    let mut after = body.clone();
    for m in [
        "object",
        "id",
        "creationDate",
        "deletedDate",
        "archivedDate",
        "collectionIds",
        "attachments",
        "organizationUseTotp",
        "edit",
        "viewPassword",
        "permissions",
        "data",
    ] {
        after[m] = item[m].clone();
    }
    after["revisionDate"] = json!("2026-11-26T11:00:00.000000Z");
    after
        .as_object_mut()
        .unwrap()
        .remove("lastKnownRevisionDate");
    (after, k)
}

/// The members whose value differs, as a sorted list of `a.b` paths, one level
/// into objects (arrays and scalars are compared as a whole).
fn changed(before: &Value, after: &Value) -> Vec<String> {
    fn walk(prefix: &str, a: &Value, b: &Value, out: &mut Vec<String>) {
        match (a, b) {
            (Value::Object(x), Value::Object(y)) => {
                let mut names: Vec<&String> = x.keys().chain(y.keys()).collect();
                names.sort();
                names.dedup();
                for n in names {
                    let path = if prefix.is_empty() {
                        n.clone()
                    } else {
                        format!("{prefix}.{n}")
                    };
                    match (x.get(n), y.get(n)) {
                        (Some(p), Some(q)) => walk(&path, p, q, out),
                        _ => out.push(path),
                    }
                }
            }
            _ if a != b => out.push(prefix.to_string()),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk("", before, after, &mut out);
    out
}

// ── The round-trip ────────────────────────────────────────────────────────────

#[test]
fn the_put_body_drops_exactly_the_servers_own_members_and_names_the_revision() {
    for own_key in [false, true] {
        let (before, _) = item(own_key);
        let body = start_body(&before);
        let dropped: Vec<&str> = before
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .filter(|k| body.get(*k).is_none())
            .collect();
        let mut want: Vec<&str> = RESPONSE_ONLY.to_vec();
        want.push("data");
        want.sort_unstable();
        let mut got = dropped.clone();
        got.sort_unstable();
        assert_eq!(got, want, "own_key={own_key}");
        assert_eq!(body["lastKnownRevisionDate"], REVISION);
        // Nothing that is the server's own goes back.
        for m in RESPONSE_ONLY {
            assert!(body.get(m).is_none(), "{m}");
        }
    }
}

#[test]
fn start_changes_only_the_fields_and_everything_else_comes_back_as_it_was() {
    for own_key in [false, true] {
        let (before, _) = item(own_key);
        let body = start_body(&before);
        // Compare with the item as read, minus what is not sent back.
        let mut sent = before.clone();
        for m in RESPONSE_ONLY {
            sent.as_object_mut().unwrap().remove(m);
        }
        sent.as_object_mut().unwrap().remove("data");
        let diff = changed(&sent, &body);
        assert_eq!(
            diff,
            ["fields", "lastKnownRevisionDate"],
            "own_key={own_key}: {diff:?}"
        );
        // Unknown members, FIDO2 credentials and the human's notes are intact.
        assert_eq!(body["aMemberNobodyKnowsYet"], "kept as it is");
        assert_eq!(
            body["login"]["fido2Credentials"],
            before["login"]["fido2Credentials"]
        );
        assert_eq!(
            body["login"]["someFutureMember"],
            before["login"]["someFutureMember"]
        );
        assert_eq!(body["notes"], before["notes"]);
        assert_eq!(body["key"], before["key"]);
        assert_eq!(body["login"], before["login"], "the login is untouched");
        assert_eq!(body["folderId"], "folder-1");
        assert_eq!(body["favorite"], true);
    }
}

#[test]
fn start_appends_a_hidden_field_with_the_new_value_under_the_items_key() {
    for own_key in [false, true] {
        let (before, k) = item(own_key);
        let body = start_body(&before);
        let fields = body["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 4);
        // The existing fields are first and unchanged (same ciphertext).
        assert_eq!(&fields[..2], &before["fields"].as_array().unwrap()[..]);
        let added = &fields[2];
        assert_eq!(added["type"], 1, "hidden");
        assert_eq!(added["linkedId"], Value::Null);
        assert_eq!(open(&k, &added["name"]), "ferrowarden_next");
        assert_eq!(open(&k, &added["value"]), NEXT);
        assert!(!body.to_string().contains(NEXT));
        // And the base: the digest of the ciphertext of the password as it is.
        let base = &fields[3];
        assert_eq!(base["type"], 1, "hidden");
        assert_eq!(base["linkedId"], Value::Null);
        assert_eq!(open(&k, &base["name"]), "ferrowarden_next_base");
        assert_eq!(
            open(&k, &base["value"]),
            password_base_of_ciphertext(before["login"]["password"].as_str().unwrap())
        );
        assert!(!body.to_string().contains(OLD));
    }
}

#[test]
fn start_on_an_item_without_fields_makes_the_list() {
    let (mut before, k) = item(true);
    before["fields"] = Value::Null;
    let body = start_body(&before);
    assert_eq!(body["fields"].as_array().unwrap().len(), 2);
    assert_eq!(open(&k, &body["fields"][0]["value"]), NEXT);
    // And aborting it again leaves no list, as it was (the discarded value is
    // in the history).
    let mut again = before.clone();
    again["fields"] = body["fields"].clone();
    let aborted = abort(&again, &org_key(), REVISION, NOW, &rid(&again)).unwrap();
    assert_eq!(aborted["fields"], Value::Null);
    assert_eq!(aborted["passwordHistory"].as_array().unwrap().len(), 1);
}

#[test]
fn start_refuses_when_one_is_pending_or_the_item_is_not_a_login() {
    let (after, _) = started(true);
    assert_eq!(
        start(&after, &org_key(), REVISION, NEXT).unwrap_err(),
        RotateError::AlreadyPending
    );
    let (mut note, _) = item(true);
    note["type"] = json!(2);
    assert_eq!(
        start(&note, &org_key(), REVISION, NEXT).unwrap_err(),
        RotateError::NotRotatable
    );
    let (mut nopass, _) = item(true);
    nopass["login"]["password"] = Value::Null;
    assert_eq!(
        start(&nopass, &org_key(), REVISION, NEXT).unwrap_err(),
        RotateError::NotRotatable
    );
    let (mut nologin, _) = item(true);
    nologin["login"] = Value::Null;
    assert_eq!(
        start(&nologin, &org_key(), REVISION, NEXT).unwrap_err(),
        RotateError::NotRotatable
    );
}

#[test]
fn the_field_name_is_matched_trimmed_and_in_any_case() {
    let (mut before, k) = item(true);
    before["fields"].as_array_mut().unwrap().push(json!({
        "name": encrypt_str(&k, "  Ferrowarden_NEXT ").unwrap(),
        "value": encrypt_str(&k, NEXT).unwrap(),
        "type": 1, "linkedId": null,
    }));
    assert_eq!(
        start(&before, &org_key(), REVISION, NEXT).unwrap_err(),
        RotateError::AlreadyPending
    );
    let pending_id = rotation_id_of_ciphertext(before["fields"][2]["value"].as_str().unwrap());
    let aborted = abort(&before, &org_key(), REVISION, NOW, &pending_id).unwrap();
    assert_eq!(aborted["fields"].as_array().unwrap().len(), 2);
}

#[test]
fn more_than_one_pending_field_is_a_conflict_for_a_person_to_fix() {
    let (mut after, k) = started(true);
    after["fields"].as_array_mut().unwrap().push(json!({
        "name": encrypt_str(&k, "ferrowarden_next").unwrap(),
        "value": encrypt_str(&k, "ANOTHER").unwrap(),
        "type": 1, "linkedId": null,
    }));
    assert_eq!(
        start(&after, &org_key(), REVISION, NEXT).unwrap_err(),
        RotateError::DuplicatePending
    );
    assert_eq!(
        commit(&after, &org_key(), REVISION, NOW, &rid(&after)).unwrap_err(),
        RotateError::DuplicatePending
    );
    assert_eq!(
        abort(&after, &org_key(), REVISION, NOW, &rid(&after)).unwrap_err(),
        RotateError::DuplicatePending
    );
}

#[test]
fn an_unreadable_field_name_stops_everything_rather_than_guessing() {
    let (mut before, _) = item(true);
    before["fields"][1]["name"] = json!(encrypt(&key(99), b"x").unwrap());
    assert!(matches!(
        start(&before, &org_key(), REVISION, NEXT).unwrap_err(),
        RotateError::Crypto(_)
    ));
}

// ── Commit ────────────────────────────────────────────────────────────────────

#[test]
fn commit_moves_the_pending_ciphertext_as_it_is_and_nothing_else_changes() {
    for own_key in [false, true] {
        let (after, k) = started(own_key);
        let pending = after["fields"][2]["value"].clone();
        let old_password = after["login"]["password"].clone();
        let body = commit(&after, &org_key(), "REV-2", NOW, &rid(&after)).unwrap();

        // The password is the pending ciphertext, byte for byte, and it opens
        // with the item's key to the new value.
        assert_eq!(body["login"]["password"], pending);
        assert_eq!(open(&k, &body["login"]["password"]), NEXT);
        assert_eq!(body["login"]["passwordRevisionDate"], NOW);
        // The old ciphertext is the newest history entry.
        assert_eq!(
            body["passwordHistory"],
            json!([{ "password": old_password, "lastUsedDate": NOW }])
        );
        assert_eq!(open(&k, &body["passwordHistory"][0]["password"]), OLD);
        // The pending field is gone and the others are as they were.
        assert_eq!(body["fields"].as_array().unwrap().len(), 2);
        assert_eq!(
            body["fields"],
            json!([after["fields"][0], after["fields"][1]])
        );
        assert_eq!(body["lastKnownRevisionDate"], "REV-2");

        // Exactly these members differ from the item that was read.
        let mut sent = after.clone();
        for m in RESPONSE_ONLY {
            sent.as_object_mut().unwrap().remove(m);
        }
        sent.as_object_mut().unwrap().remove("data");
        let diff = changed(&sent, &body);
        assert_eq!(
            diff,
            [
                "fields",
                "lastKnownRevisionDate",
                "login.password",
                "login.passwordRevisionDate",
                "passwordHistory"
            ],
            "own_key={own_key}: {diff:?}"
        );
        // The human's notes, the TOTP secret and the URIs are untouched.
        assert_eq!(body["notes"], after["notes"]);
        assert_eq!(body["login"]["totp"], after["login"]["totp"]);
        assert_eq!(body["login"]["uris"], after["login"]["uris"]);
        assert_eq!(
            body["login"]["fido2Credentials"],
            after["login"]["fido2Credentials"]
        );
    }
}

#[test]
fn password_history_is_newest_first_and_keeps_five() {
    let (mut after, k) = started(true);
    let old_ones: Vec<Value> = (0..5)
        .map(|i| json!({ "password": encrypt_str(&k, &format!("H{i}")).unwrap(), "lastUsedDate": format!("2026-0{}-01T00:00:00.000Z", i + 1) }))
        .collect();
    after["passwordHistory"] = json!(old_ones);

    let body = commit(&after, &org_key(), REVISION, NOW, &rid(&after)).unwrap();
    let history = body["passwordHistory"].as_array().unwrap();
    assert_eq!(history.len(), MAX_PASSWORD_HISTORY);
    // Newest first: the password that was just replaced, then the others in
    // the order they were; the oldest one fell off the end.
    assert_eq!(open(&k, &history[0]["password"]), OLD);
    assert_eq!(history[0]["lastUsedDate"], NOW);
    for i in 0..4 {
        assert_eq!(open(&k, &history[i + 1]["password"]), format!("H{i}"));
    }
}

#[test]
fn a_short_history_grows_by_one_at_the_front() {
    let (mut after, k) = started(false);
    after["passwordHistory"] = json!([
        { "password": encrypt_str(&k, "H0").unwrap(), "lastUsedDate": "2026-01-01T00:00:00.000Z" }
    ]);
    let body = commit(&after, &org_key(), REVISION, NOW, &rid(&after)).unwrap();
    let history = body["passwordHistory"].as_array().unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(open(&k, &history[0]["password"]), OLD);
    assert_eq!(open(&k, &history[1]["password"]), "H0");
}

#[test]
fn a_pending_value_under_another_key_fails_the_commit_closed() {
    let (mut after, _) = started(true);
    after["fields"][2]["value"] = json!(encrypt(&key(77), b"WRONG-KEY").unwrap());
    assert_eq!(
        commit(&after, &org_key(), REVISION, NOW, &rid(&after)).unwrap_err(),
        RotateError::CorruptPending
    );
    // A pending value that is not an EncString, or is empty, the same.
    for bad in [json!("not an encstring"), json!(""), Value::Null] {
        let (mut again, _) = started(true);
        again["fields"][2]["value"] = bad;
        assert_eq!(
            commit(&again, &org_key(), REVISION, NOW, &rid(&again)).unwrap_err(),
            RotateError::CorruptPending
        );
    }
    // Whitespace-only is no password either, like the one it replaces.
    for blank in [
        "   ", "	
", "",
    ] {
        let (mut again, k) = started(true);
        again["fields"][2]["value"] = json!(encrypt_str(&k, blank).unwrap());
        assert_eq!(
            commit(&again, &org_key(), REVISION, NOW, &rid(&again)).unwrap_err(),
            RotateError::CorruptPending,
            "{blank:?}"
        );
    }
    // Aborting it still works: that is how a person clears it, and what was
    // there is kept in the history as it is.
    let body = abort(&after, &org_key(), REVISION, NOW, &rid(&after)).unwrap();
    assert_eq!(
        body["passwordHistory"][0]["password"],
        after["fields"][2]["value"]
    );
}

#[test]
fn commit_without_a_pending_value_says_so() {
    let (before, _) = item(true);
    assert_eq!(
        commit(&before, &org_key(), REVISION, NOW, &rid(&before)).unwrap_err(),
        RotateError::NoPending
    );
    assert_eq!(
        abort(&before, &org_key(), REVISION, NOW, &rid(&before)).unwrap_err(),
        RotateError::NoPending
    );
}

// ── Abort ─────────────────────────────────────────────────────────────────────

#[test]
fn abort_removes_the_field_and_keeps_its_value_in_the_history() {
    for own_key in [false, true] {
        let (after, k) = started(own_key);
        let pending = after["fields"][2]["value"].clone();
        let body = abort(&after, &org_key(), "REV-3", NOW, &rid(&after)).unwrap();
        let mut sent = after.clone();
        for m in RESPONSE_ONLY {
            sent.as_object_mut().unwrap().remove(m);
        }
        sent.as_object_mut().unwrap().remove("data");
        let diff = changed(&sent, &body);
        assert_eq!(
            diff,
            ["fields", "lastKnownRevisionDate", "passwordHistory"],
            "{diff:?}"
        );
        assert_eq!(
            body["fields"],
            json!([after["fields"][0], after["fields"][1]])
        );
        // The password is as it was, and the discarded value is the newest
        // history entry, ciphertext as it is, so a person can recover it.
        assert_eq!(body["login"]["password"], after["login"]["password"]);
        assert_eq!(
            body["passwordHistory"],
            json!([{ "password": pending, "lastUsedDate": NOW }])
        );
        assert_eq!(open(&k, &body["passwordHistory"][0]["password"]), NEXT);
        assert_eq!(body["lastKnownRevisionDate"], "REV-3");
    }
}

#[test]
fn an_abort_keeps_five_history_entries_newest_first() {
    let (mut after, k) = started(true);
    let old_ones: Vec<Value> = (0..5)
        .map(|i| json!({ "password": encrypt_str(&k, &format!("H{i}")).unwrap(), "lastUsedDate": "2026-01-01T00:00:00.000Z" }))
        .collect();
    after["passwordHistory"] = json!(old_ones);
    let body = abort(&after, &org_key(), REVISION, NOW, &rid(&after)).unwrap();
    let history = body["passwordHistory"].as_array().unwrap();
    assert_eq!(history.len(), MAX_PASSWORD_HISTORY);
    assert_eq!(open(&k, &history[0]["password"]), NEXT);
    assert_eq!(open(&k, &history[1]["password"]), "H0");
    assert_eq!(open(&k, &history[4]["password"]), "H3");
}

#[test]
fn a_finish_names_the_pending_value_and_nothing_else_is_written() {
    let (after, k) = started(true);
    let right = rid(&after);
    // The id is a digest of the ciphertext (22 base64url characters), and it
    // is not derived from the value: the same value, started twice, has two
    // ids (a fresh random IV each time).
    assert_eq!(right.len(), 22);
    assert!(right
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    let (second, _) = started(true);
    assert_ne!(rid(&second), right);
    assert_eq!(
        rotation_id_of_ciphertext(after["fields"][2]["value"].as_str().unwrap()),
        right
    );

    // Another id, an empty one or one for a replaced value: refused, both ways.
    let mut replaced = after.clone();
    replaced["fields"][2]["value"] = json!(encrypt_str(&k, "SOMETHING-ELSE").unwrap());
    for wrong in [rid(&second), String::new(), "x".to_string()] {
        assert_eq!(
            commit(&after, &org_key(), REVISION, NOW, &wrong).unwrap_err(),
            RotateError::RotationMismatch
        );
        assert_eq!(
            abort(&after, &org_key(), REVISION, NOW, &wrong).unwrap_err(),
            RotateError::RotationMismatch
        );
    }
    assert_eq!(
        commit(&replaced, &org_key(), REVISION, NOW, &right).unwrap_err(),
        RotateError::RotationMismatch
    );
    assert_eq!(
        abort(&replaced, &org_key(), REVISION, NOW, &right).unwrap_err(),
        RotateError::RotationMismatch
    );
    // The right one works.
    assert!(commit(&after, &org_key(), REVISION, NOW, &right).is_ok());
}

#[test]
fn nothing_in_a_body_is_readable_text() {
    let (before, _) = item(true);
    let body = start_body(&before);
    let text = body.to_string();
    for plain in [
        NEXT,
        OLD,
        "agent_service",
        "ferrowarden_next",
        "a human wrote this",
    ] {
        assert!(!text.contains(plain), "{plain}");
    }
}

#[test]
fn errors_carry_nothing_from_the_item() {
    // The Debug text of an error is a variant name.
    let (before, _) = item(true);
    let wrong = key(1);
    let e = start(&before, &wrong, REVISION, NEXT).unwrap_err();
    let text = format!("{e:?}");
    assert!(text.starts_with("Crypto"), "{text}");
    assert!(!text.contains(NEXT));
}

// ── The base: a person's password change is never replaced ────────────────────

#[test]
fn a_commit_refuses_a_password_that_is_not_the_one_the_rotation_started_from() {
    for own_key in [false, true] {
        let (mut after, k) = started(own_key);
        // A person changes the password: another ciphertext.
        after["login"]["password"] = json!(encrypt_str(&k, "A-PERSONS-NEW-PASSWORD").unwrap());
        assert_eq!(
            commit(&after, &org_key(), REVISION, NOW, &rid(&after)).unwrap_err(),
            RotateError::PasswordChanged,
            "own_key={own_key}"
        );
        // An abort is always possible: both reserved fields go, the pending
        // value is the newest history entry, and the person's password stays.
        let body = abort(&after, &org_key(), REVISION, NOW, &rid(&after)).unwrap();
        assert_eq!(body["login"]["password"], after["login"]["password"]);
        assert_eq!(body["fields"].as_array().unwrap().len(), 2);
        assert_eq!(
            body["passwordHistory"],
            json!([{ "password": after["fields"][2]["value"], "lastUsedDate": NOW }])
        );
    }
}

#[test]
fn the_same_password_text_encrypted_again_is_a_change() {
    // The base is a digest of the stored ciphertext: a person saving the same
    // text again (a new IV) is a change like any other, and fails closed.
    let (mut after, k) = started(true);
    after["login"]["password"] = json!(encrypt_str(&k, OLD).unwrap());
    assert_eq!(
        commit(&after, &org_key(), REVISION, NOW, &rid(&after)).unwrap_err(),
        RotateError::PasswordChanged
    );
}

#[test]
fn a_missing_repeated_or_unreadable_base_fails_the_commit_closed() {
    let broken = |how: &str| {
        let (mut after, k) = started(true);
        let fields = after["fields"].as_array_mut().unwrap();
        match how {
            "missing" => {
                fields.pop();
            }
            "twice" => {
                let again = fields[3].clone();
                fields.push(again);
            }
            "garbled" => fields[3]["value"] = json!("not an encstring"),
            "empty" => fields[3]["value"] = json!(""),
            "other key" => fields[3]["value"] = json!(encrypt(&key(77), b"x").unwrap()),
            _ => fields[3]["value"] = json!(encrypt_str(&k, "").unwrap()),
        }
        after
    };
    for how in ["missing", "twice", "garbled", "empty", "other key", "blank"] {
        let after = broken(how);
        let pending_id = rotation_id_of_ciphertext(after["fields"][2]["value"].as_str().unwrap());
        assert_eq!(
            commit(&after, &org_key(), REVISION, NOW, &pending_id).unwrap_err(),
            RotateError::CorruptPending,
            "{how}"
        );
        // An abort never needs the base, and removes every base field.
        let body = abort(&after, &org_key(), REVISION, NOW, &pending_id).unwrap();
        assert_eq!(body["fields"].as_array().unwrap().len(), 2, "{how}");
    }
}

#[test]
fn a_start_drops_a_stray_base_and_matches_the_names_loosely() {
    let (mut before, k) = item(true);
    before["fields"].as_array_mut().unwrap().push(json!({
        "name": encrypt_str(&k, " Ferrowarden_NEXT_Base").unwrap(),
        "value": encrypt_str(&k, "stale").unwrap(),
        "type": 1, "linkedId": null,
    }));
    let (body, _) = start(&before, &org_key(), REVISION, NEXT).unwrap();
    // The two original fields, then the pending value and one fresh base.
    assert_eq!(body["fields"].as_array().unwrap().len(), 4);
    assert_eq!(
        open(&k, &body["fields"][3]["value"]),
        password_base_of_ciphertext(before["login"]["password"].as_str().unwrap())
    );
}

#[test]
fn an_item_that_has_master_password_reprompt_now_is_never_rotated() {
    let (mut before, _) = item(true);
    before["reprompt"] = json!(1);
    assert_eq!(
        start(&before, &org_key(), REVISION, NEXT).unwrap_err(),
        RotateError::NotRotatable
    );
    let (mut after, _) = started(true);
    after["reprompt"] = json!(1);
    assert_eq!(
        commit(&after, &org_key(), REVISION, NOW, &rid(&after)).unwrap_err(),
        RotateError::NotRotatable
    );
    assert_eq!(
        abort(&after, &org_key(), REVISION, NOW, &rid(&after)).unwrap_err(),
        RotateError::NotRotatable
    );
}
