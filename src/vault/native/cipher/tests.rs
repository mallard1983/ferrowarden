use super::super::api::{RawLogin, RawUri};
use super::super::enc::test_support::{encrypt2, key};
use super::*;
use crate::vault::model::{FieldLookup, APPROVAL_FIELD};

// A synthetic vault: the user key, one organisation key, and items
// encrypted the way a client does (with and without per-item keys).
struct Vault {
    ring: KeyRing,
    user: SymKey,
    org: SymKey,
}

fn vault() -> Vault {
    let mut org = HashMap::new();
    org.insert("org1".to_string(), key(40));
    Vault {
        ring: KeyRing {
            user: key(1),
            rsa: None,
            org,
        },
        user: key(1),
        org: key(40),
    }
}

fn e(k: &SymKey, s: &str) -> Option<String> {
    Some(encrypt2(k, [5; 16], s.as_bytes()))
}

fn login(k: &SymKey) -> RawCipher {
    RawCipher {
        id: "id-1".into(),
        organization_id: None,
        item_type: 1,
        reprompt: 0,
        name: e(k, "grafana"),
        notes: e(k, "NOTES"),
        key: None,
        deleted_date: None,
        archived_date: None,
        view_password: None,
        collection_ids: Vec::new(),
        login: Some(RawLogin {
            username: e(k, "USER"),
            password: e(k, "PASS"),
            totp: e(k, "JBSWY3DPEHPK3PXP"),
            uris: Some(vec![
                RawUri {
                    uri: e(k, "https://a.example"),
                    match_type: None,
                },
                RawUri {
                    uri: e(k, "^re$"),
                    match_type: Some(4),
                },
                RawUri {
                    uri: e(k, "https://never.example"),
                    match_type: Some(5),
                },
                RawUri {
                    uri: e(k, "b.example"),
                    match_type: Some(0),
                },
            ]),
        }),
        fields: Some(vec![
            RawField {
                name: e(k, "api"),
                value: e(k, "V"),
                field_type: 1,
                linked_id: None,
            },
            RawField {
                name: e(k, "lu"),
                value: None,
                field_type: 3,
                linked_id: Some(100),
            },
            RawField {
                name: e(k, "lp"),
                value: None,
                field_type: 3,
                linked_id: Some(101),
            },
            RawField {
                name: e(k, "dup"),
                value: e(k, "1"),
                field_type: 0,
                linked_id: None,
            },
            RawField {
                name: e(k, "dup"),
                value: e(k, "2"),
                field_type: 0,
                linked_id: None,
            },
            RawField {
                name: e(k, "unknown"),
                value: e(k, "x"),
                field_type: 9,
                linked_id: None,
            },
        ]),
    }
}

#[test]
fn metadata_lists_what_the_item_offers() {
    let v = vault();
    let (name, entry) = build_metadata(&v.ring.view(), &login(&v.user)).unwrap();
    assert_eq!(name, "grafana");
    assert_eq!(entry.kind, ItemKind::Login);
    assert_eq!(entry.uris, vec!["https://a.example", "b.example"]);
    assert!(entry.has_username && entry.has_password && entry.has_totp && entry.has_notes);
    assert!(!entry.reprompt);
    let names: Vec<_> = entry
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f.kind))
        .collect();
    assert_eq!(
        names,
        vec![
            ("api", FieldKind::Hidden),
            ("lu", FieldKind::LinkedUsername),
            ("lp", FieldKind::LinkedPassword),
            ("dup", FieldKind::Text),
            ("dup", FieldKind::Text),
        ],
        "unknown field types are not offered"
    );
    // No secret in the debug form.
    let dbg = format!("{entry:?}");
    assert!(!dbg.contains("PASS") && !dbg.contains("JBSW"));
}

#[test]
fn bindings_field_overrides_uris_and_is_hidden() {
    let v = vault();
    let mut c = login(&v.user);
    c.fields = Some(vec![RawField {
        name: e(&v.user, BINDINGS_FIELD),
        value: e(
            &v.user,
            "https://api.example, ssh://host\nhttps://m.example",
        ),
        field_type: 0,
        linked_id: None,
    }]);
    let (_, entry) = build_metadata(&v.ring.view(), &c).unwrap();
    assert_eq!(
        entry.uris,
        vec!["https://api.example", "ssh://host", "https://m.example"]
    );
    assert!(entry.fields.is_empty());
}

#[test]
fn secure_notes_and_presence_flags() {
    let v = vault();
    let c = RawCipher {
        item_type: 2,
        login: None,
        fields: None,
        notes: e(&v.user, "body"),
        ..login(&v.user)
    };
    let (_, entry) = build_metadata(&v.ring.view(), &c).unwrap();
    assert_eq!(entry.kind, ItemKind::SecureNote);
    assert!(entry.has_notes && !entry.has_password && !entry.has_username && !entry.has_totp);
    // An empty ciphertext string counts as absent.
    let mut empty = login(&v.user);
    empty.login.as_mut().unwrap().password = Some(String::new());
    assert!(
        !build_metadata(&v.ring.view(), &empty)
            .unwrap()
            .1
            .has_password
    );
}

#[test]
fn unsupported_kinds_are_not_candidates() {
    let v = vault();
    for t in [0u32, 3, 4, 5, 6, 99, 100_000] {
        let c = RawCipher {
            item_type: t,
            ..login(&v.user)
        };
        assert!(!is_supported_kind(&c), "type {t}");
    }
    assert!(is_supported_kind(&login(&v.user)));
}

#[test]
fn per_item_key_user_and_organisation_paths() {
    let v = vault();
    // User item with its own key.
    let item_key_bytes = [0x33u8; 64];
    let ik = SymKey::from_slice(&item_key_bytes).unwrap();
    let mut c = login(&ik);
    c.key = Some(encrypt2(&v.user, [9; 16], &item_key_bytes));
    let (name, _) = build_metadata(&v.ring.view(), &c).unwrap();
    assert_eq!(name, "grafana");
    // Value decryption goes through the same key.
    assert_eq!(
        builtin_value(&v.ring.view(), &c, Builtin::Password, 0, "x")
            .unwrap()
            .as_str(),
        "PASS"
    );

    // Organisation item, with and without its own key.
    let mut o = login(&v.org);
    o.organization_id = Some("org1".into());
    assert!(build_metadata(&v.ring.view(), &o).is_ok());
    let oik = SymKey::from_slice(&[0x44u8; 64]).unwrap();
    let mut o2 = login(&oik);
    o2.organization_id = Some("org1".into());
    o2.key = Some(encrypt2(&v.org, [9; 16], &[0x44u8; 64]));
    assert!(build_metadata(&v.ring.view(), &o2).is_ok());
    assert_eq!(
        builtin_value(&v.ring.view(), &o2, Builtin::Username, 0, "x")
            .unwrap()
            .as_str(),
        "USER"
    );
}

#[test]
fn fail_closed_reasons() {
    let v = vault();
    let reason_of = |c: &RawCipher| build_metadata(&v.ring.view(), c).unwrap_err();

    // Organisation without a key.
    let mut c = login(&v.org);
    c.organization_id = Some("unknown-org".into());
    assert_eq!(reason_of(&c), reason::MISSING_ORG_KEY);

    // Encrypted with the wrong key: MAC failure.
    assert_eq!(reason_of(&login(&key(77))), "mac_failure");

    // Type 0 name (no MAC): refused, never decrypted.
    let mut c = login(&v.user);
    c.name = Some("0.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==".into());
    assert_eq!(reason_of(&c), "unsupported_encstring_type");

    // Unknown and legacy type numbers.
    for t in ["1", "5", "6", "7", "9", "255"] {
        let mut c = login(&v.user);
        c.name = Some(format!("{t}.AAAA|BBBB|CCCC"));
        assert_eq!(reason_of(&c), "unsupported_encstring_type", "type {t}");
    }

    // Garbage.
    let mut c = login(&v.user);
    c.name = Some("not an encstring".into());
    assert_eq!(reason_of(&c), "malformed_encstring");
    let mut c = login(&v.user);
    c.name = Some("2.!!!|@@@|###".into());
    assert_eq!(reason_of(&c), "malformed_encstring");

    // Per-item key of the wrong length (32 bytes).
    let mut c = login(&v.user);
    c.key = Some(encrypt2(&v.user, [9; 16], &[1u8; 32]));
    assert_eq!(reason_of(&c), "bad_key_length");
    // Per-item key under the wrong wrapping key.
    let mut c = login(&v.user);
    c.key = Some(encrypt2(&key(99), [9; 16], &[1u8; 64]));
    assert_eq!(reason_of(&c), reason::ITEM_KEY);

    // A bad URI poisons the item, but a bad non-binding URI does not.
    let mut c = login(&v.user);
    c.login.as_mut().unwrap().uris.as_mut().unwrap()[0].uri = Some("2.AA==|AA==|AA==".into());
    assert_eq!(reason_of(&c), "malformed_encstring");
    let mut c = login(&v.user);
    c.login.as_mut().unwrap().uris.as_mut().unwrap()[1].uri = Some("garbage".into());
    assert!(build_metadata(&v.ring.view(), &c).is_ok());

    // Invalid UTF-8 plaintext in the name.
    let mut c = login(&v.user);
    c.name = Some(encrypt2(&v.user, [1; 16], &[0xff, 0xfe, 0xfd]));
    assert_eq!(reason_of(&c), "invalid_utf8");

    // No name at all.
    let mut c = login(&v.user);
    c.name = None;
    assert_eq!(reason_of(&c), reason::MISSING_NAME);
}

#[test]
fn values_are_decrypted_on_demand() {
    let v = vault();
    let c = login(&v.user);
    let val = |w| builtin_value(&v.ring.view(), &c, w, 59, "x").unwrap();
    assert_eq!(val(Builtin::Password).as_str(), "PASS");
    assert_eq!(val(Builtin::Username).as_str(), "USER");
    assert_eq!(val(Builtin::Notes).as_str(), "NOTES");
    // TOTP: the code for the secret, not the secret.
    let code = val(Builtin::Totp);
    assert_eq!(code.len(), 6);
    assert!(code.bytes().all(|b| b.is_ascii_digit()));
    assert_ne!(code.as_str(), "JBSWY3DPEHPK3PXP");

    assert_eq!(
        field_value(&v.ring.view(), &c, "api", "x")
            .unwrap()
            .as_str(),
        "V"
    );
    assert_eq!(
        field_value(&v.ring.view(), &c, "lu", "x").unwrap().as_str(),
        "USER"
    );
    assert_eq!(
        field_value(&v.ring.view(), &c, "lp", "x").unwrap().as_str(),
        "PASS"
    );
    assert!(matches!(
        field_value(&v.ring.view(), &c, "dup", "x"),
        Err(FerroError::AmbiguousField { .. })
    ));
    assert!(matches!(
        field_value(&v.ring.view(), &c, "missing", "x"),
        Err(FerroError::CredentialNotFound(_))
    ));
}

#[test]
fn missing_blank_and_malformed_values_are_not_found() {
    let v = vault();
    let mut c = login(&v.user);
    c.login.as_mut().unwrap().password = e(&v.user, "   ");
    c.login.as_mut().unwrap().totp = e(&v.user, "not base32 !");
    c.login.as_mut().unwrap().username = None;
    c.notes = None;
    for w in [
        Builtin::Password,
        Builtin::Totp,
        Builtin::Username,
        Builtin::Notes,
    ] {
        assert!(
            matches!(
                builtin_value(&v.ring.view(), &c, w, 0, "x"),
                Err(FerroError::CredentialNotFound(_))
            ),
            "{w:?}"
        );
    }
    // A secure note has no login values.
    let n = RawCipher {
        item_type: 2,
        ..login(&v.user)
    };
    assert!(matches!(
        builtin_value(&v.ring.view(), &n, Builtin::Password, 0, "x"),
        Err(FerroError::CredentialNotFound(_))
    ));
}

#[test]
fn a_tampered_value_is_never_decrypted() {
    let v = vault();
    let mut c = login(&v.user);
    // Flip one ciphertext byte of the password: the MAC must reject it.
    let s = c.login.as_ref().unwrap().password.clone().unwrap();
    let (head, rest) = s.split_once('|').unwrap();
    let (ct, mac) = rest.split_once('|').unwrap();
    let mut ct = ct.to_string().into_bytes();
    ct[0] = if ct[0] == b'A' { b'B' } else { b'A' };
    c.login.as_mut().unwrap().password =
        Some(format!("{head}|{}|{mac}", String::from_utf8(ct).unwrap()));
    let err = builtin_value(&v.ring.view(), &c, Builtin::Password, 0, "x").unwrap_err();
    assert!(matches!(err, FerroError::Internal(_)));
    // The message the agent sees carries no detail.
    assert!(!err.to_string().contains("mac"));
}

#[test]
fn debug_of_the_key_ring_shows_no_key() {
    let v = vault();
    let dbg = format!("{:?}", v.ring);
    assert!(dbg.contains("KeyRing") && !dbg.contains("SymKey"));
    let _ = v.org;
}

#[test]
fn only_an_explicit_false_hides_the_password() {
    let k = key(1);
    let mut c = login(&k);
    assert!(!is_password_hidden(&c), "absent: an older server");
    c.view_password = Some(true);
    assert!(!is_password_hidden(&c));
    c.view_password = Some(false);
    assert!(is_password_hidden(&c));
}

// ── The reserved approval field ───────────────────────────────────────────

fn with_approval_field(v: &Vault, value: Option<&str>) -> RawCipher {
    with_named_approval_field(v, APPROVAL_FIELD, value)
}

fn with_named_approval_field(v: &Vault, name: &str, value: Option<&str>) -> RawCipher {
    let mut c = login(&v.user);
    c.fields.as_mut().unwrap().push(RawField {
        name: e(&v.user, name),
        value: value.and_then(|v2| e(&v.user, v2)),
        field_type: 0,
        linked_id: None,
    });
    c
}

#[test]
fn an_item_without_the_approval_field_does_not_need_approval() {
    let v = vault();
    let (_, entry) = build_metadata(&v.ring.view(), &login(&v.user)).unwrap();
    assert!(!entry.approval_required && !entry.approval_field_invalid);
}

#[test]
fn the_value_required_in_any_spelling_needs_approval_and_is_not_a_warning() {
    let v = vault();
    for value in [
        "required",
        "REQUIRED",
        "Required",
        "  required\n",
        "\trequired ",
    ] {
        let (_, entry) =
            build_metadata(&v.ring.view(), &with_approval_field(&v, Some(value))).unwrap();
        assert!(entry.approval_required, "{value:?}");
        assert!(!entry.approval_field_invalid, "{value:?}");
    }
}

#[test]
fn the_field_name_matches_in_any_letter_case_and_with_spaces() {
    let v = vault();
    for name in [
        "Ferrowarden_Approval",
        "FERROWARDEN_APPROVAL",
        " ferrowarden_approval ",
    ] {
        let c = with_named_approval_field(&v, name, Some("required"));
        let (_, entry) = build_metadata(&v.ring.view(), &c).unwrap();
        assert!(entry.approval_required, "{name:?}");
        assert!(
            entry
                .fields
                .iter()
                .all(|f| !f.name.eq_ignore_ascii_case(name.trim())),
            "{name:?} must not be offered as a field"
        );
    }
}

#[test]
fn any_other_value_including_none_still_needs_approval_and_is_flagged() {
    let v = vault();
    // Fail closed: a typo, a no, an empty value or no value all mean required.
    for value in [
        Some("requird"),
        Some("optional"),
        Some("false"),
        Some("no"),
        Some("0"),
        Some("requiredx"),
        Some("not required"),
        Some(""),
        Some("   "),
        None,
    ] {
        let (_, entry) = build_metadata(&v.ring.view(), &with_approval_field(&v, value)).unwrap();
        assert!(entry.approval_required, "{value:?}");
        assert!(entry.approval_field_invalid, "{value:?}");
    }
}

#[test]
fn the_approval_field_is_not_a_field_and_its_value_is_not_kept() {
    let v = vault();
    let c = with_approval_field(&v, Some("required"));
    let (_, entry) = build_metadata(&v.ring.view(), &c).unwrap();
    // Excluded from the custom fields, like the bindings field.
    assert!(entry.fields.iter().all(|f| f.name != APPROVAL_FIELD));
    assert!(matches!(
        entry.field(APPROVAL_FIELD),
        crate::vault::model::FieldLookup::Missing
    ));
    assert_eq!(entry.fields.len(), 5, "the same fields as without it");
    // The other fields and the bindings are unchanged.
    assert_eq!(entry.uris, vec!["https://a.example", "b.example"]);
    let dbg = format!("{entry:?}");
    assert!(!dbg.contains("required\""), "{dbg}");
    // It is not available as a value either: a request for it is "no such field".
    let err = field_value(&v.ring.view(), &c, "nope", "x").unwrap_err();
    assert!(matches!(err, FerroError::CredentialNotFound(_)));
}

#[test]
fn the_approval_field_works_on_secure_notes_and_next_to_the_bindings_field() {
    let v = vault();
    let c = RawCipher {
        item_type: 2,
        login: None,
        notes: e(&v.user, "body"),
        fields: Some(vec![
            RawField {
                name: e(&v.user, BINDINGS_FIELD),
                value: e(&v.user, "https://api.example"),
                field_type: 0,
                linked_id: None,
            },
            RawField {
                name: e(&v.user, APPROVAL_FIELD),
                value: e(&v.user, "required"),
                field_type: 0,
                linked_id: None,
            },
        ]),
        ..login(&v.user)
    };
    let (_, entry) = build_metadata(&v.ring.view(), &c).unwrap();
    assert!(entry.approval_required && !entry.approval_field_invalid);
    assert_eq!(entry.uris, vec!["https://api.example"]);
    assert!(entry.fields.is_empty());
}

#[test]
fn an_unreadable_approval_field_leaves_the_item_out_rather_than_unguarded() {
    let v = vault();
    let mut c = with_approval_field(&v, Some("required"));
    // Corrupt the ciphertext of the field's value: the item cannot be read
    // safely, so it is excluded (never offered without its approval rule).
    let last = c.fields.as_mut().unwrap().last_mut().unwrap();
    last.value = Some("2.AAAA|BBBB|CCCC".to_string());
    assert!(build_metadata(&v.ring.view(), &c).is_err());
    // Likewise a name that cannot be decrypted.
    let mut c = with_approval_field(&v, Some("required"));
    let last = c.fields.as_mut().unwrap().last_mut().unwrap();
    last.name = Some("2.AAAA|BBBB|CCCC".to_string());
    assert!(build_metadata(&v.ring.view(), &c).is_err());
}

// ── The reserved pending-rotation field ───────────────────────────────────────

fn with_next_field(v: &Vault, names_and_values: &[(&str, &str)]) -> RawCipher {
    let mut c = login(&v.user);
    for (name, value) in names_and_values {
        c.fields.as_mut().unwrap().push(RawField {
            name: e(&v.user, name),
            value: e(&v.user, value),
            field_type: 1,
            linked_id: None,
        });
    }
    c
}

#[test]
fn an_item_without_a_pending_rotation_has_none() {
    let v = vault();
    let (_, entry) = build_metadata(&v.ring.view(), &login(&v.user)).unwrap();
    assert!(!entry.has_next);
    assert!(entry.collection_ids.is_empty());
}

#[test]
fn a_pending_rotation_is_flagged_and_its_field_is_never_listed() {
    let v = vault();
    let before = build_metadata(&v.ring.view(), &login(&v.user)).unwrap().1;
    for name in [
        "ferrowarden_next",
        "Ferrowarden_Next",
        "  ferrowarden_next  ",
    ] {
        let c = with_next_field(&v, &[(name, "PENDING")]);
        let (_, entry) = build_metadata(&v.ring.view(), &c).unwrap();
        assert!(entry.has_next, "{name:?}");
        // The listing's fields are those of the item without it.
        assert_eq!(entry.fields, before.fields, "{name:?}");
        assert!(matches!(
            entry.field("ferrowarden_next"),
            FieldLookup::Missing
        ));
    }
    // Two of them are still flagged (the vault refuses to guess later).
    let c = with_next_field(&v, &[("ferrowarden_next", "A"), ("ferrowarden_next", "B")]);
    assert!(build_metadata(&v.ring.view(), &c).unwrap().1.has_next);
}

#[test]
fn the_entry_carries_the_collections_of_the_item() {
    let v = vault();
    let mut c = login(&v.user);
    c.collection_ids = vec!["c-1".into(), "c-2".into()];
    let (_, entry) = build_metadata(&v.ring.view(), &c).unwrap();
    assert_eq!(entry.collection_ids, ["c-1", "c-2"]);
}

#[test]
fn the_pending_value_is_read_through_next_and_only_through_it() {
    let v = vault();
    let c = with_next_field(&v, &[("ferrowarden_next", "PENDING-VALUE")]);
    let value = builtin_value(&v.ring.view(), &c, Builtin::Next, 0, "x").unwrap();
    assert_eq!(value.as_str(), "PENDING-VALUE");
    // The password is still the password.
    let value = builtin_value(&v.ring.view(), &c, Builtin::Password, 0, "x").unwrap();
    assert_eq!(value.as_str(), "PASS");
    // The credential map never lists the field (see the test above), so a
    // `field:ferrowarden_next` placeholder is refused before it gets here.
}

#[test]
fn next_without_a_pending_value_is_not_found_and_two_of_them_are_ambiguous() {
    let v = vault();
    let none = builtin_value(&v.ring.view(), &login(&v.user), Builtin::Next, 0, "x");
    assert!(matches!(none, Err(FerroError::CredentialNotFound(_))));

    let two = with_next_field(&v, &[("ferrowarden_next", "A"), ("Ferrowarden_Next", "B")]);
    let err = builtin_value(&v.ring.view(), &two, Builtin::Next, 0, "x").unwrap_err();
    assert!(
        matches!(&err, FerroError::AmbiguousField { field, .. } if field == "ferrowarden_next"),
        "{err}"
    );

    // An empty value, or a value that is not readable, is not handed out.
    let mut empty = with_next_field(&v, &[("ferrowarden_next", "x")]);
    empty.fields.as_mut().unwrap().last_mut().unwrap().value = None;
    assert!(builtin_value(&v.ring.view(), &empty, Builtin::Next, 0, "x").is_err());
    let mut wrong = with_next_field(&v, &[("ferrowarden_next", "x")]);
    wrong.fields.as_mut().unwrap().last_mut().unwrap().value = e(&key(99), "WRONG");
    assert!(builtin_value(&v.ring.view(), &wrong, Builtin::Next, 0, "x").is_err());
}
