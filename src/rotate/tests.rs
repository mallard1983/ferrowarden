use super::*;
use crate::vault::model::ItemKind;

const COLLECTION: &str = "6c0d7f0e-52d0-4b5b-8a39-0e8a7f6d5c4b";

fn collection() -> ManagedCollection {
    ManagedCollection {
        id: COLLECTION.to_string(),
        organization_id: "org-1".to_string(),
        name: "Ferrowarden managed".to_string(),
        items: 0,
    }
}

fn managed_login(id: &str) -> CredentialEntry {
    let mut e = CredentialEntry::login(id, &["https://a.example"]);
    e.collection_ids = vec![COLLECTION.to_string()];
    e
}

// ── The item checks ───────────────────────────────────────────────────────────

#[test]
fn a_login_with_a_password_in_the_managed_collection_can_be_rotated() {
    let entries = [managed_login("1")];
    assert_eq!(check_item("svc", &entries, &collection()).unwrap().id, "1");
    // Also when the item is in other collections too.
    let mut shared = managed_login("2");
    shared.collection_ids.push("another".into());
    assert!(check_item("svc", &[shared], &collection()).is_ok());
}

#[test]
fn outside_the_managed_collection_is_one_answer_whether_the_item_exists_or_not() {
    let e = |r: FerroResult<&CredentialEntry>| r.unwrap_err().to_string();
    // Not at all.
    let nothing = e(check_item("svc", &[], &collection()));
    // Elsewhere: in no collection (a personal item), or in another one.
    let mut personal = CredentialEntry::login("1", &["https://a.example"]);
    personal.collection_ids.clear();
    let mut other = managed_login("2");
    other.collection_ids = vec!["another".into()];
    let personal_text = e(check_item("svc", &[personal], &collection()));
    let other_text = e(check_item("svc", &[other], &collection()));
    assert_eq!(nothing, personal_text);
    assert_eq!(nothing, other_text);
    assert!(matches!(
        check_item("svc", &[], &collection()),
        Err(FerroError::CredentialNotManaged(n)) if n == "svc"
    ));
}

#[test]
fn only_logins_with_a_password_and_no_reprompt_can_be_rotated() {
    let not_rotatable = |e: CredentialEntry| {
        matches!(
            check_item("svc", &[e], &collection()),
            Err(FerroError::CredentialNotRotatable(_))
        )
    };
    let mut note = managed_login("1");
    note.kind = ItemKind::SecureNote;
    assert!(not_rotatable(note));
    let mut nopass = managed_login("1");
    nopass.has_password = false;
    assert!(not_rotatable(nopass));
    let mut reprompt = managed_login("1");
    reprompt.reprompt = true;
    assert!(not_rotatable(reprompt));
    // An item outside the collection is "not managed" before it is anything
    // else: the type of an item outside it is not told.
    let mut outside_note = managed_login("1");
    outside_note.kind = ItemKind::SecureNote;
    outside_note.collection_ids.clear();
    assert!(matches!(
        check_item("svc", &[outside_note], &collection()),
        Err(FerroError::CredentialNotManaged(_))
    ));
}

#[test]
fn two_items_with_the_name_are_ambiguous() {
    let entries = [managed_login("1"), managed_login("2")];
    assert!(matches!(
        check_item("svc", &entries, &collection()),
        Err(FerroError::AmbiguousCredential(n)) if n == "svc"
    ));
}

#[test]
fn membership_comes_before_ambiguity_and_a_second_item_anywhere_is_ambiguous() {
    let personal = |id: &str| {
        let mut e = CredentialEntry::login(id, &["https://a.example"]);
        e.collection_ids.clear();
        e
    };
    // Two items with the name, neither in the managed collection: the same
    // answer as for a name that does not exist, never "ambiguous".
    let nothing = check_item("svc", &[], &collection())
        .unwrap_err()
        .to_string();
    let two_outside = [personal("1"), personal("2")];
    let outside = check_item("svc", &two_outside, &collection());
    assert!(matches!(outside, Err(FerroError::CredentialNotManaged(_))));
    assert_eq!(outside.unwrap_err().to_string(), nothing);
    // One in the collection and another one anywhere else: ambiguous, in both
    // orders.
    for entries in [
        [managed_login("1"), personal("2")],
        [personal("2"), managed_login("1")],
    ] {
        assert!(matches!(
            check_item("svc", &entries, &collection()),
            Err(FerroError::AmbiguousCredential(n)) if n == "svc"
        ));
    }
}

#[test]
fn an_operators_abort_is_offered_only_where_it_would_be_accepted() {
    let pending = |id: &str| {
        let mut e = managed_login(id);
        e.has_next = true;
        e.rotation_id = Some("rid-1".to_string());
        e
    };
    let collection = collection();
    fn abortable<'a>(entries: &'a [CredentialEntry], c: &ManagedCollection) -> Option<&'a str> {
        abortable_rotation("svc", entries, c)
    }
    assert_eq!(abortable(&[pending("1")], &collection), Some("rid-1"));

    // No rotation pending.
    assert_eq!(abortable(&[managed_login("1")], &collection), None);
    // A pending field that cannot be named (two of them, or one with no
    // value): the abort would be refused, so there is no button.
    let mut unnamed = pending("1");
    unnamed.rotation_id = None;
    assert_eq!(abortable(&[unnamed], &collection), None);
    // Ambiguous, outside the collection, or not rotatable.
    let mut other = managed_login("2");
    other.collection_ids.clear();
    assert_eq!(abortable(&[pending("1"), other], &collection), None);
    let mut outside = pending("1");
    outside.collection_ids.clear();
    assert_eq!(abortable(&[outside], &collection), None);
    let mut reprompt = pending("1");
    reprompt.reprompt = true;
    assert_eq!(abortable(&[reprompt], &collection), None);
}

#[test]
fn a_finish_body_names_the_rotation_and_nothing_else() {
    let parse = |json: &str| {
        crate::api::strict_json::parse_request::<FinishPayload>(json.as_bytes())
            .map_err(FerroError::InvalidJson)
            .and_then(FinishPayload::validate)
    };
    assert_eq!(parse(r#"{"rotation_id":"AbC-_123"}"#).unwrap(), "AbC-_123");
    for bad in [
        "{}",
        r#"{"rotation_id":null}"#,
        r#"{"rotation_id":7}"#,
        r#"{"rotation_id":"a","x":1}"#,
        r#"{"rotation_id":"a","rotation_id":"a"}"#,
        "[]",
        "null",
    ] {
        assert!(parse(bad).is_err(), "{bad}");
    }
    // The wrong shape of an id is a bad request, not a mismatch.
    for bad in ["", "has space", "slash/slash", &"a".repeat(65)] {
        let body = serde_json::json!({ "rotation_id": bad }).to_string();
        assert!(
            matches!(parse(&body), Err(FerroError::InvalidRequest(_))),
            "{bad:?}"
        );
    }
}

// ── The request ───────────────────────────────────────────────────────────────

fn payload(json: &str) -> FerroResult<RotateRequest> {
    crate::api::strict_json::parse_request::<RotatePayload>(json.as_bytes())
        .map_err(FerroError::InvalidJson)?
        .validate()
}

#[test]
fn the_defaults_are_those_of_a_create() {
    let r = payload("{}").unwrap();
    assert_eq!(r.charset, Charset::default());
    assert_eq!(r.length, generate::DEFAULT_LENGTH);
    assert_eq!(RotatePayload::default().validate().unwrap(), r);
    assert_eq!(payload(r#"{"generate":{}}"#).unwrap(), r);
}

#[test]
fn the_options_are_checked_like_a_creates() {
    let r = payload(r#"{"generate":{"length":16,"charset":"hex"}}"#).unwrap();
    assert_eq!((r.charset, r.length), (Charset::Hex, 16));
    let r = payload(r#"{"generate":{"length":128,"charset":"base64url"}}"#).unwrap();
    assert_eq!(r.length, 128);
    for bad in [
        r#"{"generate":{"length":15}}"#,
        r#"{"generate":{"length":129}}"#,
        r#"{"generate":{"length":4294967296}}"#,
        r#"{"generate":{"charset":"emoji"}}"#,
        r#"{"generate":{"charset":""}}"#,
    ] {
        assert!(
            matches!(payload(bad), Err(FerroError::InvalidRequest(_))),
            "{bad}"
        );
    }
    // Strict JSON: nulls, other types, unknown members and non-objects.
    for bad in [
        r#"{"generate":null}"#,
        r#"{"generate":{"length":null}}"#,
        r#"{"generate":{"length":"32"}}"#,
        r#"{"generate":{"x":1}}"#,
        r#"{"other":1}"#,
        r#"{"generate":{},"generate":{}}"#,
        "[]",
        "[{}]",
        r#""generate""#,
        "null",
        "7",
    ] {
        assert!(payload(bad).is_err(), "{bad}");
    }
}

#[test]
fn the_fingerprint_identifies_one_operation() {
    let r = payload("{}").unwrap();
    let base = r.fingerprint("key-1", "item-1", "svc");
    assert_eq!(base.len(), 64);
    assert!(base.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(base, r.fingerprint("key-1", "item-1", "svc"), "stable");
    // Every part of the operation changes it.
    assert_ne!(base, r.fingerprint("key-2", "item-1", "svc"), "the key");
    assert_ne!(base, r.fingerprint("key-1", "item-2", "svc"), "the item");
    assert_ne!(base, r.fingerprint("key-1", "item-1", "svc2"), "the name");
    let longer = payload(r#"{"generate":{"length":33}}"#).unwrap();
    assert_ne!(
        base,
        longer.fingerprint("key-1", "item-1", "svc"),
        "the length"
    );
    let hex = payload(r#"{"generate":{"charset":"hex"}}"#).unwrap();
    assert_ne!(
        base,
        hex.fingerprint("key-1", "item-1", "svc"),
        "the charset"
    );
}

#[test]
fn a_rotation_is_never_the_approval_of_a_create() {
    // A create's fingerprint over the same fields can never equal a rotation's:
    // they hash different canonical forms (the rotation's carries its kind).
    let r = payload("{}").unwrap();
    let rotate = r.fingerprint("key-1", "item-1", "svc");
    let create = crate::create::CreateRequest {
        name: "svc".into(),
        username: None,
        uris: vec!["https://a.example".into()],
        charset: r.charset,
        length: r.length,
        approval_required: false,
    }
    .fingerprint("key-1");
    assert_ne!(rotate, create);
}

#[test]
fn the_detail_shows_what_the_human_decides_on() {
    let r = payload(r#"{"generate":{"length":24,"charset":"ascii"}}"#).unwrap();
    let d = r.detail("svc", "Ferrowarden managed");
    assert_eq!(d.name, "svc");
    assert_eq!(d.collection, "Ferrowarden managed");
    assert_eq!((d.charset.as_str(), d.length), ("ascii", 24));
    let text = format!("{:?}", d.to_json());
    assert!(text.contains("ascii") && text.contains("24"));
}

#[test]
fn the_answers_carry_placeholders_and_never_a_value() {
    let started = Started {
        name: "Service (prod)".into(),
        current: placeholder("Service (prod)", Selector::Password),
        next: placeholder("Service (prod)", Selector::Next),
        rotation_id: "abc".into(),
    };
    let json = serde_json::to_value(&started).unwrap();
    assert_eq!(json["current"], "{{vault:'Service (prod)'}}");
    assert_eq!(json["next"], "{{vault:'Service (prod)':next}}");
    assert_eq!(json["rotation_id"], "abc");
    assert_eq!(json.as_object().unwrap().len(), 4);
    let finished = Finished {
        name: "svc".into(),
        placeholder: placeholder("svc", Selector::Password),
    };
    assert_eq!(
        serde_json::to_value(finished).unwrap(),
        serde_json::json!({"name": "svc", "placeholder": "{{vault:svc}}"})
    );
}
