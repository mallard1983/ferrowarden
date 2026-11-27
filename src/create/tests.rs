use super::*;
use serde_json::json;

fn payload(v: serde_json::Value) -> CreatePayload {
    serde_json::from_value(v).unwrap()
}

fn ok() -> serde_json::Value {
    json!({
        "name": "agent_keycloak_admin",
        "username": "admin",
        "uris": ["https://b.example.com", "https://a.example.com"],
        "generate": { "length": 32, "charset": "alphanumeric" },
        "approval_required": false,
    })
}

fn request(v: serde_json::Value) -> CreateRequest {
    payload(v).validate().unwrap().0
}

fn rejected(v: serde_json::Value) -> String {
    match payload(v).validate() {
        Err(FerroError::InvalidRequest(m)) => m,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ── Validation ────────────────────────────────────────────────────────────────

#[test]
fn a_valid_request_keeps_its_fields_and_fills_in_the_defaults() {
    let (req, urls) = payload(ok()).validate().unwrap();
    assert_eq!(req.name, "agent_keycloak_admin");
    assert_eq!(req.username.as_deref(), Some("admin"));
    assert_eq!(req.uris, ["https://b.example.com", "https://a.example.com"]);
    assert_eq!((req.charset, req.length), (Charset::Alphanumeric, 32));
    assert!(!req.approval_required);
    assert_eq!(urls.len(), 2);

    let minimal = request(json!({"name": "x", "uris": ["http://h"], "generate": {}}));
    assert_eq!(minimal.username, None);
    assert_eq!(
        (minimal.charset, minimal.length),
        (Charset::Alphanumeric, 32)
    );
    assert!(!minimal.approval_required);
}

#[test]
fn names_are_one_to_128_characters_without_controls_and_referenceable() {
    let with = |name: &str| {
        let mut v = ok();
        v["name"] = json!(name);
        v
    };
    assert!(payload(with("a")).validate().is_ok());
    assert!(payload(with(&"a".repeat(128))).validate().is_ok());
    // Characters, not bytes.
    assert!(payload(with(&"\u{e4}".repeat(128))).validate().is_ok());
    assert!(rejected(with("")).contains("1-128"));
    assert!(rejected(with(&"a".repeat(129))).contains("1-128"));
    assert!(rejected(with("   ")).contains("1-128"));
    for bad in ["a\nb", "a\tb", "a\u{0}b", "a\u{7f}b", "a\r"] {
        assert!(rejected(with(bad)).contains("control"), "{bad:?}");
    }
    // Anything else can be quoted in a placeholder, and round-trips.
    for name in [
        "plain-name_1.2",
        "Service (prod)",
        "it's",
        "back\\slash",
        "{{vault:x}}",
        "a}}b",
        "d\u{fc}ck \u{20ac}",
        "'",
        " leading and trailing ",
    ] {
        assert!(referenceable(name), "{name:?}");
        assert!(payload(with(name)).validate().is_ok(), "{name:?}");
    }
}

#[test]
fn the_username_is_optional_but_bounded() {
    let with = |u: serde_json::Value| {
        let mut v = ok();
        v["username"] = u;
        v
    };
    assert!(payload(with(json!("u"))).validate().is_ok());
    assert!(payload(with(json!("u".repeat(256)))).validate().is_ok());
    assert!(rejected(with(json!(""))).contains("username"));
    assert!(rejected(with(json!("u".repeat(257)))).contains("username"));
    assert!(rejected(with(json!("a\nb"))).contains("control"));
}

#[test]
fn uris_are_one_to_sixteen_absolute_http_or_https_urls() {
    let with = |u: serde_json::Value| {
        let mut v = ok();
        v["uris"] = u;
        v
    };
    assert!(payload(with(json!(["http://h"]))).validate().is_ok());
    let sixteen: Vec<String> = (0..16).map(|i| format!("https://h{i}.example")).collect();
    assert!(payload(with(json!(sixteen))).validate().is_ok());
    let seventeen: Vec<String> = (0..17).map(|i| format!("https://h{i}.example")).collect();
    for bad in [
        json!([]),
        json!(seventeen),
        json!(["relative/path"]),
        json!(["//host/path"]),
        json!(["ftp://host/"]),
        json!(["file:///etc/passwd"]),
        json!(["javascript:alert(1)"]),
        json!(["https://user:pw@host/"]),
        json!(["https://user@host/"]),
        json!(["https://h/a\nb"]),
        json!(["https://h.example", "https://h.example"]),
        json!([format!("https://h/{}", "a".repeat(2050))]),
    ] {
        let m = rejected(with(bad.clone()));
        assert!(m.contains("uris"), "{bad}: {m}");
    }
}

#[test]
fn generation_options_are_checked() {
    let with = |g: serde_json::Value| {
        let mut v = ok();
        v["generate"] = g;
        v
    };
    for (length, charset) in [(16, "hex"), (128, "base64url"), (40, "ascii")] {
        let r = request(with(json!({"length": length, "charset": charset})));
        assert_eq!((r.length, r.charset.as_str()), (length, charset));
    }
    for bad in [15, 129, 0, 4_294_967_296u64] {
        assert!(
            rejected(with(json!({"length": bad}))).contains("length"),
            "{bad}"
        );
    }
    let m = rejected(with(json!({"charset": "emoji"})));
    assert!(m.contains("alphanumeric") && m.contains("base64url"), "{m}");
    assert!(serde_json::from_value::<CreatePayload>(with(json!({"length": -1}))).is_err());
    assert!(serde_json::from_value::<CreatePayload>(with(json!({"length": null}))).is_err());
    assert!(serde_json::from_value::<CreatePayload>(with(json!({"extra": 1}))).is_err());
}

#[test]
fn the_body_is_strict() {
    for body in [
        json!({"uris": ["http://h"], "generate": {}}),
        json!({"name": "x", "generate": {}}),
        json!({"name": "x", "uris": ["http://h"]}),
        json!({"name": "x", "uris": ["http://h"], "generate": {}, "extra": 1}),
        json!({"name": "x", "uris": ["http://h"], "generate": {}, "username": null}),
        json!({"name": "x", "uris": ["http://h"], "generate": {}, "approval_required": null}),
        json!({"name": "x", "uris": ["http://h"], "generate": {}, "approval_required": 1}),
        json!({"name": null, "uris": ["http://h"], "generate": {}}),
    ] {
        assert!(
            serde_json::from_value::<CreatePayload>(body.clone()).is_err(),
            "{body}"
        );
    }
}

// ── The fingerprint ───────────────────────────────────────────────────────────

#[test]
fn the_same_request_from_the_same_key_has_the_same_fingerprint() {
    let a = request(ok());
    assert_eq!(a.fingerprint("key-1"), request(ok()).fingerprint("key-1"));
    assert_eq!(a.fingerprint("key-1").len(), 64);
    assert!(a
        .fingerprint("key-1")
        .bytes()
        .all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn the_uris_are_sorted_so_their_order_does_not_matter() {
    let a = request(ok());
    let mut swapped = ok();
    swapped["uris"] = json!(["https://a.example.com", "https://b.example.com"]);
    let b = request(swapped);
    assert_ne!(a.uris, b.uris);
    assert_eq!(a.fingerprint("k"), b.fingerprint("k"));
    assert_eq!(
        a.sorted_uris(),
        ["https://a.example.com", "https://b.example.com"]
    );
}

#[test]
fn any_difference_changes_the_fingerprint() {
    let base = request(ok()).fingerprint("key-1");
    let changed: Vec<(&str, serde_json::Value)> = vec![
        ("name", json!("agent_other")),
        ("username", json!("root")),
        ("uris", json!(["https://a.example.com"])),
        (
            "uris",
            json!(["https://a.example.com", "https://c.example.com"]),
        ),
        ("generate", json!({"length": 33, "charset": "alphanumeric"})),
        ("generate", json!({"length": 32, "charset": "hex"})),
        ("approval_required", json!(true)),
    ];
    for (field, value) in changed {
        let mut v = ok();
        v[field] = value.clone();
        assert_ne!(request(v).fingerprint("key-1"), base, "{field}: {value}");
    }
    // Another agent key.
    assert_ne!(request(ok()).fingerprint("key-2"), base);
    // No username is not an empty one.
    let mut none = ok();
    none.as_object_mut().unwrap().remove("username");
    assert_ne!(request(none).fingerprint("key-1"), base);
    // Defaults spelled out are the defaults left out.
    let mut explicit = ok();
    explicit["generate"] = json!({});
    assert_eq!(request(explicit).fingerprint("key-1"), base);
}

#[test]
fn a_fingerprint_cannot_be_confused_between_fields() {
    // Neither moving text from one field to the next nor a separator inside a
    // value makes two different operations hash alike.
    let a = request(json!({"name": "ab", "username": "c", "uris": ["http://h"], "generate": {}}));
    let b = request(json!({"name": "a", "username": "bc", "uris": ["http://h"], "generate": {}}));
    assert_ne!(a.fingerprint("k"), b.fingerprint("k"));
    let c = request(json!({"name": "a\",\"username\":\"b", "uris": ["http://h"], "generate": {}}));
    let d = request(json!({"name": "a", "username": "b", "uris": ["http://h"], "generate": {}}));
    assert_ne!(c.fingerprint("k"), d.fingerprint("k"));
}

#[test]
fn the_detail_for_the_approval_has_everything_and_sorted_uris_and_no_value() {
    let d = request(ok()).detail("Ferrowarden managed");
    assert_eq!(d.name, "agent_keycloak_admin");
    assert_eq!(d.username.as_deref(), Some("admin"));
    assert_eq!(d.uris, ["https://a.example.com", "https://b.example.com"]);
    assert_eq!((d.charset.as_str(), d.length), ("alphanumeric", 32));
    assert!(!d.approval_required);
    assert_eq!(d.collection, "Ferrowarden managed");
    let j = d.to_json();
    assert_eq!(
        j["generate"],
        json!({"charset": "alphanumeric", "length": 32})
    );
}
