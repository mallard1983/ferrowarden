
use super::*;

fn one(s: &str) -> Placeholder {
    let occ = scan(s).unwrap();
    assert_eq!(occ.len(), 1, "{s}");
    occ[0].placeholder.clone()
}

fn ph(item: &str, selector: Selector) -> Placeholder {
    Placeholder {
        item: item.to_string(),
        selector,
    }
}

#[test]
fn plain_password_placeholder_is_unchanged_from_0_1() {
    assert_eq!(
        one("{{vault:proxmox_token}}"),
        ph("proxmox_token", Selector::Password)
    );
    assert_eq!(
        one("{{vault:service.account.password}}"),
        ph("service.account.password", Selector::Password)
    );
}

#[test]
fn selectors() {
    assert_eq!(one("{{vault:x:password}}"), ph("x", Selector::Password));
    assert_eq!(one("{{vault:x:username}}"), ph("x", Selector::Username));
    assert_eq!(one("{{vault:x:totp}}"), ph("x", Selector::Totp));
    assert_eq!(one("{{vault:x:notes}}"), ph("x", Selector::Notes));
    assert_eq!(
        one("{{vault:x:field:api_key}}"),
        ph("x", Selector::Field("api_key".into()))
    );
}

#[test]
fn quoted_names_allow_any_characters() {
    assert_eq!(
        one("{{vault:'Proxmox (prod)'}}"),
        ph("Proxmox (prod)", Selector::Password)
    );
    assert_eq!(
        one("{{vault:'a: b }} c':field:'key:with:colons'}}"),
        ph("a: b }} c", Selector::Field("key:with:colons".into()))
    );
    assert_eq!(
        one(r"{{vault:'it\'s':username}}"),
        ph("it's", Selector::Username)
    );
    assert_eq!(
        one(r"{{vault:'back\\slash'}}"),
        ph(r"back\slash", Selector::Password)
    );
    assert_eq!(
        one("{{vault:'ünïcödé 名前'}}"),
        ph("ünïcödé 名前", Selector::Password)
    );
}

#[test]
fn spans_and_multiple_occurrences() {
    let s = "Bearer {{vault:a}} and {{vault:'b c':username}}!";
    let occ = scan(s).unwrap();
    assert_eq!(occ.len(), 2);
    assert_eq!(&s[occ[0].start..occ[0].end], "{{vault:a}}");
    assert_eq!(&s[occ[1].start..occ[1].end], "{{vault:'b c':username}}");
}

#[test]
fn adjacent_placeholders() {
    let occ = scan("{{vault:a}}{{vault:b}}").unwrap();
    assert_eq!(occ.len(), 2);
}

#[test]
fn no_placeholders() {
    assert!(scan("plain {{other}} text {vault:x}").unwrap().is_empty());
}

#[test]
fn malformed_placeholders_are_errors() {
    for bad in [
        "{{vault:}}",
        "{{vault:a b}}",
        "{{vault:a",
        "{{vault:'unterminated}}",
        "{{vault:''}}",
        "{{vault:a:}}",
        "{{vault:a:bogus}}",
        "{{vault:a:field}}",
        "{{vault:a:field:}}",
        r"{{vault:'bad \n escape'}}",
        "{{vault:a}x",
    ] {
        let err = scan(bad).unwrap_err();
        assert!(
            matches!(err, FerroError::MalformedPlaceholder(_)),
            "{bad} -> {err:?}"
        );
    }
}

#[test]
fn render_round_trips() {
    for p in [
        ph("simple", Selector::Password),
        ph("Proxmox (prod)", Selector::Username),
        ph("it's \\ odd", Selector::Field("api secret".into())),
        ph("x", Selector::Field("key:with:colons".into())),
        ph("x", Selector::Totp),
        ph("x", Selector::Notes),
    ] {
        assert_eq!(one(&p.render()), p, "{}", p.render());
    }
}

#[test]
fn rendering() {
    assert_eq!(ph("tok", Selector::Password).render(), "{{vault:tok}}");
    assert_eq!(
        ph("a b", Selector::Username).render(),
        "{{vault:'a b':username}}"
    );
    assert_eq!(
        ph("x", Selector::Field("api secret".into())).render(),
        "{{vault:x:field:'api secret'}}"
    );
    assert_eq!(quote_if_needed("it's"), r"'it\'s'");
}

#[test]
fn collect_json_includes_keys_and_rejects_malformed() {
    let mut out = BTreeSet::new();
    collect_json(
        &serde_json::json!({"{{vault:k}}": ["{{vault:'v w':notes}}", 1]}),
        &mut out,
    )
    .unwrap();
    assert!(out.contains(&ph("k", Selector::Password)));
    assert!(out.contains(&ph("v w", Selector::Notes)));
    let err = collect_json(
        &serde_json::json!({"a": "{{vault:bad name}}"}),
        &mut BTreeSet::new(),
    )
    .unwrap_err();
    assert!(matches!(err, FerroError::MalformedPlaceholder(_)));
}
