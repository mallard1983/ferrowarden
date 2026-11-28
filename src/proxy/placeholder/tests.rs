use super::*;

fn one(s: &str) -> Placeholder {
    let occ = scan(s).unwrap();
    assert_eq!(occ.len(), 1, "{s}");
    match &occ[0].token {
        Token::Vault(p) => p.clone(),
        other => panic!("{s}: expected a vault placeholder, got {other:?}"),
    }
}

fn session(s: &str) -> String {
    let occ = scan(s).unwrap();
    assert_eq!(occ.len(), 1, "{s}");
    match &occ[0].token {
        Token::Session(name) => name.clone(),
        other => panic!("{s}: expected a session, got {other:?}"),
    }
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
    let mut out = Collected::default();
    collect_json(
        &serde_json::json!({"{{vault:k}}": ["{{vault:'v w':notes}}", 1]}),
        &mut out,
    )
    .unwrap();
    assert!(out.vault.contains(&ph("k", Selector::Password)));
    assert!(out.vault.contains(&ph("v w", Selector::Notes)));
    assert!(out.sessions.is_empty());
    let err = collect_json(
        &serde_json::json!({"a": "{{vault:bad name}}"}),
        &mut Collected::default(),
    )
    .unwrap_err();
    assert!(matches!(err, FerroError::MalformedPlaceholder(_)));
}

// ── Session placeholders ──────────────────────────────────────────────────────

#[test]
fn a_session_placeholder_parses_to_its_name() {
    assert_eq!(session("{{session:portainer}}"), "portainer");
    assert_eq!(session("{{session:a.b-c_D9}}"), "a.b-c_D9");
    assert_eq!(
        session(&format!("{{{{session:{}}}}}", "x".repeat(64))).len(),
        64
    );
}

#[test]
fn session_and_vault_placeholders_are_found_in_position_order() {
    let s = "u={{vault:a:username}} t={{session:tok}} p={{vault:'b c'}}{{session:two}}";
    let occ = scan(s).unwrap();
    let kinds: Vec<String> = occ.iter().map(|o| o.token.label()).collect();
    assert_eq!(kinds, ["a:username", "session:tok", "'b c'", "session:two"]);
    assert_eq!(&s[occ[1].start..occ[1].end], "{{session:tok}}");
    assert_eq!(&s[occ[3].start..occ[3].end], "{{session:two}}");
    assert!(occ.windows(2).all(|w| w[0].end <= w[1].start));
}

#[test]
fn a_quoted_vault_name_may_contain_the_session_prefix() {
    // The vault name is consumed whole, so what is inside it is not a session.
    let occ = scan("{{vault:'x {{session:y}} z'}}").unwrap();
    assert_eq!(occ.len(), 1);
    assert!(matches!(&occ[0].token, Token::Vault(p) if p.item == "x {{session:y}} z"));
}

#[test]
fn malformed_session_placeholders_are_errors() {
    let too_long = format!("{{{{session:{}}}}}", "x".repeat(65));
    for bad in [
        "{{session:}}",
        "{{session:a b}}",
        "{{session:a",
        "{{session:'quoted'}}",
        "{{session:a:b}}",
        "{{session:a}x",
        "{{session:ä}}",
        "{{session:{{vault:x}}}}",
        too_long.as_str(),
    ] {
        let err = scan(bad).unwrap_err();
        assert!(
            matches!(err, FerroError::MalformedPlaceholder(_)),
            "{bad} -> {err:?}"
        );
    }
}

#[test]
fn near_misses_are_not_placeholders() {
    // Only the exact prefixes start a placeholder.
    assert!(
        scan("{{Session:x}} {{ session:x}} {session:x} {{sessions:x}}")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn labels_keep_the_vault_form_and_prefix_sessions() {
    assert_eq!(
        Token::Vault(ph("Proxmox (prod)", Selector::Username)).label(),
        "'Proxmox (prod)':username"
    );
    assert_eq!(Token::Vault(ph("tok", Selector::Password)).label(), "tok");
    assert_eq!(
        Token::Session("portainer".into()).label(),
        "session:portainer"
    );
}

#[test]
fn collect_splits_vault_placeholders_and_sessions() {
    let mut out = Collected::default();
    collect_json(
        &serde_json::json!({"{{session:k}}": ["{{vault:v}}", "{{session:a}} {{session:a}}", 1]}),
        &mut out,
    )
    .unwrap();
    assert_eq!(out.vault.len(), 1);
    assert_eq!(out.sessions.iter().cloned().collect::<Vec<_>>(), ["a", "k"]);
}

#[test]
fn session_names() {
    assert!(is_session_name("portainer"));
    assert!(is_session_name(&"x".repeat(64)));
    assert!(!is_session_name(""));
    assert!(!is_session_name(&"x".repeat(65)));
    assert!(!is_session_name("a b"));
    assert!(!is_session_name("a{{b"));
    assert!(!is_session_name("é"));
}

#[test]
fn the_next_selector_parses_renders_and_round_trips() {
    assert_eq!(
        one("{{vault:svc:next}}"),
        ph("svc", Selector::Next),
        "plain name"
    );
    assert_eq!(
        one("{{vault:'Service (prod)':next}}"),
        ph("Service (prod)", Selector::Next)
    );
    for name in ["svc", "Service (prod) 'x'", "a/b"] {
        let p = ph(name, Selector::Next);
        assert_eq!(one(&p.render()), p, "{name}");
    }
    assert_eq!(ph("svc", Selector::Next).render(), "{{vault:svc:next}}");
    // `next` is not a field name, and nothing after it is accepted.
    assert!(scan("{{vault:svc:next:x}}").is_err());
    assert!(
        scan("{{vault:svc:Next}}").is_err(),
        "selectors are lower case"
    );
    assert!(scan("{{vault:svc:nexts}}").is_err());
    // It is a distinct placeholder from the password.
    assert_ne!(ph("svc", Selector::Next), ph("svc", Selector::Password));
}
