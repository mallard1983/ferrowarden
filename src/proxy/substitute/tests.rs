use super::*;
use crate::vault::model::FieldInfo;
use serde_json::json;

fn ph(item: &str, selector: Selector) -> Placeholder {
    Placeholder {
        item: item.to_string(),
        selector,
    }
}

fn values(pairs: &[(Placeholder, &str)]) -> ResolvedValues {
    pairs
        .iter()
        .map(|(p, v)| {
            (
                p.clone(),
                Resolved {
                    value: Zeroizing::new(v.to_string()),
                    scrub: true,
                },
            )
        })
        .collect()
}

fn url(s: &str) -> Url {
    Url::parse(s).unwrap()
}

#[test]
fn substitute_str_replaces_all_occurrences_and_selectors() {
    let v = values(&[
        (ph("t", Selector::Password), "SECRET"),
        (ph("a b", Selector::Username), "USER"),
    ]);
    let out = substitute_str(
        "a {{vault:t}} b {{vault:t:password}} u={{vault:'a b':username}}",
        &v,
    );
    assert_eq!(out.as_str(), "a SECRET b SECRET u=USER");
}

#[test]
fn substitute_json_escapes_special_characters() {
    let v = values(&[(ph("pw", Selector::Password), r#"pa"ss\word"#)]);
    let mut out = substitute_json(&json!({"password": "{{vault:pw}}", "n": 5}), &v);
    let text = serde_json::to_string(&out).unwrap();
    let reparsed: Value = serde_json::from_str(&text).expect("still valid JSON");
    assert_eq!(reparsed["password"], r#"pa"ss\word"#);
    assert_eq!(reparsed.as_object().unwrap().len(), 2, "no injected keys");
    zeroize_json(&mut out);
}

#[test]
fn substitute_no_placeholders_returns_input() {
    let out = substitute_str("no placeholders here", &ResolvedValues::new());
    assert_eq!(out.as_str(), "no placeholders here");
}

#[test]
fn host_binding_matches_host_scheme_and_port() {
    let uris = vec!["https://api.example.com".to_string()];
    assert!(credential_allows(&uris, &url("https://API.example.com/v1")).is_ok());
    assert!(
        credential_allows(&uris, &url("http://api.example.com/v1")).is_err(),
        "scheme downgrade"
    );
    assert!(
        credential_allows(&uris, &url("https://api.example.com:8443/")).is_err(),
        "other port"
    );
    assert!(credential_allows(&uris, &url("https://evil.example.com/")).is_err());
    assert!(credential_allows(&uris, &url("https://api.example.com.evil.net/")).is_err());
}

#[test]
fn host_binding_without_scheme_matches_any_scheme_and_port() {
    let uris = vec!["nas.lan".to_string()];
    assert!(credential_allows(&uris, &url("http://nas.lan:5000/x")).is_ok());
    assert!(credential_allows(&uris, &url("https://nas.lan/x")).is_ok());
}

#[test]
fn host_binding_explicit_port() {
    let uris = vec!["http://mock-api:7777".to_string()];
    assert!(credential_allows(&uris, &url("http://mock-api:7777/a")).is_ok());
    assert!(credential_allows(&uris, &url("http://mock-api/a")).is_err());
}

#[test]
fn host_binding_requires_uris() {
    assert!(credential_allows(&[], &url("https://a.example/")).is_err());
}

fn rich_login() -> CredentialEntry {
    let mut e = CredentialEntry::login("9", &["https://a.example"]);
    e.has_username = true;
    e.has_notes = true;
    e.fields = vec![
        FieldInfo {
            name: "api key".into(),
            kind: FieldKind::Hidden,
        },
        FieldInfo {
            name: "flag".into(),
            kind: FieldKind::Boolean,
        },
        FieldInfo {
            name: "lu".into(),
            kind: FieldKind::LinkedUsername,
        },
        FieldInfo {
            name: "card".into(),
            kind: FieldKind::LinkedOther,
        },
        FieldInfo {
            name: "dup".into(),
            kind: FieldKind::Text,
        },
        FieldInfo {
            name: "dup".into(),
            kind: FieldKind::Text,
        },
    ];
    e
}

#[test]
fn plan_selectors_and_scrub_rules() {
    let e = rich_login();
    let scrub = |s: Selector| plan(&ph("x", s), &e).map(|(_, scrub)| scrub);
    assert!(scrub(Selector::Password).unwrap());
    assert!(!scrub(Selector::Username).unwrap());
    assert!(scrub(Selector::Notes).unwrap());
    assert!(scrub(Selector::Field("api key".into())).unwrap());
    assert!(!scrub(Selector::Field("flag".into())).unwrap());
    assert!(!scrub(Selector::Field("lu".into())).unwrap());
    assert!(
        matches!(
            scrub(Selector::Totp),
            Err(FerroError::UnknownPlaceholder(_))
        ),
        "no totp on item"
    );
    assert!(matches!(
        scrub(Selector::Field("card".into())),
        Err(FerroError::UnknownPlaceholder(_))
    ));
    assert!(matches!(
        scrub(Selector::Field("missing".into())),
        Err(FerroError::UnknownPlaceholder(_))
    ));
    assert!(matches!(
        scrub(Selector::Field("dup".into())),
        Err(FerroError::AmbiguousField { .. })
    ));
}

#[test]
fn plan_secure_note_has_no_login_values() {
    let mut n = CredentialEntry::login("7", &["https://n.example"]);
    n.kind = ItemKind::SecureNote;
    n.has_password = false;
    n.has_notes = true;
    n.fields = vec![FieldInfo {
        name: "token".into(),
        kind: FieldKind::Hidden,
    }];
    assert!(plan(&ph("n", Selector::Notes), &n).is_ok());
    assert!(plan(&ph("n", Selector::Field("token".into())), &n).is_ok());
    assert!(matches!(
        plan(&ph("n", Selector::Password), &n),
        Err(FerroError::UnknownPlaceholder(_))
    ));
    assert!(matches!(
        plan(&ph("n", Selector::Username), &n),
        Err(FerroError::UnknownPlaceholder(_))
    ));
}

#[tokio::test]
async fn resolve_rejects_before_fetching() {
    // Unreachable vault: any fetch attempt would return VaultUnavailable.
    let vault = crate::vault::BwServe::new("http://127.0.0.1:1".to_string());
    let mut creds = CredentialMap::new();
    creds.insert(
        "dup".into(),
        vec![
            CredentialEntry::login("1", &[]),
            CredentialEntry::login("2", &[]),
        ],
    );
    creds.insert(
        "bound".into(),
        vec![CredentialEntry::login("3", &["https://a.example"])],
    );
    let mut rp = CredentialEntry::login("4", &["https://b.example"]);
    rp.reprompt = true;
    creds.insert("guarded".into(), vec![rp]);
    let target = url("https://b.example/");
    let set = |p: Placeholder| BTreeSet::from([p]);

    let err = resolve_credentials(
        &set(ph("missing", Selector::Password)),
        &creds,
        &target,
        true,
        &vault,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, FerroError::UnknownPlaceholder(_)));

    let err = resolve_credentials(
        &set(ph("dup", Selector::Password)),
        &creds,
        &target,
        true,
        &vault,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, FerroError::AmbiguousCredential(_)));

    let err = resolve_credentials(
        &set(ph("guarded", Selector::Password)),
        &creds,
        &target,
        true,
        &vault,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, FerroError::RepromptRequired(_)));

    let err = resolve_credentials(
        &set(ph("bound", Selector::Password)),
        &creds,
        &target,
        true,
        &vault,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, FerroError::CredentialHostNotAllowed { .. }));

    // With enforcement off the binding is skipped and the fetch is attempted.
    let err = resolve_credentials(
        &set(ph("bound", Selector::Password)),
        &creds,
        &target,
        false,
        &vault,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, FerroError::VaultUnavailable));
}

#[test]
fn check_phase_needs_no_vault_and_matches_resolve_errors() {
    let mut creds = CredentialMap::new();
    creds.insert(
        "ok".into(),
        vec![CredentialEntry::login("1", &["https://b.example"])],
    );
    creds.insert(
        "dup".into(),
        vec![
            CredentialEntry::login("2", &[]),
            CredentialEntry::login("3", &[]),
        ],
    );
    let mut rp = CredentialEntry::login("4", &["https://b.example"]);
    rp.reprompt = true;
    creds.insert("guarded".into(), vec![rp]);
    let target = url("https://b.example/");
    let check =
        |p: Placeholder| check_credentials(&BTreeSet::from([p]), &creds, &target, true).map(|_| ());

    assert!(check(ph("ok", Selector::Password)).is_ok());
    assert!(matches!(
        check(ph("missing", Selector::Password)),
        Err(FerroError::UnknownPlaceholder(_))
    ));
    assert!(matches!(
        check(ph("ok", Selector::Username)),
        Err(FerroError::UnknownPlaceholder(_))
    ));
    assert!(matches!(
        check(ph("dup", Selector::Password)),
        Err(FerroError::AmbiguousCredential(_))
    ));
    assert!(matches!(
        check(ph("guarded", Selector::Password)),
        Err(FerroError::RepromptRequired(_))
    ));
    let other = url("https://evil.example/");
    assert!(matches!(
        check_credentials(
            &BTreeSet::from([ph("ok", Selector::Password)]),
            &creds,
            &other,
            true
        ),
        Err(FerroError::CredentialHostNotAllowed { .. })
    ));
    // Binding enforcement off: the check passes.
    assert!(check_credentials(
        &BTreeSet::from([ph("ok", Selector::Password)]),
        &creds,
        &other,
        false
    )
    .is_ok());
}
