use super::*;

fn pol(c: &[&str], m: &[&str]) -> KeyPolicy {
    KeyPolicy::from_raw(
        c.iter().map(|s| s.to_string()).collect(),
        m.iter().map(|s| s.to_string()).collect(),
        Vec::new(),
        vec![],
        vec![],
    )
    .unwrap()
}

#[test]
fn widening_is_detected_for_methods_and_patterns() {
    let saved = pol(&["uptime_*"], &["GET"]);
    // Same, narrower, or covered: not widening.
    assert!(!saved.is_widened_by(&saved));
    assert!(!saved.is_widened_by(&pol(&["uptime_api"], &["GET"])));
    assert!(!saved.is_widened_by(&pol(&["uptime_a*"], &["GET"])));
    assert!(!saved.is_widened_by(&pol(&[], &[])));
    assert!(!saved.is_widened_by(&pol(&["uptime_*"], &[])));
    // Wider patterns or methods.
    assert!(saved.is_widened_by(&pol(&["up*"], &["GET"])));
    assert!(saved.is_widened_by(&pol(&["*"], &["GET"])));
    assert!(saved.is_widened_by(&pol(&["uptime_*", "other"], &["GET"])));
    assert!(saved.is_widened_by(&pol(&["uptime_*"], &["GET", "POST"])));
    assert!(saved.is_widened_by(&pol(&["uptime_*"], &["*"])));
    // `*` covers everything; all methods cover each method.
    let all = pol(&["*"], &["*"]);
    assert!(!all.is_widened_by(&pol(&["a*", "b"], &["GET", "DELETE"])));
    assert!(!all.is_widened_by(&all));
    // A deny-all (legacy) key is widened by anything non-empty.
    let none = KeyPolicy::default();
    assert!(none.is_widened_by(&pol(&["a"], &[])));
    assert!(none.is_widened_by(&pol(&[], &["GET"])));
    assert!(!none.is_widened_by(&pol(&[], &[])));
}
use crate::api::strict_json::parse_strict;
use serde::Deserialize;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

// ── matcher ───────────────────────────────────────────────────────────────

#[test]
fn exact_match_and_anchoring() {
    assert!(wildcard_match("grafana", "grafana"));
    assert!(!wildcard_match("grafana", "grafana2"));
    assert!(!wildcard_match("grafana", "xgrafana"));
    assert!(!wildcard_match("grafana", "grafan"));
    assert!(!wildcard_match("uptime_*", "not_uptime_x"));
    assert!(wildcard_match("uptime_*", "uptime_kuma"));
    assert!(wildcard_match("uptime_*", "uptime_"));
    assert!(!wildcard_match("uptime_*", "uptime"));
}

#[test]
fn prefix_suffix_infix_and_multiple_stars() {
    assert!(wildcard_match("*_token", "grafana_token"));
    assert!(!wildcard_match("*_token", "grafana_token_old"));
    assert!(wildcard_match("lab_*_ro", "lab_nas_ro"));
    assert!(wildcard_match("lab_*_ro", "lab__ro"));
    assert!(!wildcard_match("lab_*_ro", "lab_ro"));
    assert!(wildcard_match("*a*b*c*", "xxaxxbxxcxx"));
    assert!(wildcard_match("*a*b*c*", "abc"));
    assert!(!wildcard_match("*a*b*c*", "acb"));
    assert!(wildcard_match("a**b", "ab"));
    assert!(wildcard_match("a**b", "axxb"));
}

#[test]
fn star_alone_matches_everything_including_empty() {
    assert!(wildcard_match("*", ""));
    assert!(wildcard_match("*", "anything at all"));
    assert!(wildcard_match("**", ""));
}

#[test]
fn empty_name_and_empty_pattern() {
    assert!(!wildcard_match("a", ""));
    assert!(wildcard_match("", ""));
    assert!(!wildcard_match("", "a"));
    assert!(wildcard_match("*", ""));
}

#[test]
fn matching_is_case_sensitive() {
    assert!(!wildcard_match("Grafana", "grafana"));
    assert!(!wildcard_match("grafana_*", "GRAFANA_x"));
}

#[test]
fn names_with_spaces_quotes_colons_and_unicode() {
    assert!(wildcard_match("Proxmox (*)", "Proxmox (prod)"));
    assert!(wildcard_match("*", "it's \"quoted\""));
    assert!(wildcard_match("it's *", "it's \"quoted\""));
    assert!(wildcard_match("db:*", "db:primary:admin"));
    assert!(wildcard_match("日本*", "日本語の名前"));
    assert!(wildcard_match("café_*", "café_x"));
    assert!(!wildcard_match("cafe_*", "café_x"));
    // `*` matches whole characters, not bytes.
    assert!(wildcard_match("?*", "?é"));
    assert!(wildcard_match("é*é", "éxé"));
}

#[test]
fn question_mark_and_brackets_are_literal() {
    assert!(wildcard_match("a?c", "a?c"));
    assert!(!wildcard_match("a?c", "abc"));
    assert!(wildcard_match("[x]", "[x]"));
    assert!(!wildcard_match("[x]", "x"));
    assert!(wildcard_match("a.c", "a.c"));
    assert!(!wildcard_match("a.c", "abc"));
}

#[test]
fn pathological_patterns_finish_fast() {
    let start = std::time::Instant::now();
    let name = "a".repeat(5000);
    // No `b` in the name: the classic exponential case for naive
    // recursive matchers. Ours is O(n*m).
    assert!(!wildcard_match("*a*a*a*a*b", &name));
    assert!(!wildcard_match(&format!("{}b", "*a".repeat(120)), &name));
    assert!(wildcard_match("*a*a*a*a*", &name));
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "took {:?}",
        start.elapsed()
    );
}

// ── validation ────────────────────────────────────────────────────────────

#[test]
fn credential_validation_rules() {
    assert_eq!(
        validate_credentials(s(&["a_*", "b"])).unwrap(),
        s(&["a_*", "b"])
    );
    assert_eq!(validate_credentials(vec![]).unwrap(), Vec::<String>::new());
    // Duplicates collapse.
    assert_eq!(validate_credentials(s(&["a", "a"])).unwrap(), s(&["a"]));
    // `*` is "unrestricted spelled out"; the list collapses to it.
    assert_eq!(validate_credentials(s(&["*"])).unwrap(), s(&["*"]));
    assert_eq!(validate_credentials(s(&["a", "*"])).unwrap(), s(&["*"]));
    // Length bounds are in characters.
    assert!(validate_credentials(s(&[""])).is_err());
    assert!(validate_credentials(vec!["a".repeat(256)]).is_ok());
    assert!(validate_credentials(vec!["a".repeat(257)]).is_err());
    assert!(validate_credentials(vec!["é".repeat(256)]).is_ok());
    assert!(validate_credentials(vec!["é".repeat(257)]).is_err());
    // Count bound.
    let many: Vec<String> = (0..256).map(|i| format!("c{i}")).collect();
    assert!(validate_credentials(many.clone()).is_ok());
    let mut too_many = many;
    too_many.push("one_more".into());
    assert!(validate_credentials(too_many).is_err());
    // Control characters.
    for bad in ["a\nb", "a\0b", "\ta", "a\u{7f}", "a\u{85}"] {
        assert!(validate_credentials(s(&[bad])).is_err(), "{bad:?}");
    }
}

#[test]
fn method_validation_normalises_and_dedupes() {
    assert_eq!(
        validate_methods(s(&["get", "Post", "GET"])).unwrap(),
        s(&["GET", "POST"])
    );
    // Canonical order regardless of input order.
    assert_eq!(
        validate_methods(s(&["delete", "head"])).unwrap(),
        s(&["HEAD", "DELETE"])
    );
    assert_eq!(validate_methods(vec![]).unwrap(), Vec::<String>::new());
    assert_eq!(validate_methods(s(&["*"])).unwrap(), s(&["*"]));
    assert_eq!(validate_methods(s(&["*", "*"])).unwrap(), s(&["*"]));
    assert!(validate_methods(s(&["*", "GET"])).is_err());
    for bad in ["TRACE", "CONNECT", "FOO", "", "GET ", "G*", "ge t"] {
        assert!(validate_methods(s(&[bad])).is_err(), "{bad:?}");
    }
    let all = validate_methods(s(&METHODS)).unwrap();
    assert_eq!(all.len(), 7);
}

#[test]
fn request_method_normalisation() {
    assert_eq!(normalize_method("get").unwrap(), "GET");
    assert_eq!(normalize_method("PaTcH").unwrap(), "PATCH");
    for bad in ["TRACE", "CONNECT", "FOO", "", " GET", "GET\n"] {
        assert!(normalize_method(bad).is_err(), "{bad:?}");
    }
}

// ── policy decisions ──────────────────────────────────────────────────────

fn ph(name: &str) -> Placeholder {
    Placeholder {
        item: name.to_string(),
        selector: crate::proxy::placeholder::Selector::Password,
    }
}

fn set(names: &[&str]) -> BTreeSet<Placeholder> {
    names.iter().map(|n| ph(n)).collect()
}

#[test]
fn default_policy_is_deny_all() {
    let p = KeyPolicy::default();
    assert_eq!(p, KeyPolicy::default());
    assert!(!p.allows_credential("anything"));
    for m in METHODS {
        assert!(!p.allows_method(m));
    }
    assert_eq!(
        p.to_json(),
        json!({"credentials": [], "methods": [], "approval": [], "create": [], "rotate": []})
    );
}

#[test]
fn star_star_is_unrestricted_but_only_for_known_methods() {
    let p = KeyPolicy::from_raw(s(&["*"]), s(&["*"]), vec![], vec![], vec![]).unwrap();
    assert!(p.allows_credential("anything"));
    for m in METHODS {
        assert!(p.allows_method(m));
    }
    assert!(!p.allows_method("TRACE"));
    assert_eq!(
        p.to_json(),
        json!({"credentials": ["*"], "methods": ["*"], "approval": [], "create": [], "rotate": []})
    );
}

#[test]
fn empty_lists_allow_nothing() {
    let p = KeyPolicy::from_raw(vec![], vec![], vec![], vec![], vec![]).unwrap();
    assert!(!p.allows_credential("x"));
    assert!(!p.allows_method("GET"));
    // A request with no placeholders still passes the scope check; only
    // the method matters then.
    let open = KeyPolicy::from_raw(vec![], s(&["*"]), vec![], vec![], vec![]).unwrap();
    assert!(open.check_request("GET", &set(&[])).is_ok());
    assert!(open.check_request("GET", &set(&["x"])).is_err());
}

#[test]
fn method_is_checked_before_scope() {
    let p = KeyPolicy::from_raw(s(&["a"]), s(&["GET"]), vec![], vec![], vec![]).unwrap();
    assert!(matches!(
        p.check_request("POST", &set(&["not_a"])),
        Err(FerroError::MethodNotAllowed(m)) if m == "POST"
    ));
    assert!(matches!(
        p.check_request("GET", &set(&["not_a"])),
        Err(FerroError::CredentialOutOfScope(_))
    ));
    assert!(p.check_request("GET", &set(&["a"])).is_ok());
}

#[test]
fn out_of_scope_error_does_not_depend_on_the_vault() {
    // The check takes only the policy and the placeholder names, so an
    // existing and a nonexistent out-of-scope name are indistinguishable.
    let p = KeyPolicy::from_raw(s(&["lab_*"]), s(&["*"]), vec![], vec![], vec![]).unwrap();
    let a = p.check_request("GET", &set(&["prod_db"])).unwrap_err();
    let b = p
        .check_request("GET", &set(&["does_not_exist_anywhere"]))
        .unwrap_err();
    assert_eq!(a.status_code(), b.status_code());
    assert_eq!(a.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(
        a.to_string(),
        "Credential prod_db is not available to this agent key"
    );
    assert_eq!(
        b.to_string(),
        "Credential does_not_exist_anywhere is not available to this agent key"
    );
    // Scope wins over every later (vault-dependent) failure: an in-scope
    // unknown name does not mask an out-of-scope one.
    assert!(matches!(
        p.check_request("GET", &set(&["lab_unknown", "prod_db"])),
        Err(FerroError::CredentialOutOfScope(n)) if n == "prod_db"
    ));
}

#[test]
fn scope_uses_the_unquoted_item_name_but_reports_the_label() {
    let p = KeyPolicy::from_raw(s(&["Proxmox (*)"]), s(&["*"]), vec![], vec![], vec![]).unwrap();
    let quoted = Placeholder {
        item: "Proxmox (prod)".into(),
        selector: crate::proxy::placeholder::Selector::Username,
    };
    assert!(p.check_request("GET", &BTreeSet::from([quoted])).is_ok());
    let other = Placeholder {
        item: "Other (x)".into(),
        selector: crate::proxy::placeholder::Selector::Username,
    };
    let e = p
        .check_request("GET", &BTreeSet::from([other]))
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "Credential 'Other (x)':username is not available to this agent key"
    );
}

#[test]
fn patching_a_deny_all_policy_leaves_the_other_field_denied() {
    let p = KeyPolicy::default()
        .patched(
            Patch::Value(s(&["a"])),
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
        )
        .unwrap();
    assert_eq!(p.credentials, s(&["a"]));
    assert!(p.methods.is_empty());
    assert!(!p.allows_method("GET"));
}

#[test]
fn patched_replaces_only_present_fields() {
    let base = KeyPolicy::from_raw(s(&["a"]), s(&["GET"]), vec![], vec![], vec![]).unwrap();
    let p = base
        .patched(
            Patch::Value(s(&["b_*"])),
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
        )
        .unwrap();
    assert_eq!(p.credentials, s(&["b_*"]));
    assert_eq!(p.methods, s(&["GET"]));
    let p = base
        .patched(
            Patch::Absent,
            Patch::Value(s(&["*"])),
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
        )
        .unwrap();
    assert_eq!(p.credentials, s(&["a"]));
    assert_eq!(p.methods, s(&["*"]));
    // Lifting a restriction.
    let p = base
        .patched(
            Patch::Value(s(&["*"])),
            Patch::Value(s(&["*"])),
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
        )
        .unwrap();
    assert_eq!(
        p,
        KeyPolicy::from_raw(s(&["*"]), s(&["*"]), vec![], vec![], vec![]).unwrap()
    );
    // Invalid values are rejected and leave `base` untouched.
    assert!(base
        .patched(
            Patch::Value(s(&[""])),
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
            Patch::Absent
        )
        .is_err());
    assert!(base
        .patched(
            Patch::Absent,
            Patch::Value(s(&["TRACE"])),
            Patch::Absent,
            Patch::Absent,
            Patch::Absent
        )
        .is_err());
}

// ── null-rejecting parsing ────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Body {
    #[serde(default, deserialize_with = "patch_credentials")]
    credentials: Patch<Vec<String>>,
    #[serde(default, deserialize_with = "patch_methods")]
    methods: Patch<Vec<String>>,
}

fn parse(json: &str) -> Result<Body, String> {
    parse_strict(json.as_bytes())
}

#[test]
fn patch_parsing_distinguishes_absent_null_and_value() {
    let b = parse("{}").unwrap();
    assert!(b.credentials.is_absent() && b.methods.is_absent());

    let b = parse(r#"{"credentials":["a"]}"#).unwrap();
    assert_eq!(b.credentials, Patch::Value(s(&["a"])));
    assert!(b.methods.is_absent());

    // An empty list is a value (meaning "nothing"), not absent.
    let b = parse(r#"{"methods":[]}"#).unwrap();
    assert_eq!(b.methods, Patch::Value(vec![]));

    let e = parse(r#"{"credentials":null}"#).unwrap_err();
    assert!(e.contains("`credentials`") && e.contains("null"), "{e}");
    let e = parse(r#"{"methods":null}"#).unwrap_err();
    assert!(e.contains("`methods`") && e.contains("null"), "{e}");
}

#[test]
fn wrong_types_are_rejected_with_a_field_name_and_no_value() {
    for (json, field) in [
        (r#"{"credentials":"*"}"#, "credentials"),
        (r#"{"credentials":5}"#, "credentials"),
        (r#"{"methods":true}"#, "methods"),
        (r#"{"methods":{"a":1}}"#, "methods"),
        (r#"{"methods":[1]}"#, ""),
        (r#"{"methods":[null]}"#, ""),
        (r#"{"credentials":[["a"]]}"#, ""),
    ] {
        let e = parse(json).unwrap_err();
        assert!(e.contains(field), "{json}: {e}");
    }
    let e = parse(r#"{"credentials":"super-secret-looking"}"#).unwrap_err();
    assert!(!e.contains("super-secret"), "{e}");
}

#[test]
fn unknown_fields_and_duplicate_keys_are_still_rejected() {
    assert!(parse(r#"{"credential":["a"]}"#).is_err());
    assert!(parse(r#"{"credentials":["a"],"credentials":["b"]}"#).is_err());
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Create {
    #[allow(dead_code)]
    #[serde(deserialize_with = "required_credentials")]
    credentials: Vec<String>,
    #[allow(dead_code)]
    #[serde(deserialize_with = "required_methods")]
    methods: Vec<String>,
}

#[test]
fn required_fields_must_be_present_and_not_null() {
    assert!(parse_strict::<Create>(br#"{"credentials":["*"],"methods":["*"]}"#).is_ok());
    let e = parse_strict::<Create>(br#"{"methods":["*"]}"#).unwrap_err();
    assert!(e.contains("missing field `credentials`"), "{e}");
    let e = parse_strict::<Create>(br#"{"credentials":[]}"#).unwrap_err();
    assert!(e.contains("missing field `methods`"), "{e}");
    let e = parse_strict::<Create>(br#"{"credentials":null,"methods":[]}"#).unwrap_err();
    assert!(e.contains("`credentials`") && e.contains("null"), "{e}");
    let e = parse_strict::<Create>(br#"{"credentials":[],"methods":null}"#).unwrap_err();
    assert!(e.contains("`methods`") && e.contains("null"), "{e}");
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Nested {
    #[serde(default, deserialize_with = "some_not_null")]
    request: Option<Inner>,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Inner {
    #[allow(dead_code)]
    a: u8,
}

#[test]
fn optional_object_rejects_null() {
    assert!(parse_strict::<Nested>(b"{}").unwrap().request.is_none());
    assert!(parse_strict::<Nested>(br#"{"request":{"a":1}}"#)
        .unwrap()
        .request
        .is_some());
    assert!(parse_strict::<Nested>(br#"{"request":null}"#).is_err());
}

// ── approval patterns ─────────────────────────────────────────────────────

fn pol_a(c: &[&str], a: &[&str]) -> KeyPolicy {
    KeyPolicy::from_raw(s(c), s(&["GET"]), s(a), vec![], vec![]).unwrap()
}

#[test]
fn approval_patterns_match_like_credential_patterns_and_default_to_none() {
    let p = pol_a(&["*"], &["proxmox_*", "Firewall (prod)", "exact"]);
    assert!(p.requires_approval("proxmox_root"));
    assert!(p.requires_approval("Firewall (prod)"));
    assert!(p.requires_approval("exact"));
    assert!(!p.requires_approval("exact2"));
    assert!(!p.requires_approval("grafana"));
    assert!(!p.requires_approval("Proxmox_root"), "case-sensitive");
    // `[]`: no extra requirement. `["*"]`: every credential.
    assert!(!KeyPolicy::default().requires_approval("anything"));
    assert!(pol_a(&["*"], &[]).approval.is_empty());
    assert!(pol_a(&["*"], &["*"]).requires_approval("anything"));
    // The same normalisation: `*` collapses the list, duplicates go.
    assert_eq!(pol_a(&["*"], &["a", "*", "b"]).approval, ["*"]);
    assert_eq!(pol_a(&["*"], &["a", "a", "b"]).approval, ["a", "b"]);
}

#[test]
fn approval_patterns_are_validated_like_credential_patterns() {
    assert!(KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), s(&[""]), vec![], vec![]).is_err());
    assert!(KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), s(&["a\nb"]), vec![], vec![]).is_err());
    let long = "x".repeat(MAX_PATTERN_CHARS + 1);
    assert!(KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), vec![long], vec![], vec![]).is_err());
    let many: Vec<String> = (0..=MAX_PATTERNS).map(|i| format!("p{i}")).collect();
    let e = KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), many, vec![], vec![]).unwrap_err();
    assert!(e.to_string().contains("approval may have at most"), "{e}");
    // The message names the field it is about.
    let e = KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), s(&[""]), vec![], vec![]).unwrap_err();
    assert!(e.to_string().contains("approval[0]"), "{e}");
}

#[test]
fn approval_follows_the_patch_rules_and_never_accepts_null() {
    let base = pol_a(&["a"], &["x"]);
    // Absent: unchanged. Present: replaced. An empty list clears it.
    let kept = base
        .patched(
            Patch::Value(s(&["b"])),
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
        )
        .unwrap();
    assert_eq!(kept.approval, ["x"]);
    let replaced = base
        .patched(
            Patch::Absent,
            Patch::Absent,
            Patch::Value(s(&["y*"])),
            Patch::Absent,
            Patch::Absent,
        )
        .unwrap();
    assert_eq!(replaced.approval, ["y*"]);
    assert_eq!(replaced.credentials, ["a"]);
    let cleared = base
        .patched(
            Patch::Absent,
            Patch::Absent,
            Patch::Value(vec![]),
            Patch::Absent,
            Patch::Absent,
        )
        .unwrap();
    assert!(cleared.approval.is_empty());
    assert!(base
        .patched(
            Patch::Absent,
            Patch::Absent,
            Patch::Value(s(&[""])),
            Patch::Absent,
            Patch::Absent
        )
        .is_err());

    // `null` is an error that says what to send instead.
    #[derive(Deserialize)]
    struct Body {
        #[serde(default, deserialize_with = "patch_approval")]
        approval: Patch<Vec<String>>,
    }
    let body: Body = parse_strict(br#"{"approval":["a"]}"#).unwrap();
    assert_eq!(body.approval, Patch::Value(s(&["a"])));
    let body: Body = parse_strict(b"{}").unwrap();
    assert!(body.approval.is_absent());
    let e = parse_strict::<Body>(br#"{"approval":null}"#).err().unwrap();
    assert!(
        e.to_string()
            .contains("policy field `approval` must be an array of strings, not null"),
        "{e}"
    );
    assert!(
        e.to_string().contains("no extra approval requirement"),
        "{e}"
    );
    for bad in [
        br#"{"approval":"*"}"#.as_slice(),
        br#"{"approval":5}"#,
        br#"{"approval":{}}"#,
    ] {
        assert!(parse_strict::<Body>(bad).is_err());
    }
}

#[test]
fn removing_or_narrowing_approval_patterns_is_a_widening() {
    let saved = pol_a(&["*"], &["proxmox_*", "firewall"]);
    // Same, more, or broader patterns: not a widening (it asks for more).
    assert!(!saved.is_widened_by(&saved));
    assert!(!saved.is_widened_by(&pol_a(&["*"], &["proxmox_*", "firewall", "nas"])));
    assert!(!saved.is_widened_by(&pol_a(&["*"], &["*"])));
    assert!(!saved.is_widened_by(&pol_a(&["*"], &["prox*", "firewall"])));
    // Removing a pattern, or narrowing one so that names are no longer
    // covered, is: the key could then use a credential without asking.
    assert!(saved.is_widened_by(&pol_a(&["*"], &["proxmox_*"])));
    assert!(saved.is_widened_by(&pol_a(&["*"], &[])));
    assert!(saved.is_widened_by(&pol_a(&["*"], &["proxmox_a*", "firewall"])));
    assert!(saved.is_widened_by(&pol_a(&["*"], &["proxmox_*", "fire"])));
    // From nothing, adding patterns never widens; having none and keeping
    // none does not either.
    let none = pol_a(&["*"], &[]);
    assert!(!none.is_widened_by(&pol_a(&["*"], &["x"])));
    assert!(!none.is_widened_by(&none));
    // It combines with the other two reasons.
    assert!(saved.is_widened_by(
        &KeyPolicy::from_raw(s(&["*"]), s(&["GET", "POST"]), s(&["*"]), vec![], vec![]).unwrap()
    ));
    assert!(!none.is_widened_by(
        &KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), s(&[]), vec![], vec![]).unwrap()
    ));
}

#[test]
fn the_policy_json_lists_the_approval_patterns() {
    let p = pol_a(&["a"], &["b"]);
    assert_eq!(
        p.to_json(),
        json!({"credentials": ["a"], "methods": ["GET"], "approval": ["b"], "create": [], "rotate": []})
    );
}

// ── create patterns ───────────────────────────────────────────────────────────

fn pol_c(c: &[&str], create: &[&str]) -> KeyPolicy {
    KeyPolicy::from_raw(s(c), s(&["GET"]), vec![], s(create), vec![]).unwrap()
}

#[test]
fn create_patterns_match_like_credential_patterns_and_default_to_none() {
    let p = pol_c(&["*"], &["agent_*", "Service (prod)", "exact"]);
    assert!(p.allows_create("agent_keycloak"));
    assert!(p.allows_create("agent_"));
    assert!(p.allows_create("Service (prod)"));
    assert!(p.allows_create("exact"));
    assert!(!p.allows_create("exact2"));
    assert!(!p.allows_create("grafana"));
    assert!(!p.allows_create("Agent_x"), "case-sensitive");
    assert!(!p.allows_create(""));

    // Nothing by default, and independent of the other lists.
    assert!(!KeyPolicy::default().allows_create("anything"));
    assert!(pol_c(&["*"], &[]).create.is_empty());
    assert!(!pol_c(&["*"], &[]).allows_create("agent_x"));
    let only_create = KeyPolicy::from_raw(vec![], vec![], vec![], s(&["agent_*"]), vec![]).unwrap();
    assert!(only_create.allows_create("agent_x") && !only_create.allows_credential("agent_x"));
    assert!(!only_create.allows_method("GET"));
    // And creating does not follow from the credential list.
    assert!(!pol_c(&["*"], &[]).allows_create("agent_x"));

    // `*` collapses the list, duplicates go.
    assert_eq!(pol_c(&["*"], &["a", "*", "b"]).create, ["*"]);
    assert_eq!(pol_c(&["*"], &["a", "a", "b"]).create, ["a", "b"]);
    assert!(pol_c(&["*"], &["*"]).allows_create("whatever"));
}

#[test]
fn create_patterns_are_validated_like_credential_patterns() {
    assert!(KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), vec![], s(&[""]), vec![]).is_err());
    assert!(KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), vec![], s(&["a\nb"]), vec![]).is_err());
    let many: Vec<String> = (0..=MAX_PATTERNS).map(|i| format!("p{i}")).collect();
    let e = KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), vec![], many, vec![]).unwrap_err();
    assert!(e.to_string().contains("create may have at most"), "{e}");
    let e = KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), vec![], s(&[""]), vec![]).unwrap_err();
    assert!(e.to_string().contains("create[0]"), "{e}");
    let long = "x".repeat(MAX_PATTERN_CHARS + 1);
    assert!(KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), vec![], vec![long], vec![]).is_err());
}

#[test]
fn create_follows_the_patch_rules_and_never_accepts_null() {
    let base = pol_c(&["a"], &["x_*"]);
    let kept = base
        .patched(
            Patch::Value(s(&["b"])),
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
        )
        .unwrap();
    assert_eq!(kept.create, ["x_*"], "absent: unchanged");
    let replaced = base
        .patched(
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
            Patch::Value(s(&["y*"])),
            Patch::Absent,
        )
        .unwrap();
    assert_eq!(replaced.create, ["y*"]);
    assert_eq!(replaced.credentials, ["a"]);
    let cleared = base
        .patched(
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
            Patch::Value(vec![]),
            Patch::Absent,
        )
        .unwrap();
    assert!(cleared.create.is_empty());
    assert!(base
        .patched(
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
            Patch::Value(s(&[""])),
            Patch::Absent
        )
        .is_err());

    #[derive(Deserialize)]
    struct Body {
        #[serde(default, deserialize_with = "patch_create")]
        create: Patch<Vec<String>>,
    }
    #[derive(Deserialize, Debug)]
    struct Required {
        #[allow(dead_code)]
        #[serde(default, deserialize_with = "required_create")]
        create: Vec<String>,
    }
    let absent: Body = serde_json::from_str("{}").unwrap();
    assert!(absent.create.is_absent());
    let e = serde_json::from_str::<Body>(r#"{"create":null}"#)
        .err()
        .unwrap()
        .to_string();
    assert!(
        e.contains("`create`") && e.contains("null") && e.contains("cannot create"),
        "{e}"
    );
    let e = serde_json::from_str::<Required>(r#"{"create":null}"#)
        .err()
        .unwrap()
        .to_string();
    assert!(e.contains("`create`") && e.contains("null"), "{e}");
    for bad in [
        r#"{"create":"*"}"#,
        r#"{"create":5}"#,
        r#"{"create":{"a":1}}"#,
    ] {
        let e = serde_json::from_str::<Body>(bad).err().unwrap().to_string();
        assert!(e.contains("`create`"), "{bad}: {e}");
    }
}

#[test]
fn adding_or_broadening_a_create_pattern_is_a_widening() {
    let saved = pol_c(&["*"], &["agent_*"]);
    // The same, narrower, or covered by the old patterns: not widening.
    assert!(!saved.is_widened_by(&saved));
    assert!(!saved.is_widened_by(&pol_c(&["*"], &["agent_a*"])));
    assert!(!saved.is_widened_by(&pol_c(&["*"], &["agent_*"])));
    assert!(
        !saved.is_widened_by(&pol_c(&["*"], &[])),
        "removing narrows"
    );
    // Adding a pattern, or broadening one, widens.
    assert!(saved.is_widened_by(&pol_c(&["*"], &["agent_*", "other"])));
    assert!(saved.is_widened_by(&pol_c(&["*"], &["agent_*", "x_*"])));
    assert!(saved.is_widened_by(&pol_c(&["*"], &["age*"])));
    assert!(saved.is_widened_by(&pol_c(&["*"], &["*"])));
    // From nothing to anything.
    let none = pol_c(&["*"], &[]);
    assert!(none.is_widened_by(&pol_c(&["*"], &["a"])));
    assert!(!none.is_widened_by(&none));
    // A star is only covered by a star.
    let star = pol_c(&["*"], &["*"]);
    assert!(!star.is_widened_by(&pol_c(&["*"], &["anything_*"])));
    assert!(!star.is_widened_by(&star));
    // And the other lists still widen on their own.
    assert!(none.is_widened_by(
        &KeyPolicy::from_raw(s(&["*"]), s(&["GET", "POST"]), vec![], vec![], vec![]).unwrap()
    ));
}

#[test]
fn the_policy_json_lists_the_create_patterns() {
    let p = pol_c(&["a"], &["agent_*"]);
    assert_eq!(
        p.to_json(),
        json!({"credentials": ["a"], "methods": ["GET"], "approval": [], "create": ["agent_*"], "rotate": []})
    );
}

// ── The rotate list ───────────────────────────────────────────────────────────

fn pol_r(c: &[&str], rotate: &[&str]) -> KeyPolicy {
    KeyPolicy::from_raw(s(c), s(&["GET"]), vec![], vec![], s(rotate)).unwrap()
}

#[test]
fn rotate_patterns_match_like_credential_patterns_and_are_their_own_permission() {
    let p = pol_r(&["*"], &["agent_*", "Service (prod)", "exact"]);
    assert!(p.allows_rotate("agent_keycloak"));
    assert!(p.allows_rotate("Service (prod)"));
    assert!(p.allows_rotate("exact"));
    assert!(!p.allows_rotate("exact2"));
    assert!(!p.allows_rotate("Agent_x"), "case-sensitive");
    assert!(!p.allows_rotate(""));
    // Nothing by default, and independent of every other list.
    assert!(!KeyPolicy::default().allows_rotate("anything"));
    assert!(!pol_r(&["*"], &[]).allows_rotate("agent_x"));
    let only = KeyPolicy::from_raw(vec![], vec![], vec![], vec![], s(&["agent_*"])).unwrap();
    assert!(only.allows_rotate("agent_x") && !only.allows_credential("agent_x"));
    assert!(!only.allows_create("agent_x"), "rotating is not creating");
    let create_only =
        KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), vec![], s(&["*"]), vec![]).unwrap();
    assert!(
        !create_only.allows_rotate("agent_x"),
        "creating is not rotating"
    );
    // `*` collapses the list, duplicates go.
    assert_eq!(pol_r(&["*"], &["a", "*", "b"]).rotate, ["*"]);
    assert_eq!(pol_r(&["*"], &["a", "a", "b"]).rotate, ["a", "b"]);
}

#[test]
fn rotate_patterns_are_validated_like_credential_patterns() {
    assert!(KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), vec![], vec![], s(&[""])).is_err());
    assert!(KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), vec![], vec![], s(&["a\nb"])).is_err());
    let many: Vec<String> = (0..=MAX_PATTERNS).map(|i| format!("p{i}")).collect();
    let e = KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), vec![], vec![], many).unwrap_err();
    assert!(e.to_string().contains("rotate may have at most"), "{e}");
    let long = "x".repeat(MAX_PATTERN_CHARS + 1);
    assert!(KeyPolicy::from_raw(s(&["*"]), s(&["GET"]), vec![], vec![], vec![long]).is_err());
}

#[test]
fn rotate_follows_the_patch_rules_and_never_accepts_null() {
    let base = pol_r(&["a"], &["x_*"]);
    let p = |rotate| {
        base.patched(
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
            Patch::Absent,
            rotate,
        )
    };
    assert_eq!(
        p(Patch::Absent).unwrap().rotate,
        ["x_*"],
        "absent: unchanged"
    );
    assert_eq!(p(Patch::Value(s(&["y*"]))).unwrap().rotate, ["y*"]);
    assert!(p(Patch::Value(vec![])).unwrap().rotate.is_empty());
    assert!(p(Patch::Value(s(&[""]))).is_err());
    // The other lists keep theirs when only `rotate` changes.
    assert_eq!(p(Patch::Value(s(&["y*"]))).unwrap().credentials, ["a"]);

    #[derive(Deserialize)]
    struct Body {
        #[serde(default, deserialize_with = "patch_rotate")]
        rotate: Patch<Vec<String>>,
    }
    #[derive(Deserialize, Debug)]
    struct Required {
        #[allow(dead_code)]
        #[serde(default, deserialize_with = "required_rotate")]
        rotate: Vec<String>,
    }
    assert!(serde_json::from_str::<Body>("{}")
        .unwrap()
        .rotate
        .is_absent());
    let e = serde_json::from_str::<Body>(r#"{"rotate":null}"#)
        .err()
        .unwrap()
        .to_string();
    assert!(
        e.contains("`rotate`") && e.contains("null") && e.contains("cannot rotate"),
        "{e}"
    );
    let e = serde_json::from_str::<Required>(r#"{"rotate":null}"#)
        .err()
        .unwrap()
        .to_string();
    assert!(e.contains("`rotate`") && e.contains("null"), "{e}");
    assert!(serde_json::from_str::<Required>(r#"{"rotate":["a"]}"#).is_ok());
    assert!(serde_json::from_str::<Required>(r#"{"rotate":"a"}"#).is_err());
}

#[test]
fn adding_or_broadening_a_rotate_pattern_is_a_widening_and_narrowing_is_not() {
    let saved = pol_r(&["*"], &["agent_*"]);
    assert!(!saved.is_widened_by(&saved));
    assert!(!saved.is_widened_by(&pol_r(&["*"], &["agent_a*"])));
    assert!(!saved.is_widened_by(&pol_r(&["*"], &[])));
    assert!(saved.is_widened_by(&pol_r(&["*"], &["agent_*", "other"])));
    assert!(saved.is_widened_by(&pol_r(&["*"], &["*"])));
    assert!(saved.is_widened_by(&pol_r(&["*"], &["age*"])));
    assert!(KeyPolicy::default().is_widened_by(&pol_r(&[], &["x"])));
}

#[test]
fn the_policy_json_lists_the_rotate_patterns() {
    let p = pol_r(&["a"], &["agent_*"]);
    assert_eq!(
        p.to_json(),
        json!({"credentials": ["a"], "methods": ["GET"], "approval": [], "create": [], "rotate": ["agent_*"]})
    );
}
