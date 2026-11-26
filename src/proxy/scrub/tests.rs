use super::*;

#[test]
fn test_scrub_bearer() {
    let body = r#"{"token": "Bearer eyJhbGciOiJIUzI1NiJ9.test.sig"}"#;
    let scrubbed = scrub_response(body, &[]);
    assert!(!scrubbed.contains("eyJhbGciOiJIUzI1NiJ9"));
    assert!(scrubbed.contains("[REDACTED]"));
}

#[test]
fn test_scrub_api_key_field() {
    let body = r#"{"api_key": "sk-abcdef1234567890abcdef"}"#;
    let scrubbed = scrub_response(body, &[]);
    assert!(!scrubbed.contains("sk-abcdef1234567890abcdef"));
    assert!(scrubbed.contains("[REDACTED]"));
}

#[test]
fn test_scrub_basic_auth_url() {
    let body = r#"connect to https://admin:supersecret@192.168.1.1/api"#;
    let scrubbed = scrub_response(body, &[]);
    assert!(!scrubbed.contains("supersecret"));
    assert!(scrubbed.contains("[REDACTED]@"));
}

#[test]
fn test_no_false_positive_on_clean_body() {
    let body = r#"{"status": "ok", "nodes": ["sg1", "sg2"]}"#;
    assert_eq!(scrub_response(body, &[]), body);
}

#[test]
fn exact_value_echo_is_scrubbed_in_any_field() {
    let secret = "zq-9f8e7d6c5b4a";
    let body =
        format!(r#"{{"headers": {{"X-Whatever": "{secret}"}}, "args": {{"q": "{secret}"}}}}"#);
    let scrubbed = scrub_response(&body, &[secret]);
    assert!(!scrubbed.contains(secret));
    assert_eq!(scrubbed.matches(REDACTED).count(), 2);
}

#[test]
fn encoded_echoes_are_scrubbed() {
    let secret = "p@ss w/rd\"+ok";
    let json_escaped = r#"p@ss w/rd\"+ok"#;
    let body = format!(
        "json={json_escaped} url={} b64={} b64url={}",
        urlencoding::encode(secret),
        STANDARD.encode(secret),
        URL_SAFE_NO_PAD.encode(secret),
    );
    let scrubbed = scrub_response(&body, &[secret]);
    assert!(!scrubbed.contains(json_escaped));
    assert!(!scrubbed.contains(&*urlencoding::encode(secret)));
    assert!(!scrubbed.contains(&STANDARD_NO_PAD.encode(secret)));
    assert!(!scrubbed.contains(&URL_SAFE_NO_PAD.encode(secret)));
}

#[test]
fn short_values_are_not_scrubbed() {
    assert_eq!(scrub_response("abc abc", &["abc"]), "abc abc");
}

#[test]
fn binary_body_is_scrubbed() {
    let mut body = vec![0xff, 0xfe];
    body.extend_from_slice(b"SECRETVALUE");
    body.push(0x00);
    let out = scrub_bytes(&body, &["SECRETVALUE"]);
    assert!(!out.windows(11).any(|w| w == b"SECRETVALUE"));
    assert!(out
        .windows(REDACTED.len())
        .any(|w| w == REDACTED.as_bytes()));
}

// ── Secrets with their own replacement (captured sessions) ────────────────────

fn captured<'a>(value: &'a str, name: &'a str) -> Secret<'a> {
    Secret {
        value,
        replacement: name,
    }
}

#[test]
fn a_secret_can_carry_its_own_replacement_text() {
    let token = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjF9.c2lnbmF0dXJl";
    let body = format!(
        r#"{{"a":"{token}","b":"{}","c":"{}","d":"{}","e":"{}"}}"#,
        urlencoding::encode(token),
        STANDARD.encode(token),
        URL_SAFE_NO_PAD.encode(token),
        STANDARD_NO_PAD.encode(token),
    );
    let out = scrub_response_with(&body, &[captured(token, "[CAPTURED:portainer]")]);
    assert_eq!(out.matches("[CAPTURED:portainer]").count(), 5, "{out}");
    assert!(!out.contains(REDACTED));
    assert!(!out.contains("eyJhbGci"));
    // Header values go through the same function.
    assert_eq!(
        scrub_response_with(token, &[captured(token, "[CAPTURED:x]")]),
        "[CAPTURED:x]"
    );
}

#[test]
fn replacements_are_chosen_per_secret() {
    let body = "first=aaaa-1111 second=bbbb-2222 third=cccc-3333";
    let out = scrub_response_with(
        body,
        &[
            captured("aaaa-1111", "[CAPTURED:one]"),
            captured("bbbb-2222", REDACTED),
            Secret::redacted("cccc-3333"),
        ],
    );
    assert_eq!(
        out,
        "first=[CAPTURED:one] second=[REDACTED] third=[REDACTED]"
    );
}

#[test]
fn a_custom_replacement_applies_to_binary_bodies_too() {
    let mut body = vec![0xff, 0xfe];
    body.extend_from_slice(b"SESSIONTOKEN");
    let out = scrub_bytes_with(&body, &[captured("SESSIONTOKEN", "[CAPTURED:s]")]);
    assert_eq!(out, [&[0xff, 0xfe][..], b"[CAPTURED:s]"].concat());
}

#[test]
fn a_short_session_value_cannot_be_scrubbed() {
    // Why the capture refuses to store anything under 4 characters.
    assert_eq!(
        scrub_response_with("abc abc", &[captured("abc", "[CAPTURED:x]")]),
        "abc abc"
    );
}

#[test]
fn a_replacement_is_not_scrubbed_again_by_the_generic_patterns() {
    // `Bearer [CAPTURED:x]` is not a bearer-shaped token, so it survives as is.
    let out = scrub_response_with(
        "Authorization: Bearer tok-0123456789",
        &[captured("tok-0123456789", "[CAPTURED:x]")],
    );
    assert_eq!(out, "Authorization: Bearer [CAPTURED:x]");
}

// ── JSON escapes the text match does not know, and the order across secrets ───

fn uescape(s: &str) -> String {
    s.chars()
        .map(|c| format!("{}{:04x}", r"\u", c as u32))
        .collect()
}

#[test]
fn lower_case_percent_encoding_is_scrubbed() {
    let secret = "ab/cd+ef=gh-1234";
    let lower = urlencoding::encode(secret).to_lowercase();
    assert!(lower.contains("%2f"));
    let out = scrub_response(&format!("x={lower}"), &[secret]);
    assert_eq!(out, format!("x={REDACTED}"));
}

#[test]
fn json_escaped_slash_is_scrubbed_by_the_structural_fallback() {
    let secret = "abc/def+ghi/jkl==";
    let body = format!(r#"{{"token": "{}", "n": 1}}"#, secret.replace('/', r"\/"));
    let out = scrub_json_body(&body, &[Secret::redacted(secret)]);
    assert!(!out.contains("abc"), "{out}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["token"], REDACTED);
    assert_eq!(v["n"], 1);
}

#[test]
fn ampersand_and_angle_escapes_are_scrubbed() {
    let secret = "a&b<c>d-12345";
    let body = r#"{"t":"a\u0026b\u003cc\u003ed-12345"}"#;
    let out = scrub_json_body(body, &[captured(secret, "[CAPTURED:x]")]);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["t"], "[CAPTURED:x]");
}

#[test]
fn a_token_written_fully_as_unicode_escapes_is_scrubbed() {
    let secret = "plain-token-12345";
    let body = format!(r#"{{"t":"{}"}}"#, uescape(secret));
    let out = scrub_json_body(&body, &[Secret::redacted(secret)]);
    assert!(!out.contains("0070"), "{out}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["t"], REDACTED);
}

#[test]
fn escaped_secrets_in_nested_keys_and_arrays_are_scrubbed() {
    let secret = "k/e/y-value-1";
    let esc = secret.replace('/', r"\/");
    let body = format!(r#"{{"a":[{{"{esc}":"v"}},["x {esc} y"]]}}"#);
    let out = scrub_json_body(&body, &[Secret::redacted(secret)]);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["a"][0][REDACTED], "v");
    assert_eq!(v["a"][1][0], format!("x {REDACTED} y"));
}

#[test]
fn a_body_without_such_escapes_is_returned_unchanged() {
    let secret = "secret-value-99";
    let body = "{\n  \"a\": 1,\n  \"b\":   [\"x\", \"y/z\"]  \n}";
    assert_eq!(scrub_json_body(body, &[Secret::redacted(secret)]), body);
    // An exact echo keeps the formatting too: only the value is replaced.
    let body = format!("{{ \"a\" :  \"{secret}\" }}");
    assert_eq!(
        scrub_json_body(&body, &[Secret::redacted(secret)]),
        format!("{{ \"a\" :  \"{REDACTED}\" }}")
    );
    // Not JSON: the text pass only.
    assert_eq!(
        scrub_json_body(&format!("plain {secret}"), &[Secret::redacted(secret)]),
        format!("plain {REDACTED}")
    );
}

#[test]
fn a_shorter_secret_inside_a_longer_one_does_not_break_the_longer_match() {
    let long = "prefix-SHORTTOKEN-suffix";
    let short = "SHORTTOKEN";
    let body = format!("a {long} b {short} c");
    // The shorter secret is listed first.
    let out = scrub_response_with(
        &body,
        &[captured(short, "[CAPTURED:s]"), Secret::redacted(long)],
    );
    assert_eq!(out, format!("a {REDACTED} b [CAPTURED:s] c"));
    let bytes = scrub_bytes_with(
        body.as_bytes(),
        &[captured(short, "[CAPTURED:s]"), Secret::redacted(long)],
    );
    assert_eq!(bytes, format!("a {REDACTED} b [CAPTURED:s] c").into_bytes());
}
