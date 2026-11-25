
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
