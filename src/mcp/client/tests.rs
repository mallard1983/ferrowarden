use super::*;

#[test]
fn request_id_must_be_plain() {
    assert_eq!(
        sanitize_request_id("0191a2b3-c4d5-7e6f-8a9b-0c1d2e3f4a5b").as_deref(),
        Some("0191a2b3-c4d5-7e6f-8a9b-0c1d2e3f4a5b")
    );
    assert_eq!(sanitize_request_id("a b"), None);
    assert_eq!(sanitize_request_id("<script>"), None);
    assert_eq!(sanitize_request_id(&"a".repeat(65)), None);
    assert_eq!(sanitize_request_id(""), None);
}

#[test]
fn redactor_replaces_key_and_prefix() {
    let base = Url::parse("https://f.example.com/pfx123abc").unwrap();
    let r = Redactor::new("KEY0123456789", &base);
    let s = r.scrub_error_text("bad KEY0123456789 at /pfx123abc/v1/forward");
    assert!(!s.contains("KEY0123456789") && !s.contains("pfx123abc"));
    // Success output only loses the key.
    let t = r.scrub_key("KEY0123456789 /pfx123abc");
    assert!(!t.contains("KEY0123456789") && t.contains("pfx123abc"));
    let mut v = serde_json::json!({"a": ["x KEY0123456789"], "KEY0123456789": 1});
    r.scrub_value(&mut v);
    assert!(!v.to_string().contains("KEY0123456789"));
}
