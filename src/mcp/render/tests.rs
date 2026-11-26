use super::*;
use serde_json::json;

#[test]
fn truncation_is_on_a_char_boundary_and_noted() {
    let text = "é".repeat(10); // 20 bytes
    let cut = truncate_text(text.clone(), 5);
    assert!(cut.starts_with("éé"));
    assert!(cut.contains("[truncated: showing the first 4 of 20 bytes"));
    assert_eq!(truncate_text(text.clone(), 20), text);
}

#[test]
fn utf8_body_text() {
    let r = ForwardedResponse::from_value(&json!({
        "status": 404,
        "headers": {"content-type": "application/json"},
        "body": "{\"error\":\"nope\"}",
        "body_encoding": "utf8"
    }))
    .unwrap();
    let text = r.text();
    assert!(text.starts_with("HTTP 404 (the target's response"));
    assert!(text.contains("content-type: application/json"));
    assert!(text.ends_with("{\"error\":\"nope\"}"));
}

#[test]
fn base64_body_is_summarised() {
    let payload = base64::engine::general_purpose::STANDARD.encode([0u8, 159, 146, 150, 1]);
    let r = ForwardedResponse::from_value(&json!({
        "status": 200, "headers": {}, "body": payload, "body_encoding": "base64"
    }))
    .unwrap();
    let text = r.text();
    assert!(text.contains("binary response body, 5 bytes"));
    assert!(!text.contains(&payload));
}

#[test]
fn big_body_is_truncated_in_text_only() {
    let body = "x".repeat(MAX_TEXT_BYTES * 2);
    let r = ForwardedResponse {
        status: 200,
        headers: BTreeMap::new(),
        body: body.clone(),
        body_encoding: "utf8".into(),
    };
    let text = r.text();
    assert!(text.len() < MAX_TEXT_BYTES + 300);
    assert!(text.contains("[truncated"));
    assert_eq!(r.body, body);
}

#[test]
fn malformed_proxy_response_is_rejected() {
    for bad in [
        json!({"status": 99, "headers": {}, "body": "", "body_encoding": "utf8"}),
        json!({"status": 200, "headers": {"a": 1}, "body": "", "body_encoding": "utf8"}),
        json!({"status": 200, "headers": {}, "body_encoding": "utf8"}),
        json!([1, 2]),
    ] {
        assert!(ForwardedResponse::from_value(&bad).is_none(), "{bad}");
    }
}

#[test]
fn credentials_text_covers_every_kind_of_entry() {
    let entries = vec![
        json!({
            "name": "Example Service (prod)",
            "type": "login",
            "placeholder": "{{vault:'Example Service (prod)'}}",
            "username": "{{vault:'Example Service (prod)':username}}",
            "fields": {"api secret": "{{vault:'Example Service (prod)':field:'api secret'}}"},
            "unavailable_fields": {"old": "linked field"},
            "bound_to": ["https://api.example.com"]
        }),
        json!({"name": "dup", "unavailable": "two vault items share this name"}),
        json!({"name": "unbound", "placeholder": "{{vault:unbound}}", "bound_to": []}),
    ];
    let text = credentials_text(&entries);
    assert!(text.contains("3 credentials available"));
    assert!(text.contains("password: {{vault:'Example Service (prod)'}}"));
    assert!(text
        .contains("field \"api secret\": {{vault:'Example Service (prod)':field:'api secret'}}"));
    assert!(text.contains("bound to: https://api.example.com"));
    assert!(text.contains("not available: two vault items share this name"));
    assert!(text.contains("bound to: no host"));
    assert!(credentials_text(&[]).contains("no credentials"));
}

#[test]
fn error_message_shapes() {
    assert_eq!(
        error_message(br#"{"error":"Credential x is not bound"}"#).as_deref(),
        Some("Credential x is not bound")
    );
    assert_eq!(error_message(b"<html>bad gateway</html>"), None);
    assert_eq!(error_message(br#"{"error":42}"#), None);
    let long = format!(r#"{{"error":"{}"}}"#, "a".repeat(2000));
    assert_eq!(error_message(long.as_bytes()).unwrap().len(), 500);
    assert_eq!(
        error_message(b"{\"error\":\"a\\nb\\u0000c\"}").as_deref(),
        Some("a b c")
    );
}

#[test]
fn guidance_per_status() {
    let cases: [(u16, &str); 9] = [
        (400, "malformed"),
        (401, "missing, invalid or revoked"),
        (
            403,
            "Do not retry it with other credentials, hosts or methods",
        ),
        (404, "not found in the vault"),
        (409, "more than one vault item"),
        (422, "copy a ready-made placeholder"),
        (429, "Wait 7 seconds"),
        (502, "could not get an answer from the target"),
        (503, "vault is locked"),
    ];
    for (status, needle) in cases {
        let g = guidance(status, Some(7));
        assert!(g.contains(needle), "{status}: {g}");
    }
    assert!(guidance(429, None).contains("Wait a little"));
    assert!(guidance(302, None).contains("redirect"));
    assert!(guidance(500, None).contains("unexpected"));
}

#[test]
fn error_text_includes_status_message_id_and_guidance() {
    let t = ferrowarden_error_text(
        403,
        Some("Credential x is not bound to this host"),
        Some("0191a2b3-0000-7000-8000-000000000001"),
        None,
    );
    assert!(t.contains("HTTP 403 Forbidden"));
    assert!(t.contains("Message: Credential x is not bound to this host"));
    assert!(t.contains("Request ID: 0191a2b3-0000-7000-8000-000000000001"));
    assert!(t.contains("Do not retry"));
    let no_msg = ferrowarden_error_text(500, None, None, None);
    assert!(no_msg.contains("HTTP 500."));
    assert!(no_msg.contains("Message: (none)"));
}
