use super::*;

#[test]
fn device_identifier_is_stable_and_per_key() {
    let a = device_identifier("user.aaaa");
    assert_eq!(a, device_identifier("user.aaaa"));
    assert_ne!(a, device_identifier("user.bbbb"));
    assert_eq!(a.get_version_num(), 5);
}

#[test]
fn sync_parsing_ignores_unknown_fields_and_keeps_ciphertext_only() {
    let body = r#"{"object":"sync","extra":1,
            "profile":{"email":"a@b.test","key":"2.x|y|z","securityStamp":"s","organizations":[{"id":"o","key":"4.k","other":true}],"junk":{}},
            "ciphers":[{"id":"1","type":1,"name":"2.n|n|n","login":{"password":"2.p|p|p","uris":[{"uri":"2.u|u|u","match":null}]},
                        "fields":[{"name":"2.f|f|f","value":null,"type":3,"linkedId":100}],"unknownField":[1,2]},
                       {"id":"2","type":5,"sshKey":{"privateKey":"2.k|k|k"},"deletedDate":"2026-01-01T00:00:00Z"}]}"#;
    let s: SyncResponse = serde_json::from_str(body).unwrap();
    assert_eq!(s.profile.email, "a@b.test");
    assert_eq!(s.ciphers.len(), 2);
    assert_eq!(
        s.ciphers[0]
            .login
            .as_ref()
            .unwrap()
            .uris
            .as_ref()
            .unwrap()
            .len(),
        1
    );
    assert!(s.ciphers[1].deleted_date.is_some());
    // Debug of a cipher shows no ciphertext.
    assert!(!format!("{:?}", s.ciphers[0]).contains("2.p"));
}

#[test]
fn classify_maps_statuses() {
    let c = |s: u16, login| Api::classify(StatusCode::from_u16(s).unwrap(), login);
    assert!(c(200, false).is_ok());
    assert_eq!(c(401, false), Err(ApiError::Unauthorized));
    assert_eq!(c(400, true), Err(ApiError::Unauthorized));
    assert_eq!(c(400, false), Err(ApiError::Unavailable));
    assert_eq!(c(429, false), Err(ApiError::RateLimited));
    assert_eq!(c(500, false), Err(ApiError::Unavailable));
    assert_eq!(c(302, false), Err(ApiError::Unavailable));
}

#[test]
fn a_missing_ca_file_is_a_clear_error() {
    let err = Api::new("https://vaultwarden", "/nonexistent/ca.crt")
        .err()
        .unwrap();
    assert!(err.contains("vault.ca_file"), "{err}");
}
