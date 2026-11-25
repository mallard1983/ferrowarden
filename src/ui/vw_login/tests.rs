use super::*;

fn classify(status: u16, body: &str) -> Result<LoginOutcome, VwError> {
    classify_token_response(status, body.as_bytes())
}

#[test]
fn device_identifier_is_stable_and_normalized() {
    let a = device_identifier("admin@example.test");
    assert_eq!(a, device_identifier("  ADMIN@Example.Test "));
    assert_ne!(a, device_identifier("other@example.test"));
    assert_eq!(a.get_version_num(), 5);
    // Pinned: a change here would add a second device to every account.
    assert_eq!(
        device_identifier("admin@example.test").to_string(),
        Uuid::new_v5(
            &DEVICE_NAMESPACE,
            b"ferrowarden-admin-ui:admin@example.test"
        )
        .to_string()
    );
}

#[test]
fn a_200_is_authenticated_whatever_the_body_says() {
    let body = r#"{"access_token":"TOKEN","refresh_token":"R","Key":"K"}"#;
    assert_eq!(classify(200, body), Ok(LoginOutcome::Authenticated));
    assert_eq!(classify(200, ""), Ok(LoginOutcome::Authenticated));
}

#[test]
fn two_factor_required_lists_only_supported_providers() {
    let body = r#"{"error":"invalid_grant","error_description":"Two factor required.",
            "TwoFactorProviders":["0","1","3","7","2","8"],
            "TwoFactorProviders2":{"0":null,"1":{"Email":"a***@example.com"},"3":{"Nfc":false},
                                   "7":{"challenge":"x"},"2":{"AuthUrl":"https://d"},"8":null}}"#;
    assert_eq!(
        classify(400, body),
        Ok(LoginOutcome::TwoFactorRequired(TwoFactorRequired {
            providers: vec![Provider::Authenticator, Provider::Email, Provider::YubiKey],
            email_hint: Some("a***@example.com".to_string()),
        }))
    );
}

#[test]
fn unsupported_only_providers_yield_an_empty_list() {
    let body = r#"{"TwoFactorProviders":["7","2"],"TwoFactorProviders2":{"7":null,"2":null}}"#;
    assert_eq!(
        classify(400, body),
        Ok(LoginOutcome::TwoFactorRequired(TwoFactorRequired {
            providers: vec![],
            email_hint: None,
        }))
    );
}

#[test]
fn provider_ids_may_be_numbers_and_duplicates_collapse() {
    let body = r#"{"TwoFactorProviders":[0,"0",1]}"#;
    let Ok(LoginOutcome::TwoFactorRequired(t)) = classify(400, body) else {
        panic!("expected two-factor");
    };
    assert_eq!(t.providers, vec![Provider::Authenticator, Provider::Email]);
}

#[test]
fn a_malformed_email_hint_is_dropped_not_rendered() {
    for hint in ["", "<script>x</script>", &"a".repeat(101), "a b@c"] {
        let body = format!(
            r#"{{"TwoFactorProviders":["1"],"TwoFactorProviders2":{{"1":{{"Email":{}}}}}}}"#,
            serde_json::to_string(hint).unwrap()
        );
        let Ok(LoginOutcome::TwoFactorRequired(t)) = classify(400, &body) else {
            panic!("expected two-factor");
        };
        assert_eq!(t.email_hint, None, "{hint:?}");
    }
}

#[test]
fn other_400s_are_invalid_credentials() {
    let wrong = r#"{"error":"","message":"Username or password is incorrect. Try again"}"#;
    assert_eq!(classify(400, wrong), Ok(LoginOutcome::InvalidCredentials));
    assert_eq!(
        classify(400, "not json"),
        Ok(LoginOutcome::InvalidCredentials)
    );
    assert_eq!(classify(400, ""), Ok(LoginOutcome::InvalidCredentials));
    // A wrong code carries no provider list.
    let bad_code = r#"{"message":"Invalid TOTP code! Server time: 2026 IP: 10.0.0.1"}"#;
    assert_eq!(
        classify(400, bad_code),
        Ok(LoginOutcome::InvalidCredentials)
    );
}

#[test]
fn rate_limit_and_everything_else() {
    assert_eq!(classify(429, ""), Err(VwError::RateLimited));
    for status in [401, 403, 404, 500, 502, 503, 301, 204] {
        assert_eq!(classify(status, "{}"), Err(VwError::Upstream), "{status}");
    }
}

#[test]
fn prelogin_pbkdf2_and_argon2() {
    let ok = r#"{"kdf":0,"kdfIterations":600000,"kdfMemory":null,"kdfParallelism":null}"#;
    assert_eq!(
        parse_prelogin(200, ok.as_bytes()),
        Ok(Kdf::Pbkdf2 {
            iterations: 600_000
        })
    );
    let argon = r#"{"kdf":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":4}"#;
    assert_eq!(
        parse_prelogin(200, argon.as_bytes()),
        Ok(Kdf::Argon2id {
            memory_mib: 64,
            iterations: 3,
            parallelism: 4
        })
    );
}

#[test]
fn prelogin_rejects_hostile_or_malformed_parameters() {
    let cases = [
        // too weak
        r#"{"kdf":0,"kdfIterations":4999}"#,
        r#"{"kdf":1,"kdfIterations":1,"kdfMemory":64,"kdfParallelism":4}"#,
        r#"{"kdf":1,"kdfIterations":3,"kdfMemory":15,"kdfParallelism":4}"#,
        // too expensive
        r#"{"kdf":0,"kdfIterations":2000001}"#,
        r#"{"kdf":0,"kdfIterations":4294967295}"#,
        r#"{"kdf":1,"kdfIterations":3,"kdfMemory":1025,"kdfParallelism":4}"#,
        r#"{"kdf":1,"kdfIterations":11,"kdfMemory":64,"kdfParallelism":4}"#,
        r#"{"kdf":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":17}"#,
        // incomplete or unknown
        r#"{"kdf":1,"kdfIterations":3,"kdfMemory":null,"kdfParallelism":4}"#,
        r#"{"kdf":1,"kdfIterations":3,"kdfMemory":64}"#,
        r#"{"kdf":2,"kdfIterations":600000}"#,
        r#"{"kdf":0}"#,
        r#"{}"#,
        r#"[]"#,
        "",
    ];
    for body in cases {
        assert_eq!(
            parse_prelogin(200, body.as_bytes()),
            Err(VwError::Upstream),
            "{body}"
        );
    }
    assert_eq!(parse_prelogin(429, b""), Err(VwError::RateLimited));
    assert_eq!(parse_prelogin(500, b"{}"), Err(VwError::Upstream));
}

#[test]
fn code_formats() {
    let totp = Provider::Authenticator;
    assert_eq!(totp.normalize_code("123456").unwrap().as_str(), "123456");
    assert_eq!(totp.normalize_code("123 456").unwrap().as_str(), "123456");
    assert_eq!(
        totp.normalize_code("12345678").unwrap().as_str(),
        "12345678"
    );
    for bad in [
        "",
        "12345",
        "123456789",
        "12345a",
        "١٢٣٤٥٦",
        "123\n456",
        " ",
    ] {
        assert!(totp.normalize_code(bad).is_none(), "{bad:?}");
    }
    assert!(Provider::Email.normalize_code("654321").is_some());
    assert!(Provider::Email.normalize_code("65432").is_none());

    let key = "ccccccdefghijklnrtuvccccccdefghijklnrtuvbbbb";
    assert_eq!(key.len(), 44);
    assert!(Provider::YubiKey.normalize_code(key).is_some());
    assert_eq!(
        Provider::YubiKey
            .normalize_code(&key.to_uppercase())
            .unwrap()
            .as_str(),
        key
    );
    for bad in [
        &key[..43],
        &format!("{key}c"),
        &format!("a{}", &key[1..]),
        "",
    ] {
        assert!(Provider::YubiKey.normalize_code(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn provider_ids_round_trip() {
    for p in [Provider::Authenticator, Provider::Email, Provider::YubiKey] {
        assert_eq!(Provider::from_id(&p.id().to_string()), Some(p));
    }
    for bad in ["2", "5", "7", "8", "", "00", "x"] {
        assert_eq!(Provider::from_id(bad), None);
    }
}
