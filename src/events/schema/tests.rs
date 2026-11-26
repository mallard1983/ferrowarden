use super::*;
use serde_json::json;

fn to_json(e: &SecurityEvent) -> Value {
    serde_json::to_value(e).unwrap()
}

fn ctx() -> RequestContext {
    RequestContext::new("172.20.0.5".parse().unwrap())
}

fn agent() -> AgentKey {
    AgentKey {
        id: "11111111-1111-1111-1111-111111111111".into(),
        name: "monitoring-agent".into(),
        created_at: Utc::now(),
        policy: Default::default(),
        policy_set: true,
    }
}

#[test]
fn all_actions_are_listed() {
    // A new variant must be added to `Action::ALL`: this match stops
    // compiling until it is handled here, and the count then fails
    // until the list is extended.
    fn index(a: Action) -> usize {
        match a {
            Action::Forward => 0,
            Action::CredentialsList => 1,
            Action::AgentAuth => 2,
            Action::AdminAuth => 3,
            Action::RateLimited => 4,
            Action::RequestRejected => 5,
            Action::KeyCreate => 6,
            Action::KeyRevoke => 7,
            Action::KeyList => 8,
            Action::KeyPolicyChange => 9,
            Action::PolicyPreview => 10,
            Action::AuditRead => 11,
            Action::StatusRead => 12,
            Action::OpenapiRead => 13,
            Action::VaultUnlock => 14,
            Action::VaultLock => 15,
            Action::VaultSync => 16,
            Action::Startup => 17,
            Action::Shutdown => 18,
            Action::EventsDropped => 19,
            Action::UiLogin => 20,
            Action::UiLogout => 21,
            Action::UiSessionExpired => 22,
            Action::UiTwoFactorEmailSent => 23,
            Action::NotifyTest => 24,
        }
    }
    for (i, a) in Action::ALL.into_iter().enumerate() {
        assert_eq!(index(a), i, "{a:?}");
        assert_eq!(Action::from_name(a.as_str()), Some(a));
    }
    assert_eq!(Action::from_name("nope"), None);
    assert_eq!(Outcome::from_name("success"), Some(Outcome::Success));
    assert_eq!(Outcome::from_name("Success"), None);
}

#[test]
fn forward_failure_matches_documented_shape() {
    let c = ctx();
    let e = SecurityEvent::new(Action::Forward)
        .request(&c)
        .key(&agent())
        .method("POST")
        .url("https://api.example.com/x?token={{vault:t}}")
        .credentials(["t"])
        .duration(Duration::from_nanos(12345678))
        .outcome(Outcome::Failure)
        .reason(Reason::CredentialHostNotAllowed)
        .status(403);
    let v = to_json(&e);

    assert_eq!(v["event"]["kind"], "event");
    assert_eq!(v["event"]["dataset"], "ferrowarden.security");
    assert_eq!(v["event"]["action"], "forward");
    assert_eq!(v["event"]["category"], json!(["web"]));
    assert_eq!(v["event"]["type"], json!(["access", "denied"]));
    assert_eq!(v["event"]["outcome"], "failure");
    assert_eq!(v["event"]["reason"], "credential_host_not_allowed");
    assert_eq!(v["event"]["duration"], 12345678);
    assert_eq!(
        v["message"],
        "forward blocked: credential not bound to target host"
    );
    assert_eq!(v["source"]["ip"], "172.20.0.5");
    assert_eq!(v["http"]["request"]["method"], "POST");
    // A number, not "Some(403)" or "403".
    assert_eq!(v["http"]["response"]["status_code"], 403);
    assert!(v["http"]["response"]["status_code"].is_u64());
    assert_eq!(
        v["url"]["original"],
        "https://api.example.com/x?token={{vault:t}}"
    );
    assert_eq!(v["url"]["domain"], "api.example.com");
    assert_eq!(v["service"]["name"], "ferrowarden");
    assert_eq!(v["ferrowarden"]["schema_version"], 1);
    assert_eq!(v["ferrowarden"]["request_id"], c.request_id.as_str());
    assert_eq!(v["ferrowarden"]["key"]["name"], "monitoring-agent");
    assert_eq!(v["ferrowarden"]["credentials"], json!(["t"]));
}

#[test]
fn inapplicable_fields_are_omitted_not_null() {
    let v = to_json(&SecurityEvent::new(Action::Shutdown));
    let text = v.to_string();
    assert!(!text.contains("null"), "{text}");
    for absent in ["source", "http", "url"] {
        assert!(v.get(absent).is_none(), "{absent} should be omitted");
    }
    assert!(v["event"].get("reason").is_none());
    assert!(v["event"].get("duration").is_none());
    assert!(v["ferrowarden"].get("request_id").is_none());
    assert!(v["ferrowarden"].get("key").is_none());
    assert!(v["ferrowarden"].get("credentials").is_none());
    assert!(v["ferrowarden"].get("details").is_none());
}

#[test]
fn timestamp_is_utc_rfc3339_with_milliseconds() {
    let v = to_json(&SecurityEvent::new(Action::Startup));
    let ts = v["@timestamp"].as_str().unwrap();
    // 2026-11-21T14:03:11.402Z
    assert_eq!(ts.len(), 24, "{ts}");
    assert!(ts.ends_with('Z'));
    assert_eq!(&ts[19..20], ".");
    assert!(DateTime::parse_from_rfc3339(ts).is_ok());
}

#[test]
fn ecs_category_and_type_follow_the_action_table() {
    let cases = [
        (Action::Forward, "web", vec!["access"]),
        (Action::CredentialsList, "web", vec!["access"]),
        (Action::AgentAuth, "authentication", vec!["start"]),
        (Action::AdminAuth, "authentication", vec!["start"]),
        (Action::RateLimited, "network", vec!["denied"]),
        (Action::RequestRejected, "web", vec!["denied"]),
        (Action::KeyCreate, "iam", vec!["creation"]),
        (Action::KeyRevoke, "iam", vec!["deletion"]),
        (Action::KeyList, "iam", vec!["access"]),
        (Action::KeyPolicyChange, "iam", vec!["change"]),
        (Action::PolicyPreview, "iam", vec!["access"]),
        (Action::AuditRead, "web", vec!["access"]),
        (Action::StatusRead, "web", vec!["access"]),
        (Action::OpenapiRead, "web", vec!["access"]),
        (Action::VaultUnlock, "authentication", vec!["start"]),
        (Action::VaultLock, "configuration", vec!["change"]),
        (Action::VaultSync, "configuration", vec!["info"]),
        (Action::Startup, "configuration", vec!["start"]),
        (Action::Shutdown, "configuration", vec!["end"]),
        (Action::EventsDropped, "configuration", vec!["info"]),
        (Action::NotifyTest, "configuration", vec!["info"]),
    ];
    for (action, category, types) in cases {
        let e = SecurityEvent::new(action);
        assert_eq!(e.event.category, vec![category], "{action:?}");
        assert_eq!(e.event.types, types, "{action:?}");
    }
    // `denied` is added to a forward only when it was blocked.
    let blocked = SecurityEvent::new(Action::Forward)
        .outcome(Outcome::Failure)
        .reason(Reason::TargetBlocked);
    assert_eq!(blocked.event.types, vec!["access", "denied"]);
    let upstream = SecurityEvent::new(Action::Forward)
        .outcome(Outcome::Failure)
        .reason(Reason::UpstreamError);
    assert_eq!(upstream.event.types, vec!["access"]);
}

#[test]
fn failure_only_actions_default_to_failure() {
    for a in [
        Action::AgentAuth,
        Action::AdminAuth,
        Action::RateLimited,
        Action::RequestRejected,
    ] {
        assert_eq!(SecurityEvent::new(a).event.outcome, Outcome::Failure);
    }
    assert_eq!(
        SecurityEvent::new(Action::Forward).event.outcome,
        Outcome::Success
    );
}

#[test]
fn action_names_match_serde_names() {
    for a in [
        Action::Forward,
        Action::CredentialsList,
        Action::AgentAuth,
        Action::AdminAuth,
        Action::RateLimited,
        Action::RequestRejected,
        Action::KeyCreate,
        Action::KeyRevoke,
        Action::KeyList,
        Action::KeyPolicyChange,
        Action::PolicyPreview,
        Action::AuditRead,
        Action::StatusRead,
        Action::OpenapiRead,
        Action::VaultUnlock,
        Action::VaultLock,
        Action::VaultSync,
        Action::Startup,
        Action::Shutdown,
        Action::EventsDropped,
        Action::UiLogin,
        Action::UiLogout,
        Action::UiSessionExpired,
        Action::UiTwoFactorEmailSent,
        Action::NotifyTest,
    ] {
        assert_eq!(serde_json::to_value(a).unwrap(), a.as_str());
    }
}

#[test]
fn every_ferro_error_variant_maps_to_a_reason() {
    // One of each variant. The `From<&FerroError>` match has no catch-all,
    // so a new variant fails to compile until it is mapped; this test pins
    // the actual mapping.
    let cases: Vec<(FerroError, Reason)> = vec![
        (FerroError::VaultLocked, Reason::VaultLocked),
        (FerroError::UnlockFailed("x".into()), Reason::UnlockFailed),
        (
            FerroError::CredentialNotFound("x".into()),
            Reason::UnknownCredential,
        ),
        (FerroError::VaultUnavailable, Reason::UpstreamError),
        (
            FerroError::AmbiguousCredential("x".into()),
            Reason::AmbiguousCredential,
        ),
        (
            FerroError::CredentialHostNotAllowed {
                name: "n".into(),
                host: "h".into(),
                reason: "r".into(),
            },
            Reason::CredentialHostNotAllowed,
        ),
        (FerroError::Unauthorized, Reason::InvalidKey),
        (FerroError::AgentKeyNotFound, Reason::KeyNotFound),
        (
            FerroError::CredentialOutOfScope("x".into()),
            Reason::CredentialOutOfScope,
        ),
        (
            FerroError::MethodNotAllowed("GET".into()),
            Reason::MethodNotAllowed,
        ),
        (FerroError::ForwardFailed("x".into()), Reason::UpstreamError),
        (
            FerroError::InvalidTargetUrl("x".into()),
            Reason::InvalidTargetUrl,
        ),
        (FerroError::TargetBlocked("x".into()), Reason::TargetBlocked),
        (FerroError::ResponseTooLarge(1), Reason::ResponseTooLarge),
        (
            FerroError::UnknownPlaceholder("x".into()),
            Reason::UnknownCredential,
        ),
        (
            FerroError::MalformedPlaceholder("x".into()),
            Reason::MalformedPlaceholder,
        ),
        (
            FerroError::AmbiguousField {
                item: "i".into(),
                field: "f".into(),
            },
            Reason::AmbiguousField,
        ),
        (
            FerroError::RepromptRequired("x".into()),
            Reason::RepromptRequired,
        ),
        (FerroError::Config("x".into()), Reason::InternalError),
        (FerroError::UnlockEndpointDisabled, Reason::InvalidRequest),
        (
            FerroError::InvalidRequest("x".into()),
            Reason::InvalidRequest,
        ),
        (FerroError::InvalidJson("x".into()), Reason::InvalidJson),
        (FerroError::Internal("x".into()), Reason::InternalError),
    ];
    for (err, reason) in &cases {
        assert_eq!(Reason::from(err), *reason, "{err}");
    }
}

#[test]
fn reason_codes_are_the_documented_snake_case_list() {
    let all = [
        (Reason::MissingKey, "missing_key"),
        (Reason::InvalidKey, "invalid_key"),
        (Reason::MissingAdminKey, "missing_admin_key"),
        (Reason::InvalidAdminKey, "invalid_admin_key"),
        (Reason::RateLimited, "rate_limited"),
        (Reason::InvalidJson, "invalid_json"),
        (Reason::InvalidRequest, "invalid_request"),
        (Reason::TargetBlocked, "target_blocked"),
        (Reason::InvalidTargetUrl, "invalid_target_url"),
        (
            Reason::CredentialHostNotAllowed,
            "credential_host_not_allowed",
        ),
        (Reason::CredentialOutOfScope, "credential_out_of_scope"),
        (Reason::MethodNotAllowed, "method_not_allowed"),
        (Reason::RepromptRequired, "reprompt_required"),
        (Reason::UnknownCredential, "unknown_credential"),
        (Reason::AmbiguousCredential, "ambiguous_credential"),
        (Reason::AmbiguousField, "ambiguous_field"),
        (Reason::MalformedPlaceholder, "malformed_placeholder"),
        (Reason::VaultLocked, "vault_locked"),
        (Reason::UpstreamError, "upstream_error"),
        (Reason::ResponseTooLarge, "response_too_large"),
        (Reason::KeyNotFound, "key_not_found"),
        (Reason::UnlockFailed, "unlock_failed"),
        (Reason::SyncFailed, "sync_failed"),
        (Reason::InternalError, "internal_error"),
        (Reason::InvalidCredentials, "invalid_credentials"),
        (Reason::TwoFactorRequired, "two_factor_required"),
        (Reason::TwoFactorFailed, "two_factor_failed"),
        (Reason::LoginLockedOut, "login_locked_out"),
        (Reason::UpstreamRateLimited, "upstream_rate_limited"),
        (Reason::InsecureTransport, "insecure_transport"),
    ];
    assert_eq!(all.len(), Reason::ALL.len());
    for ((reason, code), listed) in all.into_iter().zip(Reason::ALL) {
        assert_eq!(serde_json::to_value(reason).unwrap(), code);
        assert_eq!(reason.as_str(), code);
        assert_eq!(listed, reason, "Reason::ALL is in declaration order");
    }
}

#[test]
fn ui_events_have_the_documented_shape() {
    let c = ctx();
    let ok = to_json(
        &SecurityEvent::new(Action::UiLogin)
            .request(&c)
            .detail("provider", "email"),
    );
    assert_eq!(ok["event"]["action"], "ui_login");
    assert_eq!(ok["event"]["category"], json!(["authentication"]));
    assert_eq!(ok["event"]["type"], json!(["start"]));
    assert_eq!(ok["event"]["outcome"], "success");
    assert_eq!(ok["message"], "UI sign-in succeeded");

    let bad = to_json(
        &SecurityEvent::new(Action::UiLogin)
            .outcome(Outcome::Failure)
            .reason(Reason::InvalidCredentials),
    );
    assert_eq!(bad["event"]["type"], json!(["start", "denied"]));
    assert_eq!(
        bad["message"],
        "UI sign-in blocked: invalid password or code"
    );

    let step1 = to_json(
        &SecurityEvent::new(Action::UiLogin)
            .outcome(Outcome::Unknown)
            .reason(Reason::TwoFactorRequired),
    );
    assert_eq!(step1["event"]["outcome"], "unknown");
    assert_eq!(step1["event"]["type"], json!(["start"]));
    assert_eq!(
        step1["message"],
        "UI sign-in incomplete: password accepted, second factor required"
    );

    let outage = to_json(
        &SecurityEvent::new(Action::UiLogin)
            .outcome(Outcome::Failure)
            .reason(Reason::UpstreamError),
    );
    assert_eq!(outage["event"]["type"], json!(["start"]));

    for (a, ty) in [
        (Action::UiLogout, "end"),
        (Action::UiSessionExpired, "end"),
        (Action::UiTwoFactorEmailSent, "info"),
    ] {
        let v = to_json(&SecurityEvent::new(a));
        assert_eq!(v["event"]["category"], json!(["authentication"]));
        assert_eq!(v["event"]["type"], json!([ty]));
    }
}

#[test]
fn truncation_applies_to_agent_supplied_strings() {
    let long_url = format!("https://h.example/{}", "a".repeat(5000));
    let long = "x".repeat(500);
    let e = SecurityEvent::new(Action::Forward)
        .url(&long_url)
        .method(&long)
        .key(&AgentKey {
            id: long.clone(),
            name: long.clone(),
            created_at: Utc::now(),
            policy: Default::default(),
            policy_set: true,
        })
        .credentials([long.clone()])
        .detail_str("k", &long);
    assert_eq!(e.url.as_ref().unwrap().original.chars().count(), 2048);
    assert_eq!(e.url.as_ref().unwrap().domain.as_deref(), Some("h.example"));
    let req = e.http.as_ref().unwrap().request.as_ref().unwrap();
    assert_eq!(req.method.chars().count(), 128);
    let key = e.ferrowarden.key.as_ref().unwrap();
    assert_eq!(key.name.chars().count(), 128);
    assert_eq!(key.id.chars().count(), 128);
    assert_eq!(e.ferrowarden.credentials[0].chars().count(), 128);
    assert_eq!(
        e.ferrowarden.details.as_ref().unwrap()["k"]
            .as_str()
            .unwrap()
            .chars()
            .count(),
        128
    );
    // Multi-byte characters are cut on character boundaries.
    assert_eq!(truncate("ééé", 2), "éé");
}

#[test]
fn credential_label_count_is_capped() {
    let labels: Vec<String> = (0..500).map(|i| format!("c{i}")).collect();
    let e = SecurityEvent::new(Action::Forward).credentials(&labels);
    assert_eq!(e.ferrowarden.credentials.len(), 64);
}

#[test]
fn hostile_strings_cannot_break_the_json_line() {
    let evil = "GET\n{\"event\":{\"outcome\":\"success\"}}\r\u{0}\"\\";
    let line = serde_json::to_string(
        &SecurityEvent::new(Action::Forward)
            .method(evil)
            .url("https://h.example/\n\"x"),
    )
    .unwrap();
    assert_eq!(line.lines().count(), 1, "event must stay on one line");
    let v: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["http"]["request"]["method"], evil);
    assert_eq!(v["event"]["outcome"], "success");
}

#[test]
fn unparseable_url_has_no_domain() {
    let e = SecurityEvent::new(Action::Forward).url("not a url {{vault:x}}");
    assert!(e.url.unwrap().domain.is_none());
}

#[test]
fn builder_details_and_message() {
    let e = SecurityEvent::new(Action::CredentialsList)
        .detail("detail", true)
        .detail("count", 3);
    let v = to_json(&e);
    assert_eq!(
        v["ferrowarden"]["details"],
        json!({"detail": true, "count": 3})
    );
    assert_eq!(v["message"], "credentials listed");

    let e = SecurityEvent::new(Action::AgentAuth).reason(Reason::MissingKey);
    assert_eq!(
        e.message,
        "agent authentication blocked: no agent key presented"
    );
    let e = SecurityEvent::new(Action::VaultSync)
        .outcome(Outcome::Failure)
        .reason(Reason::SyncFailed);
    assert_eq!(e.message, "vault sync failed: credential sync failed");
}

#[test]
fn duration_saturates_instead_of_overflowing() {
    let e = SecurityEvent::new(Action::Forward).duration(Duration::MAX);
    assert_eq!(e.event.duration, Some(u64::MAX));
}
