use super::*;

#[test]
fn a_grant_lasts_from_one_minute_to_the_configured_maximum() {
    for ok in [1, 2, 59, 480] {
        assert_eq!(check_minutes(480, ok).unwrap(), ok as u32);
    }
    for bad in [0u64, 481, 10_080, u64::from(u32::MAX) + 1, u64::MAX] {
        let e = check_minutes(480, bad).unwrap_err();
        assert!(matches!(e, FerroError::InvalidRequest(_)), "{bad}");
        assert!(e.to_string().contains("from 1 to 480"), "{e}");
    }
    // The maximum is the operator's.
    assert!(check_minutes(10_080, 10_080).is_ok());
    assert!(check_minutes(1, 2).is_err());
}

#[test]
fn the_api_approver_is_a_fixed_name_that_cannot_be_a_ui_account() {
    // An email always has an `@`; the admin API's approver does not.
    assert_eq!(API_APPROVER, "admin_api");
    assert!(!API_APPROVER.contains('@'));
}

#[test]
fn the_approve_body_is_strict() {
    use crate::api::strict_json::parse_request;
    let minutes = |b: &[u8]| parse_request::<ApproveBody>(b).map(|a| a.minutes);
    assert_eq!(minutes(br#"{"minutes":15}"#).unwrap(), Some(15));
    // No `minutes` parses (the handler decides by kind whether one is needed).
    assert_eq!(minutes(br#"{}"#).unwrap(), None);
    for bad in [
        &br#"{"minutes":-1}"#[..],
        br#"{"minutes":1.5}"#,
        br#"{"minutes":"15"}"#,
        br#"{"minutes":null}"#,
        br#"{"minutes":15,"minutes":16}"#,
        br#"{"minutes":15,"extra":true}"#,
        br#"[15]"#,
        br#"15"#,
        br#"null"#,
    ] {
        assert!(minutes(bad).is_err(), "{}", String::from_utf8_lossy(bad));
    }
}
