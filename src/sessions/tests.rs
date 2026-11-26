use super::*;
use chrono::TimeZone;
use reqwest::header::{HeaderMap, HeaderValue};

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
}

fn secs(n: i64) -> ChronoDuration {
    ChronoDuration::seconds(n)
}

fn cfg() -> SessionsConfig {
    SessionsConfig::default()
}

fn spec(from: &str, name: &str, ttl: Option<u64>) -> CaptureSpec {
    CaptureSpec {
        from: from.to_string(),
        name: name.to_string(),
        ttl_secs: ttl,
    }
}

fn one(from: &str) -> Capture {
    parse_captures(Some(&[spec(from, "tok", None)]), &cfg())
        .unwrap()
        .remove(0)
}

fn bad(specs: &[CaptureSpec]) -> String {
    parse_captures(Some(specs), &cfg()).unwrap_err().to_string()
}

fn up(body: &[u8], headers: &[(&str, &str)]) -> UpstreamResponse {
    let mut map = HeaderMap::new();
    for (k, v) in headers {
        map.append(
            reqwest::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    UpstreamResponse {
        status: 200,
        headers: map,
        body: Zeroizing::new(body.to_vec()),
    }
}

fn origin(url: &str) -> Origin {
    Origin::of(&Url::parse(url).unwrap()).unwrap()
}

fn jwt(payload: &str) -> String {
    format!(
        "{}.{}.c2ln",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#),
        URL_SAFE_NO_PAD.encode(payload)
    )
}

/// Capture `source` from `up` for key `k1` with the default limits.
fn run(source: &str, ttl: Option<u64>, up: &UpstreamResponse) -> (CaptureOutcome, SessionStore) {
    let store = SessionStore::default();
    let o = origin("https://login.example.com/api/auth");
    let owner = Owner {
        key_id: "k1",
        key_name: "agent",
        origin: &o,
    };
    let c = parse_captures(Some(&[spec(source, "tok", ttl)]), &cfg())
        .unwrap()
        .remove(0);
    let out = capture(&store, &owner, &c, up, now(), 32);
    (out, store)
}

fn status(out: &CaptureOutcome) -> CaptureStatus {
    out.result.status
}

// ── Validation of `capture` ───────────────────────────────────────────────────

#[test]
fn an_absent_capture_is_no_captures_and_an_empty_one_is_an_error() {
    assert!(parse_captures(None, &cfg()).unwrap().is_empty());
    assert!(bad(&[]).contains("1 to 8"));
    let nine: Vec<CaptureSpec> = (0..9)
        .map(|i| spec("json:/a", &format!("n{i}"), None))
        .collect();
    assert!(bad(&nine).contains("1 to 8"));
    let eight: Vec<CaptureSpec> = (0..8)
        .map(|i| spec("json:/a", &format!("n{i}"), None))
        .collect();
    assert_eq!(parse_captures(Some(&eight), &cfg()).unwrap().len(), 8);
}

#[test]
fn session_names_are_plain_words_and_used_once() {
    for good in ["a", "portainer", "pve.csrf-token_2", &"x".repeat(64)] {
        assert!(
            parse_captures(Some(&[spec("json:/a", good, None)]), &cfg()).is_ok(),
            "{good}"
        );
    }
    for name in [
        "",
        "a b",
        "a/b",
        "é",
        "a{{b",
        "{{session:x}}",
        &"x".repeat(65),
    ] {
        let e = bad(&[spec("json:/a", name, None)]);
        assert!(
            e.starts_with("Invalid request: capture[0]: `as`"),
            "{name}: {e}"
        );
    }
    let e = bad(&[spec("json:/a", "x", None), spec("json:/b", "x", None)]);
    assert!(
        e.contains("capture[1]") && e.contains("more than once"),
        "{e}"
    );
}

#[test]
fn every_source_kind_is_parsed_and_checked() {
    assert_eq!(one("json:/jwt").source, Source::Json("/jwt".into()));
    assert_eq!(
        one("json:/a~0b/c~1d/0").source,
        Source::Json("/a~0b/c~1d/0".into())
    );
    assert_eq!(
        one("header:X-Auth-Token").source,
        Source::Header("x-auth-token".into())
    );
    assert_eq!(
        one("cookie:PVEAuthCookie").source,
        Source::Cookie("PVEAuthCookie".into())
    );
    for from in [
        "",
        "jwt",
        "json:",
        "json:jwt",
        "json:/a~",
        "json:/a~2",
        "header:",
        "header:bad name",
        "header:a:b",
        "cookie:",
        "cookie:a b",
        "cookie:a;b",
        "cookie:a=b",
        "body:/a",
        "JSON:/a",
        "json:/a{{vault:x}}",
        "header:{{vault:x}}",
    ] {
        let e = bad(&[spec(from, "x", None)]);
        assert!(e.contains("capture[0]"), "{from}: {e}");
    }
}

#[test]
fn the_ttl_is_between_one_second_and_the_operators_maximum() {
    let c = |ttl| parse_captures(Some(&[spec("json:/a", "x", ttl)]), &cfg());
    assert_eq!(c(None).unwrap()[0].ttl, Duration::from_secs(1800));
    assert_eq!(c(Some(1)).unwrap()[0].ttl, Duration::from_secs(1));
    assert_eq!(c(Some(86_400)).unwrap()[0].ttl, Duration::from_secs(86_400));
    for ttl in [0, 86_401, u64::MAX] {
        let e = c(Some(ttl)).unwrap_err().to_string();
        assert!(e.contains("ttl_secs") && e.contains("86400"), "{ttl}: {e}");
    }
    let tight = SessionsConfig {
        default_ttl_secs: 60,
        max_ttl_secs: 120,
        ..cfg()
    };
    assert!(parse_captures(Some(&[spec("json:/a", "x", Some(121))]), &tight).is_err());
    assert_eq!(
        parse_captures(Some(&[spec("json:/a", "x", None)]), &tight).unwrap()[0].ttl,
        Duration::from_secs(60)
    );
}

#[test]
fn switched_off_sessions_refuse_capture_and_placeholders() {
    let off = SessionsConfig {
        enabled: false,
        ..cfg()
    };
    assert!(matches!(
        parse_captures(Some(&[spec("json:/a", "x", None)]), &off),
        Err(FerroError::SessionsDisabled)
    ));
    assert!(parse_captures(None, &off).unwrap().is_empty());
    let used: BTreeSet<String> = ["x".to_string()].into();
    assert!(matches!(
        check_enabled(&off, &used),
        Err(FerroError::SessionsDisabled)
    ));
    assert!(check_enabled(&off, &BTreeSet::new()).is_ok());
    assert!(check_enabled(&cfg(), &used).is_ok());
}

#[test]
fn the_capture_member_is_strict_json() {
    use crate::api::strict_json::parse_strict;
    let ok: CaptureSpec =
        parse_strict(br#"{"from":"json:/jwt","as":"portainer","ttl_secs":60}"#).unwrap();
    assert_eq!(
        (ok.from.as_str(), ok.name.as_str(), ok.ttl_secs),
        ("json:/jwt", "portainer", Some(60))
    );
    let e = parse_strict::<CaptureSpec>(br#"{"from":"json:/a","as":"x","extra":1}"#).unwrap_err();
    assert!(e.contains("unknown field `extra`"), "{e}");
    assert!(parse_strict::<CaptureSpec>(br#"{"from":"a","from":"b","as":"x"}"#).is_err());
    assert!(
        parse_strict::<CaptureSpec>(br#"{"from":"json:/a","as":"x","ttl_secs":null}"#).is_err()
    );
    assert!(parse_strict::<CaptureSpec>(br#"{"from":"json:/a"}"#).is_err());

    use crate::api::forward::ForwardPayload;
    let req = r#""request":{"method":"GET","url":"http://x"}"#;
    // Absent is fine; null is an error (it must not turn into "no capture").
    let p: ForwardPayload = parse_strict(format!("{{{req}}}").as_bytes()).unwrap();
    assert!(p.capture.is_none());
    assert!(
        parse_strict::<ForwardPayload>(format!(r#"{{{req},"capture":null}}"#).as_bytes()).is_err()
    );
    let p: ForwardPayload =
        parse_strict(format!(r#"{{{req},"capture":[{{"from":"json:/a","as":"x"}}]}}"#).as_bytes())
            .unwrap();
    assert_eq!(p.capture.unwrap().len(), 1);
    // An empty list parses; the validation above refuses it.
    let p: ForwardPayload = parse_strict(format!(r#"{{{req},"capture":[]}}"#).as_bytes()).unwrap();
    assert_eq!(p.capture.unwrap().len(), 0);
}

// ── Extraction ────────────────────────────────────────────────────────────────

#[test]
fn a_json_pointer_finds_a_string() {
    let body = br#"{"jwt":"tok-0123456789","n":5,"o":{"k":"nested-value"},"a":["x-first","y"],"a/b":"slash-val","m~n":"tilde-val","nul":null}"#;
    let r = up(body, &[]);
    for (ptr, want) in [
        ("/jwt", Some("tok-0123456789")),
        ("/o/k", Some("nested-value")),
        ("/a/0", Some("x-first")),
        ("/a~1b", Some("slash-val")),
        ("/m~0n", Some("tilde-val")),
    ] {
        let found = extract(&Source::Json(ptr.into()), &r, now())
            .ok()
            .map(|f| f.value.to_string());
        assert_eq!(found.as_deref(), want, "{ptr}");
    }
    let err = |ptr: &str| extract(&Source::Json(ptr.into()), &r, now()).err();
    assert_eq!(err("/missing"), Some(CaptureStatus::NotFound));
    assert_eq!(err("/a/9"), Some(CaptureStatus::NotFound));
    assert_eq!(err("/n"), Some(CaptureStatus::NotAString));
    assert_eq!(err("/o"), Some(CaptureStatus::NotAString));
    assert_eq!(err("/a"), Some(CaptureStatus::NotAString));
    assert_eq!(err("/nul"), Some(CaptureStatus::NotAString));
}

#[test]
fn a_body_that_is_not_one_json_document_is_not_a_string() {
    for body in [
        &b"plain text"[..],
        b"",
        b"{\"jwt\": ",
        b"\xff\xfe",
        b"{} {}",
    ] {
        let r = up(body, &[]);
        assert_eq!(
            extract(&Source::Json("/jwt".into()), &r, now()).err(),
            Some(CaptureStatus::NotAString),
            "{body:?}"
        );
    }
}

#[test]
fn a_repeated_json_key_is_ambiguous() {
    let r = up(br#"{"jwt":"first-value-1","jwt":"second-value-2"}"#, &[]);
    assert_eq!(
        extract(&Source::Json("/jwt".into()), &r, now()).err(),
        Some(CaptureStatus::Ambiguous)
    );
}

#[test]
fn a_header_must_occur_exactly_once() {
    let r = up(b"", &[("X-Auth-Token", "header-token-1"), ("X-Other", "o")]);
    let get = |name: &str| extract(&Source::Header(name.into()), &r, now());
    assert_eq!(
        get("x-auth-token").ok().unwrap().value.as_str(),
        "header-token-1"
    );
    assert_eq!(get("x-nope").err(), Some(CaptureStatus::NotFound));
    let twice = up(b"", &[("X-A", "one"), ("x-a", "two")]);
    assert_eq!(
        extract(&Source::Header("x-a".into()), &twice, now()).err(),
        Some(CaptureStatus::Ambiguous)
    );
    // Bytes that are not text cannot be a session value.
    let mut r = up(b"", &[]);
    r.headers.insert(
        "x-bin",
        HeaderValue::from_bytes(&[0xff, 0xfe, 0x41]).unwrap(),
    );
    assert_eq!(
        extract(&Source::Header("x-bin".into()), &r, now()).err(),
        Some(CaptureStatus::NotAString)
    );
}

#[test]
fn a_cookie_is_found_among_all_set_cookie_headers() {
    let r = up(
        b"",
        &[
            ("Set-Cookie", "lang=en; Path=/"),
            (
                "Set-Cookie",
                "PVEAuthCookie=PVE:user@pam:ABCD==; Path=/; Secure; HttpOnly",
            ),
            ("Set-Cookie", "xPVEAuthCookie=other-value; Path=/"),
        ],
    );
    let got = extract(&Source::Cookie("PVEAuthCookie".into()), &r, now()).unwrap();
    // The value only, `=` signs inside it included, and none of the attributes.
    assert_eq!(got.value.as_str(), "PVE:user@pam:ABCD==");
    assert!(got.expires.is_none());
    assert_eq!(
        extract(&Source::Cookie("nope".into()), &r, now()).err(),
        Some(CaptureStatus::NotFound)
    );
    // A cookie whose name is only a prefix or a suffix is another cookie.
    assert_eq!(
        extract(&Source::Cookie("AuthCookie".into()), &r, now()).err(),
        Some(CaptureStatus::NotFound)
    );
    let twice = up(
        b"",
        &[
            ("Set-Cookie", "sid=aaaa1111; Path=/"),
            ("Set-Cookie", "sid=bbbb2222; Path=/api"),
        ],
    );
    assert_eq!(
        extract(&Source::Cookie("sid".into()), &twice, now()).err(),
        Some(CaptureStatus::Ambiguous)
    );
    // Cookie names are case-sensitive.
    assert_eq!(
        extract(&Source::Cookie("SID".into()), &twice, now()).err(),
        Some(CaptureStatus::NotFound)
    );
}

// ── Expiry ────────────────────────────────────────────────────────────────────

fn expires_at(out: &CaptureOutcome) -> String {
    out.result.expires_at.clone().expect("captured")
}

#[test]
fn the_default_expiry_is_the_ttl() {
    let r = up(br#"{"t":"token-value-1"}"#, &[]);
    let (out, store) = run("json:/t", None, &r);
    assert_eq!(status(&out), CaptureStatus::Captured);
    assert_eq!(expires_at(&out), "2026-01-01T12:30:00Z");
    assert_eq!(store.active(now()), 1);
    let (out, _) = run("json:/t", Some(90), &r);
    assert_eq!(expires_at(&out), "2026-01-01T12:01:30Z");
}

#[test]
fn a_jwt_exp_shortens_the_expiry_and_never_lengthens_it() {
    let at = |s: i64| (now() + secs(s)).timestamp();
    // exp 10 minutes ahead, ttl 30 minutes: the token's own end wins.
    let short = jwt(&format!(r#"{{"exp":{}}}"#, at(600)));
    let r = up(format!(r#"{{"t":"{short}"}}"#).as_bytes(), &[]);
    let (out, _) = run("json:/t", None, &r);
    assert_eq!(expires_at(&out), "2026-01-01T12:10:00Z");
    // exp a day ahead, ttl 30 minutes: the ttl wins.
    let long = jwt(&format!(r#"{{"exp":{}}}"#, at(86_400)));
    let r = up(format!(r#"{{"t":"{long}"}}"#).as_bytes(), &[]);
    let (out, _) = run("json:/t", None, &r);
    assert_eq!(expires_at(&out), "2026-01-01T12:30:00Z");
    // A fractional exp counts, rounded down.
    let frac = jwt(&format!(r#"{{"exp":{}.9}}"#, at(60)));
    let r = up(format!(r#"{{"t":"{frac}"}}"#).as_bytes(), &[]);
    let (out, _) = run("json:/t", None, &r);
    assert_eq!(expires_at(&out), "2026-01-01T12:01:00Z");
    // The same from a header.
    let r = up(b"", &[("Authorization", &short)]);
    let (out, _) = run("header:authorization", None, &r);
    assert_eq!(expires_at(&out), "2026-01-01T12:10:00Z");
}

#[test]
fn a_jwt_that_has_already_expired_is_not_stored_but_is_still_hidden() {
    let old = jwt(&format!(r#"{{"exp":{}}}"#, (now() - secs(5)).timestamp()));
    let r = up(format!(r#"{{"t":"{old}"}}"#).as_bytes(), &[]);
    let (out, store) = run("json:/t", None, &r);
    assert_eq!(status(&out), CaptureStatus::Expired);
    assert!(out.result.expires_at.is_none());
    assert_eq!(
        out.unstored.as_deref().map(String::as_str),
        Some(old.as_str())
    );
    assert_eq!(store.active(now()), 0);
    // exp equal to now is already over.
    let at_now = jwt(&format!(r#"{{"exp":{}}}"#, now().timestamp()));
    let r = up(format!(r#"{{"t":"{at_now}"}}"#).as_bytes(), &[]);
    assert_eq!(status(&run("json:/t", None, &r).0), CaptureStatus::Expired);
}

#[test]
fn values_that_only_look_like_a_jwt_are_not_read() {
    for value in [
        "aaa.bbb.ccc",
        "aa.bb",
        "a.b.c.d",
        // Three segments, the middle is JSON but not an object, or has no numeric exp.
        &format!("h.{}.s", URL_SAFE_NO_PAD.encode("[1,2]")),
        &format!("h.{}.s", URL_SAFE_NO_PAD.encode(r#"{"exp":"soon"}"#)),
        &format!("h.{}.s", URL_SAFE_NO_PAD.encode(r#"{"sub":"x"}"#)),
        &format!("h.{}.s", URL_SAFE_NO_PAD.encode(r#"{"exp":null}"#)),
    ] {
        assert!(jwt_expiry(value).is_none(), "{value}");
        let r = up(format!(r#"{{"t":"{value}"}}"#).as_bytes(), &[]);
        let (out, _) = run("json:/t", None, &r);
        assert_eq!(expires_at(&out), "2026-01-01T12:30:00Z", "{value}");
    }
    // Padding on the payload is tolerated.
    let padded = format!("h.{}==.s", URL_SAFE_NO_PAD.encode(r#"{"exp":1767268800}"#));
    assert!(jwt_expiry(&padded).is_some());
}

#[test]
fn a_cookie_lifetime_shortens_the_expiry_and_never_lengthens_it() {
    let cookie = |attrs: &str| {
        up(
            b"",
            &[("Set-Cookie", &format!("sid=cookie-value-1; Path=/{attrs}"))],
        )
    };
    let run_cookie = |attrs: &str| run("cookie:sid", None, &cookie(attrs)).0;
    assert_eq!(
        expires_at(&run_cookie("; Max-Age=600")),
        "2026-01-01T12:10:00Z"
    );
    assert_eq!(
        expires_at(&run_cookie("; max-age = 600")),
        "2026-01-01T12:10:00Z"
    );
    // Longer than the ttl: the ttl stays.
    assert_eq!(
        expires_at(&run_cookie("; Max-Age=86400")),
        "2026-01-01T12:30:00Z"
    );
    assert_eq!(
        expires_at(&run_cookie("; Expires=Thu, 01 Jan 2026 12:10:00 GMT")),
        "2026-01-01T12:10:00Z"
    );
    assert_eq!(
        expires_at(&run_cookie("; Expires=Thu, 01-Jan-2026 12:20:00 GMT")),
        "2026-01-01T12:20:00Z"
    );
    assert_eq!(
        expires_at(&run_cookie("; Expires=Fri, 01 Jan 2027 12:00:00 GMT")),
        "2026-01-01T12:30:00Z"
    );
    // Max-Age wins over Expires, as in RFC 6265.
    assert_eq!(
        expires_at(&run_cookie(
            "; Expires=Thu, 01 Jan 2026 12:20:00 GMT; Max-Age=300"
        )),
        "2026-01-01T12:05:00Z"
    );
    // What cannot be read is ignored: it never lengthens or fails.
    assert_eq!(
        expires_at(&run_cookie("; Max-Age=soon")),
        "2026-01-01T12:30:00Z"
    );
    assert_eq!(
        expires_at(&run_cookie("; Expires=tomorrow")),
        "2026-01-01T12:30:00Z"
    );
    assert_eq!(
        expires_at(&run_cookie("; Max-Age=99999999999999999999")),
        "2026-01-01T12:30:00Z"
    );
    // A cookie that is over already (the way a server logs out) is not kept.
    for attrs in [
        "; Max-Age=0",
        "; Max-Age=-1",
        "; Expires=Thu, 01 Jan 2026 11:00:00 GMT",
    ] {
        let out = run_cookie(attrs);
        assert_eq!(status(&out), CaptureStatus::Expired, "{attrs}");
        assert_eq!(
            out.unstored.as_deref().map(String::as_str),
            Some("cookie-value-1")
        );
    }
}

// ── Size limits ───────────────────────────────────────────────────────────────

fn captured_value_of_len(chars: usize) -> CaptureOutcome {
    let v = "v".repeat(chars);
    run(
        "json:/t",
        None,
        &up(format!(r#"{{"t":"{v}"}}"#).as_bytes(), &[]),
    )
    .0
}

#[test]
fn values_shorter_than_the_scrubbers_minimum_are_not_stored() {
    for n in [0, 1, 3] {
        let out = captured_value_of_len(n);
        assert_eq!(status(&out), CaptureStatus::TooShort, "{n}");
        // Nothing to hide with: such a value cannot be scrubbed.
        assert!(out.unstored.is_none());
    }
    assert_eq!(status(&captured_value_of_len(4)), CaptureStatus::Captured);
    // The minimum is in characters, as the scrubber counts them.
    let r = up(r#"{"t":"ééé"}"#.as_bytes(), &[]);
    assert_eq!(status(&run("json:/t", None, &r).0), CaptureStatus::TooShort);
    let r = up(r#"{"t":"éééé"}"#.as_bytes(), &[]);
    assert_eq!(status(&run("json:/t", None, &r).0), CaptureStatus::Captured);
}

#[test]
fn a_value_over_16_kib_is_not_stored_but_is_hidden() {
    assert_eq!(
        status(&captured_value_of_len(16 * 1024)),
        CaptureStatus::Captured
    );
    let out = captured_value_of_len(16 * 1024 + 1);
    assert_eq!(status(&out), CaptureStatus::TooLong);
    assert_eq!(out.unstored.unwrap().len(), 16 * 1024 + 1);
}

#[test]
fn the_key_limit_counts_live_sessions_and_replacing_is_not_new() {
    let store = SessionStore::default();
    let o = origin("https://a.example.com");
    let owner = Owner {
        key_id: "k1",
        key_name: "agent",
        origin: &o,
    };
    let put = |name: &str, v: &str, expires: DateTime<Utc>, max: usize| {
        store.insert(
            &owner,
            name,
            Zeroizing::new(v.to_string()),
            expires,
            now(),
            max,
        )
    };
    let later = now() + secs(60);
    assert!(put("a", "value-aaaa", later, 2).is_ok());
    assert!(put("b", "value-bbbb", later, 2).is_ok());
    assert_eq!(put("c", "value-cccc", later, 2), Err(LimitReached));
    // Replacing an existing name does not count as a new one.
    assert!(put("a", "value-a2", later, 2).is_ok());
    assert_eq!(store.active(now()), 2);
    // An expired session does not hold a place.
    assert!(put("old", "value-old", now() - secs(1), 3).is_ok());
    assert!(put("c", "value-cccc", later, 3).is_ok());
    // Another key has its own allowance.
    let other = Owner {
        key_id: "k2",
        ..owner
    };
    assert!(store
        .insert(
            &other,
            "a",
            Zeroizing::new("value-k2".into()),
            later,
            now(),
            1
        )
        .is_ok());

    // Through `capture`: the status and the unstored value.
    let r = up(br#"{"t":"fresh-value-1"}"#, &[]);
    let c = parse_captures(Some(&[spec("json:/t", "zzz", None)]), &cfg())
        .unwrap()
        .remove(0);
    let out = capture(&store, &owner, &c, &r, now(), 3);
    assert_eq!(status(&out), CaptureStatus::LimitReached);
    assert_eq!(
        out.unstored.as_deref().map(String::as_str),
        Some("fresh-value-1")
    );
    assert!(out.result.expires_at.is_none());
}

#[test]
fn nothing_found_means_nothing_to_hide() {
    let r = up(br#"{"other":"x"}"#, &[]);
    for (from, want) in [
        ("json:/jwt", CaptureStatus::NotFound),
        ("header:x-none", CaptureStatus::NotFound),
        ("cookie:none", CaptureStatus::NotFound),
        ("json:/other/deeper", CaptureStatus::NotFound),
    ] {
        let (out, store) = run(from, None, &r);
        assert_eq!(status(&out), want, "{from}");
        assert!(out.unstored.is_none() && out.result.expires_at.is_none());
        assert_eq!(store.active(now()), 0);
    }
    let r = up(br#"{"n":12345}"#, &[]);
    let (out, _) = run("json:/n", None, &r);
    assert_eq!(status(&out), CaptureStatus::NotAString);
    assert!(out.unstored.is_none());
}

#[test]
fn the_result_serializes_without_a_value() {
    let r = up(br#"{"t":"secret-token-value"}"#, &[]);
    let (out, _) = run("json:/t", None, &r);
    let json = serde_json::to_value(&out.result).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"as": "tok", "status": "captured", "expires_at": "2026-01-01T12:30:00Z"})
    );
    let failed =
        serde_json::to_value(CaptureOutcome::failed("x", CaptureStatus::NotAString).result)
            .unwrap();
    assert_eq!(
        failed,
        serde_json::json!({"as": "x", "status": "not_a_string"})
    );
    for status in CaptureStatus::ALL {
        assert_eq!(serde_json::to_value(status).unwrap(), status.as_str());
    }
}

// ── The store ─────────────────────────────────────────────────────────────────

fn put(store: &SessionStore, key: &str, name: &str, value: &str, url: &str, ttl: i64) {
    let o = origin(url);
    let owner = Owner {
        key_id: key,
        key_name: &format!("name-of-{key}"),
        origin: &o,
    };
    store
        .insert(
            &owner,
            name,
            Zeroizing::new(value.to_string()),
            now() + secs(ttl),
            now(),
            32,
        )
        .unwrap();
}

fn names(set: &[&str]) -> BTreeSet<String> {
    set.iter().map(|s| s.to_string()).collect()
}

#[test]
fn sessions_are_per_key() {
    let store = SessionStore::default();
    put(
        &store,
        "k1",
        "login",
        "value-of-k1",
        "https://a.example.com",
        60,
    );
    put(
        &store,
        "k2",
        "login",
        "value-of-k2",
        "https://a.example.com",
        60,
    );
    let o = origin("https://a.example.com/x");
    let got = store.resolve("k1", &names(&["login"]), &o, now()).unwrap();
    assert_eq!(got["login"].as_str(), "value-of-k1");
    let got = store.resolve("k2", &names(&["login"]), &o, now()).unwrap();
    assert_eq!(got["login"].as_str(), "value-of-k2");
    // A key that never captured the name gets the same error as for a name nobody has.
    let theirs = store
        .resolve("k3", &names(&["login"]), &o, now())
        .unwrap_err();
    let nobody = store
        .resolve("k1", &names(&["nope"]), &o, now())
        .unwrap_err();
    assert!(matches!(theirs, FerroError::UnknownSession(ref n) if n == "login"));
    assert_eq!(theirs.status_code(), nobody.status_code());
    assert_eq!(
        theirs.to_string().replace("login", "X"),
        nobody.to_string().replace("nope", "X")
    );
    assert_eq!(store.list("k3", now()), []);
    assert_eq!(store.values_for_key("k1").len(), 1);
}

#[test]
fn a_session_is_only_sent_to_the_origin_it_came_from() {
    let store = SessionStore::default();
    put(
        &store,
        "k1",
        "s",
        "value-1234",
        "https://Portainer.Example.com/api/auth",
        60,
    );
    let ok = |url: &str| store.resolve("k1", &names(&["s"]), &origin(url), now());
    assert!(ok("https://portainer.example.com/api/anything?x=1").is_ok());
    assert!(ok("https://portainer.example.com:443/").is_ok());
    assert!(ok("https://portainer.example.com./").is_ok());
    for other in [
        "http://portainer.example.com/",
        "https://portainer.example.com:8443/",
        "https://other.example.com/",
        "https://example.com/",
        "https://sub.portainer.example.com/",
    ] {
        let e = ok(other).unwrap_err();
        assert!(
            matches!(e, FerroError::SessionHostNotAllowed { ref name, .. } if name == "s"),
            "{other}: {e}"
        );
        assert_eq!(e.status_code(), axum::http::StatusCode::FORBIDDEN);
    }
    // Several names: one of them from elsewhere refuses the whole request.
    put(
        &store,
        "k1",
        "t",
        "value-5678",
        "https://elsewhere.example.com",
        60,
    );
    assert!(store
        .resolve(
            "k1",
            &names(&["s", "t"]),
            &origin("https://portainer.example.com"),
            now()
        )
        .is_err());
}

#[test]
fn origins_are_normalized() {
    assert_eq!(
        origin("HTTPS://Example.COM/x"),
        origin("https://example.com:443/y")
    );
    assert_ne!(origin("http://example.com"), origin("https://example.com"));
    assert_eq!(origin("https://example.com/").host_label(), "example.com");
    assert_eq!(origin("http://example.com:80/").host_label(), "example.com");
    assert_eq!(
        origin("http://example.com:7777/").host_label(),
        "example.com:7777"
    );
    assert_eq!(
        origin("https://example.com:8443/").host_label(),
        "example.com:8443"
    );
    assert_eq!(origin("http://[::1]:8080/").host_label(), "[::1]:8080");
    assert_eq!(origin("http://10.0.0.5/").host_label(), "10.0.0.5");
    assert_eq!(
        origin("http://user:pw@example.com/p").host_label(),
        "example.com"
    );
}

#[test]
fn a_session_expires_when_looked_up_and_is_removed_by_the_sweep() {
    let store = SessionStore::default();
    put(
        &store,
        "k1",
        "short",
        "value-short",
        "https://a.example.com",
        10,
    );
    put(
        &store,
        "k1",
        "long",
        "value-long",
        "https://a.example.com",
        100,
    );
    let o = origin("https://a.example.com");
    let at = |s: i64| now() + secs(s);
    assert!(store.resolve("k1", &names(&["short"]), &o, at(9)).is_ok());
    // Treated as absent at the instant it expires, before any sweep ran.
    let e = store
        .resolve("k1", &names(&["short"]), &o, at(10))
        .unwrap_err();
    assert!(matches!(e, FerroError::UnknownSession(_)));
    assert_eq!(store.list("k1", at(10)).len(), 1);
    assert_eq!(store.active(at(10)), 1);
    assert!(
        !store.remove("k1", "short", at(10)),
        "an expired one is not there to delete"
    );
    // Its value is still in memory until the sweep, so it is still scrubbed.
    assert_eq!(store.values_for_key("k1").len(), 2);

    assert!(store.sweep(at(5)).is_empty());
    let removed = store.sweep(at(10));
    assert_eq!(
        removed,
        [Removed {
            key_id: "k1".into(),
            key_name: "name-of-k1".into(),
            name: "short".into()
        }]
    );
    assert_eq!(store.values_for_key("k1").len(), 1);
    assert!(store.sweep(at(10)).is_empty());
}

#[test]
fn capturing_under_an_existing_name_replaces_it() {
    let store = SessionStore::default();
    put(
        &store,
        "k1",
        "s",
        "first-value",
        "https://a.example.com",
        10,
    );
    put(
        &store,
        "k1",
        "s",
        "second-value",
        "https://b.example.com:8443",
        500,
    );
    assert_eq!(store.active(now()), 1);
    let got = store
        .resolve(
            "k1",
            &names(&["s"]),
            &origin("https://b.example.com:8443"),
            now(),
        )
        .unwrap();
    assert_eq!(got["s"].as_str(), "second-value");
    assert!(store
        .resolve(
            "k1",
            &names(&["s"]),
            &origin("https://a.example.com"),
            now()
        )
        .is_err());
    let list = store.list("k1", now());
    assert_eq!(
        list,
        [SessionInfo {
            name: "s".into(),
            host: "b.example.com:8443".into(),
            expires_at: "2026-01-01T12:08:20Z".into()
        }]
    );
    assert_eq!(store.values_for_key("k1").len(), 1);
}

#[test]
fn removing_and_clearing() {
    let store = SessionStore::default();
    for (key, name) in [("k1", "a"), ("k1", "b"), ("k2", "a"), ("k3", "z")] {
        put(
            &store,
            key,
            name,
            &format!("value-{key}{name}"),
            "https://a.example.com",
            60,
        );
    }
    // Another key's name is not removable: the same `false` as for no name.
    assert!(!store.remove("k2", "b", now()));
    assert!(store.remove("k1", "b", now()));
    assert!(!store.remove("k1", "b", now()));
    assert_eq!(store.list("k2", now()).len(), 1);

    let removed = store.clear_key("k1");
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].name, "a");
    assert_eq!(removed[0].key_name, "name-of-k1");
    assert_eq!(store.active(now()), 2);
    assert!(store.clear_key("k1").is_empty());

    let all = store.clear_all();
    assert_eq!(all.len(), 2);
    assert_eq!(store.active(now()), 0);
    assert!(store.clear_all().is_empty());
}

#[test]
fn the_debug_output_never_shows_names_or_values() {
    let store = SessionStore::default();
    put(
        &store,
        "k1",
        "my-session",
        "super-secret-value",
        "https://a.example.com",
        60,
    );
    let text = format!("{store:?}");
    assert!(
        !text.contains("super-secret-value") && !text.contains("my-session"),
        "{text}"
    );
    assert!(text.contains("sessions"));
}

// ── Events ────────────────────────────────────────────────────────────────────

#[test]
fn capture_events_carry_names_and_outcomes_never_values() {
    let ok = serde_json::to_value(capture_event(&CaptureResult {
        name: "portainer".into(),
        status: CaptureStatus::Captured,
        expires_at: Some("2026-01-01T12:30:00Z".into()),
    }))
    .unwrap();
    assert_eq!(ok["event"]["action"], "session_capture");
    assert_eq!(ok["event"]["outcome"], "success");
    assert!(ok["event"].get("reason").is_none());
    assert_eq!(
        ok["event"]["category"],
        serde_json::json!(["authentication"])
    );
    assert_eq!(ok["event"]["type"], serde_json::json!(["creation"]));
    assert_eq!(ok["ferrowarden"]["details"]["session"], "portainer");
    assert_eq!(ok["ferrowarden"]["details"]["status"], "captured");
    assert_eq!(
        ok["ferrowarden"]["details"]["expires_at"],
        "2026-01-01T12:30:00Z"
    );

    let failed = serde_json::to_value(capture_event(&CaptureResult {
        name: "portainer".into(),
        status: CaptureStatus::TooLong,
        expires_at: None,
    }))
    .unwrap();
    assert_eq!(failed["event"]["outcome"], "failure");
    assert_eq!(failed["event"]["reason"], "capture_failed");
    assert_eq!(failed["ferrowarden"]["details"]["status"], "too_long");
    assert!(failed["ferrowarden"]["details"].get("expires_at").is_none());
}

#[test]
fn delete_and_expire_events_name_the_key_and_the_session() {
    let cfg: crate::config::Config =
        serde_json::from_value(serde_json::json!({"unlock_mode": "manual"})).unwrap();
    let events = Arc::new(crate::events::EventLog::buffer_only(50));
    let state = AppState::new(cfg, events.clone());
    put(
        &state.sessions,
        "k1",
        "a",
        "value-aaaa",
        "https://a.example.com",
        10,
    );
    put(
        &state.sessions,
        "k1",
        "b",
        "value-bbbb",
        "https://a.example.com",
        1000,
    );
    put(
        &state.sessions,
        "k2",
        "c",
        "value-cccc",
        "https://a.example.com",
        1000,
    );

    sweep_once(&state, now() + secs(11));
    clear_key(&state, "k1", DeleteCause::KeyRevoke);
    clear_all(&state, DeleteCause::VaultLock);
    let all: Vec<serde_json::Value> = events
        .recent(50)
        .iter()
        .rev()
        .map(|e| serde_json::to_value(&**e).unwrap())
        .collect();
    let summary: Vec<(String, String, String, String)> = all
        .iter()
        .map(|e| {
            (
                e["event"]["action"].as_str().unwrap().into(),
                e["ferrowarden"]["key"]["name"].as_str().unwrap().into(),
                e["ferrowarden"]["details"]["session"]
                    .as_str()
                    .unwrap()
                    .into(),
                e["ferrowarden"]["details"]["cause"]
                    .as_str()
                    .unwrap_or("")
                    .into(),
            )
        })
        .collect();
    let row = |a: &str, k: &str, s: &str, c: &str| (a.into(), k.into(), s.into(), c.into());
    assert_eq!(
        summary,
        [
            row("session_expire", "name-of-k1", "a", ""),
            row("session_delete", "name-of-k1", "b", "key_revoke"),
            row("session_delete", "name-of-k2", "c", "vault_lock"),
        ]
    );
    assert_eq!(all[0]["ferrowarden"]["key"]["id"], "k1");
    assert_eq!(all[0]["event"]["type"], serde_json::json!(["end"]));
    assert_eq!(all[1]["event"]["type"], serde_json::json!(["deletion"]));
    let text = serde_json::to_string(&all).unwrap();
    for value in ["value-aaaa", "value-bbbb", "value-cccc"] {
        assert!(!text.contains(value));
    }
    assert_eq!(state.sessions.active(now()), 0);
}

#[test]
fn locking_the_vault_clears_every_session() {
    let cfg: crate::config::Config =
        serde_json::from_value(serde_json::json!({"unlock_mode": "manual"})).unwrap();
    let events = Arc::new(crate::events::EventLog::buffer_only(50));
    let state = AppState::new(cfg, events.clone());
    put(
        &state.sessions,
        "k1",
        "a",
        "value-aaaa",
        "https://a.example.com",
        1000,
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        state.set_unlocked().await;
        state.set_locked("test").await;
    });
    assert_eq!(state.sessions.active(now()), 0);
    let causes: Vec<String> = events
        .recent(50)
        .iter()
        .filter_map(|e| {
            let v = serde_json::to_value(&**e).unwrap();
            (v["event"]["action"] == "session_delete").then(|| {
                v["ferrowarden"]["details"]["cause"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
        })
        .collect();
    assert_eq!(causes, ["vault_lock"]);
}
