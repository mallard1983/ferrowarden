
use super::*;

#[test]
fn safe_next_accepts_ui_paths() {
    for ok in [
        "/ui/",
        "/ui/keys",
        "/ui/keys/new",
        "/ui/keys/0b5c1c88-ad3f-4f43-9a73-1e7d0cbd2b61",
        "/ui/keys/0b5c1c88-ad3f-4f43-9a73-1e7d0cbd2b61/revoke",
        "/ui/audit",
        "/ui/a.b_c-d",
    ] {
        assert_eq!(safe_next(ok).as_deref(), Some(ok), "{ok}");
    }
}

#[test]
fn safe_next_refuses_open_redirect_payloads() {
    let long = format!("/ui/{}", "a".repeat(200));
    let bad: Vec<&str> = vec![
        "",
        "/",
        "/ui",
        "ui/keys",
        "//evil.com",
        "///evil.com",
        "/\\evil.com",
        "/\\\\evil.com",
        "/ui/\\evil.com",
        "/ui//evil.com",
        "/ui/..",
        "/ui/../x",
        "/ui/keys/../../x",
        "/ui/./keys",
        "/ui/keys/..",
        "/ui/%2e%2e/x",
        "/ui/%2f%2fevil.com",
        "/ui/%2F%2Fevil.com",
        "/ui/%5cevil.com",
        "/ui/%252f",
        "/ui/keys%00",
        "https://evil.com",
        "http://evil.com/ui/",
        "javascript:alert(1)",
        "data:text/html,x",
        "/ui/keys?x=1",
        "/ui/keys#frag",
        "/ui/keys\n",
        "/ui/keys\r\nLocation: https://evil.com",
        "/ui/ke ys",
        "/ui/k\u{e9}ys",
        "/ui/keys\u{ff0f}\u{ff0f}evil.com",
        "/ui/a:b",
        "/ui/@evil.com",
        "/ui/login",
        "/ui/login/2fa",
        "/ui/static/app.css",
        "/UI/keys",
        &long,
    ];
    for b in bad {
        assert_eq!(safe_next(b), None, "{b:?}");
    }
    // The length limit is inclusive at 200.
    let max = format!("/ui/{}", "a".repeat(196));
    assert_eq!(max.len(), 200);
    assert!(safe_next(&max).is_some());
    assert_eq!(safe_next(&format!("{max}a")), None);
}

fn h(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        map.append(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    map
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn proxies() -> Vec<Cidr> {
    vec![Cidr::parse("10.0.0.0/8").unwrap()]
}

// ── cookies ──

#[test]
fn cookies_are_host_prefixed_httponly_secure_samesite_strict() {
    for name in [SESSION_COOKIE, PENDING_COOKIE, LOGIN_COOKIE] {
        assert!(name.starts_with("__Host-"));
        let c = set_cookie(name, "abc", None);
        assert!(c.starts_with(&format!("{name}=abc; ")));
        for attr in ["Path=/", "HttpOnly", "Secure", "SameSite=Strict"] {
            assert!(c.contains(attr), "{c}");
        }
        assert!(!c.contains("Domain"));
        assert!(!c.contains("Max-Age"), "session cookie has no Max-Age");
        let timed = set_cookie(name, "abc", Some(180));
        assert!(timed.ends_with("; Max-Age=180"));
        let cleared = clear_cookie(name);
        assert!(cleared.contains("Max-Age=0") && cleared.contains("Secure"));
    }
}

#[test]
fn cookie_values_are_found_and_validated() {
    let headers = h(&[("cookie", "a=1; __Host-fw_session=abc-_DEF123; b=2")]);
    assert_eq!(cookie_value(&headers, SESSION_COOKIE), Some("abc-_DEF123"));
    assert_eq!(cookie_value(&headers, PENDING_COOKIE), None);
    // Odd values count as absent.
    for bad in ["", "a b", "a\"b", &"x".repeat(65), "ä"] {
        let headers = h(&[("cookie", &format!("__Host-fw_session={bad}"))]);
        assert_eq!(cookie_value(&headers, SESSION_COOKIE), None, "{bad:?}");
    }
    // A cookie of another name that merely ends the same way is not it.
    let headers = h(&[("cookie", "x__Host-fw_session=zzz")]);
    assert_eq!(cookie_value(&headers, SESSION_COOKIE), None);
    // Several Cookie headers (HTTP/2) are all searched.
    let headers = h(&[("cookie", "a=1"), ("cookie", "__Host-fw_login=tok")]);
    assert_eq!(cookie_value(&headers, LOGIN_COOKIE), Some("tok"));
}

// ── HTTPS detection ──

#[test]
fn tls_listener_is_secure() {
    assert!(is_secure(true, ip("203.0.113.5"), &HeaderMap::new(), &[]));
}

#[test]
fn plain_http_is_not_secure() {
    assert!(!is_secure(false, ip("127.0.0.1"), &HeaderMap::new(), &[]));
}

#[test]
fn trusted_proxy_with_xfp_https_is_secure() {
    let headers = h(&[("x-forwarded-proto", "https")]);
    assert!(is_secure(false, ip("10.1.2.3"), &headers, &proxies()));
    let headers = h(&[("x-forwarded-proto", "HTTPS")]);
    assert!(is_secure(false, ip("10.1.2.3"), &headers, &proxies()));
    let headers = h(&[("x-forwarded-proto", "http")]);
    assert!(!is_secure(false, ip("10.1.2.3"), &headers, &proxies()));
    // No header, no security.
    assert!(!is_secure(
        false,
        ip("10.1.2.3"),
        &HeaderMap::new(),
        &proxies()
    ));
}

#[test]
fn xfp_from_an_untrusted_peer_is_ignored() {
    let headers = h(&[("x-forwarded-proto", "https")]);
    assert!(!is_secure(false, ip("203.0.113.5"), &headers, &proxies()));
    assert!(!is_secure(false, ip("203.0.113.5"), &headers, &[]));
}

#[test]
fn the_nearest_proxys_xfp_wins() {
    // A client-supplied "https" earlier in the chain must not count.
    let headers = h(&[("x-forwarded-proto", "https, http")]);
    assert!(!is_secure(false, ip("10.0.0.2"), &headers, &proxies()));
    let headers = h(&[
        ("x-forwarded-proto", "http"),
        ("x-forwarded-proto", "https"),
    ]);
    assert!(is_secure(false, ip("10.0.0.2"), &headers, &proxies()));
    let headers = h(&[
        ("x-forwarded-proto", "https"),
        ("x-forwarded-proto", "http"),
    ]);
    assert!(!is_secure(false, ip("10.0.0.2"), &headers, &proxies()));
}

// ── origin ──

fn tr(secure_headers: &[(&str, &str)], peer: &str) -> Transport {
    transport(false, ip(peer), &h(secure_headers), None, &proxies())
}

#[test]
fn origin_is_built_from_scheme_and_host() {
    let t = tr(&[("host", "Admin.Example.test:3001")], "127.0.0.1");
    assert!(!t.secure);
    assert_eq!(t.origin.as_deref(), Some("http://admin.example.test:3001"));
    let t = tr(
        &[
            ("host", "internal:3001"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "vault.example.test"),
        ],
        "10.0.0.2",
    );
    assert!(t.secure);
    assert_eq!(t.origin.as_deref(), Some("https://vault.example.test"));
    // X-Forwarded-Host from an untrusted peer is ignored.
    let t = tr(
        &[("host", "real.test"), ("x-forwarded-host", "evil.test")],
        "203.0.113.5",
    );
    assert_eq!(t.origin.as_deref(), Some("http://real.test"));
    // HTTP/2 has no Host header; the URI authority stands in.
    let t = transport(true, ip("1.1.1.1"), &HeaderMap::new(), Some("h2.test"), &[]);
    assert_eq!(t.origin.as_deref(), Some("https://h2.test"));
    let t = transport(true, ip("1.1.1.1"), &HeaderMap::new(), None, &[]);
    assert_eq!(t.origin, None);
}

fn own() -> Transport {
    Transport {
        secure: true,
        origin: Some("https://admin.example.test".to_string()),
    }
}

#[test]
fn same_origin_post_passes() {
    assert!(origin_ok(&h(&[("sec-fetch-site", "same-origin")]), &own()));
    assert!(origin_ok(
        &h(&[("origin", "https://admin.example.test")]),
        &own()
    ));
    assert!(origin_ok(
        &h(&[("origin", "HTTPS://Admin.Example.Test")]),
        &own()
    ));
}

#[test]
fn cross_site_post_is_rejected() {
    for site in ["cross-site", "same-site", "none", "", "Same-Origin"] {
        assert!(
            !origin_ok(&h(&[("sec-fetch-site", site)]), &own()),
            "{site}"
        );
    }
    for origin in [
        "https://evil.test",
        "http://admin.example.test",
        "https://admin.example.test:8443",
        "https://admin.example.test.evil.test",
        "null",
        "",
    ] {
        assert!(!origin_ok(&h(&[("origin", origin)]), &own()), "{origin}");
    }
}

#[test]
fn sec_fetch_site_decides_when_present() {
    // Present and cross-site: rejected even with a matching Origin.
    let headers = h(&[
        ("sec-fetch-site", "cross-site"),
        ("origin", "https://admin.example.test"),
    ]);
    assert!(!origin_ok(&headers, &own()));
    // Present and same-origin: passes without Origin.
    assert!(origin_ok(&h(&[("sec-fetch-site", "same-origin")]), &own()));
}

#[test]
fn a_post_with_neither_header_is_rejected() {
    assert!(!origin_ok(&HeaderMap::new(), &own()));
    assert!(!origin_ok(
        &h(&[("referer", "https://admin.example.test/")]),
        &own()
    ));
}

#[test]
fn an_origin_header_needs_a_known_own_origin() {
    let no_host = Transport {
        secure: true,
        origin: None,
    };
    assert!(!origin_ok(&h(&[("origin", "https://x.test")]), &no_host));
}

// ── strict form parsing ──

const ALLOWED: &[&str] = &["csrf", "password", "code"];

fn parse(body: &str) -> Result<Form, FormError> {
    parse_form(body.as_bytes(), ALLOWED)
}

#[test]
fn parses_and_decodes_fields() {
    let mut f = parse("csrf=abc&password=p%40ss+w%C3%B6rd%25%2B%26%3D").unwrap();
    assert_eq!(f.take("csrf").unwrap().as_str(), "abc");
    assert_eq!(f.take("password").unwrap().as_str(), "p@ss wörd%+&=");
    assert!(f.take("password").is_none());
    assert!(f.take("code").is_none());
}

#[test]
fn empty_values_and_empty_body_are_fine() {
    let mut f = parse("csrf=&password=").unwrap();
    assert_eq!(f.take("password").unwrap().as_str(), "");
    assert!(parse("").is_ok());
}

#[test]
fn unknown_fields_are_rejected() {
    assert_eq!(parse("csrf=a&admin=1").err(), Some(FormError::Unknown));
    assert_eq!(parse("Password=a").err(), Some(FormError::Unknown));
    assert_eq!(parse("pass%77ord=a").err(), None, "decoded name is checked");
    assert_eq!(parse("=a").err(), Some(FormError::Unknown));
}

#[test]
fn duplicate_fields_are_rejected() {
    assert_eq!(parse("csrf=a&csrf=b").err(), Some(FormError::Duplicate));
    // Also when the names differ only in encoding.
    assert_eq!(parse("csrf=a&c%73rf=b").err(), Some(FormError::Duplicate));
}

#[test]
fn malformed_bodies_are_rejected() {
    for body in [
        "csrf",
        "csrf=a&",
        "&csrf=a",
        "csrf=a&&password=b",
        "csrf=%zz",
        "csrf=%4",
        "csrf=%",
        "csrf=%ff",    // not UTF-8
        "csrf=%c3%28", // invalid UTF-8
    ] {
        assert_eq!(parse(body).err(), Some(FormError::Malformed), "{body}");
    }
}

#[test]
fn oversized_bodies_are_rejected() {
    let big = format!("password={}", "a".repeat(MAX_FORM_BYTES));
    assert_eq!(parse(&big).err(), Some(FormError::TooLarge));
    let ok = format!("password={}", "a".repeat(MAX_FORM_BYTES - 9));
    assert!(parse(&ok).is_ok());
}

#[tokio::test]
async fn body_reader_enforces_the_limit() {
    let body = Body::from("password=abc");
    assert_eq!(&read_body(body, 100).await.unwrap()[..], b"password=abc");
    let body = Body::from("x".repeat(101));
    assert_eq!(read_body(body, 100).await.err(), Some(FormError::TooLarge));
    let body = Body::from("x".repeat(100));
    assert!(read_body(body, 100).await.is_ok());
}

#[test]
fn content_type_must_be_a_urlencoded_form() {
    assert!(is_form_content_type(&h(&[(
        "content-type",
        "application/x-www-form-urlencoded"
    )])));
    assert!(is_form_content_type(&h(&[(
        "content-type",
        "application/x-www-form-urlencoded; charset=UTF-8"
    )])));
    for bad in [
        "application/json",
        "multipart/form-data; boundary=x",
        "text/plain",
    ] {
        assert!(!is_form_content_type(&h(&[("content-type", bad)])));
    }
    assert!(!is_form_content_type(&HeaderMap::new()));
}

// ── headers ──

#[test]
fn security_headers_are_all_set() {
    let mut headers = HeaderMap::new();
    apply_security_headers(&mut headers, false);
    assert_eq!(
        headers["content-security-policy"],
        "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; \
form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    );
    assert!(headers["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("font-src 'self';"));
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["referrer-policy"], "no-referrer");
    assert_eq!(headers["x-frame-options"], "DENY");
    assert_eq!(headers["cache-control"], "no-store");
    assert!(headers["permissions-policy"]
        .to_str()
        .unwrap()
        .contains("interest-cohort=()"));
    assert_eq!(headers["cross-origin-opener-policy"], "same-origin");
    assert_eq!(headers["cross-origin-resource-policy"], "same-origin");
    assert!(!headers.contains_key("strict-transport-security"));
    // No scripts.
    assert!(!headers["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("script-src"));

    let mut secure = HeaderMap::new();
    apply_security_headers(&mut secure, true);
    assert_eq!(secure["strict-transport-security"], "max-age=31536000");
}

#[test]
fn a_handlers_own_cache_control_is_kept() {
    let mut headers = h(&[("cache-control", "public, max-age=86400")]);
    apply_security_headers(&mut headers, true);
    assert_eq!(headers["cache-control"], "public, max-age=86400");
}
