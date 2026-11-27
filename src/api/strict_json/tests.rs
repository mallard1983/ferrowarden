use super::*;
use crate::api::forward::ForwardPayload;
use serde::Deserialize;
use serde_json::Value;

fn ok(s: &str) {
    check_json(s.as_bytes()).unwrap_or_else(|e| panic!("{s} rejected: {e}"));
}
fn err(s: &str) -> String {
    check_json(s.as_bytes()).expect_err(s).to_string()
}

#[test]
fn accepts_valid_documents() {
    ok(r#"{"a":1,"b":[1,2,{"c":null}],"d":"x","e":true,"f":1.5,"g":-3}"#);
    ok(r#"[]"#);
    ok(r#""just a string""#);
    ok(r#"  {"a":{}}  "#);
    // Duplicate *values* and the same key in different objects are fine.
    ok(r#"{"a":"x","b":"x","c":{"a":"x"},"d":[{"a":1},{"a":1}]}"#);
}

#[test]
fn rejects_duplicate_top_level_key() {
    let e = err(r#"{"a":1,"b":2,"a":3}"#);
    assert!(e.contains(r#"duplicate key "a""#), "{e}");
}

#[test]
fn rejects_duplicate_nested_key() {
    assert!(err(r#"{"x":{"y":{"k":1,"k":2}}}"#).contains("duplicate key"));
}

#[test]
fn rejects_duplicate_key_in_array_of_objects() {
    assert!(err(r#"{"x":[{"a":1},{"k":1,"k":2}]}"#).contains("duplicate key"));
    assert!(err(r#"[[{"k":1,"k":2}]]"#).contains("duplicate key"));
}

#[test]
fn rejects_duplicate_via_unicode_escape() {
    assert!(err(r#"{"a":1,"a":2}"#).contains(r#"duplicate key "a""#));
    assert!(err(r#"{"ab":1,"ab":2}"#).contains("duplicate key"));
}

#[test]
fn keys_are_compared_exactly() {
    ok(r#"{"a":1,"A":2,"a ":3}"#);
}

#[test]
fn depth_limit() {
    let nest = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    ok(&nest(MAX_DEPTH));
    let e = err(&nest(MAX_DEPTH + 1));
    assert!(e.contains("nesting deeper than 64"), "{e}");
    let objs = |n: usize| format!("{}1{}", r#"{"a":"#.repeat(n), "}".repeat(n));
    ok(&objs(MAX_DEPTH));
    assert!(err(&objs(MAX_DEPTH + 1)).contains("nesting deeper"));
}

#[test]
fn rejects_trailing_data() {
    assert!(err(r#"{"a":1} {"a":2}"#).contains("trailing"));
    assert!(err(r#"{"a":1}x"#).contains("trailing"));
    assert!(check_json(b"{\"a\":1}  \n").is_ok());
}

#[test]
fn rejects_lone_surrogate_escapes() {
    assert!(check_json(br#"{"a":"\ud800"}"#).is_err());
    assert!(check_json(br#"{"\udc00":1}"#).is_err());
    assert!(check_json(br#"{"a":"\ud800x"}"#).is_err());
    // A valid pair is fine.
    ok(r#"{"a":"😀"}"#);
}

#[test]
fn rejects_invalid_utf8() {
    assert!(check_json(b"{\"a\":\"\xff\"}").is_err());
    assert!(check_json(b"{\"\xc3\x28\":1}").is_err());
    assert!(parse_strict::<Value>(b"{\"a\":\"\xff\"}").is_err());
}

#[test]
fn rejects_syntax_errors() {
    assert!(check_json(b"").is_err());
    assert!(check_json(b"{").is_err());
    assert!(check_json(br#"{"a":}"#).is_err());
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pw {
    #[allow(dead_code)]
    password: String,
}

#[test]
fn errors_never_echo_values() {
    const SECRET: &str = "SECRETVAL";
    let docs = [
        // type error with a secret in an unrelated sibling
        r#"{"request": {"method": "GET", "url": 5, "body": {"pw":"SECRETVAL"}}}"#,
        // wrong-typed string where a map is expected
        r#"{"request": "SECRETVAL"}"#,
        // wrong-typed secret in the password field
        r#"{"password": ["SECRETVAL"]}"#,
        r#"{"password": 12345}"#,
        r#"{"password": {"SECRETVAL": "SECRETVAL"}}"#,
        // unknown field alongside a secret value
        r#"{"password": "SECRETVAL", "extra": "SECRETVAL"}"#,
        // duplicate key with secret values
        r#"{"password": "SECRETVAL", "password": "SECRETVAL"}"#,
        // syntax errors right after a secret
        r#"{"password": "SECRETVAL" "x": 1}"#,
        r#"{"password": "SECRETVAL"} SECRETVAL"#,
        r#"{"password": "SECRETVAL\ud800"}"#,
        r#"{"password": SECRETVAL}"#,
    ];
    for doc in docs {
        for m in [
            parse_strict::<Pw>(doc.as_bytes()).err(),
            parse_strict::<ForwardPayload>(doc.as_bytes()).err(),
        ]
        .into_iter()
        .flatten()
        {
            assert!(!m.contains(SECRET), "{doc} leaked into: {m}");
        }
    }
    let m = parse_strict::<ForwardPayload>(
        br#"{"request": {"method": "GET", "url": 5, "body": {"pw":"SECRETVAL"}}}"#,
    )
    .err()
    .unwrap();
    assert!(!m.contains(SECRET), "{m}");
    assert!(m.contains("wrong type"), "{m}");
    assert!(m.contains("line 1"), "{m}");

    // The unlock payload specifically.
    let m = parse_strict::<crate::api::unlock::UnlockPayload>(br#"{"password": ["SECRETVAL"]}"#)
        .err()
        .unwrap();
    assert!(!m.contains(SECRET), "{m}");
}

#[test]
fn helpful_messages_for_fields() {
    let m = parse_strict::<Pw>(br#"{"password":"x","extra":1}"#)
        .err()
        .unwrap();
    assert!(m.contains("unknown field `extra`"), "{m}");
    let m = parse_strict::<Pw>(br#"{}"#).err().unwrap();
    assert!(m.contains("missing field `password`"), "{m}");
    let m = parse_strict::<Pw>(br#"{"password":"x","password":"y"}"#)
        .err()
        .unwrap();
    assert!(m.contains(r#"duplicate key "password""#), "{m}");
    let m = parse_strict::<Pw>(b"{\n  \"password\": }").err().unwrap();
    assert!(m.contains("malformed JSON") && m.contains("line 2"), "{m}");
}

#[test]
fn long_keys_and_messages_are_truncated() {
    let key = "k".repeat(500);
    let m = parse_strict::<Pw>(format!(r#"{{"{key}":1,"{key}":2}}"#).as_bytes())
        .err()
        .unwrap();
    assert!(m.len() < 300, "{}", m.len());
}

#[test]
fn content_type_matching() {
    let h = |v: &str| {
        let mut m = HeaderMap::new();
        m.insert(header::CONTENT_TYPE, v.parse().unwrap());
        m
    };
    assert!(is_json_content_type(&h("application/json")));
    assert!(is_json_content_type(&h("Application/JSON; charset=utf-8")));
    assert!(is_json_content_type(&h("application/vnd.api+json")));
    assert!(!is_json_content_type(&h("text/plain")));
    assert!(!is_json_content_type(&h("application/jsonx")));
    assert!(!is_json_content_type(&HeaderMap::new()));
}

#[tokio::test]
async fn extractor_end_to_end() {
    use axum::body::Body;
    use axum::extract::DefaultBodyLimit;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::Router;
    use tower::ServiceExt;

    async fn h(StrictJson(_p): StrictJson<Pw>) -> &'static str {
        "ok"
    }
    let app = Router::new()
        .route("/", post(h))
        .layer(DefaultBodyLimit::max(64));
    let send = |ct: Option<&str>, body: String| {
        let app = app.clone();
        let mut r = Request::post("/");
        if let Some(ct) = ct {
            r = r.header(header::CONTENT_TYPE, ct);
        }
        async move {
            app.oneshot(r.body(Body::from(body)).unwrap())
                .await
                .unwrap()
                .status()
        }
    };
    let json = Some("application/json");
    let good = r#"{"password":"x"}"#;
    assert_eq!(send(json, good.into()).await, StatusCode::OK);
    assert_eq!(
        send(json, r#"{"password":"x","password":"y"}"#.into()).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(send(None, good.into()).await, StatusCode::BAD_REQUEST);
    assert_eq!(
        send(Some("text/plain"), good.into()).await,
        StatusCode::BAD_REQUEST
    );
    // The body limit still applies.
    let big = format!(r#"{{"password":"{}"}}"#, "x".repeat(200));
    assert_eq!(send(json, big).await, StatusCode::BAD_REQUEST);
}

#[test]
fn request_structs_reject_unknown_fields() {
    use crate::api::admin::CreateKeyRequest;
    use crate::api::unlock::UnlockPayload;

    let m = parse_strict::<ForwardPayload>(
        br#"{"request":{"method":"GET","url":"http://x"},"extra":1}"#,
    )
    .err()
    .unwrap();
    assert!(m.contains("unknown field `extra`"), "{m}");
    assert!(
        parse_strict::<ForwardPayload>(br#"{"request":{"method":"GET","url":"http://x"}}"#).is_ok()
    );
    let m = parse_strict::<CreateKeyRequest>(br#"{"name":"a","role":"admin"}"#)
        .err()
        .unwrap();
    assert!(m.contains("unknown field `role`"), "{m}");
    assert!(parse_strict::<CreateKeyRequest>(
        br#"{"name":"a","credentials":["*"],"methods":["*"]}"#
    )
    .is_ok());
    // The policy is mandatory.
    let m = parse_strict::<CreateKeyRequest>(br#"{"name":"a"}"#)
        .err()
        .unwrap();
    assert!(m.contains("missing field `credentials`"), "{m}");
    let m = parse_strict::<UnlockPayload>(br#"{"password":"p","remember":true}"#)
        .err()
        .unwrap();
    assert!(m.contains("unknown field `remember`"), "{m}");
    assert!(parse_strict::<UnlockPayload>(br#"{"password":"p"}"#).is_ok());
}

#[test]
fn a_request_body_must_be_a_json_object() {
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct One {
        #[allow(dead_code)]
        n: u32,
    }
    assert!(parse_request::<One>(br#" {"n":1} "#).is_ok());
    // serde reads a struct from an array; a request body may not be one.
    assert!(parse_strict::<One>(br#"[1]"#).is_ok());
    for bad in [&br#"[1]"#[..], br#"1"#, br#""n""#, br#"null"#, br#"true"#] {
        let m = parse_request::<One>(bad).unwrap_err();
        assert!(
            m.contains("JSON object") || m.contains("malformed") || m.contains("wrong type"),
            "{m}"
        );
    }
}

#[tokio::test]
async fn an_optional_body_may_be_left_out_and_is_otherwise_strict() {
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::Router;
    use tower::ServiceExt;

    async fn none(OptionalStrictJson(_b): OptionalStrictJson<NoBody>) -> &'static str {
        "ok"
    }
    let app = Router::new().route("/", post(none));
    let send = |ct: Option<&str>, body: &'static str| {
        let app = app.clone();
        let mut r = Request::post("/");
        if let Some(ct) = ct {
            r = r.header(header::CONTENT_TYPE, ct);
        }
        async move {
            app.oneshot(r.body(Body::from(body)).unwrap())
                .await
                .unwrap()
                .status()
        }
    };
    let json = Some("application/json");
    // Left out: no body, or only whitespace, with or without a Content-Type.
    assert_eq!(send(None, "").await, StatusCode::OK);
    assert_eq!(send(None, " \n").await, StatusCode::OK);
    assert_eq!(send(json, "").await, StatusCode::OK);
    // Present: the strict rules, Content-Type included.
    assert_eq!(send(json, "{}").await, StatusCode::OK);
    assert_eq!(send(None, "{}").await, StatusCode::BAD_REQUEST);
    assert_eq!(
        send(Some("text/plain"), "{}").await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(json, r#"{"minutes":5}"#).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(send(json, "[]").await, StatusCode::BAD_REQUEST);
    assert_eq!(send(json, "null").await, StatusCode::BAD_REQUEST);
    assert_eq!(
        send(json, r#"{"a":1,"a":2}"#).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(send(json, "{").await, StatusCode::BAD_REQUEST);
}
