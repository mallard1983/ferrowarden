//! Strict JSON request bodies.
//!
//! axum's `Json<T>` accepts documents that different parsers read differently:
//! duplicate object keys silently resolve last-wins inside maps and
//! `serde_json::Value`, and unknown fields are ignored. Per-key policies need an
//! unambiguous request, so [`StrictJson`] rejects:
//!
//! * duplicate object keys at any depth (compared after JSON unescaping),
//! * nesting deeper than [`MAX_DEPTH`],
//! * trailing data, invalid UTF-8 and lone surrogate escapes,
//! * unknown fields (structs opt in with `#[serde(deny_unknown_fields)]`).
//!
//! The first pass is a validating visitor that never copies or keeps string
//! *values* (they may be secrets); only object keys are held, per object. The
//! second pass is a normal `serde_json::from_slice` over the same bytes, so
//! both passes use the same parser. Error messages never include values from
//! the body; see [`describe`].

use axum::{
    body::Bytes,
    extract::{FromRequest, Request},
    http::{header, HeaderMap},
};
use serde::de::{DeserializeOwned, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use std::collections::HashSet;
use std::fmt;

use crate::error::FerroError;

/// Maximum nesting depth of arrays and objects (the top-level value is depth 1).
pub const MAX_DEPTH: usize = 64;

/// Longest error message returned to the client, in characters.
const MAX_MESSAGE_CHARS: usize = 200;

/// Drop-in replacement for `axum::Json<T>` as a request extractor.
pub struct StrictJson<T>(pub T);

impl<S, T> FromRequest<S> for StrictJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = FerroError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        if !is_json_content_type(req.headers()) {
            return Err(FerroError::InvalidJson(
                "Content-Type must be application/json".to_string(),
            ));
        }
        // `Bytes` enforces the body limit (axum's DefaultBodyLimit, 2 MiB unless
        // a layer overrides it), exactly as `Json<T>` does.
        let bytes = Bytes::from_request(req, state).await.map_err(|_| {
            FerroError::InvalidJson(
                "request body could not be read (too large or interrupted)".to_string(),
            )
        })?;
        parse_strict(&bytes)
            .map(StrictJson)
            .map_err(FerroError::InvalidJson)
    }
}

/// Same rule as axum's `Json`: `application/json` or `application/*+json`,
/// ignoring parameters and case.
fn is_json_content_type(headers: &HeaderMap) -> bool {
    let Some(value) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let essence = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match essence.strip_prefix("application/") {
        Some(sub) => sub == "json" || (sub.ends_with("+json") && sub.len() > "+json".len()),
        None => false,
    }
}

/// Validate `bytes` as strict JSON, then deserialize them as `T`.
/// The error is safe to return to the client: it never contains body values.
pub fn parse_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    check_json(bytes).map_err(|e| describe(&e))?;
    serde_json::from_slice(bytes).map_err(|e| describe(&e))
}

/// First pass: reject duplicate keys, excessive nesting and trailing data.
pub fn check_json(bytes: &[u8]) -> Result<(), serde_json::Error> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    Doc { depth: 1 }.deserialize(&mut de)?;
    de.end()
}

/// Turn a serde_json error into a client-safe message. serde_json's own
/// messages for type and value errors echo the offending value
/// (`invalid type: string "..."`), so only syntax errors and a short allowlist
/// of messages that mention field names (never values) are passed through.
fn describe(e: &serde_json::Error) -> String {
    use serde_json::error::Category;

    let full = e.to_string();
    // serde_json appends " at line L column C" last, so split on the last one.
    let msg = full
        .rsplit_once(" at line ")
        .map_or(full.as_str(), |(m, _)| m);
    let at = format!("line {}, column {}", e.line(), e.column());
    let text = match e.classify() {
        Category::Io => return "request body could not be read".to_string(),
        Category::Syntax | Category::Eof => format!("malformed JSON: {msg} ({at})"),
        Category::Data => {
            const SAFE: [&str; 5] = [
                "duplicate key ",
                "nesting deeper than ",
                "unknown field `",
                "missing field `",
                "duplicate field `",
            ];
            if SAFE.iter().any(|p| msg.starts_with(p)) {
                format!("{msg} ({at})")
            } else {
                format!("a value has the wrong type or is not valid for its field ({at})")
            }
        }
    };
    truncate(&text)
}

fn truncate(s: &str) -> String {
    if s.chars().count() <= MAX_MESSAGE_CHARS {
        return s.to_string();
    }
    let mut t: String = s.chars().take(MAX_MESSAGE_CHARS).collect();
    t.push_str("...");
    t
}

/// Walks one JSON value. Scalars are discarded without being copied.
struct Doc {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Doc {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Doc {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        self.check_depth()?;
        while seq
            .next_element_seed(Doc {
                depth: self.depth + 1,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        self.check_depth()?;
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if seen.contains(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate key {}",
                    quote_key(&key)
                )));
            }
            seen.insert(key);
            map.next_value_seed(Doc {
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }
}

impl Doc {
    fn check_depth<E: serde::de::Error>(&self) -> Result<(), E> {
        if self.depth > MAX_DEPTH {
            return Err(E::custom(format!("nesting deeper than {MAX_DEPTH} levels")));
        }
        Ok(())
    }
}

/// A key for an error message: escaped and shortened.
fn quote_key(key: &str) -> String {
    const MAX_KEY_CHARS: usize = 64;
    if key.chars().count() <= MAX_KEY_CHARS {
        format!("{key:?}")
    } else {
        let short: String = key.chars().take(MAX_KEY_CHARS).collect();
        format!("{short:?}...")
    }
}

#[cfg(test)]
mod tests {
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
        let m =
            parse_strict::<crate::api::unlock::UnlockPayload>(br#"{"password": ["SECRETVAL"]}"#)
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
        assert!(parse_strict::<ForwardPayload>(
            br#"{"request":{"method":"GET","url":"http://x"}}"#
        )
        .is_ok());
        let m = parse_strict::<CreateKeyRequest>(br#"{"name":"a","role":"admin"}"#)
            .err()
            .unwrap();
        assert!(m.contains("unknown field `role`"), "{m}");
        assert!(parse_strict::<CreateKeyRequest>(br#"{"name":"a"}"#).is_ok());
        let m = parse_strict::<UnlockPayload>(br#"{"password":"p","remember":true}"#)
            .err()
            .unwrap();
        assert!(m.contains("unknown field `remember`"), "{m}");
        assert!(parse_strict::<UnlockPayload>(br#"{"password":"p"}"#).is_ok());
    }
}
