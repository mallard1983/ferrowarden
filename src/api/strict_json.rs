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

/// Parse a request body that was read without the extractor (a route whose
/// body depends on something else, such as the kind of the approval it
/// decides): the same checks as [`StrictJson`].
pub fn parse_body<T: DeserializeOwned>(headers: &HeaderMap, bytes: &[u8]) -> Result<T, FerroError> {
    if !is_json_content_type(headers) {
        return Err(FerroError::InvalidJson(
            "Content-Type must be application/json".to_string(),
        ));
    }
    parse_strict(bytes).map_err(FerroError::InvalidJson)
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
            const SAFE: [&str; 6] = [
                "duplicate key ",
                "nesting deeper than ",
                "unknown field `",
                "missing field `",
                "duplicate field `",
                "policy field `",
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
mod tests;
