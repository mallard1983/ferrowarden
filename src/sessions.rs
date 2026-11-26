//! Captured sessions: login tokens kept inside Ferrowarden (docs/sessions.md).
//!
//! Many APIs log in with a username and password and answer with a token (a
//! JWT, a cookie, a ticket) that every later call carries. The login works
//! through Ferrowarden, but the token it returns would reach the agent. A
//! request can therefore ask for a value to be **captured**: Ferrowarden reads
//! it from the target's raw answer, keeps it in memory, and shows the agent
//! `[CAPTURED:name]` instead. Later requests write `{{session:name}}`.
//!
//! What this module holds:
//!
//! * the request side: [`CaptureSpec`] (the strict `capture` member of
//!   `POST /v1/forward`) and its validation ([`parse_captures`]);
//! * extraction from a response ([`capture`]): a JSON pointer, a header or a
//!   `Set-Cookie` cookie, with an expiry that can only be shortened by the
//!   token's own `exp`, `Max-Age` or `Expires`;
//! * the store ([`SessionStore`]): in memory, never persisted, never logged,
//!   keyed by (agent key id, session name), each value bound to the origin it
//!   was captured from;
//! * the lifecycle: the periodic sweep and the places that clear sessions
//!   (key revoke, policy change, vault lock).
//!
//! A value found at a capture source is removed from the response the agent
//! sees whether or not it could be stored: the caller scrubs every encoding of
//! it (see [`CaptureOutcome::unstored`]).
//!
//! Naming: the admin UI has its own "sessions" (`ui::session`). Everything
//! here is a *captured session*.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use reqwest::header::{HeaderName, SET_COOKIE};
use reqwest::Url;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use zeroize::Zeroizing;

use crate::config::SessionsConfig;
use crate::error::{FerroError, FerroResult};
use crate::events::{Action, Outcome, Reason, SecurityEvent};
use crate::proxy::placeholder::is_session_name;
use crate::proxy::scrub::MIN_SCRUB_LEN;
use crate::proxy::substitute::{zeroize_json, SessionValues};
use crate::proxy::UpstreamResponse;
use crate::state::AppState;

/// Most `capture` entries in one request.
pub const MAX_CAPTURES: usize = 8;
/// The longest value that is stored, in bytes.
pub const MAX_VALUE_BYTES: usize = 16 * 1024;
/// How often expired sessions are removed.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

// ── The request: `capture` ────────────────────────────────────────────────────

/// Deserialize a field that may be left out but not be `null`: used with
/// `#[serde(default)]`, so an absent field is `None` and `null` is an error.
pub fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// One entry of the `capture` member of `POST /v1/forward`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSpec {
    /// Where the value is: `json:/pointer`, `header:Name` or `cookie:name`.
    pub from: String,
    /// The session name `{{session:NAME}}` will use.
    #[serde(rename = "as")]
    pub name: String,
    /// Lifetime in seconds, 1 to `sessions.max_ttl_secs`. Default
    /// `sessions.default_ttl_secs`.
    #[serde(default, deserialize_with = "present")]
    pub ttl_secs: Option<u64>,
}

/// Where a captured value is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// An RFC 6901 pointer into the JSON response body.
    Json(String),
    /// A response header (lower-case name).
    Header(String),
    /// A cookie of the response's `Set-Cookie` headers.
    Cookie(String),
}

/// A validated `capture` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture {
    pub name: String,
    pub source: Source,
    pub ttl: Duration,
}

fn invalid(index: usize, what: &str) -> FerroError {
    FerroError::InvalidRequest(format!("capture[{index}]: {what}"))
}

/// Is `s` a valid RFC 6901 JSON pointer that points below the root?
fn valid_pointer(s: &str) -> Result<(), &'static str> {
    if !s.starts_with('/') {
        return Err("a JSON pointer starts with '/' (for example json:/jwt)");
    }
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '~' && !matches!(chars.peek(), Some('0' | '1')) {
            return Err("in a JSON pointer, '~' must be followed by 0 or 1");
        }
    }
    Ok(())
}

/// A cookie name is an RFC 6265 token.
fn valid_cookie_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '.'
                        | '^'
                        | '_'
                        | '`'
                        | '|'
                        | '~'
                )
        })
}

fn parse_source(index: usize, from: &str) -> FerroResult<Source> {
    if from.contains("{{") {
        return Err(invalid(index, "`from` may not contain a placeholder"));
    }
    if let Some(pointer) = from.strip_prefix("json:") {
        valid_pointer(pointer).map_err(|m| invalid(index, m))?;
        return Ok(Source::Json(pointer.to_string()));
    }
    if let Some(name) = from.strip_prefix("header:") {
        let parsed = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid(index, "`header:` needs a valid header name"))?;
        return Ok(Source::Header(parsed.as_str().to_string()));
    }
    if let Some(name) = from.strip_prefix("cookie:") {
        if !valid_cookie_name(name) {
            return Err(invalid(index, "`cookie:` needs a valid cookie name"));
        }
        return Ok(Source::Cookie(name.to_string()));
    }
    Err(invalid(
        index,
        "`from` must start with `json:`, `header:` or `cookie:`",
    ))
}

/// Validate the `capture` member of a forward request, before anything is
/// sent. `None` (member absent) is no captures; an empty list, more than
/// [`MAX_CAPTURES`] entries, a bad name, source or TTL, or a duplicate `as` is
/// a 400. With `sessions.enabled = false` any `capture` is refused.
pub fn parse_captures(
    specs: Option<&[CaptureSpec]>,
    cfg: &SessionsConfig,
) -> FerroResult<Vec<Capture>> {
    let Some(specs) = specs else {
        return Ok(Vec::new());
    };
    if !cfg.enabled {
        return Err(FerroError::SessionsDisabled);
    }
    if specs.is_empty() || specs.len() > MAX_CAPTURES {
        return Err(FerroError::InvalidRequest(format!(
            "capture must list 1 to {MAX_CAPTURES} entries"
        )));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(specs.len());
    for (i, spec) in specs.iter().enumerate() {
        if spec.name.contains("{{") || spec.from.contains("{{") {
            return Err(invalid(i, "`as` and `from` may not contain a placeholder"));
        }
        if !is_session_name(&spec.name) {
            return Err(invalid(
                i,
                "`as` must be 1 to 64 characters: letters, digits, '_', '-' or '.'",
            ));
        }
        if !seen.insert(spec.name.as_str()) {
            return Err(invalid(i, "`as` is used more than once in this request"));
        }
        let source = parse_source(i, &spec.from)?;
        let ttl_secs = spec.ttl_secs.unwrap_or(cfg.default_ttl_secs);
        if ttl_secs == 0 || ttl_secs > cfg.max_ttl_secs {
            return Err(invalid(
                i,
                &format!("`ttl_secs` must be between 1 and {}", cfg.max_ttl_secs),
            ));
        }
        out.push(Capture {
            name: spec.name.clone(),
            source,
            ttl: Duration::from_secs(ttl_secs),
        });
    }
    Ok(out)
}

/// Refuse `{{session:...}}` placeholders when sessions are switched off.
pub fn check_enabled(cfg: &SessionsConfig, used: &BTreeSet<String>) -> FerroResult<()> {
    if !cfg.enabled && !used.is_empty() {
        return Err(FerroError::SessionsDisabled);
    }
    Ok(())
}

// ── The answer: `captures` ────────────────────────────────────────────────────

/// What became of one capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStatus {
    Captured,
    NotFound,
    NotAString,
    Ambiguous,
    TooShort,
    TooLong,
    Expired,
    LimitReached,
}

impl CaptureStatus {
    /// Every status, for the metrics series and the tests.
    pub const ALL: [CaptureStatus; 8] = [
        CaptureStatus::Captured,
        CaptureStatus::NotFound,
        CaptureStatus::NotAString,
        CaptureStatus::Ambiguous,
        CaptureStatus::TooShort,
        CaptureStatus::TooLong,
        CaptureStatus::Expired,
        CaptureStatus::LimitReached,
    ];

    /// The wire name, the same text serde writes.
    pub fn as_str(self) -> &'static str {
        match self {
            CaptureStatus::Captured => "captured",
            CaptureStatus::NotFound => "not_found",
            CaptureStatus::NotAString => "not_a_string",
            CaptureStatus::Ambiguous => "ambiguous",
            CaptureStatus::TooShort => "too_short",
            CaptureStatus::TooLong => "too_long",
            CaptureStatus::Expired => "expired",
            CaptureStatus::LimitReached => "limit_reached",
        }
    }
}

/// One entry of the `captures` member of the forward response. Never holds a
/// value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureResult {
    #[serde(rename = "as")]
    pub name: String,
    pub status: CaptureStatus,
    /// RFC 3339, only when `status` is `captured`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

// ── Extraction ────────────────────────────────────────────────────────────────

/// A value read from a response, with the earliest expiry the response itself
/// implies (the token's `exp` or the cookie's lifetime).
struct Found {
    value: Zeroizing<String>,
    expires: Option<DateTime<Utc>>,
}

fn earliest(a: Option<DateTime<Utc>>, b: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The `exp` of a value that looks like a JWT: three base64url segments whose
/// middle one decodes to a JSON object with a numeric `exp`. The signature is
/// not checked: the value is only ever used to make a lifetime shorter.
fn jwt_expiry(value: &str) -> Option<DateTime<Utc>> {
    let mut parts = value.split('.');
    let (_, payload, _) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    let exp = claims.as_object()?.get("exp")?;
    let secs = exp.as_i64().or_else(|| {
        exp.as_f64()
            .filter(|f| f.is_finite())
            .map(|f| f.floor() as i64)
    })?;
    DateTime::from_timestamp(secs, 0)
}

/// The response body as a JSON value, or why it cannot be read.
fn parse_body(body: &[u8]) -> Result<Value, CaptureStatus> {
    let text = std::str::from_utf8(body).map_err(|_| CaptureStatus::NotAString)?;
    // A body that repeats a key is ambiguous: which one is "the" token? The
    // same check the agent's own requests get.
    if let Err(e) = crate::api::strict_json::check_json(text.as_bytes()) {
        return Err(if e.to_string().starts_with("duplicate key") {
            CaptureStatus::Ambiguous
        } else {
            CaptureStatus::NotAString
        });
    }
    serde_json::from_str(text).map_err(|_| CaptureStatus::NotAString)
}

fn from_json(pointer: &str, up: &UpstreamResponse) -> Result<Found, CaptureStatus> {
    let mut doc = parse_body(&up.body)?;
    let found = match doc.pointer(pointer) {
        None => Err(CaptureStatus::NotFound),
        Some(Value::String(s)) => Ok(Zeroizing::new(s.clone())),
        Some(_) => Err(CaptureStatus::NotAString),
    };
    zeroize_json(&mut doc);
    found.map(|value| Found {
        value,
        expires: None,
    })
}

fn from_header(name: &str, up: &UpstreamResponse) -> Result<Found, CaptureStatus> {
    let mut all = up.headers.get_all(name).iter();
    let Some(first) = all.next() else {
        return Err(CaptureStatus::NotFound);
    };
    if all.next().is_some() {
        return Err(CaptureStatus::Ambiguous);
    }
    let value = first.to_str().map_err(|_| CaptureStatus::NotAString)?;
    Ok(Found {
        value: Zeroizing::new(value.to_string()),
        expires: None,
    })
}

/// Parse an `Expires` attribute: the RFC 2822 form, and the older
/// `Wed, 21-Oct-2026 07:28:00 GMT` form some servers still send.
fn parse_cookie_date(text: &str) -> Option<DateTime<Utc>> {
    let text = text.trim();
    if let Ok(t) = DateTime::parse_from_rfc2822(text) {
        return Some(t.with_timezone(&Utc));
    }
    chrono::NaiveDateTime::parse_from_str(text, "%a, %d-%b-%Y %H:%M:%S GMT")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(text, "%a, %d-%b-%y %H:%M:%S GMT"))
        .ok()
        .map(|t| t.and_utc())
}

/// One `Set-Cookie` header: the cookie's name, value and the expiry its
/// attributes give (`Max-Age` wins over `Expires`; unreadable ones are
/// ignored, so they can only ever shorten a lifetime, never lengthen it).
fn parse_set_cookie(
    header: &str,
    now: DateTime<Utc>,
) -> Option<(&str, &str, Option<DateTime<Utc>>)> {
    let mut parts = header.split(';');
    let (name, value) = parts.next()?.split_once('=')?;
    let (mut max_age, mut expires) = (None, None);
    for attr in parts {
        let (key, val) = match attr.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        if key.eq_ignore_ascii_case("max-age") {
            max_age = val
                .parse::<i64>()
                .ok()
                .and_then(ChronoDuration::try_seconds)
                .and_then(|d| now.checked_add_signed(d));
        } else if key.eq_ignore_ascii_case("expires") {
            expires = parse_cookie_date(val);
        }
    }
    Some((name.trim(), value.trim(), max_age.or(expires)))
}

fn from_cookie(
    name: &str,
    up: &UpstreamResponse,
    now: DateTime<Utc>,
) -> Result<Found, CaptureStatus> {
    let mut found: Option<Found> = None;
    for header in up.headers.get_all(SET_COOKIE) {
        let Ok(text) = header.to_str() else { continue };
        let Some((cookie, value, expires)) = parse_set_cookie(text, now) else {
            continue;
        };
        if cookie != name {
            continue;
        }
        if found.is_some() {
            return Err(CaptureStatus::Ambiguous);
        }
        found = Some(Found {
            value: Zeroizing::new(value.to_string()),
            expires,
        });
    }
    found.ok_or(CaptureStatus::NotFound)
}

fn extract(
    source: &Source,
    up: &UpstreamResponse,
    now: DateTime<Utc>,
) -> Result<Found, CaptureStatus> {
    let mut found = match source {
        Source::Json(pointer) => from_json(pointer, up),
        Source::Header(name) => from_header(name, up),
        Source::Cookie(name) => from_cookie(name, up, now),
    }?;
    found.expires = earliest(found.expires, jwt_expiry(&found.value));
    Ok(found)
}

/// The result of one capture: what to tell the agent, and a value that was
/// found but not stored.
pub struct CaptureOutcome {
    pub result: CaptureResult,
    /// Set when a string was found at the source but not stored (too long,
    /// already expired, or the key's limit was reached). The caller removes it
    /// from the response like a stored one, with `[REDACTED]`.
    pub unstored: Option<Zeroizing<String>>,
}

impl CaptureOutcome {
    fn failed(name: &str, status: CaptureStatus) -> Self {
        Self {
            result: CaptureResult {
                name: name.to_string(),
                status,
                expires_at: None,
            },
            unstored: None,
        }
    }
}

/// Who a capture is stored for, and what it is bound to.
pub struct Owner<'a> {
    pub key_id: &'a str,
    pub key_name: &'a str,
    pub origin: &'a Origin,
}

/// Read one value from the target's raw answer and, when it is usable, store
/// it under `capture.name` for `owner`. Never fails the request: the outcome
/// carries a status.
pub fn capture(
    store: &SessionStore,
    owner: &Owner<'_>,
    capture: &Capture,
    up: &UpstreamResponse,
    now: DateTime<Utc>,
    max_per_key: usize,
) -> CaptureOutcome {
    let name = capture.name.as_str();
    let found = match extract(&capture.source, up, now) {
        Ok(found) => found,
        Err(status) => return CaptureOutcome::failed(name, status),
    };
    // A value shorter than the scrubber's minimum cannot be removed from the
    // response, so it is not stored (and cannot be hidden).
    if found.value.chars().count() < MIN_SCRUB_LEN {
        return CaptureOutcome::failed(name, CaptureStatus::TooShort);
    }
    let unstored = |status| CaptureOutcome {
        result: CaptureResult {
            name: name.to_string(),
            status,
            expires_at: None,
        },
        unstored: Some(found.value.clone()),
    };
    if found.value.len() > MAX_VALUE_BYTES {
        return unstored(CaptureStatus::TooLong);
    }
    let by_ttl =
        ChronoDuration::try_seconds(i64::try_from(capture.ttl.as_secs()).unwrap_or(i64::MAX))
            .and_then(|d| now.checked_add_signed(d))
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
    let expires = earliest(Some(by_ttl), found.expires).unwrap_or(by_ttl);
    if expires <= now {
        return unstored(CaptureStatus::Expired);
    }
    match store.insert(owner, name, found.value.clone(), expires, now, max_per_key) {
        Ok(()) => CaptureOutcome {
            result: CaptureResult {
                name: name.to_string(),
                status: CaptureStatus::Captured,
                expires_at: Some(rfc3339(expires)),
            },
            unstored: None,
        },
        Err(LimitReached) => unstored(CaptureStatus::LimitReached),
    }
}

// ── The store ─────────────────────────────────────────────────────────────────

/// Where a session was captured: scheme, lower-case host and port of the
/// login request's URL. A session is only ever sent to the same origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    /// The origin of `url`; `None` when it has no host or port.
    pub fn of(url: &Url) -> Option<Origin> {
        let host = url
            .host_str()?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        Some(Origin {
            scheme: url.scheme().to_ascii_lowercase(),
            host,
            port: url.port_or_known_default()?,
        })
    }

    /// The scheme, lower case.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The port (the scheme's default when the URL gave none).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The host, with `:port` when the port is not the scheme's default. What
    /// `GET /v1/sessions` shows.
    pub fn host_label(&self) -> String {
        let default = match self.scheme.as_str() {
            "http" => 80,
            "https" => 443,
            _ => 0,
        };
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// The key already holds `sessions.max_per_key` live sessions.
#[derive(Debug, PartialEq, Eq)]
pub struct LimitReached;

struct Entry {
    value: Zeroizing<String>,
    key_name: String,
    origin: Origin,
    expires: DateTime<Utc>,
}

/// One live session as `GET /v1/sessions` lists it. Never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionInfo {
    pub name: String,
    pub host: String,
    pub expires_at: String,
}

/// A session removed from the store, for the event that records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed {
    pub key_id: String,
    pub key_name: String,
    pub name: String,
}

/// The captured sessions of every agent key. In memory only: nothing is
/// written to disk, logged or put in an event, and a restart empties it.
#[derive(Default)]
pub struct SessionStore {
    map: Mutex<HashMap<(String, String), Entry>>,
}

/// Never prints a value (or a name): counts only.
impl std::fmt::Debug for SessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionStore")
            .field("sessions", &self.lock().len())
            .finish_non_exhaustive()
    }
}

impl SessionStore {
    fn lock(&self) -> MutexGuard<'_, HashMap<(String, String), Entry>> {
        // A poisoned lock only means another thread panicked mid-update; the
        // map is still structurally valid.
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Store `value` under `name` for the key, replacing a session of the same
    /// name (new value, origin and expiry). A new name is refused with
    /// [`LimitReached`] when the key already holds `max_per_key` live sessions;
    /// replacing one does not count as new.
    pub fn insert(
        &self,
        owner: &Owner<'_>,
        name: &str,
        value: Zeroizing<String>,
        expires: DateTime<Utc>,
        now: DateTime<Utc>,
        max_per_key: usize,
    ) -> Result<(), LimitReached> {
        let mut map = self.lock();
        let slot = (owner.key_id.to_string(), name.to_string());
        if !map.contains_key(&slot) {
            let live = map
                .iter()
                .filter(|((key, _), e)| key == owner.key_id && e.expires > now)
                .count();
            if live >= max_per_key {
                return Err(LimitReached);
            }
        }
        map.insert(
            slot,
            Entry {
                value,
                key_name: owner.key_name.to_string(),
                origin: owner.origin.clone(),
                expires,
            },
        );
        Ok(())
    }

    /// Look up every name in `names` for the key, for a request to `origin`.
    /// A name that is absent, expired or another key's gives the same
    /// [`FerroError::UnknownSession`]; one captured from another origin gives
    /// [`FerroError::SessionHostNotAllowed`]. Returns the values to substitute.
    pub fn resolve(
        &self,
        key_id: &str,
        names: &BTreeSet<String>,
        origin: &Origin,
        now: DateTime<Utc>,
    ) -> FerroResult<SessionValues> {
        let map = self.lock();
        let mut out = SessionValues::new();
        for name in names {
            let entry = map
                .get(&(key_id.to_string(), name.clone()))
                .filter(|e| e.expires > now)
                .ok_or_else(|| FerroError::UnknownSession(name.clone()))?;
            if entry.origin != *origin {
                return Err(FerroError::SessionHostNotAllowed {
                    name: name.clone(),
                    host: origin.host_label(),
                });
            }
            out.insert(name.clone(), entry.value.clone());
        }
        Ok(out)
    }

    /// Every session value of the key, with its name: the key's exact-value
    /// scrub set. Sessions that have expired but not yet been swept are
    /// included, so a value is hidden for as long as it is in memory.
    pub fn values_for_key(&self, key_id: &str) -> Vec<(String, Zeroizing<String>)> {
        self.lock()
            .iter()
            .filter(|((key, _), _)| key == key_id)
            .map(|((_, name), e)| (name.clone(), e.value.clone()))
            .collect()
    }

    /// The key's live sessions, by name. Never values.
    pub fn list(&self, key_id: &str, now: DateTime<Utc>) -> Vec<SessionInfo> {
        let mut out: Vec<SessionInfo> = self
            .lock()
            .iter()
            .filter(|((key, _), e)| key == key_id && e.expires > now)
            .map(|((_, name), e)| SessionInfo {
                name: name.clone(),
                host: e.origin.host_label(),
                expires_at: rfc3339(e.expires),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Remove one session of the key. Returns false when it is absent or has
    /// expired (the same answer for both, and for another key's name).
    pub fn remove(&self, key_id: &str, name: &str, now: DateTime<Utc>) -> bool {
        let mut map = self.lock();
        let slot = (key_id.to_string(), name.to_string());
        match map.get(&slot) {
            Some(e) if e.expires > now => {
                map.remove(&slot);
                true
            }
            _ => false,
        }
    }

    /// Remove every session of the key.
    pub fn clear_key(&self, key_id: &str) -> Vec<Removed> {
        self.drain(|(key, _), _| key == key_id)
    }

    /// Remove every session of every key.
    pub fn clear_all(&self) -> Vec<Removed> {
        self.drain(|_, _| true)
    }

    /// Remove the sessions that have expired.
    pub fn sweep(&self, now: DateTime<Utc>) -> Vec<Removed> {
        self.drain(|_, e| e.expires <= now)
    }

    fn drain(&self, mut pick: impl FnMut(&(String, String), &Entry) -> bool) -> Vec<Removed> {
        let mut map = self.lock();
        let slots: Vec<(String, String)> = map
            .iter()
            .filter(|(slot, e)| pick(slot, e))
            .map(|(slot, _)| slot.clone())
            .collect();
        let mut removed: Vec<Removed> = slots
            .into_iter()
            .filter_map(|slot| {
                map.remove(&slot).map(|e| Removed {
                    key_id: slot.0,
                    key_name: e.key_name.clone(),
                    name: slot.1,
                })
            })
            .collect();
        removed.sort_by(|a, b| (&a.key_id, &a.name).cmp(&(&b.key_id, &b.name)));
        removed
    }

    /// How many sessions are live (the metrics gauge).
    pub fn active(&self, now: DateTime<Utc>) -> usize {
        self.lock().values().filter(|e| e.expires > now).count()
    }
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

/// Why a session was deleted, as `session_delete` records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteCause {
    /// The agent called `DELETE /v1/sessions/{name}`.
    Agent,
    /// The key was revoked.
    KeyRevoke,
    /// The key's policy was changed.
    KeyPolicyChange,
    /// The vault was locked.
    VaultLock,
}

impl DeleteCause {
    pub fn as_str(self) -> &'static str {
        match self {
            DeleteCause::Agent => "agent",
            DeleteCause::KeyRevoke => "key_revoke",
            DeleteCause::KeyPolicyChange => "key_policy_change",
            DeleteCause::VaultLock => "vault_lock",
        }
    }
}

/// Record one removed session: a `session_delete` event with the key, the
/// session name and the cause. One event per session, never the value.
pub fn emit_deleted(state: &AppState, removed: &Removed, cause: DeleteCause) {
    state.events.emit(
        SecurityEvent::new(Action::SessionDelete)
            .key_named(&removed.key_id, &removed.key_name)
            .detail_str("session", &removed.name)
            .detail("cause", cause.as_str()),
    );
}

/// Remove every session of a key (revoked, or its policy changed) and record
/// each removal.
pub fn clear_key(state: &AppState, key_id: &str, cause: DeleteCause) {
    for removed in state.sessions.clear_key(key_id) {
        emit_deleted(state, &removed, cause);
    }
}

/// Remove every session of every key (the vault was locked) and record each
/// removal.
pub fn clear_all(state: &AppState, cause: DeleteCause) {
    for removed in state.sessions.clear_all() {
        emit_deleted(state, &removed, cause);
    }
}

/// Remove the expired sessions and record each as `session_expire`.
pub fn sweep_once(state: &AppState, now: DateTime<Utc>) {
    for removed in state.sessions.sweep(now) {
        state.events.emit(
            SecurityEvent::new(Action::SessionExpire)
                .key_named(&removed.key_id, &removed.key_name)
                .detail_str("session", &removed.name),
        );
    }
}

/// Start the periodic sweep. Expired sessions are already treated as absent
/// when looked up; the sweep frees them and records the expiry.
pub fn spawn_sweeper(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        ticker.tick().await; // fires immediately; there is nothing to sweep yet
        loop {
            ticker.tick().await;
            sweep_once(&state, Utc::now());
        }
    });
}

// ── Events for a capture ──────────────────────────────────────────────────────

/// The `session_capture` event for one capture entry: key, session name,
/// target, outcome and, on failure, the status. Never the value.
pub fn capture_event(result: &CaptureResult) -> SecurityEvent {
    let event = SecurityEvent::new(Action::SessionCapture)
        .detail_str("session", &result.name)
        .detail("status", result.status.as_str());
    match (&result.status, &result.expires_at) {
        (CaptureStatus::Captured, Some(expires)) => event.detail("expires_at", expires.as_str()),
        (CaptureStatus::Captured, None) => event,
        _ => event
            .outcome(Outcome::Failure)
            .reason(Reason::CaptureFailed),
    }
}

#[cfg(test)]
mod tests;
