//! HTTP plumbing of the admin UI: cookies, the HTTPS rule, the CSRF origin
//! check, strict form parsing and the security headers.
//!
//! Everything here is a plain function of its inputs, so each rule is tested
//! on its own.

use std::net::IpAddr;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue};
use http_body_util::BodyExt;
use zeroize::Zeroizing;

use crate::net::Cidr;

// ── Cookies ───────────────────────────────────────────────────────────────────
//
// All three use the `__Host-` prefix: the browser then only accepts them if
// they are `Secure`, have `Path=/` and no `Domain`, so a sibling subdomain
// cannot plant them. All are `HttpOnly` and `SameSite=Strict`.

pub const SESSION_COOKIE: &str = "__Host-fw_session";
pub const PENDING_COOKIE: &str = "__Host-fw_pending";
pub const LOGIN_COOKIE: &str = "__Host-fw_login";

/// Lifetime of the pending-login cookie: Vaultwarden's incomplete-2FA window.
pub const PENDING_COOKIE_MAX_AGE: u64 = 180;
/// Lifetime of the login CSRF cookie.
pub const LOGIN_COOKIE_MAX_AGE: u64 = 900;

/// `Set-Cookie` value. `max_age: None` makes a browser-session cookie.
pub fn set_cookie(name: &str, value: &str, max_age: Option<u64>) -> String {
    let mut cookie = format!("{name}={value}; Path=/; HttpOnly; Secure; SameSite=Strict");
    if let Some(age) = max_age {
        cookie.push_str(&format!("; Max-Age={age}"));
    }
    cookie
}

/// `Set-Cookie` value that removes the cookie.
pub fn clear_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict")
}

/// The value of cookie `name`, if it is present and looks like one of our
/// tokens (base64url, at most 64 characters). Anything else is treated as
/// absent, so odd input never reaches a lookup.
pub fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    for header in headers.get_all(header::COOKIE) {
        let Ok(header) = header.to_str() else {
            continue;
        };
        for pair in header.split(';') {
            let Some((n, v)) = pair.trim().split_once('=') else {
                continue;
            };
            if n == name {
                let ok = !v.is_empty()
                    && v.len() <= 64
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
                return ok.then_some(v);
            }
        }
    }
    None
}

// ── HTTPS rule and origin ─────────────────────────────────────────────────────

/// What the UI middleware worked out about one request.
#[derive(Debug, Clone)]
pub struct Transport {
    /// The request reached us over TLS (the listener's own, or a trusted
    /// reverse proxy's, as reported by `X-Forwarded-Proto`).
    pub secure: bool,
    /// The origin the browser sees: `https://host` (or `http://host`).
    /// `None` if the request names no host.
    pub origin: Option<String>,
}

fn peer_is_trusted(peer: IpAddr, trusted: &[Cidr]) -> bool {
    let peer = peer.to_canonical();
    trusted.iter().any(|c| c.contains(&peer))
}

/// A request is secure if the UI listener itself is TLS, or the TCP peer is a
/// trusted proxy and the nearest hop's `X-Forwarded-Proto` is `https`. The
/// header from any other peer is ignored: it is client-controlled.
pub fn is_secure(listener_tls: bool, peer: IpAddr, headers: &HeaderMap, trusted: &[Cidr]) -> bool {
    if listener_tls {
        return true;
    }
    if !peer_is_trusted(peer, trusted) {
        return false;
    }
    // The rightmost value was added by the proxy nearest to us.
    headers
        .get_all("x-forwarded-proto")
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("https"))
}

/// Work out the request's own origin. The host comes from `Host` (or the
/// request URI's authority, for HTTP/2); behind a trusted proxy that rewrites
/// it, from `X-Forwarded-Host`.
pub fn transport(
    listener_tls: bool,
    peer: IpAddr,
    headers: &HeaderMap,
    uri_authority: Option<&str>,
    trusted: &[Cidr],
) -> Transport {
    let secure = is_secure(listener_tls, peer, headers, trusted);
    let forwarded_host = peer_is_trusted(peer, trusted)
        .then(|| {
            headers
                .get_all("x-forwarded-host")
                .iter()
                .next_back()
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .map(str::trim)
                .filter(|v| !v.is_empty())
        })
        .flatten();
    let host = forwarded_host
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
        })
        .or(uri_authority);
    let origin = host.map(|h| {
        format!(
            "{}://{}",
            if secure { "https" } else { "http" },
            h.to_ascii_lowercase()
        )
    });
    Transport { secure, origin }
}

/// The origin check required on every POST. `Sec-Fetch-Site`, if the browser
/// sent it, must be `same-origin`; otherwise `Origin`, if present, must equal
/// the request's own origin; a request with neither is rejected.
pub fn origin_ok(headers: &HeaderMap, transport: &Transport) -> bool {
    if let Some(site) = headers.get("sec-fetch-site") {
        return site.as_bytes() == b"same-origin";
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let (Ok(origin), Some(own)) = (origin.to_str(), transport.origin.as_deref()) else {
            return false;
        };
        return origin.eq_ignore_ascii_case(own);
    }
    false
}

// ── Strict form parsing ───────────────────────────────────────────────────────

/// Largest form body accepted (a master password plus tokens fits easily).
pub const MAX_FORM_BYTES: usize = 8 * 1024;
/// Largest form body on the key pages: up to 256 patterns of 256 characters,
/// percent-encoded, plus the request-check fields.
pub const MAX_ADMIN_FORM_BYTES: usize = 160 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormError {
    /// Bad percent-encoding, empty pair, missing `=`, invalid UTF-8.
    Malformed,
    /// A field that the form does not have.
    Unknown,
    /// The same field twice.
    Duplicate,
    TooLarge,
}

/// A parsed form: every value is a `Zeroizing<String>`, because the password
/// is one of them. Decoding writes straight into a buffer sized up front, so
/// no intermediate copy of a value is left behind in freed memory.
pub struct Form {
    fields: Vec<(String, Zeroizing<String>)>,
}

impl Form {
    /// Remove and return a field's value.
    pub fn take(&mut self, name: &str) -> Option<Zeroizing<String>> {
        let i = self.fields.iter().position(|(n, _)| n == name)?;
        Some(self.fields.swap_remove(i).1)
    }
}

/// Percent-decode `input` (`+` is a space) into a buffer that is wiped on drop.
fn decode(input: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = |b: u8| (b as char).to_digit(16);
                let hi = hex(*input.get(i + 1)?)?;
                let lo = hex(*input.get(i + 2)?)?;
                out.push((hi * 16 + lo) as u8);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    Some(out)
}

fn into_string(mut bytes: Zeroizing<Vec<u8>>) -> Option<Zeroizing<String>> {
    // Moves the buffer out (no copy); the emptied wrapper wipes nothing.
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(s) => Some(Zeroizing::new(s)),
        Err(e) => {
            // Wipe the rejected bytes too.
            drop(Zeroizing::new(e.into_bytes()));
            None
        }
    }
}

/// Parse an `application/x-www-form-urlencoded` body into pairs, accepting only
/// the `allowed` field names, each at most once.
pub fn parse_form(body: &[u8], allowed: &[&str]) -> Result<Form, FormError> {
    parse_form_limited(body, allowed, MAX_FORM_BYTES)
}

/// [`parse_form`] with a different size limit.
pub fn parse_form_limited(body: &[u8], allowed: &[&str], limit: usize) -> Result<Form, FormError> {
    if body.len() > limit {
        return Err(FormError::TooLarge);
    }
    let mut fields: Vec<(String, Zeroizing<String>)> = Vec::new();
    if body.is_empty() {
        return Ok(Form { fields });
    }
    for pair in body.split(|b| *b == b'&') {
        let eq = pair
            .iter()
            .position(|b| *b == b'=')
            .ok_or(FormError::Malformed)?;
        let name = decode(&pair[..eq])
            .and_then(into_string)
            .ok_or(FormError::Malformed)?;
        if !allowed.contains(&name.as_str()) {
            return Err(FormError::Unknown);
        }
        if fields.iter().any(|(n, _)| n == name.as_str()) {
            return Err(FormError::Duplicate);
        }
        let value = decode(&pair[eq + 1..])
            .and_then(into_string)
            .ok_or(FormError::Malformed)?;
        fields.push((name.as_str().to_string(), value));
    }
    Ok(Form { fields })
}

/// Read a request body into a buffer we own and wipe, refusing more than
/// `limit` bytes. (The HTTP stack's own read buffers are outside our control.)
pub async fn read_body(body: Body, limit: usize) -> Result<Zeroizing<Vec<u8>>, FormError> {
    let mut body = body;
    let mut out = Zeroizing::new(Vec::with_capacity(limit));
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| FormError::Malformed)?;
        if let Some(data) = frame.data_ref() {
            if out.len() + data.len() > limit {
                return Err(FormError::TooLarge);
            }
            out.extend_from_slice(data);
        }
    }
    Ok(out)
}

/// Is this a form submission? (Exact media type, parameters ignored.)
pub fn is_form_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| {
            v.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

// ── The `next` redirect target ────────────────────────────────────────────────

/// Longest accepted `next`.
const MAX_NEXT_CHARS: usize = 200;

/// Validate a post-sign-in redirect target. Only a plain path inside the UI
/// is accepted: it starts with `/ui/`, is at most 200 characters, and
/// consists solely of ASCII letters, digits and `/ _ - .`. That excludes
/// everything an open redirect needs: a scheme or host (`:`, `@`), a second
/// slash (`//`), a backslash, percent-encoding (so `%2f%2f` and `%5c` cannot
/// decode into those later), whitespace and control characters, and query or
/// fragment. `.` and `..` segments are refused, and so are the sign-in and
/// static-file paths (a redirect there would loop or do nothing).
///
/// Returns the path unchanged, or `None`: callers then use `/ui/`.
pub fn safe_next(raw: &str) -> Option<String> {
    if raw.len() > MAX_NEXT_CHARS || !raw.starts_with("/ui/") {
        return None;
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.'))
    {
        return None;
    }
    if raw.contains("//") {
        return None;
    }
    if matches!(raw.split('/').nth(2), Some("login") | Some("static")) {
        return None;
    }
    if raw.split('/').any(|seg| seg == "." || seg == "..") {
        return None;
    }
    Some(raw.to_string())
}

// ── Security headers ──────────────────────────────────────────────────────────

/// No scripts at all: `default-src 'none'`; the stylesheet, its font and the
/// icons come from this origin, and nothing inline (no `style=` attributes,
/// no `<style>` blocks) is allowed.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'self'; \
font-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

fn set(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    headers.insert(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    );
}

/// Put the hardening headers on a response. `Cache-Control: no-store` unless
/// the handler chose its own (static assets); HSTS when the request was
/// secure.
pub fn apply_security_headers(headers: &mut HeaderMap, secure: bool) {
    set(headers, "content-security-policy", CONTENT_SECURITY_POLICY);
    set(headers, "x-content-type-options", "nosniff");
    set(headers, "referrer-policy", "no-referrer");
    set(headers, "x-frame-options", "DENY");
    set(
        headers,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    );
    set(headers, "cross-origin-opener-policy", "same-origin");
    set(headers, "cross-origin-resource-policy", "same-origin");
    if !headers.contains_key(header::CACHE_CONTROL) {
        set(headers, "cache-control", "no-store");
    }
    if secure {
        set(headers, "strict-transport-security", "max-age=31536000");
    }
}

#[cfg(test)]
mod tests;
