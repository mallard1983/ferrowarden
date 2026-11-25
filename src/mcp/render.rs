//! Plain-text renderings of Ferrowarden's answers, and the error mapping.
//!
//! The structured content of a result carries the data; the text is for
//! harnesses that show only text. Nothing here sees the agent key or the base
//! URL: the one place where text from Ferrowarden's error body is used goes
//! through [`super::client::Redactor`] first.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use base64::Engine as _;
use serde_json::Value;

/// The text rendering of one result is cut off at this many bytes. The
/// structured content is not cut: Ferrowarden already caps response size.
pub const MAX_TEXT_BYTES: usize = 100 * 1024;

/// The most characters of Ferrowarden's own `error` message that are shown.
const MAX_ERROR_MESSAGE_CHARS: usize = 500;

/// Cut `text` to at most `max` bytes on a character boundary and say so.
pub fn truncate_text(text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let total = text.len();
    let mut out = text[..end].to_string();
    let _ = write!(
        out,
        "\n[truncated: showing the first {end} of {total} bytes; the structured content holds the full response]"
    );
    out
}

/// One credential entry of `GET /v1/credentials?detail=true`, as text.
fn push_credential(out: &mut String, entry: &Value) {
    let Some(obj) = entry.as_object() else {
        // A plain name (when the server ignored detail=true).
        if let Some(name) = entry.as_str() {
            let _ = writeln!(out, "- {name}");
        }
        return;
    };
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("(unnamed)");
    match obj.get("type").and_then(Value::as_str) {
        Some(kind) => {
            let _ = writeln!(out, "- {name} ({kind})");
        }
        None => {
            let _ = writeln!(out, "- {name}");
        }
    }
    for (label, key) in [
        ("password", "placeholder"),
        ("username", "username"),
        ("totp", "totp"),
        ("notes", "notes"),
    ] {
        if let Some(p) = obj.get(key).and_then(Value::as_str) {
            let _ = writeln!(out, "    {label}: {p}");
        }
    }
    if let Some(fields) = obj.get("fields").and_then(Value::as_object) {
        for (field, p) in fields {
            if let Some(p) = p.as_str() {
                let _ = writeln!(out, "    field {field:?}: {p}");
            }
        }
    }
    if let Some(unavailable) = obj.get("unavailable_fields").and_then(Value::as_object) {
        for (field, why) in unavailable {
            if let Some(why) = why.as_str() {
                let _ = writeln!(out, "    field {field:?} is not available: {why}");
            }
        }
    }
    if let Some(why) = obj.get("unavailable").and_then(Value::as_str) {
        let _ = writeln!(out, "    not available: {why}");
    }
    if let Some(hosts) = obj.get("bound_to").and_then(Value::as_array) {
        let hosts: Vec<&str> = hosts.iter().filter_map(Value::as_str).collect();
        if hosts.is_empty() {
            let _ = writeln!(out, "    bound to: no host (it cannot be sent anywhere)");
        } else {
            let _ = writeln!(out, "    bound to: {}", hosts.join(", "));
        }
    }
}

/// Text for the `list_credentials` result. `entries` is the JSON array.
pub fn credentials_text(entries: &[Value]) -> String {
    if entries.is_empty() {
        return "This agent key may use no credentials (the list is empty). \
                If you expected some, tell the user."
            .to_string();
    }
    let mut out = format!(
        "{} credential{} available to this agent key. Copy the placeholders exactly; \
         a credential is only sent to the hosts listed under \"bound to\".\n",
        entries.len(),
        if entries.len() == 1 { "" } else { "s" }
    );
    for entry in entries {
        push_credential(&mut out, entry);
    }
    truncate_text(out, MAX_TEXT_BYTES)
}

/// What a forwarded request came back with.
#[derive(Debug)]
pub struct ForwardedResponse {
    pub status: u64,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    pub body_encoding: String,
}

impl ForwardedResponse {
    /// Read Ferrowarden's `ProxyResponse` JSON. `None` if it does not have
    /// the documented shape.
    pub fn from_value(value: &Value) -> Option<Self> {
        let obj = value.as_object()?;
        let status = obj.get("status")?.as_u64()?;
        if !(100..=599).contains(&status) {
            return None;
        }
        let headers = obj
            .get("headers")?
            .as_object()?
            .iter()
            .map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
            .collect::<Option<BTreeMap<_, _>>>()?;
        let body = obj.get("body")?.as_str()?.to_string();
        let body_encoding = obj.get("body_encoding")?.as_str()?.to_string();
        Some(Self {
            status,
            headers,
            body,
            body_encoding,
        })
    }

    /// Status line, response headers, a blank line, then the body. A base64
    /// body is summarised, not printed.
    pub fn text(&self) -> String {
        let mut out = format!(
            "HTTP {} (the target's response; Ferrowarden forwarded the request)\n",
            self.status
        );
        for (name, value) in &self.headers {
            let _ = writeln!(out, "{name}: {value}");
        }
        out.push('\n');
        if self.body_encoding == "base64" {
            match base64::engine::general_purpose::STANDARD.decode(self.body.as_bytes()) {
                Ok(bytes) => {
                    let _ = write!(
                        out,
                        "[binary response body, {} bytes; the structured content has it as base64]",
                        bytes.len()
                    );
                }
                Err(_) => out.push_str("[binary response body (base64)]"),
            }
        } else if self.body.is_empty() {
            out.push_str("[empty body]");
        } else {
            out.push_str(&self.body);
        }
        truncate_text(out, MAX_TEXT_BYTES)
    }
}

/// A short reason phrase for the statuses Ferrowarden itself returns.
fn reason(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

/// One line of guidance for an answer that came from Ferrowarden itself (not
/// from the target the request was forwarded to).
pub fn guidance(status: u16, retry_after_secs: Option<u64>) -> String {
    match status {
        400 => "Ferrowarden rejected the request as malformed. Fix the request (method, url, \
                headers, body) before trying again; do not resend it unchanged."
            .to_string(),
        401 => "The agent key is missing, invalid or revoked. Retrying will not help; \
                tell the user."
            .to_string(),
        403 => "This request is not allowed for this agent key or target. Do not retry it with \
                other credentials, hosts or methods; tell the user what was refused."
            .to_string(),
        404 => "A credential that passed the earlier checks was not found in the vault. \
                Call list_credentials, and tell the user if it is still missing."
            .to_string(),
        409 => "A name matches more than one vault item or field. Tell the user; do not guess \
                which one is meant."
            .to_string(),
        422 => "A placeholder is malformed or names a credential or field that does not exist. \
                Call list_credentials and copy a ready-made placeholder exactly."
            .to_string(),
        429 => match retry_after_secs {
            Some(secs) => format!("Rate limited. Wait {secs} seconds before the next call."),
            None => "Rate limited. Wait a little before the next call.".to_string(),
        },
        502 => "Ferrowarden could not get an answer from the target (it timed out, refused the \
                connection or sent more than the size limit). This is not a policy refusal; \
                tell the user if it keeps happening."
            .to_string(),
        503 => {
            "The vault is locked. Tell the user; calls will fail until it is unlocked.".to_string()
        }
        s if (300..400).contains(&s) => {
            "Ferrowarden answered with a redirect. FERROWARDEN_URL may point at the wrong \
             address (a reverse proxy, or a missing or wrong api_prefix); tell the user."
                .to_string()
        }
        _ => "Ferrowarden returned an unexpected error. Tell the user.".to_string(),
    }
}

/// Pull the `error` message out of Ferrowarden's error body, shortened and
/// without control characters. `None` if the body is not Ferrowarden's JSON
/// error shape (a reverse proxy's HTML page, for example, is not echoed).
pub fn error_message(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let message = value.get("error")?.as_str()?;
    let cleaned: String = message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_ERROR_MESSAGE_CHARS)
        .collect();
    let cleaned = cleaned.trim();
    (!cleaned.is_empty()).then(|| cleaned.to_string())
}

/// The text of a tool error for an error answer from Ferrowarden.
pub fn ferrowarden_error_text(
    status: u16,
    message: Option<&str>,
    request_id: Option<&str>,
    retry_after_secs: Option<u64>,
) -> String {
    let phrase = reason(status);
    let mut out = if phrase.is_empty() {
        format!("Ferrowarden refused or failed the call: HTTP {status}.")
    } else {
        format!("Ferrowarden refused or failed the call: HTTP {status} {phrase}.")
    };
    match message {
        Some(m) => {
            let _ = write!(out, "\nMessage: {m}");
        }
        None => out.push_str("\nMessage: (none)"),
    }
    if let Some(id) = request_id {
        let _ = write!(out, "\nRequest ID: {id}");
    }
    let _ = write!(out, "\n{}", guidance(status, retry_after_secs));
    out
}

#[cfg(test)]
mod tests;
