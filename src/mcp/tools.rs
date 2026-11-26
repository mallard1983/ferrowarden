//! The two tools: their definitions (names, descriptions, input schemas) and
//! what a call does.
//!
//! The input schemas are written out here, not generated, so that each one is
//! readable next to the OpenAPI document it must agree with. A unit test loads
//! `docs/openapi.yaml` and compares them.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use rmcp::model::{CallToolResult, ContentBlock, JsonObject, Tool, ToolAnnotations};
use serde::Deserialize;
use serde_json::{json, Value};

use super::client::{FerroClient, Raw, Unreachable};
use super::render::{self, ForwardedResponse};

pub const TOOL_LIST_CREDENTIALS: &str = "list_credentials";
pub const TOOL_HTTP_REQUEST: &str = "http_request";

/// The HTTP methods of `ProxyRequest.method` in `docs/openapi.yaml`.
pub const METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

const LIST_CREDENTIALS_DESCRIPTION: &str = "\
List the vault credentials this agent key may use, by name, without their values. \
Each entry has ready-made placeholders such as {{vault:NAME}} (the password) and \
{{vault:NAME:username}}: copy them verbatim into http_request instead of writing your own. \
Each credential works only for the hosts in its bound_to list; a request to any other host \
is refused. Entries marked not available say why. Call this before the first http_request.";

const HTTP_REQUEST_DESCRIPTION: &str = "\
Send an HTTP request through Ferrowarden, which substitutes credentials from the vault and \
returns the response. Put a placeholder such as {{vault:NAME}} wherever a credential belongs; \
call list_credentials first and copy its ready-made placeholders exactly. Placeholders are \
allowed in the URL path and query, in header values and in the body, not in the scheme, host \
or port. A credential is only sent to the hosts it is bound to. The result has the target's \
status, response headers and body; a 4xx or 5xx from the target is a normal result with that \
status. Known credential values are replaced with [REDACTED] in the response; do not ask a \
target to echo or transform a credential. To log in to a service without ever seeing its token, \
add capture to the login request, for example [{\"from\": \"json:/jwt\", \"as\": \"portainer\"}]: \
Ferrowarden keeps the value (a JSON pointer, a header: or a cookie: of the response) and shows \
[CAPTURED:portainer] instead; later calls write {{session:portainer}} where the token belongs, \
and it is only sent to the host it came from. The result lists what each capture did. If \
Ferrowarden itself refuses the call, the result is \
an error: 403 means the request is not allowed for this key or target, so do not retry it with \
other credentials, hosts or methods, and tell the user; 422 means a placeholder is malformed or \
unknown, so call list_credentials and copy a placeholder from it.";

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        _ => unreachable!("tool schemas are objects"),
    }
}

/// Input schema of `list_credentials`: no arguments.
pub fn list_credentials_schema() -> JsonObject {
    object(json!({
        "type": "object",
        "properties": {},
        "additionalProperties": false
    }))
}

/// Input schema of `http_request`: the `ProxyRequest` of `docs/openapi.yaml`.
pub fn http_request_schema() -> JsonObject {
    object(json!({
        "type": "object",
        "properties": {
            "method": {
                "type": "string",
                "enum": METHODS,
                "description": "The HTTP method."
            },
            "url": {
                "type": "string",
                "description": "The full target URL (http or https). Placeholders are allowed in the path, query and user info, not in the scheme, host or port."
            },
            "headers": {
                "type": "object",
                "description": "Headers to send to the target, string values only. Placeholders are allowed in values. Names that differ only by letter case count as duplicates.",
                "additionalProperties": { "type": "string" }
            },
            "body": {
                "description": "The request body. A string is sent as it is (raw text such as form data). Any other JSON value (object, array, number or boolean) is sent as JSON. Placeholders are allowed inside strings. Leave it out for no body."
            },
            "capture": {
                "type": "array",
                "minItems": 1,
                "maxItems": 8,
                "description": "Values of the response to keep inside Ferrowarden instead of showing them (a login token). Each is stored under a name for later {{session:NAME}} placeholders, and the response shows [CAPTURED:NAME] in its place. Leave it out for no capture.",
                "items": {
                    "type": "object",
                    "properties": {
                        "from": {
                            "type": "string",
                            "description": "Where the value is: json:/pointer (an RFC 6901 pointer into a JSON response body, to a string), header:Name, or cookie:name (from the response's Set-Cookie headers)."
                        },
                        "as": {
                            "type": "string",
                            "pattern": "^[A-Za-z0-9_.-]{1,64}$",
                            "description": "The session name: 1 to 64 letters, digits, '_', '-' or '.'. Used as {{session:NAME}}."
                        },
                        "ttl_secs": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "How long to keep it, in seconds. Default 30 minutes; never longer than the token's own expiry."
                        }
                    },
                    "required": ["from", "as"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["method", "url"],
        "additionalProperties": false
    }))
}

/// The tools this server offers, in a stable order.
pub fn definitions() -> Vec<Tool> {
    vec![
        Tool::new(
            TOOL_LIST_CREDENTIALS,
            LIST_CREDENTIALS_DESCRIPTION,
            Arc::new(list_credentials_schema()),
        )
        .with_title("List credentials")
        .with_annotations(
            ToolAnnotations::default()
                .read_only(true)
                .idempotent(true)
                .open_world(false),
        ),
        Tool::new(
            TOOL_HTTP_REQUEST,
            HTTP_REQUEST_DESCRIPTION,
            Arc::new(http_request_schema()),
        )
        .with_title("HTTP request with vault credentials")
        .with_annotations(
            ToolAnnotations::default()
                .destructive(true)
                .open_world(true),
        ),
    ]
}

/// Arguments of `http_request`. Unknown fields are refused, as the schema says.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestArgs {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default)]
    pub capture: Option<Vec<CaptureArg>>,
}

/// One entry of `capture`. Ferrowarden validates the values; this only keeps
/// the shape (and the unknown-field refusal) of the schema.
#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureArg {
    pub from: String,
    #[serde(rename = "as")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}

impl HttpRequestArgs {
    /// The body of `POST /v1/forward`.
    pub fn payload(&self) -> Value {
        let mut request = serde_json::Map::new();
        request.insert("method".into(), Value::String(self.method.clone()));
        request.insert("url".into(), Value::String(self.url.clone()));
        if !self.headers.is_empty() {
            request.insert("headers".into(), json!(self.headers));
        }
        if let Some(body) = &self.body {
            request.insert("body".into(), body.clone());
        }
        let mut payload = serde_json::Map::new();
        payload.insert("request".into(), Value::Object(request));
        if let Some(capture) = &self.capture {
            payload.insert("capture".into(), json!(capture));
        }
        Value::Object(payload)
    }
}

fn tool_error(text: String, structured: Value) -> CallToolResult {
    let mut result = CallToolResult::error(vec![ContentBlock::text(text)]);
    result.structured_content = Some(structured);
    result
}

fn tool_ok(text: String, structured: Value) -> CallToolResult {
    let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
    result.structured_content = Some(structured);
    result
}

/// The argument problem, without echoing values: serde's messages can quote
/// the offending value, so only the fact and the (truncated) field-level
/// description are used.
fn argument_error(error: &serde_json::Error) -> CallToolResult {
    let detail: String = error.to_string().chars().take(200).collect();
    tool_error(
        format!(
            "Invalid arguments for {TOOL_HTTP_REQUEST}: {detail}. \
             Required: method, url. Optional: headers (object of strings), body, \
             capture (list of {{from, as, ttl_secs}})."
        ),
        json!({ "error_source": "mcp", "error": "invalid arguments" }),
    )
}

fn unreachable_result(kind: Unreachable) -> CallToolResult {
    tool_error(
        format!(
            "Could not reach Ferrowarden: {}. The call was not delivered, so it is not known \
             whether anything was sent. Tell the user; check FERROWARDEN_URL and the network.",
            kind.describe()
        ),
        json!({ "error_source": "mcp", "error": "could not reach Ferrowarden" }),
    )
}

fn unexpected_result(raw: &Raw, what: &str) -> CallToolResult {
    let id = raw.request_id.as_deref();
    let mut text = format!(
        "Ferrowarden answered HTTP {} but the body was not {what}.",
        raw.status
    );
    if let Some(id) = id {
        text.push_str(&format!("\nRequest ID: {id}"));
    }
    text.push_str(
        "\nFERROWARDEN_URL may point at the wrong address (for example a missing api_prefix). \
         Tell the user.",
    );
    tool_error(
        text,
        json!({ "error_source": "ferrowarden", "status": raw.status, "request_id": id }),
    )
}

/// An answer from Ferrowarden that is not a 2xx: a tool error, distinct from
/// a target's own 4xx or 5xx, which arrives inside a 2xx.
fn failure_result(client: &FerroClient, raw: &Raw) -> CallToolResult {
    let message = render::error_message(&raw.body).map(|m| client.redactor.scrub_error_text(&m));
    // A human's approval is needed (or was refused): the agent is told what to
    // do about it, which is not what any other 403 or 429 asks of it.
    if let Some(code) = render::approval_code(&raw.body) {
        let approval_id = render::approval_id(&raw.body);
        let text = render::approval_error_text(
            raw.status,
            code,
            message.as_deref(),
            raw.request_id.as_deref(),
            approval_id.as_deref(),
        );
        return tool_error(
            text,
            json!({
                "error_source": "ferrowarden",
                "status": raw.status,
                "code": code,
                "approval_id": approval_id,
                "error": message,
                "request_id": raw.request_id,
            }),
        );
    }
    let text = render::ferrowarden_error_text(
        raw.status,
        message.as_deref(),
        raw.request_id.as_deref(),
        raw.retry_after_secs,
    );
    tool_error(
        text,
        json!({
            "error_source": "ferrowarden",
            "status": raw.status,
            "error": message,
            "request_id": raw.request_id,
            "retry_after_secs": raw.retry_after_secs,
        }),
    )
}

fn log_outcome(tool: &str, started: Instant, outcome: &Result<Raw, Unreachable>, host: &str) {
    let duration_ms = started.elapsed().as_millis() as u64;
    match outcome {
        Ok(raw) => tracing::info!(
            tool,
            status = raw.status,
            request_id = raw.request_id.as_deref().unwrap_or("-"),
            duration_ms,
            host,
            "tool call finished"
        ),
        Err(kind) => tracing::warn!(
            tool,
            error = ?kind,
            duration_ms,
            host,
            "could not reach Ferrowarden"
        ),
    }
}

/// `list_credentials`.
pub async fn list_credentials(client: &FerroClient) -> CallToolResult {
    let started = Instant::now();
    let outcome = client.list_credentials().await;
    log_outcome(TOOL_LIST_CREDENTIALS, started, &outcome, client.host());
    let raw = match outcome {
        Ok(raw) => raw,
        Err(kind) => return unreachable_result(kind),
    };
    if !(200..300).contains(&raw.status) {
        return failure_result(client, &raw);
    }
    let Ok(Value::Array(mut entries)) = serde_json::from_slice::<Value>(&raw.body) else {
        return unexpected_result(&raw, "a JSON list of credentials");
    };
    for entry in &mut entries {
        client.redactor.scrub_value(entry);
    }
    let text = render::credentials_text(&entries);
    tool_ok(text, json!({ "credentials": entries }))
}

/// `http_request`. `arguments` is the raw argument object from the client.
pub async fn http_request(client: &FerroClient, arguments: Option<JsonObject>) -> CallToolResult {
    let args: HttpRequestArgs =
        match serde_json::from_value(Value::Object(arguments.unwrap_or_default())) {
            Ok(args) => args,
            Err(error) => return argument_error(&error),
        };
    let payload = args.payload();
    drop(args);

    let started = Instant::now();
    let outcome = client.forward(&payload).await;
    log_outcome(TOOL_HTTP_REQUEST, started, &outcome, client.host());
    let raw = match outcome {
        Ok(raw) => raw,
        Err(kind) => return unreachable_result(kind),
    };
    if !(200..300).contains(&raw.status) {
        return failure_result(client, &raw);
    }
    let Ok(mut value) = serde_json::from_slice::<Value>(&raw.body) else {
        return unexpected_result(&raw, "Ferrowarden's JSON response");
    };
    client.redactor.scrub_value(&mut value);
    let Some(response) = ForwardedResponse::from_value(&value) else {
        return unexpected_result(&raw, "a forwarded response");
    };
    tool_ok(response.text(), value)
}

#[cfg(test)]
mod tests;
