//! `GET /v1/openapi.json`: the hand-written OpenAPI description
//! (`docs/openapi.yaml`), served to callers who hold a key.
//!
//! The YAML is embedded in the binary and parsed once, when the router is
//! built. Two JSON documents are prepared from it, one per kind of caller:
//!
//! * **agent**: the agent and meta operations only. Admin paths, and every
//!   schema, response, parameter and header only they use, are removed, so an
//!   agent key does not learn what the operator API looks like.
//! * **admin**: the whole document.
//!
//! In both, `servers[0].url` is the configured `api_prefix` (or `/`), so a
//! client can use the document as it is. The prefix exists only in these
//! bodies, which are sent only after authentication, and is not written to
//! events or logs.

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::api::admin::authenticate_admin;
use crate::api::credentials::authenticate_agent;
use crate::error::{FerroError, FerroResult};
use crate::events::{emit_rejected, Action, SecurityEvent};
use crate::middleware::request_context::RequestContext;
use crate::state::AppState;

/// The specification, embedded at build time.
pub const SPEC_YAML: &str = include_str!("../../docs/openapi.yaml");

/// Tag of the operations that only the admin key may see.
const ADMIN_TAG: &str = "admin";

/// HTTP methods an OpenAPI path item can hold operations for.
const OPERATION_KEYS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// Parse the embedded specification. A failure is a bug in
/// `docs/openapi.yaml`; a unit test keeps it from shipping.
pub fn parse_spec() -> Result<Value, String> {
    serde_norway::from_str::<Value>(SPEC_YAML)
        .map_err(|e| format!("docs/openapi.yaml does not parse: {e}"))
}

/// The two documents served by the endpoint, serialized once.
pub struct OpenApiDocs {
    agent: String,
    admin: String,
}

impl OpenApiDocs {
    /// Build both documents for `api_prefix` ("" or "/seg[/seg...]").
    pub fn build(api_prefix: &str) -> Result<Self, String> {
        let spec = parse_spec()?;
        let serialize =
            |v: &Value| serde_json::to_string(v).map_err(|e| format!("OpenAPI document: {e}"));
        Ok(Self {
            agent: serialize(&with_server(agent_view(&spec), api_prefix))?,
            admin: serialize(&with_server(spec, api_prefix))?,
        })
    }
}

/// Which document a caller gets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Variant {
    Agent,
    Admin,
}

impl Variant {
    fn as_str(self) -> &'static str {
        match self {
            Variant::Agent => "agent",
            Variant::Admin => "admin",
        }
    }
}

/// Set `servers` to the one entry a client needs: the API base URL.
fn with_server(mut spec: Value, api_prefix: &str) -> Value {
    let url = if api_prefix.is_empty() {
        "/"
    } else {
        api_prefix
    };
    spec["servers"] = json!([{ "url": url, "description": "This Ferrowarden instance." }]);
    spec
}

/// `agent` credentials by default; `admin` when only an admin header is
/// present. A request carrying `X-Agent-Key` is checked as an agent request
/// whatever else it sends.
fn authenticate_variant_is_admin(headers: &HeaderMap) -> bool {
    !headers.contains_key("x-agent-key")
        && (headers.contains_key("x-admin-key") || headers.contains_key(header::AUTHORIZATION))
}

/// GET /v1/openapi.json
///
/// Agent key: agent and meta operations. Admin key (either header form): the
/// full document. Anything else: 401, recorded as `agent_auth` or
/// `admin_auth` like on the other routes. The query string must be empty.
pub async fn get_openapi(
    State(state): State<Arc<AppState>>,
    Extension(docs): Extension<Arc<OpenApiDocs>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Query(params): Query<Vec<(String, String)>>,
) -> FerroResult<Response> {
    const ENDPOINT: &str = "/v1/openapi.json";

    let (variant, agent) = if authenticate_variant_is_admin(&headers) {
        authenticate_admin(&state, &ctx, &headers, ENDPOINT)?;
        (Variant::Admin, None)
    } else {
        let agent = authenticate_agent(&state, &ctx, &headers, ENDPOINT).await?;
        (Variant::Agent, Some(agent))
    };

    if let Some((name, _)) = params.first() {
        let e = FerroError::InvalidRequest(format!(
            "unknown query parameter {:?}; this endpoint takes none",
            name.chars().take(64).collect::<String>()
        ));
        emit_rejected(&state.events, &ctx, agent.as_ref(), ENDPOINT, &e);
        return Err(e);
    }

    let mut event = SecurityEvent::new(Action::OpenapiRead)
        .request(&ctx)
        .status(200)
        .detail("variant", variant.as_str());
    if let Some(agent) = &agent {
        event = event.key(agent);
    }
    state.events.emit(event);

    let body = match variant {
        Variant::Agent => docs.agent.clone(),
        Variant::Admin => docs.admin.clone(),
    };
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response())
}

// ── The agent view ────────────────────────────────────────────────────────────

/// The document for an agent key: operations tagged `admin` are removed, and
/// so is everything that only they used.
pub fn agent_view(spec: &Value) -> Value {
    let mut spec = spec.clone();

    // Operations.
    if let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) {
        for item in paths.values_mut().filter_map(Value::as_object_mut) {
            for key in OPERATION_KEYS {
                let admin_only = item
                    .get(key)
                    .and_then(|op| op.get("tags"))
                    .and_then(Value::as_array)
                    .is_some_and(|tags| tags.iter().any(|t| t == ADMIN_TAG));
                if admin_only {
                    item.remove(key);
                }
            }
        }
        paths.retain(|_, item| {
            item.as_object()
                .is_some_and(|o| OPERATION_KEYS.iter().any(|k| o.contains_key(*k)))
        });
        // The admin key is not an option for what is left.
        for item in paths.values_mut().filter_map(Value::as_object_mut) {
            for key in OPERATION_KEYS {
                if let Some(Value::Array(requirements)) =
                    item.get_mut(key).and_then(|op| op.get_mut("security"))
                {
                    requirements.retain(|r| {
                        r.as_object()
                            .is_some_and(|o| o.keys().all(|name| !name.starts_with("admin")))
                    });
                }
            }
        }
    }

    // Tags.
    if let Some(tags) = spec.get_mut("tags").and_then(Value::as_array_mut) {
        tags.retain(|t| t["name"] != ADMIN_TAG);
    }

    // Components that nothing left refers to. Security schemes are kept only
    // if a remaining operation names them.
    let used = reachable_refs(&spec);
    let used_schemes = used_security_schemes(&spec);
    if let Some(components) = spec.get_mut("components").and_then(Value::as_object_mut) {
        for (kind, entries) in components.iter_mut() {
            let Some(entries) = entries.as_object_mut() else {
                continue;
            };
            if kind == "securitySchemes" {
                entries.retain(|name, _| used_schemes.contains(name));
            } else {
                entries.retain(|name, _| used.contains(&(kind.clone(), name.clone())));
            }
        }
    }
    spec
}

/// Names of the security schemes the operations still list.
fn used_security_schemes(spec: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(paths) = spec.get("paths").and_then(Value::as_object) {
        for item in paths.values().filter_map(Value::as_object) {
            for key in OPERATION_KEYS {
                let Some(reqs) = item
                    .get(key)
                    .and_then(|op| op.get("security"))
                    .and_then(Value::as_array)
                else {
                    continue;
                };
                for req in reqs.iter().filter_map(Value::as_object) {
                    out.extend(req.keys().cloned());
                }
            }
        }
    }
    out
}

/// Every `(kind, name)` of `#/components/<kind>/<name>` that the paths refer
/// to, directly or through other components.
fn reachable_refs(spec: &Value) -> BTreeSet<(String, String)> {
    fn note(
        value: &Value,
        seen: &mut BTreeSet<(String, String)>,
        pending: &mut Vec<(String, String)>,
    ) {
        let mut found = Vec::new();
        collect_refs(value, &mut found);
        for r in found {
            if seen.insert(r.clone()) {
                pending.push(r);
            }
        }
    }

    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut pending: Vec<(String, String)> = Vec::new();
    if let Some(paths) = spec.get("paths") {
        note(paths, &mut seen, &mut pending);
    }
    while let Some((kind, name)) = pending.pop() {
        if let Some(entry) = spec
            .get("components")
            .and_then(|c| c.get(&kind))
            .and_then(|k| k.get(&name))
        {
            note(entry, &mut seen, &mut pending);
        }
    }
    seen
}

fn collect_refs(value: &Value, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                match (k.as_str(), v.as_str()) {
                    ("$ref", Some(target)) => {
                        if let Some(rest) = target.strip_prefix("#/components/") {
                            if let Some((kind, name)) = rest.split_once('/') {
                                out.push((kind.to_string(), name.to_string()));
                            }
                        }
                    }
                    _ => collect_refs(v, out),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|v| collect_refs(v, out)),
        _ => {}
    }
}

/// Every `(method, path)` the document describes, methods upper-case.
#[cfg(test)]
pub fn operations(spec: &Value) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    if let Some(paths) = spec.get("paths").and_then(Value::as_object) {
        for (path, item) in paths {
            for key in OPERATION_KEYS {
                if item.get(key).is_some() {
                    out.insert((key.to_ascii_uppercase(), path.clone()));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
