use axum::{extract::State, http::HeaderMap, Json};
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

use crate::api::credentials::authenticate_agent;
use crate::audit::{build_entry, Outcome};
use crate::error::{FerroError, FerroResult};
use crate::proxy::forward::{ProxyRequest, ZeroizingHeaders};
use crate::proxy::{
    extract_json_placeholder_names, extract_placeholder_names, forward_request,
    resolve_credentials, substitute_json, substitute_str, zeroize_json, ForwardLimits,
};
use crate::state::AppState;
use crate::vault::VaultClient;

#[derive(Deserialize)]
pub struct ForwardPayload {
    pub request: ProxyRequest,
}

/// POST /v1/forward
///
/// The agent sends a fully-formed API request with {{vault:name}} placeholders.
/// Ferrowarden checks the target against the outbound policy and each
/// credential's host binding, substitutes real credentials, forwards to the
/// target, scrubs the response, and returns it. The agent never sees
/// credential values.
pub async fn forward(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ForwardPayload>,
) -> FerroResult<Json<crate::proxy::forward::ProxyResponse>> {
    // Authenticate the agent first — before touching the vault or making any
    // outbound connections
    let agent = authenticate_agent(&state, &headers).await?;
    let req = payload.request;

    // Collect every placeholder name for the audit log before doing anything else.
    let mut names: HashSet<String> = extract_placeholder_names(&req.url);
    for v in req.headers.values() {
        names.extend(extract_placeholder_names(v));
    }
    if let Some(body) = &req.body {
        extract_json_placeholder_names(body, &mut names);
    }
    let mut placeholder_names: Vec<String> = names.iter().cloned().collect();
    placeholder_names.sort();

    let result = run_forward(&state, &req, &names).await;

    let (outcome, status) = match &result {
        Ok(resp) => (Outcome::Success, Some(resp.status)),
        Err(e) => (outcome_for(e), None),
    };
    state
        .audit
        .record(build_entry(
            &agent.id,
            &agent.name,
            &req.method,
            &req.url,
            placeholder_names,
            outcome,
            status,
        ))
        .await;

    if let Err(FerroError::VaultLocked) = &result {
        // bw serve locked behind our back (e.g. restarted). Reflect it so
        // /v1/admin/status is honest; the refresher re-unlocks in file mode.
        state.set_locked().await;
    }

    result.map(Json)
}

async fn run_forward(
    state: &Arc<AppState>,
    req: &ProxyRequest,
    names: &HashSet<String>,
) -> FerroResult<crate::proxy::forward::ProxyResponse> {
    if state.is_locked().await {
        return Err(FerroError::VaultLocked);
    }

    // Parse the URL *before* substitution. Placeholders are not valid in a
    // host, so this also pins the scheme/host/port the credentials are bound to.
    let target = Url::parse(&req.url)
        .map_err(|_| FerroError::InvalidTargetUrl("URL could not be parsed (placeholders are only allowed in the path, query, or user info)".to_string()))?;
    state.target_policy.check_url(&target).await?;

    let credentials = state.credentials.read().await.clone();
    let vault = VaultClient::new(state.config.bw_serve_url.clone());

    // Validate every name (exists, unambiguous, bound to this host) before
    // fetching any value.
    let values = resolve_credentials(
        names,
        &credentials,
        &target,
        state.config.enforce_credential_hosts,
        &vault,
    )
    .await?;

    // URL: substitute, then require the scheme/host/port to be unchanged.
    let subst_url = substitute_str(&req.url, &values);
    let subst_target = Url::parse(subst_url.as_str()).map_err(|_| {
        FerroError::InvalidTargetUrl("URL is invalid after credential substitution".to_string())
    })?;
    if subst_target.scheme() != target.scheme()
        || subst_target.host_str() != target.host_str()
        || subst_target.port_or_known_default() != target.port_or_known_default()
    {
        return Err(FerroError::InvalidTargetUrl(
            "placeholders may not change the URL scheme, host, or port".to_string(),
        ));
    }

    let mut subst_headers: ZeroizingHeaders = HashMap::new();
    for (k, v) in &req.headers {
        subst_headers.insert(k.clone(), substitute_str(v, &values));
    }

    // Body: a JSON string is sent as raw text; anything else is sent as JSON
    // with placeholders substituted inside its strings (never into the
    // serialized text, so values are escaped correctly).
    let subst_body: Option<Zeroizing<String>> = match &req.body {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(substitute_str(s, &values)),
        Some(other) => {
            let mut v = substitute_json(other, &values);
            let text = Zeroizing::new(
                serde_json::to_string(&v).map_err(|e| FerroError::Internal(e.to_string()))?,
            );
            zeroize_json(&mut v);
            if !subst_headers
                .keys()
                .any(|k| k.eq_ignore_ascii_case("content-type"))
            {
                subst_headers.insert(
                    "Content-Type".to_string(),
                    Zeroizing::new("application/json".to_string()),
                );
            }
            Some(text)
        }
    };

    let secrets: Vec<&str> = values.values().map(|v| v.as_str()).collect();
    let limits = ForwardLimits {
        timeout: Duration::from_secs(state.config.forward_timeout_secs),
        max_response_bytes: state.config.max_response_bytes,
    };

    forward_request(
        &req.method,
        &subst_target,
        subst_headers,
        subst_body,
        &secrets,
        &state.target_policy,
        &limits,
    )
    .await
    // `values`, `subst_url`, headers and body are Zeroizing and wiped on drop.
}

fn outcome_for(error: &FerroError) -> Outcome {
    match error {
        FerroError::VaultLocked => Outcome::VaultLocked,
        FerroError::UnknownPlaceholder(_)
        | FerroError::CredentialNotFound(_)
        | FerroError::AmbiguousCredential(_) => Outcome::UnknownCredential,
        FerroError::CredentialHostNotAllowed { .. } | FerroError::TargetBlocked(_) => {
            Outcome::Blocked
        }
        FerroError::ForwardFailed(_)
        | FerroError::InvalidTargetUrl(_)
        | FerroError::ResponseTooLarge(_) => Outcome::ForwardFailed,
        _ => Outcome::InternalError,
    }
}
