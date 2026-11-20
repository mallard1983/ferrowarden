use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::audit::{build_entry, Outcome};
use crate::api::credentials::authenticate_agent;
use crate::error::{FerroError, FerroResult};
use crate::proxy::{extract_placeholder_names, forward_request, substitute};
use crate::proxy::forward::{ProxyRequest, ZeroizingHeaders};
use crate::state::AppState;
use crate::vault::VaultClient;

#[derive(Deserialize)]
pub struct ForwardPayload {
    pub request: ProxyRequest,
}

/// POST /v1/forward
///
/// The agent sends a fully-formed API request with {{vault:name}} placeholders.
/// Ferrowarden substitutes real credentials, forwards to the target, scrubs the
/// response, and returns it. The agent never sees credential values.
pub async fn forward(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ForwardPayload>,
) -> FerroResult<Json<crate::proxy::forward::ProxyResponse>> {
    // Authenticate the agent first — before touching the vault or making any
    // outbound connections
    let agent = authenticate_agent(&state, &headers).await?;

    if state.is_locked().await {
        state.audit.record(build_entry(
            &agent.id,
            &agent.name,
            &payload.request.method,
            &payload.request.url,
            vec![],
            Outcome::VaultLocked,
            None,
        )).await;
        return Err(FerroError::VaultLocked);
    }

    let req = payload.request;

    // Build a single string containing all substitutable content so we can
    // extract placeholder names in one pass: URL + header values + body
    let header_values: String = req.headers.values().cloned().collect::<Vec<_>>().join("\n");
    let body_str = req.body
        .as_ref()
        .map(|b| b.to_string())
        .unwrap_or_default();
    let combined = format!("{}\n{}\n{}", req.url, header_values, body_str);

    let known_names = state.credential_names.read().await.clone();

    // Extract placeholder names for the audit log before substitution
    let placeholder_names: Vec<String> = extract_placeholder_names(&combined)
        .unwrap_or_default()
        .into_iter()
        .collect();

    let vault = VaultClient::new(state.config.bw_serve_url.clone());

    // Substitute placeholders in URL, headers, and body independently.
    // Each substituted value is Zeroizing and wiped when the binding is dropped.
    let subst_url = substitute(&req.url, &vault, &known_names).await
        .map_err(|e| {
            let _ = record_failed(&state, &agent, &req.method, &req.url, &placeholder_names, &e);
            e
        })?;

    let mut subst_headers: ZeroizingHeaders = HashMap::new();
    for (k, v) in &req.headers {
        let subst_val = substitute(v, &vault, &known_names).await
            .map_err(|e| {
                let _ = record_failed(&state, &agent, &req.method, &req.url, &placeholder_names, &e);
                e
            })?;
        subst_headers.insert(k.clone(), subst_val);
    }

    let subst_body: Option<Zeroizing<String>> = match &req.body {
        Some(b) => {
            let s = substitute(&b.to_string(), &vault, &known_names).await
                .map_err(|e| {
                    let _ = record_failed(&state, &agent, &req.method, &req.url, &placeholder_names, &e);
                    e
                })?;
            Some(s)
        }
        None => None,
    };

    // Forward the substituted request — all Zeroizing values are dropped
    // inside forward_request after the outbound call completes
    let response = forward_request(
        &req.method,
        subst_url.as_str(),
        subst_headers,
        subst_body,
    ).await
    .map_err(|e| {
        let _ = record_failed(&state, &agent, &req.method, &req.url, &placeholder_names, &e);
        e
    })?;

    // Record successful audit entry
    state.audit.record(build_entry(
        &agent.id,
        &agent.name,
        &req.method,
        &req.url,
        placeholder_names,
        Outcome::Success,
        Some(response.status),
    )).await;

    Ok(Json(response))
}

/// Fire-and-forget audit entry for failed requests.
/// Returns () so it can be called from map_err closures without propagating.
fn record_failed(
    state: &Arc<AppState>,
    agent: &crate::state::AgentKey,
    method: &str,
    url: &str,
    credential_names: &[String],
    error: &FerroError,
) -> () {
    let outcome = match error {
        FerroError::VaultLocked => Outcome::VaultLocked,
        FerroError::UnknownPlaceholder(_) | FerroError::CredentialNotFound(_) => Outcome::UnknownCredential,
        FerroError::ForwardFailed(_) | FerroError::InvalidTargetUrl(_) => Outcome::ForwardFailed,
        _ => Outcome::InternalError,
    };

    let entry = build_entry(
        &agent.id,
        &agent.name,
        method,
        url,
        credential_names.to_vec(),
        outcome,
        None,
    );

    // Spawn a task so we don't need to await in a non-async context
    let audit = state.audit.clone();
    tokio::spawn(async move {
        audit.record(entry).await;
    });
}
