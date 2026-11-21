use axum::{extract::State, http::HeaderMap, Json};
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

use crate::api::credentials::authenticate_agent;
use crate::api::strict_json::StrictJson;
use crate::error::{FerroError, FerroResult};
use crate::events::{emit_rejected, Action, SecurityEvent};
use crate::middleware::request_context::RequestContext;
use crate::policy::KeyPolicy;
use crate::proxy::forward::{ProxyRequest, ZeroizingHeaders};
use crate::proxy::placeholder::{self, Placeholder};
use crate::proxy::{
    check_credentials, fetch_credentials, forward_request, substitute_json, substitute_str,
    zeroize_json, CredentialPlan, ForwardLimits,
};
use crate::state::AppState;
use crate::vault::refresh::reunlock_if_possible;
use crate::vault::VaultClient;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    ctx: RequestContext,
    headers: HeaderMap,
    body: Result<StrictJson<ForwardPayload>, FerroError>,
) -> FerroResult<Json<crate::proxy::forward::ProxyResponse>> {
    const ENDPOINT: &str = "/v1/forward";
    // Authenticate the agent first — before looking at the body (so a caller
    // without a valid key learns nothing from parse errors), touching the
    // vault or making any outbound connections.
    let agent = authenticate_agent(&state, &ctx, &headers, ENDPOINT).await?;
    let payload = match body {
        Ok(StrictJson(payload)) => payload,
        Err(e) => {
            emit_rejected(&state.events, &ctx, Some(&agent), ENDPOINT, &e);
            return Err(e);
        }
    };
    let req = payload.request;

    // Parse every placeholder (URL, header values, body) before anything
    // else. A malformed one is rejected here rather than forwarded literally.
    let collected = req.validate().and_then(|()| collect_placeholders(&req));
    let names = collected.as_ref().cloned().unwrap_or_default();
    // Audit labels: the canonical placeholder text, e.g. `grafana_token` or
    // `'Proxmox (prod)':username` — never values.
    let placeholder_names: Vec<String> = names.iter().map(Placeholder::label).collect();

    // The key's policy is enforced here, before run_forward: so before any
    // vault access, target check or DNS lookup. The checks see only the
    // method and the placeholder names the agent sent, never the vault, which
    // is what keeps an out-of-scope name from revealing whether it exists.
    let mut result = match collected {
        Ok(_) => match agent.policy.check_request(&req.normalized_method(), &names) {
            Ok(()) => run_forward(&state, &req, &names).await,
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    };

    if let Err(FerroError::VaultLocked) = &result {
        // bw serve is locked — typically it restarted. Reflect that so
        // /v1/admin/status is honest, and in file mode unlock it again now and
        // retry once rather than failing until the next refresh. The retry
        // cannot duplicate an outbound call: VaultLocked only ever occurs
        // before anything is sent to the target.
        state.set_locked("forward_vault_locked").await;
        if reunlock_if_possible(&state).await {
            result = run_forward(&state, &req, &names).await;
        }
    }

    // One event per forward, whatever happened. `url` is the agent's URL
    // before substitution, so it holds placeholders, never values.
    let event = SecurityEvent::new(Action::Forward)
        .request(&ctx)
        .key(&agent)
        .method(&req.method)
        .url(&req.url)
        .credentials(&placeholder_names)
        .duration(ctx.started.elapsed());
    state.events.emit(match &result {
        Ok(resp) => event.status(resp.status),
        Err(e) => event.failed_with(e).status(e.status_code().as_u16()),
    });

    result.map(Json)
}

/// Every distinct placeholder in the request's URL, header values and body.
pub(crate) fn collect_placeholders(req: &ProxyRequest) -> FerroResult<BTreeSet<Placeholder>> {
    let mut out = BTreeSet::new();
    placeholder::collect(&req.url, &mut out)?;
    for v in req.headers.values() {
        placeholder::collect(v, &mut out)?;
    }
    if let Some(body) = &req.body {
        placeholder::collect_json(body, &mut out)?;
    }
    Ok(out)
}

/// Everything `/v1/forward` checks without touching the vault or the network
/// beyond the policy's own IP-literal test: the vault state, the target URL
/// against the outbound policy, and every placeholder against the cached item
/// metadata. Returns the parsed target and the plan of what to fetch.
///
/// With `preview` set, a locked vault is tolerated when a credential cache
/// exists (the policy preview answers from the cache); a real forward needs
/// the vault unlocked.
async fn prepare(
    state: &Arc<AppState>,
    req: &ProxyRequest,
    names: &BTreeSet<Placeholder>,
    preview: bool,
) -> FerroResult<(Url, CredentialPlan)> {
    if state.is_locked().await && !(preview && !state.credentials.read().await.is_empty()) {
        return Err(FerroError::VaultLocked);
    }

    // Parse the URL *before* substitution. Placeholders are not valid in a
    // host, so this also pins the scheme/host/port the credentials are bound to.
    let target = Url::parse(&req.url)
        .map_err(|_| FerroError::InvalidTargetUrl("URL could not be parsed (placeholders are only allowed in the path, query, or user info)".to_string()))?;
    state.target_policy.check_url(&target).await?;

    // Validate every placeholder (item exists and is unambiguous, no re-prompt,
    // selected value/field exists, bound to this host) before fetching any value.
    let plan = {
        let credentials = state.credentials.read().await;
        check_credentials(
            names,
            &credentials,
            &target,
            state.config.enforce_credential_hosts,
        )?
    };
    Ok((target, plan))
}

/// Run every check `/v1/forward` would run for `req` under `policy`, in the
/// same order, without fetching a value or opening a connection. Used by the
/// policy preview. (Name-based hosts are additionally checked at DNS
/// resolution time, which only happens when a request is really forwarded.)
pub(crate) async fn check_only(
    state: &Arc<AppState>,
    policy: &KeyPolicy,
    req: &ProxyRequest,
) -> FerroResult<()> {
    req.validate()?;
    let names = collect_placeholders(req)?;
    policy.check_request(&req.normalized_method(), &names)?;
    prepare(state, req, &names, true).await.map(|_| ())
}

async fn run_forward(
    state: &Arc<AppState>,
    req: &ProxyRequest,
    names: &BTreeSet<Placeholder>,
) -> FerroResult<crate::proxy::forward::ProxyResponse> {
    let (target, plan) = prepare(state, req, names, false).await?;
    let vault = VaultClient::new(state.config.bw_serve_url.clone());
    let values = fetch_credentials(&plan, &vault).await?;

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

    // Exact-value scrubbing covers secrets only: usernames, TOTP codes and
    // boolean fields are excluded (see `Resolved::scrub`).
    let secrets: Vec<&str> = values
        .values()
        .filter(|r| r.scrub)
        .map(|r| r.value.as_str())
        .collect();
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
