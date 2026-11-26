use axum::{extract::State, http::HeaderMap, Json};
use chrono::Utc;
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

use crate::api::credentials::authenticate_agent;
use crate::api::strict_json::StrictJson;
use crate::approvals::{self, ApprovalNeed, GateResult};
use crate::error::{FerroError, FerroResult};
use crate::events::{emit_rejected, Action, SecurityEvent};
use crate::middleware::request_context::RequestContext;
use crate::policy::KeyPolicy;
use crate::proxy::forward::{ProxyRequest, ProxyResponse, ZeroizingHeaders};
use crate::proxy::placeholder::{self, Collected, Placeholder};
use crate::proxy::scrub::Secret;
use crate::proxy::{
    check_credentials, fetch_credentials, render_response, send_request, substitute_json,
    substitute_str, zeroize_json, CredentialPlan, ForwardLimits,
};
use crate::sessions::{self, Capture, CaptureSpec, Origin, Owner};
use crate::state::{AgentKey, AppState};
use crate::vault::refresh::reunlock_if_possible;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardPayload {
    pub request: ProxyRequest,
    /// Values to keep inside Ferrowarden instead of showing them to the agent
    /// (docs/sessions.md). May be left out; `null` and `[]` are errors.
    #[serde(default, deserialize_with = "crate::sessions::present")]
    pub capture: Option<Vec<CaptureSpec>>,
}

/// POST /v1/forward
///
/// The agent sends a fully-formed API request with {{vault:name}} placeholders.
/// Ferrowarden checks the target against the outbound policy and each
/// credential's host binding, substitutes real credentials, forwards to the
/// target, scrubs the response, and returns it. The agent never sees
/// credential values.
///
/// With `capture`, values of the response (a login token) are kept in
/// Ferrowarden under a name, hidden from the agent, and later requests use
/// them as `{{session:name}}`.
///
/// A credential that needs a human's approval (its vault item says so, or the
/// key's policy does) is not fetched, and nothing is sent, until a human has
/// decided: the request is held for up to `approval.wait_secs`, then answered
/// `approval_pending` for the agent to retry (docs/approvals.md).
pub async fn forward(
    State(state): State<Arc<AppState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    body: Result<StrictJson<ForwardPayload>, FerroError>,
) -> FerroResult<Json<ProxyResponse>> {
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

    // Parse every placeholder (URL, header values, body) and every `capture`
    // entry before anything else. A malformed one is rejected here rather than
    // forwarded literally, and nothing has been sent.
    let (checked, captures, used) = match check_request(&state, &req, payload.capture.as_deref()) {
        Ok((captures, used)) => (Ok(()), captures, used),
        Err(e) => (Err(e), Vec::new(), Collected::default()),
    };
    // Audit labels: the canonical placeholder text, e.g. `grafana_token` or
    // `'Proxmox (prod)':username` — never values. Sessions are listed apart.
    let placeholder_names: Vec<String> = used.vault.iter().map(Placeholder::label).collect();
    let session_names: Vec<String> = used.sessions.iter().cloned().collect();

    // The key's policy is enforced here, before run_forward: so before any
    // vault access, target check or DNS lookup. The checks see only the
    // method and the placeholder names the agent sent, never the vault, which
    // is what keeps an out-of-scope name from revealing whether it exists.
    // Session names are not credential names and are not matched against the
    // credential patterns: a session can only ever be sent back to the origin
    // it came from, and the method policy applies as it does to any request.
    // What the approval gate did, if it ran: set by `run_forward` when the
    // request got through it; a refusal is read from the error.
    let mut gate_passed: Option<GateResult> = None;
    let mut result = match checked.and_then(|()| {
        agent
            .policy
            .check_request(&req.normalized_method(), &used.vault)
    }) {
        Ok(()) => {
            run_forward(
                &state,
                &agent,
                &ctx,
                &req,
                &used,
                &captures,
                &mut gate_passed,
            )
            .await
        }
        Err(e) => Err(e),
    };

    if let Err(FerroError::VaultLocked) = &result {
        // The vault is locked (the account's key changed, or it was locked
        // behind our back). Reflect that so
        // /v1/admin/status is honest, and in file mode unlock it again now and
        // retry once rather than failing until the next refresh. The retry
        // cannot duplicate an outbound call: VaultLocked only ever occurs
        // before anything is sent to the target.
        state.set_locked("forward_vault_locked").await;
        if reunlock_if_possible(&state).await {
            gate_passed = None;
            result = run_forward(
                &state,
                &agent,
                &ctx,
                &req,
                &used,
                &captures,
                &mut gate_passed,
            )
            .await;
        }
    }

    // One event per capture entry, and one for the use of sessions: names and
    // outcomes, never values.
    if let Ok(resp) = &result {
        for r in resp.captures.iter().flatten() {
            state.events.emit(
                sessions::capture_event(r)
                    .request(&ctx)
                    .key(&agent)
                    .url(&req.url),
            );
        }
    }
    if !session_names.is_empty() {
        let event = SecurityEvent::new(Action::SessionUse)
            .request(&ctx)
            .key(&agent)
            .url(&req.url)
            .sessions(&session_names);
        match &result {
            Ok(_) => state.events.emit(event),
            // The session was refused: say which way. Other failures say
            // nothing about the session, so they leave no `session_use`.
            Err(e @ (FerroError::UnknownSession(_) | FerroError::SessionHostNotAllowed { .. })) => {
                state.events.emit(event.failed_with(e));
            }
            Err(_) => {}
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
        .sessions(&session_names)
        .items(used.vault.iter().map(|p| p.item.as_str()))
        .duration(ctx.started.elapsed());
    // Whether the approval gate ran, and how it ended.
    let approval = match &result {
        Ok(_) => gate_passed.map(GateResult::as_str),
        Err(e) => approvals::refusal_result(e),
    };
    let event = match approval {
        Some(result) => event.detail("approval", result),
        None => event,
    };
    state.events.emit(match &result {
        Ok(resp) => event
            .response_bytes(resp.upstream_bytes)
            .status(resp.status),
        Err(e) => event.failed_with(e).status(e.status_code().as_u16()),
    });

    result.map(Json)
}

/// Everything about the body that can be checked on its own: the method and
/// headers, the `capture` entries, every placeholder (and that sessions are
/// switched on when they are used).
fn check_request(
    state: &AppState,
    req: &ProxyRequest,
    capture: Option<&[CaptureSpec]>,
) -> FerroResult<(Vec<Capture>, Collected)> {
    req.validate()?;
    let captures = sessions::parse_captures(capture, &state.config.sessions)?;
    let used = collect_placeholders(req)?;
    sessions::check_enabled(&state.config.sessions, &used.sessions)?;
    Ok((captures, used))
}

/// Every distinct placeholder in the request's URL, header values and body.
pub(crate) fn collect_placeholders(req: &ProxyRequest) -> FerroResult<Collected> {
    let mut out = Collected::default();
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
///
/// Session placeholders are checked for syntax, and for sessions being
/// switched on, but not against the session store: sessions are runtime state
/// of an agent key, not something a policy decides.
///
/// Returns the credentials of the request that would need approval under
/// `policy`, and why. A preview never creates an approval request.
pub(crate) async fn check_only(
    state: &Arc<AppState>,
    policy: &KeyPolicy,
    req: &ProxyRequest,
) -> FerroResult<Vec<ApprovalNeed>> {
    let (_, used) = check_request(state, req, None)?;
    policy.check_request(&req.normalized_method(), &used.vault)?;
    let (_, plan) = prepare(state, req, &used.vault, true).await?;
    Ok(approvals::needs(&approvals::required_items(
        policy,
        &plan.approval_fields(),
    )))
}

async fn run_forward(
    state: &Arc<AppState>,
    agent: &AgentKey,
    ctx: &RequestContext,
    req: &ProxyRequest,
    used: &Collected,
    captures: &[Capture],
    gate_passed: &mut Option<GateResult>,
) -> FerroResult<ProxyResponse> {
    let (target, plan) = prepare(state, req, &used.vault, false).await?;

    // Sessions: every name must be this key's own, live, and captured from the
    // origin this request goes to. Checked before a value is fetched and
    // before any connection is made.
    let origin = Origin::of(&target)
        .ok_or_else(|| FerroError::InvalidTargetUrl("URL has no host or port".to_string()))?;
    let session_values = state
        .sessions
        .resolve(&agent.id, &used.sessions, &origin, Utc::now())?;

    // Approval: the last check, after every other one (so nobody is asked
    // about a request that would be refused anyway) and before any value is
    // fetched or any connection is opened. A request that needs approval is
    // held here, or refused with `approval_pending` / `approval_denied`.
    let required = approvals::required_items(&agent.policy, &plan.approval_fields());
    if !required.is_empty() {
        *gate_passed = Some(
            approvals::gate(
                state,
                agent,
                ctx,
                &req.normalized_method(),
                &req.url,
                &origin,
                &required,
            )
            .await?,
        );
    }

    let values = fetch_credentials(&plan, &*state.vault).await?;

    // URL: substitute, then require the scheme/host/port to be unchanged.
    let subst_url = substitute_str(&req.url, &values, &session_values);
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
        subst_headers.insert(k.clone(), substitute_str(v, &values, &session_values));
    }

    // Body: a JSON string is sent as raw text; anything else is sent as JSON
    // with placeholders substituted inside its strings (never into the
    // serialized text, so values are escaped correctly).
    let subst_body: Option<Zeroizing<String>> = match &req.body {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(substitute_str(s, &values, &session_values)),
        Some(other) => {
            let mut v = substitute_json(other, &values, &session_values);
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

    let limits = ForwardLimits {
        timeout: Duration::from_secs(state.config.forward_timeout_secs),
        max_response_bytes: state.config.max_response_bytes,
    };

    let up = send_request(
        &req.method,
        &subst_target,
        subst_headers,
        subst_body,
        &state.target_policy,
        &limits,
    )
    .await?;

    // Captures read the raw answer, before anything is scrubbed, whatever the
    // status. A failed capture does not fail the request: the login already
    // happened at the target, so the agent still gets the (scrubbed) answer.
    let owner = Owner {
        key_id: &agent.id,
        key_name: &agent.name,
        origin: &origin,
    };
    let now = Utc::now();
    let mut results = Vec::with_capacity(captures.len());
    let mut unstored: Vec<Zeroizing<String>> = Vec::new();
    for c in captures {
        let outcome = sessions::capture(
            &state.sessions,
            &owner,
            c,
            &up,
            now,
            state.config.sessions.max_per_key,
        );
        results.push(outcome.result);
        unstored.extend(outcome.unstored);
    }

    // The scrub set. First every session value of this key (the ones just
    // captured included), whether or not this request used them: they come
    // back as `[CAPTURED:name]`. Then the vault values substituted into this
    // request, and finally values that were found at a capture source but
    // could not be stored. Exact-value scrubbing covers secrets only:
    // usernames, TOTP codes and boolean fields are excluded (see
    // `Resolved::scrub`).
    let session_secrets = state.sessions.values_for_key(&agent.id);
    let session_labels: Vec<String> = session_secrets
        .iter()
        .map(|(name, _)| format!("[CAPTURED:{name}]"))
        .collect();
    let mut secrets: Vec<Secret<'_>> = session_secrets
        .iter()
        .zip(&session_labels)
        .map(|((_, value), label)| Secret {
            value: value.as_str(),
            replacement: label,
        })
        .collect();
    secrets.extend(
        values
            .values()
            .filter(|r| r.scrub)
            .map(|r| Secret::redacted(r.value.as_str())),
    );
    secrets.extend(unstored.iter().map(|v| Secret::redacted(v.as_str())));

    let mut response = render_response(&up, &secrets);
    if !captures.is_empty() {
        response.captures = Some(results);
    }
    Ok(response)
    // `values`, `subst_url`, headers, body and the session values are
    // Zeroizing and wiped on drop.
}
