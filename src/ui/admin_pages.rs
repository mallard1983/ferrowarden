//! The key and audit pages of the admin UI (phase 2).
//!
//! Every key operation goes through `api::key_service`, the same code the
//! JSON admin API uses; this module only turns forms into typed input and
//! results into pages. Rules that hold for every handler here:
//!
//! * a session is required; a POST also needs the same-origin proof and the
//!   session's CSRF token, and its form is parsed strictly (an allow-list of
//!   fields, none repeated);
//! * creating a key, revoking one and saving a policy need a sign-in within
//!   the sudo window, checked on the GET of the form **and** on the POST;
//! * everything shown goes through askama's escaping; names from the vault,
//!   key names and event contents are never trusted;
//! * a new token is rendered once, in the response to the POST that created
//!   the key: never in a redirect, URL, event or log line;
//! * the create form carries a single-use id, so reloading or re-sending the
//!   page that follows it cannot create a second key;
//! * a Save or Create after the sudo window ran out parks the draft (see
//!   `ui::drafts`) and restores it, unsaved, after the next sign-in.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use askama::Template;
use axum::{
    body::Body,
    extract::{Extension, Path, Request, State},
    http::{HeaderMap, StatusCode, Uri},
};
use zeroize::{Zeroize, Zeroizing};

use crate::api::key_service::{self, AuditFilter, Caller, KeySummary, Preview, Via};
use crate::approvals::ApprovalNeed;
use crate::error::FerroError;
use crate::events::{Action, Outcome};
use crate::middleware::request_context::RequestContext;
use crate::policy::{KeyPolicy, Patch, METHODS};
use crate::proxy::forward::ProxyRequest;
use crate::ui::drafts::{DraftTarget, RequestDraft, SavedDraft};
use crate::ui::handlers::{page, status_page, Reply};
use crate::ui::pages::{
    ApprovalRow, AuditPage, AuditRow, CredRow, DraftForm, KeyFacts, KeyFormUsedPage, KeyNewPage,
    KeyPage, KeyRevokePage, KeyRow, KeyTokenPage, KeysPage, LimitOpt, MethodBox, Nav,
    NotifyTestRow, NotifyTestView, Opt, PolicyView, PreviewView, RequestCheckView,
};
use crate::ui::session::{secrets_equal, SessionView};
use crate::ui::web::{
    is_form_content_type, origin_ok, parse_form, parse_form_limited, read_body, safe_next, Form,
    Transport, MAX_ADMIN_FORM_BYTES,
};
use crate::ui::{lock, UiState};

const MSG_BAD: &str = "The request could not be understood.";
const MSG_FAILED: &str = "Ferrowarden could not complete that. See the logs and try again.";
const MSG_VAULT_LOCKED: &str =
    "The vault is locked, so the list of credentials is not available. Unlock it and try again.";

/// Credential patterns shown per key in the list before "and N more".
const PATTERNS_SHOWN: usize = 3;
/// Most header lines in a request check.
const MAX_REQUEST_HEADERS: usize = 50;
/// Audit page sizes (the first is not the default).
const AUDIT_LIMITS: [usize; 3] = [25, 100, 500];
const AUDIT_DEFAULT_LIMIT: usize = 100;

/// Shown above the editor when a parked draft was put back.
const NOTICE_DRAFT_RESTORED: &str =
    "Your unsaved changes were restored. Review them and save again.";
/// Shown when the draft a sign-in came back for is gone.
const NOTICE_DRAFT_EXPIRED: &str =
    "The unsaved changes could not be restored: they expired, were already restored, or were made from another address. This is the saved policy.";

const NOTICE_DRAFT_EXPIRED_NEW: &str = "The unsaved form could not be restored: it expired, was \
already restored, or was made from another address. Fill in the form again.";

const NEW_FIELDS: [&str; 14] = [
    "csrf",
    "form_id",
    "name",
    "credentials",
    "approval",
    "create",
    "m_GET",
    "m_HEAD",
    "m_POST",
    "m_PUT",
    "m_PATCH",
    "m_DELETE",
    "m_OPTIONS",
    "m_all",
];

const EDIT_FIELDS: [&str; 18] = [
    "csrf",
    "op",
    "confirm",
    "credentials",
    "approval",
    "create",
    "m_GET",
    "m_HEAD",
    "m_POST",
    "m_PUT",
    "m_PATCH",
    "m_DELETE",
    "m_OPTIONS",
    "m_all",
    "req_method",
    "req_url",
    "req_headers",
    "req_body",
];

// -- Shared plumbing ------------------------------------------------------------

pub(super) fn nav<'a>(
    ui: &UiState,
    current: &'a str,
    email: &'a str,
    view: &'a SessionView,
) -> Option<Nav<'a>> {
    Some(Nav {
        current,
        pending_approvals: ui.pending_approvals(),
        account_email: email,
        csrf: &view.csrf,
    })
}

/// Steps of every POST here: same-origin proof, a session, the strictly
/// parsed form, the CSRF token. `allowed` must contain `csrf`.
pub(super) async fn begin_post(
    ui: &UiState,
    ctx: &RequestContext,
    transport: &Transport,
    request: Request,
    endpoint: &'static str,
    allowed: &[&str],
) -> Result<(SessionView, Form), Reply> {
    let (parts, body) = request.into_parts();
    let headers = &parts.headers;
    if !origin_ok(headers, transport) {
        return Err(ui.forbidden(ctx, endpoint, "origin_check_failed"));
    }
    let view = ui.require_session(headers, ctx)?;
    let Some(mut form) = read_admin_form(headers, body, allowed).await else {
        return Err(bad_request(ui, &view).await);
    };
    let csrf_ok = form
        .take("csrf")
        .is_some_and(|field| secrets_equal(&view.csrf, &field));
    if !csrf_ok {
        return Err(ui.forbidden(ctx, endpoint, "csrf_check_failed"));
    }
    Ok((view, form))
}

async fn read_admin_form(headers: &HeaderMap, body: Body, allowed: &[&str]) -> Option<Form> {
    if !is_form_content_type(headers) {
        return None;
    }
    let bytes = read_body(body, MAX_ADMIN_FORM_BYTES).await.ok()?;
    parse_form_limited(&bytes, allowed, MAX_ADMIN_FORM_BYTES).ok()
}

async fn bad_request(ui: &UiState, view: &SessionView) -> Reply {
    ui.message_in(
        view,
        StatusCode::BAD_REQUEST,
        "Bad request",
        MSG_BAD,
        Some(("/ui/keys", "Keys")),
    )
    .await
}

async fn not_found(ui: &UiState, view: &SessionView) -> Reply {
    ui.message_in(
        view,
        StatusCode::NOT_FOUND,
        "Not found",
        "There is no such key.",
        Some(("/ui/keys", "Keys")),
    )
    .await
}

async fn failed(ui: &UiState, view: &SessionView, e: &FerroError) -> Reply {
    match e {
        FerroError::AgentKeyNotFound => not_found(ui, view).await,
        FerroError::VaultLocked => {
            ui.message_in(
                view,
                StatusCode::SERVICE_UNAVAILABLE,
                "Vault locked",
                MSG_VAULT_LOCKED,
                Some(("/ui/keys", "Keys")),
            )
            .await
        }
        _ => {
            ui.message_in(
                view,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                MSG_FAILED,
                Some(("/ui/keys", "Keys")),
            )
            .await
        }
    }
}

/// The text shown next to a form for a validation error. Only the policy and
/// name validators' own fixed messages: they never contain input.
fn validation_text(e: &FerroError) -> Option<String> {
    match e {
        FerroError::InvalidRequest(message) => Some(message.clone()),
        _ => None,
    }
}

/// A draft id from the URL: base64url, as `random_token` makes them.
fn valid_token(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A key id from the URL: the UUIDs we generate, nothing else.
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub(super) fn caller(ctx: &RequestContext) -> Caller<'_> {
    Caller { ctx, via: Via::Ui }
}

pub(super) fn fmt_time(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%d %H:%M UTC").to_string()
}

/// `["*"]` reads "all methods", `[]` "none".
fn methods_label(methods: &[String]) -> String {
    match methods {
        [] => "none".to_string(),
        [one] if one == "*" => "all methods (*)".to_string(),
        many => many.join(", "),
    }
}

/// The same as chips: `none`, `all (*)`, or one per method.
fn method_chips(methods: &[String]) -> Vec<String> {
    match methods {
        [] => vec!["none".to_string()],
        [one] if one == "*" => vec!["all (*)".to_string()],
        many => many.to_vec(),
    }
}

/// The notice behind `?m=`: a fixed list, never echoed.
fn notice_text(code: &str) -> Option<&'static str> {
    match code {
        "saved" => Some("Policy saved. It applies to the very next request."),
        "revoked" => Some("Key revoked. Its token no longer works."),
        _ => None,
    }
}

fn notice_from_query(uri: &Uri) -> Option<&'static str> {
    uri.query()
        .and_then(|q| parse_form(q.as_bytes(), &["m"]).ok())
        .and_then(|mut f| f.take("m"))
        .and_then(|m| notice_text(&m))
}

// -- The policy form --------------------------------------------------------------

/// One line per pattern, blank lines ignored, each trimmed.
fn split_patterns(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// A policy draft as the form carries it.
struct Draft {
    patterns: Vec<String>,
    /// Credential patterns that need approval for the key.
    approval: Vec<String>,
    /// Credential name patterns the key may create in the managed collection.
    create: Vec<String>,
    /// Upper-case method names, plus `*` when "all methods" is ticked.
    methods: Vec<String>,
    checked: Vec<bool>,
    all: bool,
}

impl Draft {
    /// Read `credentials`, `m_<METHOD>` and `m_all`. A checkbox value other
    /// than the `1` the form sends is a malformed request.
    fn from_form(form: &mut Form) -> Result<Self, ()> {
        let text = form
            .take("credentials")
            .map(|v| v.to_string())
            .unwrap_or_default();
        let patterns = split_patterns(&text);
        let approval = split_patterns(
            &form
                .take("approval")
                .map(|v| v.to_string())
                .unwrap_or_default(),
        );
        let create = split_patterns(
            &form
                .take("create")
                .map(|v| v.to_string())
                .unwrap_or_default(),
        );
        let mut methods = Vec::new();
        let mut checked = Vec::new();
        for m in METHODS {
            let on = flag(form, &format!("m_{m}"))?;
            if on {
                methods.push(m.to_string());
            }
            checked.push(on);
        }
        let all = flag(form, "m_all")?;
        if all {
            methods.push("*".to_string());
        }
        Ok(Self {
            patterns,
            approval,
            create,
            methods,
            checked,
            all,
        })
    }

    /// The draft for a key's saved policy (empty for a key without one).
    fn from_key(key: &KeySummary) -> Self {
        let (patterns, methods, approval, create) = if key.policy_set {
            (
                key.credentials.clone(),
                key.methods.clone(),
                key.approval.clone(),
                key.create.clone(),
            )
        } else {
            (Vec::new(), Vec::new(), Vec::new(), Vec::new())
        };
        let all = methods.iter().any(|m| m == "*");
        let checked = METHODS
            .iter()
            .map(|m| methods.iter().any(|x| x == m))
            .collect();
        Self {
            patterns,
            approval,
            create,
            methods,
            checked,
            all,
        }
    }

    /// An empty draft (the blank create form).
    fn blank() -> Self {
        Self {
            patterns: Vec::new(),
            approval: Vec::new(),
            create: Vec::new(),
            methods: Vec::new(),
            checked: vec![false; METHODS.len()],
            all: false,
        }
    }

    /// The draft a parked [`SavedDraft`] holds.
    fn from_saved(saved: &SavedDraft) -> Self {
        let mut checked = saved.checked.clone();
        checked.resize(METHODS.len(), false);
        let mut methods: Vec<String> = METHODS
            .iter()
            .zip(&checked)
            .filter(|(_, on)| **on)
            .map(|(m, _)| m.to_string())
            .collect();
        if saved.all_methods {
            methods.push("*".to_string());
        }
        Self {
            patterns: saved.patterns.clone(),
            approval: saved.approval.clone(),
            create: saved.create.clone(),
            methods,
            checked,
            all: saved.all_methods,
        }
    }

    /// What to park when the sign-in has to be repeated first.
    fn to_saved(
        &self,
        target: DraftTarget,
        name: &str,
        request: Option<&RequestFields>,
    ) -> SavedDraft {
        SavedDraft {
            target,
            name: name.to_string(),
            patterns: self.patterns.clone(),
            approval: self.approval.clone(),
            create: self.create.clone(),
            checked: self.checked.clone(),
            all_methods: self.all,
            request: request.map(|r| RequestDraft {
                method: r.method.clone(),
                url: Zeroizing::new(r.url.clone()),
                headers: Zeroizing::new(r.headers.clone()),
                body: Zeroizing::new(r.body.clone()),
            }),
        }
    }

    fn method_boxes(&self) -> Vec<MethodBox> {
        METHODS
            .iter()
            .zip(&self.checked)
            .map(|(m, on)| MethodBox {
                field: format!("m_{m}"),
                label: m,
                checked: *on,
            })
            .collect()
    }

    fn patterns_text(&self) -> String {
        self.patterns.join("\n")
    }

    fn approval_text(&self) -> String {
        self.approval.join("\n")
    }

    fn create_text(&self) -> String {
        self.create.join("\n")
    }
}

/// A checkbox field: absent = off, `1` = on, anything else is an error.
fn flag(form: &mut Form, name: &str) -> Result<bool, ()> {
    match form.take(name) {
        None => Ok(false),
        Some(v) if v.as_str() == "1" => Ok(true),
        Some(_) => Err(()),
    }
}

/// The request-check part of the edit form.
#[derive(Default)]
struct RequestFields {
    method: String,
    url: String,
    headers: String,
    body: String,
}

impl RequestFields {
    fn from_form(form: &mut Form) -> Result<Self, ()> {
        let text = |form: &mut Form, name: &str| {
            form.take(name).map(|v| v.to_string()).unwrap_or_default()
        };
        let method = text(form, "req_method");
        let method = if method.is_empty() {
            "GET".to_string()
        } else {
            method
        };
        if !METHODS.contains(&method.as_str()) {
            return Err(());
        }
        Ok(Self {
            method,
            url: text(form, "req_url"),
            headers: text(form, "req_headers"),
            body: text(form, "req_body"),
        })
    }

    fn from_saved(saved: &SavedDraft) -> Self {
        match &saved.request {
            Some(r) => Self {
                method: r.method.clone(),
                url: r.url.to_string(),
                headers: r.headers.to_string(),
                body: r.body.to_string(),
            },
            None => Self::default(),
        }
    }

    fn method_options(&self) -> Vec<Opt> {
        let current = if self.method.is_empty() {
            "GET"
        } else {
            &self.method
        };
        METHODS
            .iter()
            .map(|m| Opt {
                value: m.to_string(),
                selected: *m == current,
            })
            .collect()
    }

    /// Build the request to check. The headers are `Name: value` lines,
    /// parsed strictly: at most 50, names without spaces, no repeated name
    /// in any letter case. The body is sent as a raw string. Errors are
    /// fixed texts that quote nothing.
    fn to_request(&self) -> Result<ProxyRequest, &'static str> {
        let url = self.url.trim();
        if url.is_empty() {
            return Err("Enter a URL to check.");
        }
        let mut headers = HashMap::new();
        let mut seen = std::collections::HashSet::new();
        for line in self
            .headers
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
        {
            if headers.len() >= MAX_REQUEST_HEADERS {
                return Err("At most 50 headers can be checked.");
            }
            let Some((name, value)) = line.split_once(':') else {
                return Err("Each header line must look like Name: value.");
            };
            let name = name.trim();
            if name.is_empty() || name.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err("Each header line must look like Name: value.");
            }
            if !seen.insert(name.to_ascii_lowercase()) {
                return Err("A header name may appear only once (names are not case-sensitive).");
            }
            headers.insert(name.to_string(), value.trim().to_string());
        }
        let body = if self.body.is_empty() {
            None
        } else {
            Some(serde_json::Value::String(self.body.clone()))
        };
        Ok(ProxyRequest {
            method: self.method.clone(),
            url: url.to_string(),
            headers,
            body,
        })
    }
}

// -- Keys list ----------------------------------------------------------------------

pub async fn keys_list(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    uri: Uri,
) -> Reply {
    let view = match ui.require_session(&headers, &ctx) {
        Ok(view) => view,
        Err(redirect) => return redirect,
    };
    let mut keys = key_service::list_keys(&ui.app, caller(&ctx)).await;
    keys.sort_by(|a, b| {
        (a.name.to_lowercase(), &a.name, &a.id).cmp(&(b.name.to_lowercase(), &b.name, &b.id))
    });
    let rows = keys
        .iter()
        .map(|k| KeyRow {
            id: k.id.clone(),
            short_id: k.id.chars().take(8).collect(),
            name: k.name.clone(),
            created: fmt_time(k.created_at),
            policy_set: k.policy_set,
            method_chips: method_chips(&k.methods),
            shown: k.credentials.iter().take(PATTERNS_SHOWN).cloned().collect(),
            more: k.credentials.len().saturating_sub(PATTERNS_SHOWN),
            count: k.credentials.len(),
        })
        .collect();
    let email = ui.account_email().await.unwrap_or_default();
    page(
        StatusCode::OK,
        KeysPage {
            css_path: &ui.css_path,
            nav: nav(&ui, "keys", &email, &view),
            sudo: ui.sudo_info(&view),
            notice: notice_from_query(&uri),
            rows,
        }
        .render(),
    )
}

// -- Create ---------------------------------------------------------------------------

/// What the create form shows besides the key's own fields.
struct NewForm<'a> {
    status: StatusCode,
    notice: Option<&'a str>,
    error: Option<&'a str>,
    name: &'a str,
    draft: &'a Draft,
    /// The single-use id this form submits.
    form_id: &'a str,
}

fn new_form_page(ui: &UiState, view: &SessionView, email: &str, form: NewForm<'_>) -> Reply {
    page(
        form.status,
        KeyNewPage {
            css_path: &ui.css_path,
            nav: nav(ui, "keys", email, view),
            sudo: ui.sudo_info(view),
            csrf: &view.csrf,
            form_id: form.form_id,
            notice: form.notice,
            error: form.error,
            name: form.name,
            patterns: &form.draft.patterns_text(),
            approval: &form.draft.approval_text(),
            create: &form.draft.create_text(),
            methods: form.draft.method_boxes(),
            all_methods: form.draft.all,
        }
        .render(),
    )
}

/// A fresh single-use id for the create form of this session.
fn issue_form_id(ui: &UiState, view: &SessionView) -> Option<Zeroizing<String>> {
    lock(&ui.sessions).issue_form_id(view)
}

/// The page for a create POST whose form id is unknown or used up: nothing
/// is created, and the token of a key made by the first submission is not
/// shown again.
async fn form_used(ui: &UiState, view: &SessionView) -> Reply {
    let email = ui.account_email().await.unwrap_or_default();
    page(
        StatusCode::CONFLICT,
        KeyFormUsedPage {
            css_path: &ui.css_path,
            nav: nav(ui, "keys", &email, view),
        }
        .render(),
    )
}

/// Park an unsaved draft and send the browser to sign in again, to come back
/// to the draft's URL. Without room for a draft (RNG failure) it is the plain
/// redirect to sign in, which comes back to the form itself.
fn park_and_redirect(
    ui: &UiState,
    ctx: &RequestContext,
    view: &SessionView,
    saved: SavedDraft,
) -> Reply {
    let target = saved.target.clone();
    let parked = lock(&ui.drafts).park(saved, ctx.client_ip, ui.now());
    let plain = match &target {
        DraftTarget::NewKey => "/ui/keys/new".to_string(),
        DraftTarget::Key(id) => format!("/ui/keys/{id}"),
    };
    let next = match parked {
        Some(draft_id) => match &target {
            DraftTarget::NewKey => format!("/ui/keys/new/draft/{}", draft_id.as_str()),
            DraftTarget::Key(id) => format!("/ui/keys/{id}/draft/{}", draft_id.as_str()),
        },
        None => plain.clone(),
    };
    // The draft URL has to pass the same validator as any `next`; if it ever
    // did not, the plain page is the safe fallback.
    let next = if safe_next(&next).is_some() {
        next
    } else {
        plain
    };
    match ui.require_sudo(view, &next) {
        Err(redirect) => redirect,
        // Cannot happen (the caller saw a stale sign-in); go to the page.
        Ok(()) => Reply::redirect(&next),
    }
}

pub async fn key_new_get(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    headers: HeaderMap,
) -> Reply {
    let view = match ui.require_session(&headers, &ctx) {
        Ok(view) => view,
        Err(redirect) => return redirect,
    };
    if let Err(redirect) = ui.require_sudo(&view, "/ui/keys/new") {
        return redirect;
    }
    let email = ui.account_email().await.unwrap_or_default();
    let Some(form_id) = issue_form_id(&ui, &view) else {
        return failed(&ui, &view, &FerroError::Internal("no random id".into())).await;
    };
    new_form_page(
        &ui,
        &view,
        &email,
        NewForm {
            status: StatusCode::OK,
            notice: None,
            error: None,
            name: "",
            draft: &Draft::blank(),
            form_id: &form_id,
        },
    )
}

/// The create form after a sign-in that came back for a parked draft:
/// pre-filled, not submitted.
pub async fn key_new_draft(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(draft_id): Path<String>,
) -> Reply {
    let view = match ui.require_session(&headers, &ctx) {
        Ok(view) => view,
        Err(redirect) => return redirect,
    };
    let saved = if valid_token(&draft_id) {
        lock(&ui.drafts).take(&draft_id, &DraftTarget::NewKey, ctx.client_ip, ui.now())
    } else {
        None
    };
    let email = ui.account_email().await.unwrap_or_default();
    let Some(form_id) = issue_form_id(&ui, &view) else {
        return failed(&ui, &view, &FerroError::Internal("no random id".into())).await;
    };
    let (notice, name, draft) = match &saved {
        Some(s) => (NOTICE_DRAFT_RESTORED, s.name.as_str(), Draft::from_saved(s)),
        None => (NOTICE_DRAFT_EXPIRED_NEW, "", Draft::blank()),
    };
    new_form_page(
        &ui,
        &view,
        &email,
        NewForm {
            status: StatusCode::OK,
            notice: Some(notice),
            error: None,
            name,
            draft: &draft,
            form_id: &form_id,
        },
    )
}

pub async fn key_new_post(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    Extension(transport): Extension<Transport>,
    request: Request,
) -> Reply {
    let (view, mut form) =
        match begin_post(&ui, &ctx, &transport, request, "/ui/keys/new", &NEW_FIELDS).await {
            Ok(ok) => ok,
            Err(reply) => return reply,
        };
    let form_id = form
        .take("form_id")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let name = form.take("name").map(|v| v.to_string()).unwrap_or_default();
    let Ok(draft) = Draft::from_form(&mut form) else {
        return bad_request(&ui, &view).await;
    };

    // An id that is unknown, used up or from another session creates
    // nothing, whatever else is in the form.
    if !lock(&ui.sessions).form_id_valid(&view, &form_id) {
        return form_used(&ui, &view).await;
    }
    // A stale sign-in: keep what was typed and come back to it, unsaved.
    if !view.sudo_active(ui.now()) {
        return park_and_redirect(
            &ui,
            &ctx,
            &view,
            draft.to_saved(DraftTarget::NewKey, &name, None),
        );
    }
    // Use the id up before creating, so of two racing submissions only one
    // creates a key.
    if !lock(&ui.sessions).consume_form_id(&view, &form_id) {
        return form_used(&ui, &view).await;
    }

    let created = key_service::create_key(
        &ui.app,
        caller(&ctx),
        &name,
        draft.patterns.clone(),
        draft.methods.clone(),
        draft.approval.clone(),
        draft.create.clone(),
    )
    .await;
    let email = ui.account_email().await.unwrap_or_default();
    match created {
        Ok(mut created) => {
            // Rendered straight into this response: no redirect, no URL, so
            // the token is in no history and no log. The page and the
            // service's own copy are all there is.
            let reply = page(
                StatusCode::OK,
                KeyTokenPage {
                    css_path: &ui.css_path,
                    nav: nav(&ui, "keys", &email, &view),
                    id: &created.id,
                    name: &created.name,
                    token: &created.token,
                    credentials: &created.credentials,
                    methods: &methods_label(&created.methods),
                    approval: &created.approval,
                    create: &created.create,
                }
                .render(),
            );
            created.token.zeroize();
            reply
        }
        Err(e) => {
            // Nothing was created: the form on screen stays usable.
            lock(&ui.sessions).restore_form_id(&view, &form_id);
            match validation_text(&e) {
                Some(text) => new_form_page(
                    &ui,
                    &view,
                    &email,
                    NewForm {
                        status: StatusCode::BAD_REQUEST,
                        notice: None,
                        error: Some(&text),
                        name: &name,
                        draft: &draft,
                        form_id: &form_id,
                    },
                ),
                None => failed(&ui, &view, &e).await,
            }
        }
    }
}

// -- View and edit a key -------------------------------------------------------------

/// What the key page shows besides the key itself.
#[derive(Default)]
struct KeyExtras {
    notice: Option<&'static str>,
    error: Option<String>,
    preview: Option<PreviewView>,
    check: Option<RequestCheckView>,
    confirm: bool,
    status: StatusCode,
}

fn key_page(
    ui: &UiState,
    view: &SessionView,
    email: &str,
    key: &KeySummary,
    draft: &Draft,
    request: &RequestFields,
    extras: KeyExtras,
) -> Reply {
    page(
        extras.status,
        KeyPage {
            css_path: &ui.css_path,
            nav: nav(ui, "keys", email, view),
            sudo: ui.sudo_info(view),
            csrf: &view.csrf,
            key: KeyFacts {
                id: key.id.clone(),
                name: key.name.clone(),
                created: fmt_time(key.created_at),
                policy_set: key.policy_set,
                credentials: key.credentials.clone(),
                methods: methods_label(&key.methods),
                approval: key.approval.clone(),
                create: key.create.clone(),
            },
            notice: extras.notice,
            error: extras.error.as_deref(),
            form: DraftForm {
                patterns: draft.patterns_text(),
                approval: draft.approval_text(),
                create: draft.create_text(),
                methods: draft.method_boxes(),
                all_methods: draft.all,
                req_methods: request.method_options(),
                req_url: request.url.clone(),
                req_headers: request.headers.clone(),
                req_body: request.body.clone(),
            },
            preview: extras.preview,
            check: extras.check,
            confirm: extras.confirm,
        }
        .render(),
    )
}

fn policy_view(p: &KeyPolicy) -> PolicyView {
    PolicyView {
        credentials: p.credentials.clone(),
        methods: methods_label(&p.methods),
        approval: p.approval.clone(),
        create: p.create.clone(),
    }
}

/// `vault field`, `key policy` or both, for one credential that needs approval.
fn approval_row(need: &ApprovalNeed) -> ApprovalRow {
    let mut why = Vec::new();
    if need.reasons.vault_field {
        why.push("vault field");
    }
    if need.reasons.key_policy {
        why.push("key policy");
    }
    ApprovalRow {
        name: need.item.clone(),
        why: why.join(" and "),
    }
}

/// Split a preview into what the template shows.
fn views(p: Preview) -> (PreviewView, Option<RequestCheckView>) {
    let widens = p.widens();
    let Preview {
        saved,
        draft,
        credentials,
        gained,
        lost,
        approval_required,
        request_check,
        ..
    } = p;
    let creds = credentials
        .into_iter()
        .map(|d| CredRow {
            gained: gained.contains(&d.name),
            d,
        })
        .collect();
    let check = request_check.map(|c| RequestCheckView {
        allowed: c.allowed,
        status: c.status.unwrap_or(200),
        reason: serde_json::to_value(c.reason)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default(),
        message: c.message.unwrap_or_default(),
        note: key_service::DNS_NOTE,
        approval: c.approval.iter().map(approval_row).collect(),
    });
    (
        PreviewView {
            saved: policy_view(&saved),
            draft: policy_view(&draft),
            gained,
            lost,
            creds,
            approval_required: approval_required.iter().map(approval_row).collect(),
            widens,
        },
        check,
    )
}

pub async fn key_get(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
) -> Reply {
    let view = match ui.require_session(&headers, &ctx) {
        Ok(view) => view,
        Err(redirect) => return redirect,
    };
    if !valid_id(&id) {
        return not_found(&ui, &view).await;
    }
    let Ok(key) = key_service::get_key(&ui.app, &id).await else {
        return not_found(&ui, &view).await;
    };
    let email = ui.account_email().await.unwrap_or_default();
    key_page(
        &ui,
        &view,
        &email,
        &key,
        &Draft::from_key(&key),
        &RequestFields::default(),
        KeyExtras {
            notice: notice_from_query(&uri),
            ..KeyExtras::default()
        },
    )
}

/// The editor after a sign-in that came back for a parked draft: the draft is
/// in the form, nothing is saved. A draft that is gone (expired, used,
/// another address) gives the saved policy and says so.
pub async fn key_draft(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path((id, draft_id)): Path<(String, String)>,
) -> Reply {
    let view = match ui.require_session(&headers, &ctx) {
        Ok(view) => view,
        Err(redirect) => return redirect,
    };
    if !valid_id(&id) {
        return not_found(&ui, &view).await;
    }
    let Ok(key) = key_service::get_key(&ui.app, &id).await else {
        return not_found(&ui, &view).await;
    };
    let saved = if valid_token(&draft_id) {
        lock(&ui.drafts).take(
            &draft_id,
            &DraftTarget::Key(id.clone()),
            ctx.client_ip,
            ui.now(),
        )
    } else {
        None
    };
    let email = ui.account_email().await.unwrap_or_default();
    let (notice, draft, request) = match &saved {
        Some(s) => (
            NOTICE_DRAFT_RESTORED,
            Draft::from_saved(s),
            RequestFields::from_saved(s),
        ),
        None => (
            NOTICE_DRAFT_EXPIRED,
            Draft::from_key(&key),
            RequestFields::default(),
        ),
    };
    key_page(
        &ui,
        &view,
        &email,
        &key,
        &draft,
        &request,
        KeyExtras {
            notice: Some(notice),
            ..KeyExtras::default()
        },
    )
}

pub async fn key_post(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    Extension(transport): Extension<Transport>,
    Path(id): Path<String>,
    request: Request,
) -> Reply {
    let (view, mut form) = match begin_post(
        &ui,
        &ctx,
        &transport,
        request,
        "/ui/keys/{id}",
        &EDIT_FIELDS,
    )
    .await
    {
        Ok(ok) => ok,
        Err(reply) => return reply,
    };
    if !valid_id(&id) {
        return not_found(&ui, &view).await;
    }
    let op = form.take("op").map(|v| v.to_string());
    let confirm = match flag(&mut form, "confirm") {
        Ok(c) => c,
        Err(()) => return bad_request(&ui, &view).await,
    };
    let Ok(draft) = Draft::from_form(&mut form) else {
        return bad_request(&ui, &view).await;
    };
    let Ok(request) = RequestFields::from_form(&mut form) else {
        return bad_request(&ui, &view).await;
    };
    let op = match op.as_deref() {
        Some(op @ ("check" | "request" | "save")) => op,
        _ => return bad_request(&ui, &view).await,
    };

    let Ok(key) = key_service::get_key(&ui.app, &id).await else {
        return not_found(&ui, &view).await;
    };
    let email = ui.account_email().await.unwrap_or_default();
    let render = |status, extras| {
        key_page(
            &ui,
            &view,
            &email,
            &key,
            &draft,
            &request,
            KeyExtras { status, ..extras },
        )
    };
    let invalid = |text: String| {
        render(
            StatusCode::BAD_REQUEST,
            KeyExtras {
                error: Some(text),
                ..KeyExtras::default()
            },
        )
    };

    match op {
        "check" | "request" => {
            let proxy_request = if op == "request" {
                match request.to_request() {
                    Ok(r) => Some(r),
                    Err(text) => return invalid(text.to_string()),
                }
            } else {
                None
            };
            let preview = key_service::preview_key(
                &ui.app,
                caller(&ctx),
                &id,
                Patch::Value(draft.patterns.clone()),
                Patch::Value(draft.methods.clone()),
                Patch::Value(draft.approval.clone()),
                Patch::Value(draft.create.clone()),
                proxy_request.as_ref(),
            )
            .await;
            match preview {
                Ok(preview) => {
                    let (preview, check) = views(preview);
                    render(
                        StatusCode::OK,
                        KeyExtras {
                            preview: Some(preview),
                            check,
                            ..KeyExtras::default()
                        },
                    )
                }
                Err(e) => match validation_text(&e) {
                    Some(text) => invalid(text),
                    None => failed(&ui, &view, &e).await,
                },
            }
        }
        _ => {
            // Save. Sudo first: a stale sign-in never gets as far as a diff.
            // What was typed is parked, and comes back unsaved after the
            // sign-in.
            if !view.sudo_active(ui.now()) {
                return park_and_redirect(
                    &ui,
                    &ctx,
                    &view,
                    draft.to_saved(DraftTarget::Key(id.clone()), "", Some(&request)),
                );
            }
            let saved = KeyPolicy {
                credentials: key.credentials.clone(),
                methods: key.methods.clone(),
                approval: key.approval.clone(),
                create: key.create.clone(),
            };
            let new_policy = match saved.patched(
                Patch::Value(draft.patterns.clone()),
                Patch::Value(draft.methods.clone()),
                Patch::Value(draft.approval.clone()),
                Patch::Value(draft.create.clone()),
            ) {
                Ok(p) => p,
                Err(e) => {
                    return match validation_text(&e) {
                        Some(text) => invalid(text),
                        None => failed(&ui, &view, &e).await,
                    }
                }
            };
            // A change that gives the key more access is shown, and has to
            // be confirmed, before it is saved. The test needs no vault: it
            // is by pattern, so it also covers credentials added later.
            if !confirm && saved.is_widened_by(&new_policy) {
                // The diff against the vault is a courtesy: a locked vault
                // still gets the confirmation, without it.
                let diff = key_service::compute_preview(
                    &ui.app,
                    &id,
                    Patch::Value(draft.patterns.clone()),
                    Patch::Value(draft.methods.clone()),
                    Patch::Value(draft.approval.clone()),
                    Patch::Value(draft.create.clone()),
                    None,
                )
                .await
                .ok()
                .map(|p| views(p).0);
                return render(
                    StatusCode::OK,
                    KeyExtras {
                        preview: diff,
                        confirm: true,
                        ..KeyExtras::default()
                    },
                );
            }
            match key_service::patch_key(
                &ui.app,
                caller(&ctx),
                &id,
                Patch::Value(draft.patterns.clone()),
                Patch::Value(draft.methods.clone()),
                Patch::Value(draft.approval.clone()),
                Patch::Value(draft.create.clone()),
            )
            .await
            {
                Ok(_) => Reply::redirect(&format!("/ui/keys/{id}?m=saved")),
                Err(e) => match validation_text(&e) {
                    Some(text) => invalid(text),
                    None => failed(&ui, &view, &e).await,
                },
            }
        }
    }
}

// -- Revoke -----------------------------------------------------------------------------

pub async fn revoke_get(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Reply {
    let view = match ui.require_session(&headers, &ctx) {
        Ok(view) => view,
        Err(redirect) => return redirect,
    };
    if !valid_id(&id) {
        return not_found(&ui, &view).await;
    }
    if let Err(redirect) = ui.require_sudo(&view, &format!("/ui/keys/{id}/revoke")) {
        return redirect;
    }
    let Ok(key) = key_service::get_key(&ui.app, &id).await else {
        return not_found(&ui, &view).await;
    };
    let email = ui.account_email().await.unwrap_or_default();
    page(
        StatusCode::OK,
        KeyRevokePage {
            css_path: &ui.css_path,
            nav: nav(&ui, "keys", &email, &view),
            sudo: ui.sudo_info(&view),
            csrf: &view.csrf,
            id: &key.id,
            name: &key.name,
        }
        .render(),
    )
}

pub async fn revoke_post(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    Extension(transport): Extension<Transport>,
    Path(id): Path<String>,
    request: Request,
) -> Reply {
    let (view, _form) = match begin_post(
        &ui,
        &ctx,
        &transport,
        request,
        "/ui/keys/{id}/revoke",
        &["csrf"],
    )
    .await
    {
        Ok(ok) => ok,
        Err(reply) => return reply,
    };
    if !valid_id(&id) {
        return not_found(&ui, &view).await;
    }
    if let Err(redirect) = ui.require_sudo(&view, &format!("/ui/keys/{id}/revoke")) {
        return redirect;
    }
    match key_service::revoke_key(&ui.app, caller(&ctx), &id).await {
        Ok(_) => Reply::redirect("/ui/keys?m=revoked"),
        Err(e) => failed(&ui, &view, &e).await,
    }
}

// -- Test notification ----------------------------------------------------------------------

/// `POST /ui/notify/test`: send a test notification to every enabled sender
/// and show what each one answered on the status page. A session, the
/// same-origin proof and the CSRF token are required; no sign-in within the
/// sudo window, since it changes nothing and at most one test is sent every
/// ten seconds.
pub async fn notify_test_post(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    Extension(transport): Extension<Transport>,
    request: Request,
) -> Reply {
    let (view, _form) =
        match begin_post(&ui, &ctx, &transport, request, "/ui/notify/test", &["csrf"]).await {
            Ok(ok) => ok,
            Err(reply) => return reply,
        };
    let test = match crate::api::admin::run_notify_test(&ui.app, &ctx, "ui").await {
        Ok(results) => NotifyTestView {
            wait: None,
            rows: results
                .into_iter()
                .map(|r| NotifyTestRow {
                    sender: r.sender,
                    ok: r.ok,
                    detail: match (r.ok, r.status, r.error) {
                        (true, Some(status), _) => format!("HTTP {status}"),
                        (_, _, Some(error)) => error,
                        _ => String::new(),
                    },
                })
                .collect(),
        },
        Err(wait) => NotifyTestView {
            wait: Some(wait),
            rows: Vec::new(),
        },
    };
    status_page(&ui, &view, &transport, Some(test)).await
}

// -- Audit ---------------------------------------------------------------------------------

pub async fn audit_get(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    uri: Uri,
) -> Reply {
    let view = match ui.require_session(&headers, &ctx) {
        Ok(view) => view,
        Err(redirect) => return redirect,
    };
    // Unknown or repeated parameters are an error, not first-wins.
    let parsed = parse_form(
        uri.query().unwrap_or("").as_bytes(),
        &["action", "outcome", "key", "ip", "limit"],
    );
    let Ok(mut query) = parsed else {
        return bad_request(&ui, &view).await;
    };
    let mut text = |name: &str| {
        query
            .take(name)
            .map(|v| v.to_string())
            .filter(|v| !v.is_empty())
    };
    let (action, outcome, key, ip, limit) = (
        text("action"),
        text("outcome"),
        text("key"),
        text("ip"),
        text("limit"),
    );

    let filter = (|| {
        let action = match &action {
            Some(a) => Some(Action::from_name(a)?),
            None => None,
        };
        let outcome = match &outcome {
            Some(o) => Some(Outcome::from_name(o)?),
            None => None,
        };
        let ip = match &ip {
            Some(i) => Some(i.parse::<IpAddr>().ok()?),
            None => None,
        };
        let limit = match &limit {
            Some(l) => l
                .parse::<usize>()
                .ok()
                .filter(|l| AUDIT_LIMITS.contains(l))?,
            None => AUDIT_DEFAULT_LIMIT,
        };
        if key.as_ref().is_some_and(|k| k.chars().count() > 128) {
            return None;
        }
        Some((
            AuditFilter {
                action,
                outcome,
                key: key.clone(),
                ip,
            },
            limit,
        ))
    })();
    let Some((filter, limit)) = filter else {
        return bad_request(&ui, &view).await;
    };

    let events = key_service::read_audit(&ui.app, caller(&ctx), limit, &filter);
    let rows = events
        .iter()
        .map(|e| AuditRow {
            // Readable and short enough not to wrap; the exact RFC 3339
            // timestamp is in the event JSON under Details.
            time: e.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            action: e.event.action.as_str().to_string(),
            outcome: e.event.outcome.as_str().to_string(),
            reason: e
                .event
                .reason
                .and_then(|r| serde_json::to_value(r).ok())
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default(),
            key_name: e
                .ferrowarden
                .key
                .as_ref()
                .map(|k| k.name.clone())
                .unwrap_or_default(),
            ip: e
                .source
                .as_ref()
                .map(|s| s.ip.to_string())
                .unwrap_or_default(),
            method: e
                .http
                .as_ref()
                .and_then(|h| h.request.as_ref())
                .map(|r| r.method.clone())
                .unwrap_or_default(),
            host: e
                .url
                .as_ref()
                .and_then(|u| u.domain.clone())
                .unwrap_or_default(),
            status: e
                .http
                .as_ref()
                .and_then(|h| h.response.as_ref())
                .map(|r| r.status_code.to_string())
                .unwrap_or_default(),
            request_id: e.ferrowarden.request_id.clone().unwrap_or_default(),
            json: serde_json::to_string_pretty(&**e).unwrap_or_default(),
        })
        .collect();

    let selected_action = filter.action;
    let selected_outcome = filter.outcome;
    let email = ui.account_email().await.unwrap_or_default();
    page(
        StatusCode::OK,
        AuditPage {
            css_path: &ui.css_path,
            nav: nav(&ui, "audit", &email, &view),
            rows,
            actions: Action::ALL
                .iter()
                .map(|a| Opt {
                    value: a.as_str().to_string(),
                    selected: selected_action == Some(*a),
                })
                .collect(),
            outcomes: [Outcome::Success, Outcome::Failure, Outcome::Unknown]
                .iter()
                .map(|o| Opt {
                    value: o.as_str().to_string(),
                    selected: selected_outcome == Some(*o),
                })
                .collect(),
            limits: AUDIT_LIMITS
                .iter()
                .map(|l| LimitOpt {
                    value: *l,
                    selected: *l == limit,
                })
                .collect(),
            key: filter.key.as_deref().unwrap_or(""),
            ip: ip.as_deref().unwrap_or(""),
        }
        .render(),
    )
}
