//! Route handlers of the admin UI.
//!
//! The order of checks in every POST is the same, and deliberate:
//! 1. origin (same-origin proof) -> 403,
//! 2. content type, size and strict parse of the form -> 400,
//! 3. CSRF token -> 403,
//! 4. lockouts -> 429 (before any key derivation or upstream call),
//! 5. only then the work.
//!
//! Vaultwarden's words never reach a page or an event: the pages say one of a
//! few fixed things.

use std::sync::Arc;

use askama::Template;
use axum::{
    body::Body,
    extract::{Extension, Path, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use zeroize::Zeroizing;

use crate::events::{Action, Outcome, Reason, SecurityEvent};
use crate::middleware::request_context::RequestContext;
use crate::ui::crypto::{self, Kdf};
use crate::ui::lockout::LockedBy;
use crate::ui::pages::{
    InsecurePage, LoginPage, MessagePage, Nav, NotifySenderRow, NotifyTestView, NotifyView,
    ProviderOption, StatusPage, SudoInfo, TwoFactorPage,
};
use crate::ui::session::{
    random_token, secrets_equal, Lookup, PendingCheck, PendingLogin, SessionView,
};
use crate::ui::vw_login::{LoginOutcome, Provider, TwoFactorRequired, VwError};
use crate::ui::web::{
    clear_cookie, cookie_value, is_form_content_type, origin_ok, parse_form, read_body, safe_next,
    set_cookie, Form, Transport, LOGIN_COOKIE, LOGIN_COOKIE_MAX_AGE, MAX_FORM_BYTES,
    PENDING_COOKIE, PENDING_COOKIE_MAX_AGE, SESSION_COOKIE,
};
use crate::ui::{lock, UiState};
use crate::vault::Vault;

// ── Fixed texts ───────────────────────────────────────────────────────────────

const MSG_INVALID: &str = "Invalid password or code.";
const MSG_LOCKED: &str = "Too many attempts. Try again later.";
const MSG_BUSY: &str = "Another sign-in is being checked. Wait a moment and try again.";
const MSG_UPSTREAM: &str =
    "Ferrowarden could not complete the sign-in with Vaultwarden. Try again later.";
const MSG_REJECTED: &str = "The request was rejected. Go back, reload the page and try again.";
const MSG_BAD_REQUEST: &str = "The request could not be understood.";
const MSG_NO_SUPPORTED_FACTOR: &str = "This account requires a second factor that the admin UI \
cannot complete. The UI supports an authenticator app (TOTP), an email code or a YubiKey OTP. \
Add one of them to the account, or sign in another way.";

/// The `?m=` values the login page understands: a fixed list, never echoed.
fn login_notice(code: &str) -> Option<&'static str> {
    match code {
        "expired" => Some("That sign-in expired or was cancelled. Start again."),
        "failed" => Some(MSG_INVALID),
        "logged_out" => Some("You have been signed out."),
        "session" => Some("Your session ended. Sign in again."),
        "sudo" => Some("Sign in again to continue."),
        _ => None,
    }
}

// ── Response plumbing ─────────────────────────────────────────────────────────

pub struct Reply {
    pub(super) status: StatusCode,
    body: Option<String>,
    location: Option<String>,
    cookies: Vec<String>,
}

impl Reply {
    pub(super) fn html(status: StatusCode, body: String) -> Self {
        Self {
            status,
            body: Some(body),
            location: None,
            cookies: Vec::new(),
        }
    }

    pub(super) fn redirect(location: &str) -> Self {
        Self {
            status: StatusCode::SEE_OTHER,
            body: None,
            location: Some(location.to_string()),
            cookies: Vec::new(),
        }
    }

    pub(super) fn cookie(mut self, cookie: String) -> Self {
        self.cookies.push(cookie);
        self
    }

    pub(super) fn clear(self, name: &str) -> Self {
        self.cookie(clear_cookie(name))
    }
}

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        let has_body = self.body.is_some();
        let mut response = Response::new(match self.body {
            Some(body) => Body::from(body),
            None => Body::empty(),
        });
        *response.status_mut() = self.status;
        let headers = response.headers_mut();
        if has_body {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
        }
        if let Some(location) = self.location {
            if let Ok(value) = HeaderValue::from_str(&location) {
                headers.insert(header::LOCATION, value);
            }
        }
        for cookie in self.cookies {
            // Cookie values here are base64url tokens: always valid header text.
            if let Ok(value) = HeaderValue::from_str(&cookie) {
                headers.append(header::SET_COOKIE, value);
            }
        }
        response
    }
}

pub(super) fn page(status: StatusCode, rendered: askama::Result<String>) -> Reply {
    match rendered {
        Ok(body) => Reply::html(status, body),
        // Never show the template error: it could quote template source.
        Err(_) => Reply::html(
            StatusCode::INTERNAL_SERVER_ERROR,
            "<!doctype html><title>Error</title><h1>Internal error</h1>".to_string(),
        ),
    }
}

/// Plain page for a request that arrived over plain HTTP.
pub fn insecure_page(ui: &UiState) -> Response {
    page(
        StatusCode::BAD_REQUEST,
        InsecurePage {
            css_path: &ui.css_path,
            nav: None,
        }
        .render(),
    )
    .into_response()
}

impl UiState {
    pub(super) fn message(
        &self,
        status: StatusCode,
        heading: &str,
        message: &str,
        link: Option<(&str, &str)>,
    ) -> Reply {
        page(
            status,
            MessagePage {
                css_path: &self.css_path,
                nav: None,
                heading,
                message,
                link: link.map(|l| l.0),
                link_label: link.map(|l| l.1).unwrap_or(""),
            }
            .render(),
        )
    }

    pub(super) fn internal_error(&self) -> Reply {
        self.message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            "Ferrowarden could not process the request. Try again.",
            Some(("/ui/login", "Back to sign in")),
        )
    }

    fn back_to_login(&self, status: StatusCode, heading: &str, message: &str) -> Reply {
        self.message(
            status,
            heading,
            message,
            Some(("/ui/login", "Back to sign in")),
        )
    }

    // ── events ───────────────────────────────────────────────────────────────

    fn login_event(
        &self,
        ctx: &RequestContext,
        outcome: Outcome,
        reason: Option<Reason>,
        provider: Option<Provider>,
        status: StatusCode,
    ) {
        let mut event = SecurityEvent::new(Action::UiLogin)
            .request(ctx)
            .outcome(outcome)
            .status(status.as_u16());
        if let Some(reason) = reason {
            event = event.reason(reason);
        }
        if let Some(provider) = provider {
            event = event.detail("provider", provider.name());
        }
        self.app.events.emit(event);
    }

    fn locked_event(&self, ctx: &RequestContext, by: LockedBy, provider: Option<Provider>) {
        let mut event = SecurityEvent::new(Action::UiLogin)
            .request(ctx)
            .outcome(Outcome::Failure)
            .reason(Reason::LoginLockedOut)
            .status(StatusCode::TOO_MANY_REQUESTS.as_u16())
            .detail("scope", by.as_str());
        if let Some(provider) = provider {
            event = event.detail("provider", provider.name());
        }
        self.app.events.emit(event);
    }

    /// A POST refused for CSRF or origin reasons (403).
    pub(super) fn rejected_event(
        &self,
        ctx: &RequestContext,
        endpoint: &'static str,
        why: &'static str,
    ) {
        self.app.events.emit(
            SecurityEvent::new(Action::RequestRejected)
                .request(ctx)
                .reason(Reason::InvalidRequest)
                .status(StatusCode::FORBIDDEN.as_u16())
                .detail("endpoint", endpoint)
                .detail("error", why),
        );
    }

    pub(super) fn forbidden(
        &self,
        ctx: &RequestContext,
        endpoint: &'static str,
        why: &'static str,
    ) -> Reply {
        self.rejected_event(ctx, endpoint, why);
        self.message(
            StatusCode::FORBIDDEN,
            "Request rejected",
            MSG_REJECTED,
            Some(("/ui/login", "Back to sign in")),
        )
    }

    // ── pages ────────────────────────────────────────────────────────────────

    /// The pre-session CSRF token for a form: the browser's current one, so a
    /// second tab or a re-rendered page keeps working, or a fresh one. The
    /// cookie is (re)issued either way, which also renews its lifetime.
    fn login_token(headers: &HeaderMap) -> Option<Zeroizing<String>> {
        match cookie_value(headers, LOGIN_COOKIE) {
            Some(existing) if existing.len() == 43 => Some(Zeroizing::new(existing.to_string())),
            _ => random_token(),
        }
    }

    /// The login form.
    fn login_page(
        &self,
        headers: &HeaderMap,
        status: StatusCode,
        error: Option<&str>,
        notice: Option<&str>,
        next: Option<&str>,
    ) -> Reply {
        let Some(token) = Self::login_token(headers) else {
            return self.internal_error();
        };
        page(
            status,
            LoginPage {
                css_path: &self.css_path,
                csrf: &token,
                error,
                notice,
                next,
            }
            .render(),
        )
        .cookie(set_cookie(LOGIN_COOKIE, &token, Some(LOGIN_COOKIE_MAX_AGE)))
    }

    /// The second-factor form for the pending login `id`.
    fn twofa_page(
        &self,
        ctx: &RequestContext,
        headers: &HeaderMap,
        selected: Option<Provider>,
        status: StatusCode,
        error: Option<&str>,
        notice: Option<&str>,
    ) -> Reply {
        let now = self.now();
        let Some(pending_id) = cookie_value(headers, PENDING_COOKIE) else {
            return self.pending_gone(&PendingCheck::Missing);
        };
        let (providers, hint) = {
            let mut slot = lock(&self.pending);
            match slot.peek(pending_id, ctx.client_ip, now) {
                Ok(p) => (p.providers.clone(), p.email_hint.clone()),
                Err(check) => return self.pending_gone(&check),
            }
        };
        let selected = selected
            .filter(|s| providers.contains(s))
            .or_else(|| providers.first().copied());
        let Some(selected) = selected else {
            return self.internal_error();
        };
        let Some(token) = Self::login_token(headers) else {
            return self.internal_error();
        };
        let options = providers
            .iter()
            .map(|p| ProviderOption {
                id: p.id(),
                label: p.label(),
                selected: *p == selected,
            })
            .collect();
        page(
            status,
            TwoFactorPage {
                css_path: &self.css_path,
                csrf: &token,
                error,
                notice,
                providers: options,
                selected_id: selected.id(),
                selected_label: selected.label(),
                is_email: selected == Provider::Email,
                is_yubikey: selected == Provider::YubiKey,
                email_hint: if selected == Provider::Email {
                    hint.as_deref()
                } else {
                    None
                },
            }
            .render(),
        )
        .cookie(set_cookie(LOGIN_COOKIE, &token, Some(LOGIN_COOKIE_MAX_AGE)))
    }

    /// The pending login is gone, expired or belongs to another address: back
    /// to the password form with a fixed message. (The slot itself is left
    /// alone for a wrong-address request.)
    fn pending_gone(&self, _check: &PendingCheck) -> Reply {
        Reply::redirect("/ui/login?m=expired").clear(PENDING_COOKIE)
    }

    // ── sessions ─────────────────────────────────────────────────────────────

    /// Who is calling? Emits `ui_session_expired` when it finds a session
    /// that ran out.
    pub(super) fn authenticate(&self, headers: &HeaderMap, ctx: &RequestContext) -> Auth {
        let Some(id) = cookie_value(headers, SESSION_COOKIE) else {
            return Auth::None;
        };
        let lookup = lock(&self.sessions).lookup(id, self.now());
        match lookup {
            Lookup::Valid(view) => Auth::Session(view),
            Lookup::Expired => {
                self.app
                    .events
                    .emit(SecurityEvent::new(Action::UiSessionExpired).request(ctx));
                Auth::Expired
            }
            Lookup::Missing => Auth::None,
        }
    }

    /// A session, or the redirect that sends the browser to sign in.
    pub(super) fn require_session(
        &self,
        headers: &HeaderMap,
        ctx: &RequestContext,
    ) -> Result<SessionView, Reply> {
        match self.authenticate(headers, ctx) {
            Auth::Session(view) => Ok(view),
            Auth::Expired => Err(Reply::redirect("/ui/login?m=session").clear(SESSION_COOKIE)),
            Auth::None => Err(Reply::redirect("/ui/login")),
        }
    }

    /// The sudo window: a sensitive action needs a sign-in within the last
    /// ten minutes. If it is stale, the redirect to sign in again, which
    /// brings the browser back to `next` afterwards. Used on the GET of a
    /// sensitive form and on its POST.
    pub(super) fn require_sudo(&self, view: &SessionView, next: &str) -> Result<(), Reply> {
        if view.sudo_active(self.now()) {
            return Ok(());
        }
        // `next` is built from fixed paths and a validated key id; it goes
        // through the same validator as one read from the query, so the
        // redirect can never carry anything else.
        let target = match safe_next(next) {
            Some(next) => format!("/ui/login?m=sudo&next={next}"),
            None => "/ui/login?m=sudo".to_string(),
        };
        Err(Reply::redirect(&target))
    }

    /// "Signed in N minutes ago" and the sudo state, for pages with
    /// sensitive actions.
    pub(super) fn sudo_info(&self, view: &SessionView) -> SudoInfo {
        let now = self.now();
        let minutes = view.signed_in_minutes(now);
        SudoInfo {
            active: view.sudo_active(now),
            signed_in: match minutes {
                0 => "just now".to_string(),
                1 => "1 minute ago".to_string(),
                n => format!("{n} minutes ago"),
            },
        }
    }

    /// A message page inside the signed-in frame (with the navigation).
    pub(super) async fn message_in(
        &self,
        view: &SessionView,
        status: StatusCode,
        heading: &str,
        message: &str,
        link: Option<(&str, &str)>,
    ) -> Reply {
        let email = self.account_email().await.unwrap_or_default();
        page(
            status,
            MessagePage {
                css_path: &self.css_path,
                nav: Some(Nav {
                    current: "",
                    account_email: &email,
                    csrf: &view.csrf,
                }),
                heading,
                message,
                link: link.map(|l| l.0),
                link_label: link.map(|l| l.1).unwrap_or(""),
            }
            .render(),
        )
    }

    /// Start a session after a verified sign-in: new id (rotation), the old
    /// session and any pending login are gone, the login cookie is cleared.
    /// The browser goes to `next` if it passes `safe_next` again, else to
    /// the status page.
    fn start_session(
        &self,
        ctx: &RequestContext,
        headers: &HeaderMap,
        provider: Option<Provider>,
        next: Option<&str>,
    ) -> Reply {
        let now = self.now();
        let created = {
            let mut sessions = lock(&self.sessions);
            if let Some(old) = cookie_value(headers, SESSION_COOKIE) {
                sessions.destroy(old);
            }
            sessions.create(now)
        };
        let Some((id, _csrf)) = created else {
            return self.internal_error();
        };
        lock(&self.pending).clear();
        lock(&self.lockouts).record_success(ctx.client_ip);
        self.login_event(ctx, Outcome::Success, None, provider, StatusCode::SEE_OTHER);
        let target = next
            .and_then(safe_next)
            .unwrap_or_else(|| "/ui/".to_string());
        Reply::redirect(&target)
            .cookie(set_cookie(SESSION_COOKIE, &id, None))
            .clear(PENDING_COOKIE)
            .clear(LOGIN_COOKIE)
    }

    // ── form handling ────────────────────────────────────────────────────────

    /// Steps 2 of the POST order: content type, bounded read, strict parse.
    async fn read_form(
        &self,
        headers: &HeaderMap,
        body: Body,
        allowed: &[&str],
    ) -> Result<Form, Reply> {
        let bad =
            || Err(self.back_to_login(StatusCode::BAD_REQUEST, "Bad request", MSG_BAD_REQUEST));
        if !is_form_content_type(headers) {
            return bad();
        }
        let Ok(bytes) = read_body(body, MAX_FORM_BYTES).await else {
            return bad();
        };
        match parse_form(&bytes, allowed) {
            Ok(form) => Ok(form),
            Err(_) => bad(),
        }
    }
}

pub(super) enum Auth {
    Session(SessionView),
    Expired,
    None,
}

/// The pre-session CSRF check: the cookie value and the form field must match.
fn login_csrf_ok(headers: &HeaderMap, field: Option<&Zeroizing<String>>) -> bool {
    match (cookie_value(headers, LOGIN_COOKIE), field) {
        (Some(cookie), Some(field)) => secrets_equal(cookie, field),
        _ => false,
    }
}

// ── GET / and unknown paths ───────────────────────────────────────────────────

pub async fn root() -> Reply {
    Reply::redirect("/ui/")
}

pub async fn fallback(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    uri: Uri,
    headers: HeaderMap,
) -> Reply {
    let path = uri.path();
    if path == "/ui" || path.starts_with("/ui/") {
        return match ui.require_session(&headers, &ctx) {
            Ok(view) => {
                ui.message_in(
                    &view,
                    StatusCode::NOT_FOUND,
                    "Not found",
                    "There is nothing here.",
                    Some(("/ui/", "Status")),
                )
                .await
            }
            Err(redirect) => redirect,
        };
    }
    ui.message(
        StatusCode::NOT_FOUND,
        "Not found",
        "There is nothing here.",
        None,
    )
}

/// A static asset: no session needed, cached for a day. (`nosniff` and the
/// other security headers are added by the gate for every response.)
fn asset(body: Body, content_type: &'static str) -> Response {
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    response
}

/// `/ui/static/{file}`: the stylesheet (under its content-hashed name), the
/// font and the icons. Anything else is a 404.
pub async fn static_file(State(ui): State<Arc<UiState>>, Path(file): Path<String>) -> Response {
    if file == ui.css_path.rsplit('/').next().unwrap_or_default() {
        return asset(Body::from(crate::ui::CSS), "text/css; charset=utf-8");
    }
    match file.as_str() {
        crate::ui::FONT_FILE => asset(Body::from(crate::ui::FONT), "font/woff2"),
        "favicon.ico" => asset(Body::from(crate::ui::FAVICON_ICO), "image/x-icon"),
        "favicon-32.png" => asset(Body::from(crate::ui::FAVICON_32), "image/png"),
        "apple-touch-icon.png" => asset(Body::from(crate::ui::APPLE_TOUCH_ICON), "image/png"),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `/favicon.ico`: browsers ask for it at the root whatever the page says.
pub async fn favicon() -> Response {
    asset(Body::from(crate::ui::FAVICON_ICO), "image/x-icon")
}

// ── Status page ───────────────────────────────────────────────────────────────

pub async fn index(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    Extension(transport): Extension<Transport>,
    headers: HeaderMap,
) -> Reply {
    let view = match ui.authenticate(&headers, &ctx) {
        Auth::Session(view) => view,
        Auth::Expired => return Reply::redirect("/ui/login?m=session").clear(SESSION_COOKIE),
        Auth::None => return Reply::redirect("/ui/login"),
    };
    status_page(&ui, &view, &transport, None).await
}

/// The status page for a signed-in session. `test` is the outcome of a test
/// notification, shown above the Notifications section.
pub(super) async fn status_page(
    ui: &UiState,
    view: &SessionView,
    transport: &Transport,
    test: Option<NotifyTestView>,
) -> Reply {
    let email = ui.account_email().await.unwrap_or_default();
    let nav = Nav {
        current: "status",
        account_email: &email,
        csrf: &view.csrf,
    };
    let vault_locked = ui.app.is_locked().await;
    let credential_count = ui.app.credentials.read().await.len();
    let (key_count, keys_without_policy) = {
        let keys = ui.app.agent_keys.read().await;
        (keys.len(), keys.values().filter(|k| !k.policy_set).count())
    };
    let last_sync = ui
        .app
        .vault
        .status()
        .await
        .ok()
        .and_then(|s| s.last_sync)
        .unwrap_or_else(|| "unknown".to_string());
    let remaining = view.expires_at.saturating_duration_since(ui.now());
    let expires = chrono::Utc::now()
        + chrono::Duration::from_std(remaining).unwrap_or_else(|_| chrono::Duration::zero());
    let expires = expires.format("%Y-%m-%d %H:%M UTC").to_string();

    let snapshot = ui.app.notify.snapshot();
    let notify = NotifyView {
        enabled: snapshot.enabled(),
        sent: snapshot.sent(),
        failed: snapshot.failed(),
        suppressed: snapshot.suppressed,
        dropped: snapshot.dropped,
        categories: snapshot.categories.join(", "),
        senders: snapshot
            .senders
            .into_iter()
            .map(|s| NotifySenderRow {
                kind: s.kind,
                host: s.host,
                sent: s.sent,
                failed: s.failed,
            })
            .collect(),
        test,
    };

    page(
        StatusCode::OK,
        StatusPage {
            css_path: &ui.css_path,
            nav: Some(nav),
            account_email: &email,
            vault_locked,
            vault_backend: ui.app.vault.name(),
            credential_count,
            last_sync: &last_sync,
            version: env!("CARGO_PKG_VERSION"),
            https: transport.secure,
            api_tls: ui.app.config.tls_enabled,
            key_count,
            keys_without_policy,
            events_dropped: ui.app.events.dropped_total(),
            session_expires: &expires,
            csrf: &view.csrf,
            notify,
        }
        .render(),
    )
}

// ── Sign-in: password ─────────────────────────────────────────────────────────

pub async fn login_get(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    uri: Uri,
) -> Reply {
    // `?m=` picks a fixed message; `?next=` is where to go after signing in.
    // Anything else, or a bad `next`, is ignored.
    let (code, next) = match uri
        .query()
        .and_then(|q| parse_form(q.as_bytes(), &["m", "next"]).ok())
    {
        Some(mut f) => (f.take("m"), f.take("next").and_then(|n| safe_next(&n))),
        None => (None, None),
    };
    match ui.authenticate(&headers, &ctx) {
        Auth::Session(view) => {
            // A current sign-in needs no form. A stale one does when the
            // browser came for a specific page that needs a recent sign-in.
            match &next {
                Some(next) if view.sudo_active(ui.now()) => return Reply::redirect(next),
                Some(_) => {}
                None => return Reply::redirect("/ui/"),
            }
        }
        Auth::Expired => {
            return ui
                .login_page(
                    &headers,
                    StatusCode::OK,
                    None,
                    login_notice("session"),
                    next.as_deref(),
                )
                .clear(SESSION_COOKIE)
        }
        Auth::None => {}
    }
    let notice = code.and_then(|m| login_notice(&m));
    ui.login_page(&headers, StatusCode::OK, None, notice, next.as_deref())
}

pub async fn login_post(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    Extension(transport): Extension<Transport>,
    request: Request,
) -> Reply {
    let (parts, body) = request.into_parts();
    let headers = &parts.headers;

    if !origin_ok(headers, &transport) {
        return ui.forbidden(&ctx, "/ui/login", "origin_check_failed");
    }
    let mut form = match ui
        .read_form(headers, body, &["csrf", "password", "next"])
        .await
    {
        Ok(form) => form,
        Err(reply) => return reply,
    };
    let csrf = form.take("csrf");
    if !login_csrf_ok(headers, csrf.as_ref()) {
        return ui.forbidden(&ctx, "/ui/login", "csrf_check_failed");
    }
    let Some(password) = form.take("password") else {
        return ui.back_to_login(StatusCode::BAD_REQUEST, "Bad request", MSG_BAD_REQUEST);
    };
    // Validated again: the hidden field is as tamperable as a query string.
    let next = form.take("next").and_then(|n| safe_next(&n));
    drop(form);

    // Lockouts come first: no key derivation, no upstream call.
    let ip = ctx.client_ip;
    let locked = lock(&ui.lockouts).check_password(ip, ui.now());
    if let Err(by) = locked {
        ui.locked_event(&ctx, by, None);
        return ui.message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts",
            MSG_LOCKED,
            None,
        );
    }

    if password.is_empty() {
        return ui.login_page(
            headers,
            StatusCode::BAD_REQUEST,
            Some("Enter the master password."),
            None,
            next.as_deref(),
        );
    }

    // One verification at a time (see `UiState::login_gate`). A concurrent
    // submission is refused before any work; it is not counted as a failure.
    let Ok(_verifying) = ui.login_gate.try_acquire() else {
        ui.login_event(
            &ctx,
            Outcome::Failure,
            Some(Reason::LoginLockedOut),
            None,
            StatusCode::TOO_MANY_REQUESTS,
        );
        return ui.message(
            StatusCode::TOO_MANY_REQUESTS,
            "Sign-in busy",
            MSG_BUSY,
            None,
        );
    };

    let upstream_error = |status: StatusCode| {
        ui.login_event(
            &ctx,
            Outcome::Failure,
            Some(Reason::UpstreamError),
            None,
            status,
        );
        ui.back_to_login(status, "Sign-in unavailable", MSG_UPSTREAM)
    };
    let upstream_limited = || {
        ui.login_event(
            &ctx,
            Outcome::Failure,
            Some(Reason::UpstreamRateLimited),
            None,
            StatusCode::TOO_MANY_REQUESTS,
        );
        ui.message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts",
            MSG_LOCKED,
            None,
        )
    };

    let Some(email) = ui.account_email().await else {
        return upstream_error(StatusCode::BAD_GATEWAY);
    };
    let kdf: Kdf = match ui.vw.prelogin(&email).await {
        Ok(kdf) => kdf,
        Err(VwError::RateLimited) => return upstream_limited(),
        Err(VwError::Upstream) => return upstream_error(StatusCode::BAD_GATEWAY),
    };

    // Key derivation is CPU-heavy: off the async workers. The closure owns
    // the password and wipes it when it returns; only the hash comes back.
    let derive_email = email.clone();
    let derived =
        tokio::task::spawn_blocking(move || crypto::auth_hash(&password, &derive_email, kdf)).await;
    let auth_hash = match derived {
        Ok(Ok(hash)) => hash,
        _ => return upstream_error(StatusCode::BAD_GATEWAY),
    };

    match ui.vw.token(&email, &auth_hash, None).await {
        Ok(LoginOutcome::Authenticated) => ui.start_session(&ctx, headers, None, next.as_deref()),
        Ok(LoginOutcome::TwoFactorRequired(two_factor)) => {
            begin_two_factor(&ui, &ctx, auth_hash, email, two_factor, next)
        }
        Ok(LoginOutcome::InvalidCredentials) => {
            lock(&ui.lockouts).record_failure(ip, ui.now());
            ui.login_event(
                &ctx,
                Outcome::Failure,
                Some(Reason::InvalidCredentials),
                None,
                StatusCode::UNAUTHORIZED,
            );
            ui.login_page(
                headers,
                StatusCode::UNAUTHORIZED,
                Some(MSG_INVALID),
                None,
                next.as_deref(),
            )
        }
        Err(VwError::RateLimited) => upstream_limited(),
        Err(VwError::Upstream) => upstream_error(StatusCode::BAD_GATEWAY),
    }
}

/// The password was right and a second factor is needed: park the hash in the
/// pending slot and send the browser to the second-factor page.
fn begin_two_factor(
    ui: &UiState,
    ctx: &RequestContext,
    auth_hash: Zeroizing<String>,
    email: String,
    two_factor: TwoFactorRequired,
    next: Option<String>,
) -> Reply {
    if two_factor.providers.is_empty() {
        // The password is right but nothing here can finish the login. The
        // hash is dropped (and wiped) with this function's arguments.
        ui.login_event(
            ctx,
            Outcome::Failure,
            Some(Reason::TwoFactorRequired),
            None,
            StatusCode::UNPROCESSABLE_ENTITY,
        );
        return ui.back_to_login(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Second factor not supported",
            MSG_NO_SUPPORTED_FACTOR,
        );
    }
    // `next` stays on the server, with the pending login, until the second
    // factor is verified.
    let login =
        PendingLogin::new(auth_hash, email, two_factor, ctx.client_ip, ui.now()).with_next(next);
    let Some(id) = lock(&ui.pending).set(login) else {
        return ui.internal_error();
    };
    ui.login_event(
        ctx,
        Outcome::Unknown,
        Some(Reason::TwoFactorRequired),
        None,
        StatusCode::SEE_OTHER,
    );
    Reply::redirect("/ui/login/2fa").cookie(set_cookie(
        PENDING_COOKIE,
        &id,
        Some(PENDING_COOKIE_MAX_AGE),
    ))
}

// ── Sign-in: second factor ────────────────────────────────────────────────────

pub async fn twofa_get(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    headers: HeaderMap,
    uri: Uri,
) -> Reply {
    let selected = uri
        .query()
        .and_then(|q| parse_form(q.as_bytes(), &["provider"]).ok())
        .and_then(|mut f| f.take("provider"))
        .and_then(|p| Provider::from_id(&p));
    ui.twofa_page(&ctx, &headers, selected, StatusCode::OK, None, None)
}

pub async fn twofa_post(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    Extension(transport): Extension<Transport>,
    request: Request,
) -> Reply {
    let (parts, body) = request.into_parts();
    let headers = &parts.headers;

    if !origin_ok(headers, &transport) {
        return ui.forbidden(&ctx, "/ui/login/2fa", "origin_check_failed");
    }
    let mut form = match ui
        .read_form(headers, body, &["csrf", "provider", "action", "code"])
        .await
    {
        Ok(form) => form,
        Err(reply) => return reply,
    };
    let csrf = form.take("csrf");
    if !login_csrf_ok(headers, csrf.as_ref()) {
        return ui.forbidden(&ctx, "/ui/login/2fa", "csrf_check_failed");
    }
    let Some(pending_id) = cookie_value(headers, PENDING_COOKIE) else {
        return Reply::redirect("/ui/login?m=expired");
    };
    let provider = form.take("provider").and_then(|p| Provider::from_id(&p));
    let action = form.take("action");
    let code = form.take("code");
    drop(form);

    let Some(provider) = provider else {
        return ui.back_to_login(StatusCode::BAD_REQUEST, "Bad request", MSG_BAD_REQUEST);
    };
    // The provider must be one the server offered for this login.
    let offered = lock(&ui.pending)
        .peek(pending_id, ctx.client_ip, ui.now())
        .map(|p| p.offers(provider));
    match offered {
        Ok(true) => {}
        Ok(false) => {
            return ui.back_to_login(StatusCode::BAD_REQUEST, "Bad request", MSG_BAD_REQUEST)
        }
        Err(check) => return ui.pending_gone(&check),
    }

    match action.as_ref().map(|a| a.as_str()) {
        Some("send_email") if provider == Provider::Email => {
            send_email(&ui, &ctx, headers, pending_id).await
        }
        Some("verify") => verify_code(&ui, &ctx, headers, pending_id, provider, code).await,
        _ => ui.back_to_login(StatusCode::BAD_REQUEST, "Bad request", MSG_BAD_REQUEST),
    }
}

async fn send_email(
    ui: &UiState,
    ctx: &RequestContext,
    headers: &HeaderMap,
    pending_id: &str,
) -> Reply {
    let provider = Some(Provider::Email);
    let ip = ctx.client_ip;
    let locked = lock(&ui.lockouts).check_code(ip, ui.now());
    if let Err(by) = locked {
        ui.locked_event(ctx, by, provider);
        return ui.message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts",
            MSG_LOCKED,
            None,
        );
    }

    let begun = lock(&ui.pending).begin_email_send(pending_id, ip, ui.now());
    let (hash, email) =
        match begun {
            Err(check) => return ui.pending_gone(&check),
            Ok(None) => return ui.twofa_page(
                ctx,
                headers,
                provider,
                StatusCode::TOO_MANY_REQUESTS,
                Some("A code was requested a moment ago. Wait a minute before asking for another."),
                None,
            ),
            Ok(Some(pair)) => pair,
        };

    let failed_event = |reason: Reason, status: StatusCode| {
        ui.app.events.emit(
            SecurityEvent::new(Action::UiTwoFactorEmailSent)
                .request(ctx)
                .outcome(Outcome::Failure)
                .reason(reason)
                .status(status.as_u16()),
        );
    };
    match ui.vw.send_email_login(&email, &hash).await {
        Ok(()) => {
            ui.app.events.emit(
                SecurityEvent::new(Action::UiTwoFactorEmailSent)
                    .request(ctx)
                    .status(StatusCode::OK.as_u16()),
            );
            ui.twofa_page(
                ctx,
                headers,
                provider,
                StatusCode::OK,
                None,
                Some("The code was sent. It can take a minute to arrive."),
            )
        }
        Err(VwError::RateLimited) => {
            failed_event(Reason::UpstreamRateLimited, StatusCode::TOO_MANY_REQUESTS);
            ui.twofa_page(
                ctx,
                headers,
                provider,
                StatusCode::TOO_MANY_REQUESTS,
                Some(MSG_LOCKED),
                None,
            )
        }
        Err(VwError::Upstream) => {
            failed_event(Reason::UpstreamError, StatusCode::BAD_GATEWAY);
            ui.twofa_page(
                ctx,
                headers,
                provider,
                StatusCode::BAD_GATEWAY,
                Some("The code could not be sent. Try again later."),
                None,
            )
        }
    }
}

async fn verify_code(
    ui: &UiState,
    ctx: &RequestContext,
    headers: &HeaderMap,
    pending_id: &str,
    provider: Provider,
    code: Option<Zeroizing<String>>,
) -> Reply {
    let ip = ctx.client_ip;
    let Some(code) = code.as_ref().and_then(|c| provider.normalize_code(c)) else {
        // Wrong shape: nothing is sent anywhere and nothing is counted.
        return ui.twofa_page(
            ctx,
            headers,
            Some(provider),
            StatusCode::BAD_REQUEST,
            Some("That code does not look right. Check it and try again."),
            None,
        );
    };

    // Lockout first (per IP; the password was already right).
    let locked = lock(&ui.lockouts).check_code(ip, ui.now());
    if let Err(by) = locked {
        ui.locked_event(ctx, by, Some(provider));
        return ui.message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts",
            MSG_LOCKED,
            None,
        );
    }

    // Reserve one of the three attempts before the call.
    let begun = lock(&ui.pending).begin_code_attempt(pending_id, ip, ui.now());
    let (hash, email) = match begun {
        Ok(pair) => pair,
        Err(check) => return ui.pending_gone(&check),
    };

    let result = ui.vw.token(&email, &hash, Some((provider, &code))).await;
    drop(code);
    drop(hash);

    match result {
        Ok(LoginOutcome::Authenticated) => {
            let next = lock(&ui.pending)
                .peek(pending_id, ip, ui.now())
                .ok()
                .and_then(|p| p.next.clone());
            ui.start_session(ctx, headers, Some(provider), next.as_deref())
        }
        // Anything but a success on the second step is a rejected code (the
        // server asking for the second factor again counts as a rejection).
        Ok(LoginOutcome::InvalidCredentials) | Ok(LoginOutcome::TwoFactorRequired(_)) => {
            lock(&ui.lockouts).record_failure(ip, ui.now());
            ui.login_event(
                ctx,
                Outcome::Failure,
                Some(Reason::TwoFactorFailed),
                Some(provider),
                StatusCode::UNAUTHORIZED,
            );
            let used_up = lock(&ui.pending).code_rejected(pending_id);
            if used_up {
                Reply::redirect("/ui/login?m=failed").clear(PENDING_COOKIE)
            } else {
                ui.twofa_page(
                    ctx,
                    headers,
                    Some(provider),
                    StatusCode::UNAUTHORIZED,
                    Some(MSG_INVALID),
                    None,
                )
            }
        }
        Err(error) => {
            // No verdict: the attempt is given back.
            lock(&ui.pending).refund_code_attempt(pending_id);
            let (reason, status, text) = match error {
                VwError::RateLimited => (
                    Reason::UpstreamRateLimited,
                    StatusCode::TOO_MANY_REQUESTS,
                    MSG_LOCKED,
                ),
                VwError::Upstream => (Reason::UpstreamError, StatusCode::BAD_GATEWAY, MSG_UPSTREAM),
            };
            ui.login_event(ctx, Outcome::Failure, Some(reason), Some(provider), status);
            ui.twofa_page(ctx, headers, Some(provider), status, Some(text), None)
        }
    }
}

// ── Sign-out ──────────────────────────────────────────────────────────────────

pub async fn logout_post(
    State(ui): State<Arc<UiState>>,
    ctx: RequestContext,
    Extension(transport): Extension<Transport>,
    request: Request,
) -> Reply {
    let (parts, body) = request.into_parts();
    let headers = &parts.headers;

    if !origin_ok(headers, &transport) {
        return ui.forbidden(&ctx, "/ui/logout", "origin_check_failed");
    }
    let view = match ui.authenticate(headers, &ctx) {
        Auth::Session(view) => view,
        Auth::Expired => return Reply::redirect("/ui/login?m=session").clear(SESSION_COOKIE),
        Auth::None => return Reply::redirect("/ui/login"),
    };
    let mut form = match ui.read_form(headers, body, &["csrf"]).await {
        Ok(form) => form,
        Err(reply) => return reply,
    };
    let ok = form
        .take("csrf")
        .is_some_and(|field| secrets_equal(&view.csrf, &field));
    if !ok {
        return ui.forbidden(&ctx, "/ui/logout", "csrf_check_failed");
    }

    if let Some(id) = cookie_value(headers, SESSION_COOKIE) {
        lock(&ui.sessions).destroy(id);
    }
    lock(&ui.pending).clear();
    ui.app.events.emit(
        SecurityEvent::new(Action::UiLogout)
            .request(&ctx)
            .status(StatusCode::SEE_OTHER.as_u16()),
    );
    Reply::redirect("/ui/login?m=logged_out")
        .clear(SESSION_COOKIE)
        .clear(PENDING_COOKIE)
        .clear(LOGIN_COOKIE)
}
