//! The admin web UI (phase 1: sign-in with Vaultwarden, sessions, status).
//!
//! It is a **separate axum server** on `ui.bind`. The agent and admin API
//! router is never merged into it and it is never merged into that one, so an
//! agent that can reach the API port cannot reach the UI. The UI accepts the
//! vault master password, which makes it the most sensitive code in the
//! project; `docs/admin-ui.md` and `docs/security.md` describe the threat
//! model. In short:
//!
//! * the password is verified by Vaultwarden itself (the real login
//!   handshake); Ferrowarden keeps only a session, never a Vaultwarden token;
//! * the sign-in form is only served over HTTPS (own TLS, or a trusted proxy);
//! * every POST needs a CSRF token and a same-origin proof;
//! * wrong passwords and codes are rate-limited before any key derivation or
//!   upstream call;
//! * no scripts, no external assets (the stylesheet, its font and the icons
//!   are embedded and served from the UI's own origin), strict security
//!   headers.

mod admin_pages;
pub mod crypto;
mod drafts;
mod handlers;
pub mod lockout;
mod pages;
pub mod session;
pub mod vw_login;
pub mod web;

#[cfg(test)]
mod tests;

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use sha2::{Digest, Sha256};

use crate::config::split_list;
use crate::events::{Action, Outcome, Reason, SecurityEvent};
use crate::middleware::request_context::{request_context, RequestContext, TrustedProxies};
use crate::net::Cidr;
use crate::state::AppState;
use crate::vault::Vault;
use drafts::DraftStore;
use lockout::Lockouts;
use session::{PendingSlot, SessionStore};
use vw_login::VwClient;
use web::Transport;

pub(crate) const CSS: &str = include_str!("app.css");
/// Inter (variable, latin subset; SIL OFL, see `assets/fonts/OFL-Inter.txt`).
pub(crate) const FONT_FILE: &str = "inter-latin-wght.woff2";
pub(crate) const FONT: &[u8] = include_bytes!("assets/fonts/inter-latin-wght.woff2");
/// The brand kit's favicons (`branding/assets/favicons`), copied next to the
/// sources so the Docker build (which only copies `src/`) can embed them.
pub(crate) const FAVICON_ICO: &[u8] = include_bytes!("assets/favicons/favicon.ico");
pub(crate) const FAVICON_32: &[u8] = include_bytes!("assets/favicons/favicon-32.png");
pub(crate) const APPLE_TOUCH_ICON: &[u8] = include_bytes!("assets/favicons/apple-touch-icon.png");

/// One "insecure transport" event per this long (with a count of the rest).
const INSECURE_EVENT_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding one of these locks leaves plain data behind;
    // carry on rather than turning every later request into a 500.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Everything the UI handlers share.
pub struct UiState {
    pub(crate) app: Arc<AppState>,
    pub(crate) vw: VwClient,
    pub(crate) sessions: Mutex<SessionStore>,
    pub(crate) pending: Mutex<PendingSlot>,
    pub(crate) lockouts: Mutex<Lockouts>,
    /// Unsaved key forms parked while the operator signs in again.
    pub(crate) drafts: Mutex<DraftStore>,
    /// One password verification at a time. Lockouts only count failures
    /// once Vaultwarden has answered, so without this a burst of concurrent
    /// submissions would all pass the lockout check: each would run a KDF
    /// (Argon2 can take up to 1 GiB) and spend a slot of Vaultwarden's
    /// per-IP login limit, which every Ferrowarden attempt shares.
    pub(crate) login_gate: tokio::sync::Semaphore,
    /// The vault account's email, cached after the first successful lookup.
    email: Mutex<Option<String>>,
    pub(crate) trusted: Arc<Vec<Cidr>>,
    /// The UI listener itself terminates TLS.
    pub(crate) listener_tls: bool,
    pub(crate) insecure_http: bool,
    pub(crate) css_path: String,
    insecure_events: Mutex<InsecureThrottle>,
    /// Added to the clock so tests can move through time.
    #[cfg(test)]
    skew: Mutex<Duration>,
}

#[derive(Default)]
struct InsecureThrottle {
    last: Option<Instant>,
    suppressed: u64,
}

impl UiState {
    pub fn new(app: Arc<AppState>) -> Result<Arc<Self>, String> {
        let ui = &app.config.ui;
        let vw = VwClient::new(ui)?;
        let trusted = Arc::new(
            split_list(&app.config.trusted_proxies)
                .iter()
                .filter_map(|e| Cidr::parse(e))
                .collect::<Vec<_>>(),
        );
        let digest = Sha256::digest(CSS.as_bytes());
        let hash: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        Ok(Arc::new(Self {
            sessions: Mutex::new(SessionStore::new(
                Duration::from_secs(ui.session_idle_minutes * 60),
                Duration::from_secs(ui.session_max_hours * 3600),
            )),
            pending: Mutex::new(PendingSlot::new()),
            lockouts: Mutex::new(Lockouts::new()),
            drafts: Mutex::new(DraftStore::new()),
            login_gate: tokio::sync::Semaphore::new(1),
            email: Mutex::new(None),
            trusted,
            listener_tls: app.config.tls_enabled,
            insecure_http: ui.insecure_http,
            css_path: format!("/ui/static/app-{hash}.css"),
            insecure_events: Mutex::new(InsecureThrottle::default()),
            #[cfg(test)]
            skew: Mutex::new(Duration::ZERO),
            vw,
            app,
        }))
    }

    /// Signed-in sessions that have not expired (the metrics endpoint's
    /// `ferrowarden_ui_sessions`).
    pub fn live_sessions(&self) -> usize {
        lock(&self.sessions).live(self.now())
    }

    pub(crate) fn now(&self) -> Instant {
        #[cfg(test)]
        {
            Instant::now() + *lock(&self.skew)
        }
        #[cfg(not(test))]
        {
            Instant::now()
        }
    }

    /// Move the clock forward (tests of idle and absolute expiry).
    #[cfg(test)]
    pub(crate) fn advance(&self, by: Duration) {
        *lock(&self.skew) += by;
    }

    /// The vault account to sign in as: what the vault backend reports. Cached after
    /// the first success; `None` if the vault backend is unreachable or not logged in.
    pub(crate) async fn account_email(&self) -> Option<String> {
        if let Some(email) = lock(&self.email).clone() {
            return Some(email);
        }
        let status = self.app.vault.status().await.ok()?;
        if status.status == "unauthenticated" {
            return None;
        }
        let email = status.user_email?;
        *lock(&self.email) = Some(email.clone());
        Some(email)
    }

    /// `ui_login` / `insecure_transport`, at most one per interval.
    fn note_insecure_request(&self, ctx: &RequestContext) {
        let suppressed = {
            let mut t = lock(&self.insecure_events);
            let now = self.now();
            if t.last
                .is_some_and(|l| now.duration_since(l) < INSECURE_EVENT_INTERVAL)
            {
                t.suppressed += 1;
                return;
            }
            t.last = Some(now);
            std::mem::take(&mut t.suppressed)
        };
        self.app.events.emit(
            SecurityEvent::new(Action::UiLogin)
                .request(ctx)
                .outcome(Outcome::Failure)
                .reason(Reason::InsecureTransport)
                .status(StatusCode::BAD_REQUEST.as_u16())
                .detail("suppressed", suppressed),
        );
    }
}

/// Per request: decide whether the connection counts as HTTPS, refuse the UI
/// on plain HTTP unless `insecure_http` is set, and put the security headers
/// on whatever response comes out.
async fn gate(State(ui): State<Arc<UiState>>, mut request: Request, next: Next) -> Response {
    let ctx = request
        .extensions()
        .get::<RequestContext>()
        .cloned()
        .unwrap_or_else(|| RequestContext::new([127, 0, 0, 1].into()));
    let transport: Transport = web::transport(
        ui.listener_tls,
        ctx.peer_ip,
        request.headers(),
        request.uri().authority().map(|a| a.as_str()),
        &ui.trusted,
    );
    let secure = transport.secure;
    let is_static =
        request.uri().path().starts_with("/ui/static/") || request.uri().path() == "/favicon.ico";

    let mut response = if !secure && !ui.insecure_http && !is_static {
        ui.note_insecure_request(&ctx);
        handlers::insecure_page(&ui)
    } else {
        request.extensions_mut().insert(transport);
        next.run(request).await
    };
    web::apply_security_headers(response.headers_mut(), secure);
    response
}

/// The UI router: its own routes, the gate, and the request-context layer
/// (request id and client IP, as on the API router) outermost.
pub fn router(ui: Arc<UiState>) -> Router {
    let trusted = TrustedProxies(ui.trusted.clone());
    Router::new()
        .route("/", get(handlers::root))
        .route("/ui", get(handlers::root))
        .route("/ui/", get(handlers::index))
        .route(
            "/ui/login",
            get(handlers::login_get).post(handlers::login_post),
        )
        .route(
            "/ui/login/2fa",
            get(handlers::twofa_get).post(handlers::twofa_post),
        )
        .route("/ui/logout", post(handlers::logout_post))
        .route("/ui/keys", get(admin_pages::keys_list))
        .route(
            "/ui/keys/new",
            get(admin_pages::key_new_get).post(admin_pages::key_new_post),
        )
        .route(
            "/ui/keys/new/draft/{draft_id}",
            get(admin_pages::key_new_draft),
        )
        .route(
            "/ui/keys/{id}",
            get(admin_pages::key_get).post(admin_pages::key_post),
        )
        .route(
            "/ui/keys/{id}/draft/{draft_id}",
            get(admin_pages::key_draft),
        )
        .route(
            "/ui/keys/{id}/revoke",
            get(admin_pages::revoke_get).post(admin_pages::revoke_post),
        )
        .route("/ui/audit", get(admin_pages::audit_get))
        .route("/ui/notify/test", post(admin_pages::notify_test_post))
        .route("/ui/static/{file}", get(handlers::static_file))
        .route("/favicon.ico", get(handlers::favicon))
        .fallback(handlers::fallback)
        .with_state(ui.clone())
        .layer(middleware::from_fn_with_state(ui, gate))
        .layer(middleware::from_fn_with_state(trusted, request_context))
}
