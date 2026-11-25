//! The senders: Gotify, ntfy and a generic webhook.
//!
//! One `reqwest` client serves all of them: `https://` is enforced by the
//! configuration (loopback and `allow_http` excepted), redirects are never
//! followed, the connection and the whole request time out, and an extra CA
//! can be trusted. A failed send is retried twice with backoff on network
//! errors and 5xx answers, never on 4xx, and then counted and logged (at most
//! once a minute per sender). Tokens are held in `Zeroizing` memory, set as
//! sensitive header values and never logged.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::header::{HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::redirect::Policy;
use reqwest::{Client, RequestBuilder, Url};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::content::Notification;
use crate::config::NotifyConfig;
use crate::error::{FerroError, FerroResult};

/// The same deadline for connecting and for the whole request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Warn about a failing sender at most this often.
const WARN_EVERY: Duration = Duration::from_secs(60);

/// How the senders behave on the wire; the defaults are the documented
/// ones, tests shorten them.
#[derive(Debug, Clone)]
pub struct SendOptions {
    pub timeout: Duration,
    /// Waits before the first and second retry.
    pub retry_delays: Vec<Duration>,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            timeout: REQUEST_TIMEOUT,
            retry_delays: vec![Duration::from_millis(500), Duration::from_secs(2)],
        }
    }
}

/// Why a send failed, in words that carry no URL, path or token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    Timeout,
    Connect,
    Status(u16),
    Other,
}

impl SendError {
    /// The HTTP status, when the notifier answered.
    pub fn status(&self) -> Option<u16> {
        match self {
            SendError::Status(s) => Some(*s),
            _ => None,
        }
    }

    /// Network errors and server errors are worth another try.
    fn retryable(&self) -> bool {
        match self {
            SendError::Status(s) => *s >= 500,
            _ => true,
        }
    }

    fn from_reqwest(e: &reqwest::Error) -> Self {
        if e.is_timeout() {
            SendError::Timeout
        } else if e.is_connect() {
            SendError::Connect
        } else {
            SendError::Other
        }
    }
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendError::Timeout => write!(f, "timed out"),
            SendError::Connect => write!(f, "could not connect"),
            SendError::Status(s) => write!(f, "the notifier answered HTTP {s}"),
            SendError::Other => write!(f, "the request failed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderKind {
    Gotify,
    Ntfy,
    Webhook,
}

impl SenderKind {
    pub fn name(self) -> &'static str {
        match self {
            SenderKind::Gotify => "gotify",
            SenderKind::Ntfy => "ntfy",
            SenderKind::Webhook => "webhook",
        }
    }
}

pub struct Sender {
    kind: SenderKind,
    url: Url,
    /// Host only, for display.
    host: String,
    token: Option<Zeroizing<String>>,
    client: Client,
    retry_delays: Vec<Duration>,
    pub sent: AtomicU64,
    pub failed: AtomicU64,
    last_warn: Mutex<Option<Instant>>,
}

impl Sender {
    pub fn name(&self) -> &'static str {
        self.kind.name()
    }

    /// The host of the notifier URL, for the admin UI.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The token as a header value that stays out of debug output.
    fn secret_header(&self, prefix: &str) -> Option<HeaderValue> {
        let token = self.token.as_ref()?;
        let text = Zeroizing::new(format!("{prefix}{}", token.as_str()));
        let mut value = HeaderValue::from_str(&text).ok()?;
        value.set_sensitive(true);
        Some(value)
    }

    /// The request for `n`: the shape each notifier expects.
    pub fn build_request(&self, n: &Notification) -> RequestBuilder {
        match self.kind {
            SenderKind::Gotify => {
                let url = format!("{}/message", self.url.as_str().trim_end_matches('/'));
                let mut req = self.client.post(url).json(&serde_json::json!({
                    "title": n.title,
                    "message": n.message,
                    "priority": n.severity.gotify_priority(),
                }));
                if let Some(v) = self.secret_header("") {
                    req = req.header(HeaderName::from_static("x-gotify-key"), v);
                }
                req
            }
            SenderKind::Ntfy => {
                let mut req = self
                    .client
                    .post(self.url.clone())
                    .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                    .header("Title", n.title.as_str())
                    .header("Priority", n.severity.ntfy_priority())
                    .header("Tags", n.tags)
                    .body(n.message.clone());
                if let Some(v) = self.secret_header("Bearer ") {
                    req = req.header(AUTHORIZATION, v);
                }
                req
            }
            SenderKind::Webhook => {
                let mut req = self.client.post(self.url.clone()).json(&n.webhook_body());
                if let Some(v) = self.secret_header("Bearer ") {
                    req = req.header(AUTHORIZATION, v);
                }
                req
            }
        }
    }

    /// Send `n`; with `retries`, a network error or a 5xx answer is retried
    /// after each of the configured delays. Returns the HTTP status.
    pub async fn deliver(&self, n: &Notification, retries: bool) -> Result<u16, SendError> {
        let delays: &[Duration] = if retries { &self.retry_delays } else { &[] };
        let mut attempt = 0;
        loop {
            let error = match self.build_request(n).send().await {
                Ok(resp) if resp.status().is_success() => return Ok(resp.status().as_u16()),
                Ok(resp) => SendError::Status(resp.status().as_u16()),
                Err(e) => SendError::from_reqwest(&e),
            };
            match delays.get(attempt) {
                Some(delay) if error.retryable() => {
                    tokio::time::sleep(*delay).await;
                    attempt += 1;
                }
                _ => return Err(error),
            }
        }
    }

    /// Deliver and count; a failure is logged at most once a minute.
    async fn deliver_and_count(&self, n: &Notification) {
        match self.deliver(n, true).await {
            Ok(_) => {
                self.sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                self.failed.fetch_add(1, Ordering::Relaxed);
                let mut last = self.last_warn.lock().unwrap_or_else(|e| e.into_inner());
                if last.is_none_or(|at| at.elapsed() >= WARN_EVERY) {
                    *last = Some(Instant::now());
                    tracing::warn!(
                        sender = self.name(),
                        host = %self.host,
                        error = %e,
                        "notification could not be delivered"
                    );
                }
            }
        }
    }
}

/// One sender's worker: takes notifications off its queue one at a time, so a
/// slow notifier delays only itself.
pub async fn run_worker(sender: Arc<Sender>, mut rx: mpsc::Receiver<Arc<Notification>>) {
    while let Some(n) = rx.recv().await {
        sender.deliver_and_count(&n).await;
    }
}

/// The extra CA certificates in `path`, or why they cannot be used (no file
/// content in the message).
pub fn load_ca(path: &str) -> Result<Vec<reqwest::Certificate>, String> {
    let pem =
        std::fs::read(path).map_err(|e| format!("cannot read notify.ca_file ({:?})", e.kind()))?;
    let certs = reqwest::Certificate::from_pem_bundle(&pem)
        .map_err(|_| "notify.ca_file is not a PEM certificate bundle".to_string())?;
    if certs.is_empty() {
        return Err("notify.ca_file contains no certificate".to_string());
    }
    Ok(certs)
}

/// The shared client: no redirects, a timeout, optional extra CA. It ignores
/// proxy environment variables, like the other clients of the project.
fn build_client(cfg: &NotifyConfig, opts: &SendOptions) -> FerroResult<Client> {
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .timeout(opts.timeout)
        .connect_timeout(opts.timeout)
        .no_proxy()
        .user_agent(concat!("ferrowarden/", env!("CARGO_PKG_VERSION")));
    if !cfg.ca_file.trim().is_empty() {
        for cert in load_ca(cfg.ca_file.trim()).map_err(FerroError::Config)? {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder
        .build()
        .map_err(|_| FerroError::Config("cannot build the notifier HTTP client".to_string()))
}

/// The senders `cfg` enables, sharing one client.
pub fn build(cfg: &NotifyConfig, opts: &SendOptions) -> FerroResult<Vec<Arc<Sender>>> {
    let client = build_client(cfg, opts)?;
    let mut out = Vec::new();
    for (name, raw) in cfg.urls() {
        let (kind, token) = match name {
            "gotify" => (SenderKind::Gotify, cfg.tokens.gotify.clone()),
            "ntfy" => (SenderKind::Ntfy, cfg.tokens.ntfy.clone()),
            _ => (SenderKind::Webhook, cfg.tokens.webhook.clone()),
        };
        let url = Url::parse(raw)
            .map_err(|_| FerroError::Config(format!("notify.{name}_url is not a valid URL")))?;
        let host = url.host_str().unwrap_or_default().to_string();
        out.push(Arc::new(Sender {
            kind,
            url,
            host,
            token,
            client: client.clone(),
            retry_delays: opts.retry_delays.clone(),
            sent: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            last_warn: Mutex::new(None),
        }));
    }
    Ok(out)
}
