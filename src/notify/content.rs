//! What a notification says, and the only fields it may be built from.
//!
//! [`EventFields`] is the allow-list. [`EventFields::from_event`] is the one
//! place a [`SecurityEvent`] is read for a notification, and it reads exactly
//! these things: the category and action, the outcome and reason code, the key
//! name and short id, the credential names (placeholder labels), the target
//! **host** (`url.domain`, never `url.original`), the source IP, the request id
//! and the timestamp, plus one count. The one exception is the approval prompt
//! (`approval_requested`), which also carries the method, the target host with
//! its port, the path **without the query string** (cut to 200 characters),
//! the approval id, its expiry and a link: the operator needs them to decide.
//! Every title and message is rendered from
//! an `EventFields` and nothing else, and the webhook's `event` object is that
//! same struct serialized, so there is no field for a URL path or query, a
//! header name or value, a body, a credential value, a token, the API prefix or
//! a Vaultwarden message to be copied into. Free text that does come from an
//! agent or an operator (names, hosts) is reduced to a safe character set and
//! cut short first.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{json, Value};

use super::Category;
use crate::events::{Action, Outcome, SecurityEvent};

/// Longest name (key or credential) in a notification.
const MAX_NAME: usize = 48;
/// Credential names kept in the event fields.
const MAX_CREDENTIALS: usize = 10;
/// Credential names spelled out in a message.
const NAMES_IN_MESSAGE: usize = 3;
/// Longest host name (RFC 1035).
const MAX_HOST: usize = 253;
/// Longest path in an approval prompt.
const MAX_PATH: usize = 200;
/// Longest link in an approval prompt.
const MAX_LINK: usize = 512;

/// How urgent a notification is. Maps to Gotify priority 8/4 and ntfy
/// `high`/`default`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    High,
    Normal,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Normal => "normal",
        }
    }
    pub fn gotify_priority(self) -> u8 {
        match self {
            Severity::High => 8,
            Severity::Normal => 4,
        }
    }
    pub fn ntfy_priority(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Normal => "default",
        }
    }
}

// ── The allow-list ────────────────────────────────────────────────────────────

/// The event fields a notification may carry. Adding a field here is the only
/// way to put more of an event into a notification.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EventFields {
    pub category: &'static str,
    pub action: &'static str,
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
    /// The first eight characters of the key id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Placeholder labels, never values.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<String>,
    /// The host only (`url.domain`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// RFC 3339, UTC.
    pub timestamp: String,
    /// How many occurrences this notification stands for.
    pub count: u64,
    /// What an approval prompt shows (`approval_requested` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalFields>,
}

/// The fields of an approval prompt beyond the common ones. Never a value: the
/// path has no query string, and the credentials are names.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ApprovalFields {
    pub id: String,
    pub method: String,
    /// The target host, with `:port` when the port is not the default.
    pub target: String,
    /// The path as the agent sent it, without query or fragment, cut to 200
    /// characters.
    pub path: String,
    /// RFC 3339, UTC.
    pub expires_at: String,
    /// `<ui.public_url>/approvals/<id>`, when `ui.public_url` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

impl ApprovalFields {
    fn from_event(event: &SecurityEvent) -> Option<Self> {
        if event.event.action != Action::ApprovalRequested {
            return None;
        }
        let details = event.ferrowarden.details.as_ref()?;
        let text = |key: &str| details.get(key).and_then(Value::as_str);
        Some(Self {
            id: clean_token(text("approval_id")?, 64),
            method: clean_id(
                &event
                    .http
                    .as_ref()?
                    .request
                    .as_ref()?
                    .method
                    .to_ascii_uppercase(),
                16,
            ),
            target: clean_host(text("host")?)?,
            path: clean_path(text("path").unwrap_or("/")),
            expires_at: clean_time(text("expires_at")?),
            link: text("link").and_then(clean_link),
        })
    }
}

impl EventFields {
    /// Project `event` onto the allow-list. This function is the whole
    /// interface between an event and a notification.
    pub fn from_event(category: Category, event: &SecurityEvent, count: u64) -> Self {
        Self {
            category: category.as_str(),
            action: event.event.action.as_str(),
            outcome: event.event.outcome.as_str(),
            reason: event.event.reason.map(|r| r.as_str()),
            key_name: event
                .ferrowarden
                .key
                .as_ref()
                .map(|k| clean_name(&k.name, MAX_NAME)),
            key_id: event
                .ferrowarden
                .key
                .as_ref()
                .map(|k| clean_id(&k.id, 8))
                .filter(|id| !id.is_empty()),
            credentials: event
                .ferrowarden
                .credentials
                .iter()
                .take(MAX_CREDENTIALS)
                .map(|c| clean_name(c, MAX_NAME))
                .collect(),
            target_host: event
                .url
                .as_ref()
                .and_then(|u| u.domain.as_deref())
                .and_then(clean_host),
            source_ip: event.source.as_ref().map(|s| s.ip.to_string()),
            request_id: event
                .ferrowarden
                .request_id
                .as_deref()
                .map(|r| clean_id(r, 40))
                .filter(|r| !r.is_empty()),
            timestamp: rfc3339(event.timestamp),
            count,
            approval: ApprovalFields::from_event(event),
        }
    }

    /// Fields of a notification Ferrowarden raises itself (paused, dropped,
    /// test): fixed words and a count, nothing from a request.
    pub fn internal(
        category: Category,
        action: &'static str,
        outcome: Outcome,
        count: u64,
        at: DateTime<Utc>,
    ) -> Self {
        Self {
            category: category.as_str(),
            action,
            outcome: outcome.as_str(),
            reason: None,
            key_name: None,
            key_id: None,
            credentials: Vec::new(),
            target_host: None,
            source_ip: None,
            request_id: None,
            timestamp: rfc3339(at),
            count,
            approval: None,
        }
    }
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// A name for display: letters, digits and a few punctuation marks survive,
/// everything else (control characters, braces, slashes, quotes of other
/// kinds) becomes `?`. Cut to `max` characters.
fn clean_name(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| {
            if c.is_ascii_alphanumeric()
                || matches!(c, ' ' | '_' | '.' | '-' | ':' | '\'' | '(' | ')' | '+')
            {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// An identifier: letters, digits and `-` only, cut to `max` characters.
fn clean_id(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(max)
        .collect()
}

/// A path for display: printable ASCII only (anything else becomes `?`), cut
/// to [`MAX_PATH`] characters. The query string is gone before it gets here.
fn clean_path(s: &str) -> String {
    let path = s.split(['?', '#']).next().unwrap_or("");
    path.chars()
        .take(MAX_PATH)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

/// An RFC 3339 time: digits and `-:.TZ+` only.
fn clean_time(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_digit() || matches!(c, '-' | ':' | '.' | 'T' | 'Z' | '+'))
        .take(40)
        .collect()
}

/// A link for display: an absolute `http(s)` URL of printable ASCII.
fn clean_link(s: &str) -> Option<String> {
    let ok = s.len() <= MAX_LINK
        && (s.starts_with("https://") || s.starts_with("http://"))
        && s.chars().all(|c| c.is_ascii_graphic());
    ok.then(|| s.to_string())
}

/// A URL-safe token (an approval id): letters, digits, `-` and `_`.
fn clean_token(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(max)
        .collect()
}

/// A host name or IP literal as the URL parser produced it. Anything with
/// other characters is dropped rather than shown.
fn clean_host(s: &str) -> Option<String> {
    let ok = !s.is_empty()
        && s.len() <= MAX_HOST
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'));
    ok.then(|| s.to_ascii_lowercase())
}

// ── What kind of notification it is ───────────────────────────────────────────

/// Why a notification is sent. It decides the title, the text, the severity
/// and the tags.
#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Blocked,
    AuthFailures {
        agent: u32,
        admin: u32,
        ui: u32,
        window_secs: u64,
    },
    LockedOut,
    VaultLocked,
    VaultUnlockFailed,
    VaultSyncFailed,
    VaultRecovered,
    KeyCreated,
    KeyRevoked,
    KeyPolicyChanged,
    UiSignIn,
    EventsDropped,
    NotificationsDropped,
    Paused {
        limit: u32,
    },
    Test,
    /// A request is waiting for a human to approve or deny it.
    ApprovalRequest,
}

impl Kind {
    pub fn severity(&self) -> Severity {
        match self {
            Kind::Blocked
            | Kind::AuthFailures { .. }
            | Kind::LockedOut
            | Kind::VaultLocked
            | Kind::VaultUnlockFailed
            | Kind::VaultSyncFailed
            | Kind::EventsDropped
            | Kind::NotificationsDropped
            | Kind::Paused { .. }
            | Kind::ApprovalRequest => Severity::High,
            Kind::VaultRecovered
            | Kind::KeyCreated
            | Kind::KeyRevoked
            | Kind::KeyPolicyChanged
            | Kind::UiSignIn
            | Kind::Test => Severity::Normal,
        }
    }

    /// ntfy tags (emoji short codes).
    fn tags(&self) -> &'static str {
        match self {
            Kind::Blocked
            | Kind::EventsDropped
            | Kind::NotificationsDropped
            | Kind::Paused { .. } => "warning",
            Kind::AuthFailures { .. } | Kind::LockedOut => "lock,warning",
            Kind::VaultLocked | Kind::VaultUnlockFailed | Kind::VaultSyncFailed => "lock",
            Kind::VaultRecovered | Kind::Test => "white_check_mark",
            Kind::KeyCreated | Kind::KeyRevoked | Kind::KeyPolicyChanged | Kind::UiSignIn => "key",
            Kind::ApprovalRequest => "key,hourglass_flowing_sand",
        }
    }

    fn title(&self) -> &'static str {
        match self {
            Kind::Blocked => "Ferrowarden: request blocked",
            Kind::AuthFailures { .. } => "Ferrowarden: repeated authentication failures",
            Kind::LockedOut => "Ferrowarden: sign-in locked out",
            Kind::VaultLocked => "Ferrowarden: vault locked",
            Kind::VaultUnlockFailed => "Ferrowarden: vault unlock failed",
            Kind::VaultSyncFailed => "Ferrowarden: vault sync failed",
            Kind::VaultRecovered => "Ferrowarden: vault unlocked",
            Kind::KeyCreated => "Ferrowarden: agent key created",
            Kind::KeyRevoked => "Ferrowarden: agent key revoked",
            Kind::KeyPolicyChanged => "Ferrowarden: agent key policy changed",
            Kind::UiSignIn => "Ferrowarden: admin UI sign-in",
            Kind::EventsDropped => "Ferrowarden: security events dropped",
            Kind::NotificationsDropped => "Ferrowarden: notifications dropped",
            Kind::Paused { .. } => "Ferrowarden: notifications paused",
            Kind::Test => "Ferrowarden: test notification",
            Kind::ApprovalRequest => "Ferrowarden: approval needed",
        }
    }
}

// ── Rendering ─────────────────────────────────────────────────────────────────

/// A finished notification: what every sender gets.
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub message: String,
    /// ntfy tags.
    pub tags: &'static str,
    /// The allow-listed fields the message was built from.
    pub event: EventFields,
    /// Occurrences folded into this notification by rate limiting.
    pub suppressed: u64,
}

impl Notification {
    /// Render `kind` from `fields`. `suppressed` and `since` summarise what
    /// the rate limit held back for the same subject.
    pub fn render(
        category: Category,
        kind: &Kind,
        fields: EventFields,
        suppressed: u64,
        since: Option<DateTime<Utc>>,
    ) -> Self {
        let mut message = message(kind, &fields);
        if suppressed > 0 {
            message.push_str(&format!(" And {suppressed} more"));
            if let Some(since) = since {
                message.push_str(&format!(" since {}", since.format("%H:%M UTC")));
            }
            message.push('.');
        }
        Self {
            category,
            severity: kind.severity(),
            title: kind.title().to_string(),
            message,
            tags: kind.tags(),
            event: fields,
            suppressed,
        }
    }

    /// The test notification. It carries no event, only fixed words.
    pub fn test() -> Self {
        let fields = EventFields::internal(
            Category::System,
            "notify_test",
            Outcome::Success,
            1,
            Utc::now(),
        );
        Self::render(Category::System, &Kind::Test, fields, 0, None)
    }

    /// The JSON body of the generic webhook.
    pub fn webhook_body(&self) -> Value {
        json!({
            "source": "ferrowarden",
            "schema_version": 1,
            "category": self.category.as_str(),
            "severity": self.severity.as_str(),
            "title": self.title,
            "message": self.message,
            "event": self.event,
            "suppressed": self.suppressed,
        })
    }
}

/// Why a request was blocked, in a few plain words.
fn why(reason: Option<&str>) -> &'static str {
    match reason {
        Some("credential_host_not_allowed") => "credential not bound to that host",
        Some("target_blocked") => "target not allowed by the outbound policy",
        Some("credential_out_of_scope") => "credential not available to this key",
        Some("method_not_allowed") => "method not allowed for this key",
        Some("reprompt_required") => "credential needs a master password re-prompt",
        _ => "refused by policy",
    }
}

/// `a`, `a and b`, `a, b and c`, `a, b, c and N more`.
fn list(names: &[String]) -> String {
    let shown: Vec<&str> = names
        .iter()
        .take(NAMES_IN_MESSAGE)
        .map(String::as_str)
        .collect();
    let more = names.len().saturating_sub(NAMES_IN_MESSAGE);
    let mut out = match shown.as_slice() {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    };
    if more > 0 {
        out = format!("{} and {more} more", shown.join(", "));
    }
    out
}

/// `Source 1.2.3.4, request 0193abcd….` (whatever is known), or nothing.
fn origin(f: &EventFields) -> String {
    let mut parts = Vec::new();
    if let Some(ip) = &f.source_ip {
        parts.push(format!("Source {ip}"));
    }
    if let Some(id) = &f.request_id {
        let short: String = id.chars().take(8).collect();
        let ellipsis = if id.chars().count() > 8 {
            "\u{2026}"
        } else {
            ""
        };
        parts.push(format!("request {short}{ellipsis}"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" {}.", parts.join(", "))
    }
}

/// `Key "name" (id 11111111)`, or a fallback.
fn key_phrase(f: &EventFields, fallback: &str) -> String {
    match (&f.key_name, &f.key_id) {
        (Some(name), Some(id)) => format!("Key \"{name}\" (id {id})"),
        (Some(name), None) => format!("Key \"{name}\""),
        (None, Some(id)) => format!("Key {id}"),
        (None, None) => fallback.to_string(),
    }
}

fn window_text(secs: u64) -> String {
    if secs.is_multiple_of(3600) {
        let h = secs / 3600;
        format!("{h} hour{}", if h == 1 { "" } else { "s" })
    } else if secs.is_multiple_of(60) {
        let m = secs / 60;
        format!("{m} minute{}", if m == 1 { "" } else { "s" })
    } else {
        format!("{secs} seconds")
    }
}

fn message(kind: &Kind, f: &EventFields) -> String {
    let tail = origin(f);
    match kind {
        Kind::Blocked => {
            let who = key_phrase(f, "An agent key");
            let what = match (f.credentials.is_empty(), &f.target_host) {
                (false, Some(host)) => format!("tried to send {} to {host}", list(&f.credentials)),
                (false, None) => format!("tried to use {}", list(&f.credentials)),
                (true, Some(host)) => format!("sent a request to {host}"),
                (true, None) => "sent a request".to_string(),
            };
            format!("{who} {what}. Blocked: {}.{tail}", why(f.reason))
        }
        Kind::AuthFailures {
            agent,
            admin,
            ui,
            window_secs,
        } => {
            let ip = f.source_ip.as_deref().unwrap_or("one address");
            let mut parts = Vec::new();
            if *agent > 0 {
                parts.push(format!("agent key {agent}"));
            }
            if *admin > 0 {
                parts.push(format!("admin key {admin}"));
            }
            if *ui > 0 {
                parts.push(format!("admin UI {ui}"));
            }
            format!(
                "{} failed authentication attempts from {ip} in the last {} ({}).{}",
                f.count,
                window_text(*window_secs),
                parts.join(", "),
                request_only(f)
            )
        }
        Kind::LockedOut => {
            let ip = f.source_ip.as_deref().unwrap_or("one address");
            format!("The admin UI locked out sign-ins from {ip} after too many failed attempts.{}", request_only(f))
        }
        Kind::VaultLocked => format!(
            "The vault is locked. Agents cannot use credentials until it is unlocked again.{tail}"
        ),
        Kind::VaultUnlockFailed => format!(
            "Ferrowarden could not unlock the vault. Credentials stay unavailable until it can.{tail}"
        ),
        Kind::VaultSyncFailed => format!("Ferrowarden could not sync with the vault.{tail}"),
        Kind::VaultRecovered => {
            "The vault is unlocked again. Credentials are available to agents.".to_string()
        }
        Kind::KeyCreated => format!("{} was created.{tail}", key_phrase(f, "An agent key")),
        Kind::KeyRevoked => format!("{} was revoked.{tail}", key_phrase(f, "An agent key")),
        Kind::KeyPolicyChanged => {
            format!("The policy of {} was changed.{tail}", key_phrase(f, "an agent key"))
        }
        Kind::UiSignIn => format!("Someone signed in to the admin UI.{tail}"),
        Kind::EventsDropped => format!(
            "{} security event{} dropped because the event queue was full.",
            f.count,
            if f.count == 1 { " was" } else { "s were" }
        ),
        Kind::NotificationsDropped => format!(
            "{} notification{} dropped because a queue was full.",
            f.count,
            if f.count == 1 { " was" } else { "s were" }
        ),
        Kind::Paused { limit } => format!(
            "Notification limit reached ({limit} per hour). Notifications are paused until the hour rolls over; {} suppressed so far.",
            f.count
        ),
        Kind::Test => "This is a test notification from Ferrowarden. If you can read it, this notifier is set up correctly.".to_string(),
        Kind::ApprovalRequest => approval_message(f),
    }
}

/// The approval prompt: who, which credentials, what request, how to decide.
/// Nothing a request carried beyond its method, host and path.
fn approval_message(f: &EventFields) -> String {
    let who = key_phrase(f, "An agent key");
    let what = if f.credentials.is_empty() {
        "a credential".to_string()
    } else {
        list(&f.credentials)
    };
    let Some(a) = &f.approval else {
        return format!("{who} is waiting for approval to use {what}.");
    };
    let expires = DateTime::parse_from_rfc3339(&a.expires_at)
        .map(|t| t.with_timezone(&Utc).format("%H:%M UTC").to_string())
        .unwrap_or_else(|_| a.expires_at.clone());
    let decide = match &a.link {
        Some(link) => format!("Approve or deny: {link}"),
        None => {
            "Open the Approvals page of the Ferrowarden admin UI to approve or deny.".to_string()
        }
    };
    format!(
        "{who} wants to use {what} for {} {}{}. {decide} Approval {}, open until {expires}.",
        a.method, a.target, a.path, a.id
    )
}

/// ` Request 0193abcd….` when only a request id is worth showing.
fn request_only(f: &EventFields) -> String {
    match &f.request_id {
        Some(id) => {
            let short: String = id.chars().take(8).collect();
            let ellipsis = if id.chars().count() > 8 {
                "\u{2026}"
            } else {
                ""
            };
            format!(" Request {short}{ellipsis}.")
        }
        None => String::new(),
    }
}
