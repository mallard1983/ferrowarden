//! The security event schema (schema_version 1).
//!
//! One [`SecurityEvent`] per security-relevant thing Ferrowarden does,
//! serialized as a single JSON object with ECS-style field names. Fields that
//! do not apply are omitted, never null. Callers build events with the
//! fluent builder and never choose ECS category/type themselves: those are
//! derived from the action and outcome.
//!
//! Nothing here can carry a secret: every free-form string comes from the
//! caller, is truncated, and is only ever emitted through serde (JSON escaping
//! prevents log injection). Credential values, tokens and hashes have no
//! field to live in.

use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::Url;
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use std::net::IpAddr;
use std::time::Duration;

use crate::error::FerroError;
use crate::middleware::request_context::RequestContext;
use crate::state::AgentKey;

/// Bumped on breaking changes to the event format.
pub const SCHEMA_VERSION: u32 = 1;
/// Value of `event.dataset`; distinguishes events from application logs.
pub const DATASET: &str = "ferrowarden.security";
/// Longest `url.original`, in characters.
pub const MAX_URL_CHARS: usize = 2048;
/// Longest agent-supplied string (method, key name, label, ...), in characters.
pub const MAX_FIELD_CHARS: usize = 128;
/// Longest error message copied into `details.error`, in characters.
pub const MAX_ERROR_CHARS: usize = 256;
/// Most credential labels recorded on one event.
const MAX_CREDENTIAL_LABELS: usize = 64;

/// Cut `s` to at most `max` characters.
pub fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

// ── Enums ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Forward,
    CredentialsList,
    AgentAuth,
    AdminAuth,
    RateLimited,
    RequestRejected,
    KeyCreate,
    KeyRevoke,
    KeyList,
    KeyPolicyChange,
    PolicyPreview,
    AuditRead,
    StatusRead,
    OpenapiRead,
    VaultUnlock,
    VaultLock,
    VaultSync,
    Startup,
    Shutdown,
    EventsDropped,
    UiLogin,
    UiLogout,
    UiSessionExpired,
    UiTwoFactorEmailSent,
    NotifyTest,
}

impl Action {
    /// Every action, in the order the audit view lists them. Keep in step
    /// with the enum: the `all_actions_are_listed` test counts the variants.
    pub const ALL: [Action; 25] = [
        Action::Forward,
        Action::CredentialsList,
        Action::AgentAuth,
        Action::AdminAuth,
        Action::RateLimited,
        Action::RequestRejected,
        Action::KeyCreate,
        Action::KeyRevoke,
        Action::KeyList,
        Action::KeyPolicyChange,
        Action::PolicyPreview,
        Action::AuditRead,
        Action::StatusRead,
        Action::OpenapiRead,
        Action::VaultUnlock,
        Action::VaultLock,
        Action::VaultSync,
        Action::Startup,
        Action::Shutdown,
        Action::EventsDropped,
        Action::UiLogin,
        Action::UiLogout,
        Action::UiSessionExpired,
        Action::UiTwoFactorEmailSent,
        Action::NotifyTest,
    ];

    /// The action whose wire name (`as_str`) is `name`.
    pub fn from_name(name: &str) -> Option<Action> {
        Action::ALL.into_iter().find(|a| a.as_str() == name)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Action::Forward => "forward",
            Action::CredentialsList => "credentials_list",
            Action::AgentAuth => "agent_auth",
            Action::AdminAuth => "admin_auth",
            Action::RateLimited => "rate_limited",
            Action::RequestRejected => "request_rejected",
            Action::KeyCreate => "key_create",
            Action::KeyRevoke => "key_revoke",
            Action::KeyList => "key_list",
            Action::KeyPolicyChange => "key_policy_change",
            Action::PolicyPreview => "policy_preview",
            Action::AuditRead => "audit_read",
            Action::StatusRead => "status_read",
            Action::OpenapiRead => "openapi_read",
            Action::VaultUnlock => "vault_unlock",
            Action::VaultLock => "vault_lock",
            Action::VaultSync => "vault_sync",
            Action::Startup => "startup",
            Action::Shutdown => "shutdown",
            Action::EventsDropped => "events_dropped",
            Action::UiLogin => "ui_login",
            Action::UiLogout => "ui_logout",
            Action::UiSessionExpired => "ui_session_expired",
            Action::UiTwoFactorEmailSent => "ui_two_factor_email_sent",
            Action::NotifyTest => "notify_test",
        }
    }

    /// ECS `event.category`.
    fn category(self) -> &'static str {
        match self {
            Action::Forward
            | Action::CredentialsList
            | Action::RequestRejected
            | Action::AuditRead
            | Action::StatusRead
            | Action::OpenapiRead => "web",
            Action::AgentAuth
            | Action::AdminAuth
            | Action::VaultUnlock
            | Action::UiLogin
            | Action::UiLogout
            | Action::UiSessionExpired
            | Action::UiTwoFactorEmailSent => "authentication",
            Action::RateLimited => "network",
            Action::KeyCreate
            | Action::KeyRevoke
            | Action::KeyList
            | Action::KeyPolicyChange
            | Action::PolicyPreview => "iam",
            Action::VaultLock
            | Action::VaultSync
            | Action::Startup
            | Action::Shutdown
            | Action::EventsDropped
            | Action::NotifyTest => "configuration",
        }
    }

    /// Actions that are only ever recorded when something went wrong.
    fn failure_only(self) -> bool {
        matches!(
            self,
            Action::AgentAuth | Action::AdminAuth | Action::RateLimited | Action::RequestRejected
        )
    }

    /// Words for the human-readable `message` of a failure.
    fn label(self) -> &'static str {
        match self {
            Action::Forward => "forward",
            Action::CredentialsList => "credentials list",
            Action::AgentAuth => "agent authentication",
            Action::AdminAuth => "admin authentication",
            Action::RateLimited | Action::RequestRejected => "request",
            Action::KeyCreate => "key creation",
            Action::KeyRevoke => "key revocation",
            Action::KeyList => "key listing",
            Action::KeyPolicyChange => "key policy change",
            Action::PolicyPreview => "policy preview",
            Action::AuditRead => "audit read",
            Action::StatusRead => "status read",
            Action::OpenapiRead => "OpenAPI read",
            Action::VaultUnlock => "vault unlock",
            Action::VaultLock => "vault lock",
            Action::VaultSync => "vault sync",
            Action::Startup => "startup",
            Action::Shutdown => "shutdown",
            Action::EventsDropped => "event delivery",
            Action::UiLogin => "UI sign-in",
            Action::UiLogout => "UI sign-out",
            Action::UiSessionExpired => "UI session",
            Action::UiTwoFactorEmailSent => "UI email code",
            Action::NotifyTest => "test notification",
        }
    }

    /// Message for a successful (or outcome-less) event.
    fn ok_message(self) -> &'static str {
        match self {
            Action::Forward => "forward succeeded",
            Action::CredentialsList => "credentials listed",
            Action::AgentAuth => "agent authenticated",
            Action::AdminAuth => "admin authenticated",
            Action::RateLimited => "request rate limited",
            Action::RequestRejected => "request rejected",
            Action::KeyCreate => "agent key created",
            Action::KeyRevoke => "agent key revoked",
            Action::KeyList => "agent keys listed",
            Action::KeyPolicyChange => "agent key policy changed",
            Action::PolicyPreview => "policy previewed",
            Action::AuditRead => "audit log read",
            Action::StatusRead => "status read",
            Action::OpenapiRead => "OpenAPI document read",
            Action::VaultUnlock => "vault unlocked",
            Action::VaultLock => "vault locked",
            Action::VaultSync => "credential cache refreshed",
            Action::Startup => "ferrowarden started",
            Action::Shutdown => "ferrowarden shutting down",
            Action::EventsDropped => "security events were dropped",
            Action::UiLogin => "UI sign-in succeeded",
            Action::UiLogout => "UI signed out",
            Action::UiSessionExpired => "UI session expired",
            Action::UiTwoFactorEmailSent => "UI email code requested",
            Action::NotifyTest => "test notification sent",
        }
    }
}

/// ECS `event.outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
    Unknown,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
            Outcome::Unknown => "unknown",
        }
    }

    pub fn from_name(name: &str) -> Option<Outcome> {
        [Outcome::Success, Outcome::Failure, Outcome::Unknown]
            .into_iter()
            .find(|o| o.as_str() == name)
    }
}

/// `event.reason`: a fixed code, never free text from a request. Extend only
/// by adding variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    MissingKey,
    InvalidKey,
    MissingAdminKey,
    InvalidAdminKey,
    RateLimited,
    InvalidJson,
    InvalidRequest,
    TargetBlocked,
    InvalidTargetUrl,
    CredentialHostNotAllowed,
    CredentialOutOfScope,
    MethodNotAllowed,
    RepromptRequired,
    UnknownCredential,
    AmbiguousCredential,
    AmbiguousField,
    MalformedPlaceholder,
    VaultLocked,
    UpstreamError,
    ResponseTooLarge,
    KeyNotFound,
    UnlockFailed,
    SyncFailed,
    InternalError,
    InvalidCredentials,
    TwoFactorRequired,
    TwoFactorFailed,
    LoginLockedOut,
    UpstreamRateLimited,
    InsecureTransport,
}

impl Reason {
    /// Every reason, in declaration order (tests and the notifier tables).
    #[cfg(test)]
    pub const ALL: [Reason; 30] = [
        Reason::MissingKey,
        Reason::InvalidKey,
        Reason::MissingAdminKey,
        Reason::InvalidAdminKey,
        Reason::RateLimited,
        Reason::InvalidJson,
        Reason::InvalidRequest,
        Reason::TargetBlocked,
        Reason::InvalidTargetUrl,
        Reason::CredentialHostNotAllowed,
        Reason::CredentialOutOfScope,
        Reason::MethodNotAllowed,
        Reason::RepromptRequired,
        Reason::UnknownCredential,
        Reason::AmbiguousCredential,
        Reason::AmbiguousField,
        Reason::MalformedPlaceholder,
        Reason::VaultLocked,
        Reason::UpstreamError,
        Reason::ResponseTooLarge,
        Reason::KeyNotFound,
        Reason::UnlockFailed,
        Reason::SyncFailed,
        Reason::InternalError,
        Reason::InvalidCredentials,
        Reason::TwoFactorRequired,
        Reason::TwoFactorFailed,
        Reason::LoginLockedOut,
        Reason::UpstreamRateLimited,
        Reason::InsecureTransport,
    ];

    /// The wire code (`event.reason`), the same text serde writes.
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::MissingKey => "missing_key",
            Reason::InvalidKey => "invalid_key",
            Reason::MissingAdminKey => "missing_admin_key",
            Reason::InvalidAdminKey => "invalid_admin_key",
            Reason::RateLimited => "rate_limited",
            Reason::InvalidJson => "invalid_json",
            Reason::InvalidRequest => "invalid_request",
            Reason::TargetBlocked => "target_blocked",
            Reason::InvalidTargetUrl => "invalid_target_url",
            Reason::CredentialHostNotAllowed => "credential_host_not_allowed",
            Reason::CredentialOutOfScope => "credential_out_of_scope",
            Reason::MethodNotAllowed => "method_not_allowed",
            Reason::RepromptRequired => "reprompt_required",
            Reason::UnknownCredential => "unknown_credential",
            Reason::AmbiguousCredential => "ambiguous_credential",
            Reason::AmbiguousField => "ambiguous_field",
            Reason::MalformedPlaceholder => "malformed_placeholder",
            Reason::VaultLocked => "vault_locked",
            Reason::UpstreamError => "upstream_error",
            Reason::ResponseTooLarge => "response_too_large",
            Reason::KeyNotFound => "key_not_found",
            Reason::UnlockFailed => "unlock_failed",
            Reason::SyncFailed => "sync_failed",
            Reason::InternalError => "internal_error",
            Reason::InvalidCredentials => "invalid_credentials",
            Reason::TwoFactorRequired => "two_factor_required",
            Reason::TwoFactorFailed => "two_factor_failed",
            Reason::LoginLockedOut => "login_locked_out",
            Reason::UpstreamRateLimited => "upstream_rate_limited",
            Reason::InsecureTransport => "insecure_transport",
        }
    }

    /// A request that was refused on policy or authentication grounds, as
    /// opposed to one that failed for operational reasons. Adds ECS type
    /// `denied` and turns "failed" into "blocked" in the message.
    pub fn is_denial(self) -> bool {
        matches!(
            self,
            Reason::MissingKey
                | Reason::InvalidKey
                | Reason::MissingAdminKey
                | Reason::InvalidAdminKey
                | Reason::RateLimited
                | Reason::InvalidJson
                | Reason::InvalidRequest
                | Reason::TargetBlocked
                | Reason::CredentialHostNotAllowed
                | Reason::CredentialOutOfScope
                | Reason::MethodNotAllowed
                | Reason::RepromptRequired
                | Reason::InvalidCredentials
                | Reason::TwoFactorFailed
                | Reason::LoginLockedOut
                | Reason::InsecureTransport
        )
    }

    /// Fixed text for the `message` field.
    pub fn description(self) -> &'static str {
        match self {
            Reason::MissingKey => "no agent key presented",
            Reason::InvalidKey => "invalid agent key",
            Reason::MissingAdminKey => "no admin key presented",
            Reason::InvalidAdminKey => "invalid admin key",
            Reason::RateLimited => "rate limit exceeded",
            Reason::InvalidJson => "invalid JSON body",
            Reason::InvalidRequest => "invalid request",
            Reason::TargetBlocked => "target not allowed by the outbound policy",
            Reason::InvalidTargetUrl => "invalid target URL",
            Reason::CredentialHostNotAllowed => "credential not bound to target host",
            Reason::CredentialOutOfScope => "credential not available to this agent key",
            Reason::MethodNotAllowed => "method not allowed for this agent key",
            Reason::RepromptRequired => "credential requires master password re-prompt",
            Reason::UnknownCredential => "unknown credential or field",
            Reason::AmbiguousCredential => "credential name is ambiguous",
            Reason::AmbiguousField => "credential field name is ambiguous",
            Reason::MalformedPlaceholder => "malformed placeholder",
            Reason::VaultLocked => "vault is locked",
            Reason::UpstreamError => "upstream request failed",
            Reason::ResponseTooLarge => "response exceeded the size limit",
            Reason::KeyNotFound => "agent key not found",
            Reason::UnlockFailed => "vault unlock failed",
            Reason::SyncFailed => "credential sync failed",
            Reason::InternalError => "internal error",
            Reason::InvalidCredentials => "invalid password or code",
            Reason::TwoFactorRequired => "password accepted, second factor required",
            Reason::TwoFactorFailed => "second factor code rejected",
            Reason::LoginLockedOut => "too many failed attempts",
            Reason::UpstreamRateLimited => "Vaultwarden rate limit reached",
            Reason::InsecureTransport => "the connection is not HTTPS",
        }
    }
}

/// Every [`FerroError`] maps to exactly one reason. The match is exhaustive on
/// purpose (no catch-all): adding an error variant must force a decision here.
impl From<&FerroError> for Reason {
    fn from(error: &FerroError) -> Self {
        match error {
            FerroError::VaultLocked => Reason::VaultLocked,
            FerroError::UnlockFailed(_) => Reason::UnlockFailed,
            FerroError::CredentialNotFound(_) => Reason::UnknownCredential,
            FerroError::VaultClient(_) => Reason::UpstreamError,
            FerroError::VaultUnavailable => Reason::UpstreamError,
            FerroError::AmbiguousCredential(_) => Reason::AmbiguousCredential,
            FerroError::CredentialHostNotAllowed { .. } => Reason::CredentialHostNotAllowed,
            FerroError::Unauthorized => Reason::InvalidKey,
            FerroError::AgentKeyNotFound => Reason::KeyNotFound,
            FerroError::CredentialOutOfScope(_) => Reason::CredentialOutOfScope,
            FerroError::MethodNotAllowed(_) => Reason::MethodNotAllowed,
            FerroError::ForwardFailed(_) => Reason::UpstreamError,
            FerroError::InvalidTargetUrl(_) => Reason::InvalidTargetUrl,
            FerroError::TargetBlocked(_) => Reason::TargetBlocked,
            FerroError::ResponseTooLarge(_) => Reason::ResponseTooLarge,
            FerroError::UnknownPlaceholder(_) => Reason::UnknownCredential,
            FerroError::MalformedPlaceholder(_) => Reason::MalformedPlaceholder,
            FerroError::AmbiguousField { .. } => Reason::AmbiguousField,
            FerroError::RepromptRequired(_) => Reason::RepromptRequired,
            FerroError::Config(_) => Reason::InternalError,
            FerroError::UnlockEndpointDisabled => Reason::InvalidRequest,
            FerroError::InvalidRequest(_) => Reason::InvalidRequest,
            FerroError::InvalidJson(_) => Reason::InvalidJson,
            FerroError::Internal(_) => Reason::InternalError,
        }
    }
}

// ── Event structure ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct EventInfo {
    pub kind: &'static str,
    pub dataset: &'static str,
    pub action: Action,
    pub category: Vec<&'static str>,
    #[serde(rename = "type")]
    pub types: Vec<&'static str>,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    /// Nanoseconds; only where measured (forward).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Source {
    pub ip: IpAddr,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Http {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<HttpRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<HttpResponse>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpRequest {
    pub method: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpResponse {
    /// A number, not a string.
    pub status_code: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct UrlInfo {
    /// The URL as the agent sent it, before substitution (placeholders, never
    /// values), truncated.
    pub original: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Service {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyInfo {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FerrowardenInfo {
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Map<String, Value>>,
}

fn serialize_timestamp<S: Serializer>(t: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// One security event. Build with [`SecurityEvent::new`] and the fluent
/// setters; hand it to `EventLog::emit`.
#[derive(Debug, Clone, Serialize)]
pub struct SecurityEvent {
    /// UTC RFC 3339 with milliseconds and `Z`.
    #[serde(rename = "@timestamp", serialize_with = "serialize_timestamp")]
    pub timestamp: DateTime<Utc>,
    pub message: String,
    pub event: EventInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<Http>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<UrlInfo>,
    pub service: Service,
    pub ferrowarden: FerrowardenInfo,
}

impl SecurityEvent {
    pub fn new(action: Action) -> Self {
        let outcome = if action.failure_only() {
            Outcome::Failure
        } else {
            Outcome::Success
        };
        let mut event = Self {
            timestamp: Utc::now(),
            message: String::new(),
            event: EventInfo {
                kind: "event",
                dataset: DATASET,
                action,
                category: vec![action.category()],
                types: Vec::new(),
                outcome,
                reason: None,
                duration: None,
            },
            source: None,
            http: None,
            url: None,
            service: Service {
                name: "ferrowarden",
                version: env!("CARGO_PKG_VERSION"),
            },
            ferrowarden: FerrowardenInfo {
                schema_version: SCHEMA_VERSION,
                request_id: None,
                key: None,
                credentials: Vec::new(),
                details: None,
            },
        };
        event.refresh();
        event
    }

    /// Recompute the fields derived from action, outcome and reason.
    fn refresh(&mut self) {
        let action = self.event.action;
        let denied = self.event.reason.is_some_and(Reason::is_denial);
        self.event.types = match action {
            Action::Forward => {
                if denied {
                    vec!["access", "denied"]
                } else {
                    vec!["access"]
                }
            }
            Action::CredentialsList
            | Action::KeyList
            | Action::PolicyPreview
            | Action::AuditRead
            | Action::StatusRead
            | Action::OpenapiRead => vec!["access"],
            Action::KeyPolicyChange => vec!["change"],
            Action::AgentAuth | Action::AdminAuth | Action::VaultUnlock => vec!["start"],
            Action::UiLogin => {
                if denied {
                    vec!["start", "denied"]
                } else {
                    vec!["start"]
                }
            }
            Action::UiLogout | Action::UiSessionExpired => vec!["end"],
            Action::UiTwoFactorEmailSent => vec!["info"],
            Action::RateLimited | Action::RequestRejected => vec!["denied"],
            Action::KeyCreate => vec!["creation"],
            Action::KeyRevoke => vec!["deletion"],
            Action::VaultLock => vec!["change"],
            Action::VaultSync | Action::EventsDropped | Action::NotifyTest => vec!["info"],
            Action::Startup => vec!["start"],
            Action::Shutdown => vec!["end"],
        };
        self.message = match (self.event.outcome, self.event.reason) {
            (Outcome::Failure, Some(reason)) => format!(
                "{} {}: {}",
                action.label(),
                if reason.is_denial() {
                    "blocked"
                } else {
                    "failed"
                },
                reason.description()
            ),
            (Outcome::Failure, None) => format!("{} failed", action.label()),
            // Step one of two (password accepted, second factor pending).
            (Outcome::Unknown, Some(reason)) => {
                format!("{} incomplete: {}", action.label(), reason.description())
            }
            _ => action.ok_message().to_string(),
        };
    }

    pub fn outcome(mut self, outcome: Outcome) -> Self {
        self.event.outcome = outcome;
        self.refresh();
        self
    }

    pub fn reason(mut self, reason: Reason) -> Self {
        self.event.reason = Some(reason);
        self.refresh();
        self
    }

    /// Mark the event as a failure for `error` (outcome and reason).
    pub fn failed_with(self, error: &FerroError) -> Self {
        self.outcome(Outcome::Failure).reason(Reason::from(error))
    }

    /// Attach the request ID and client IP.
    pub fn request(mut self, ctx: &RequestContext) -> Self {
        self.ferrowarden.request_id = Some(ctx.request_id.clone());
        self.source = Some(Source { ip: ctx.client_ip });
        self
    }

    /// The agent key that made the request.
    pub fn key(mut self, key: &AgentKey) -> Self {
        self.ferrowarden.key = Some(KeyInfo {
            id: truncate(&key.id, MAX_FIELD_CHARS),
            name: truncate(&key.name, MAX_FIELD_CHARS),
        });
        self
    }

    pub fn method(mut self, method: &str) -> Self {
        self.http.get_or_insert_with(Http::default).request = Some(HttpRequest {
            method: truncate(method, MAX_FIELD_CHARS),
        });
        self
    }

    pub fn status(mut self, status_code: u16) -> Self {
        self.http.get_or_insert_with(Http::default).response = Some(HttpResponse { status_code });
        self
    }

    /// The agent-supplied URL, before substitution.
    pub fn url(mut self, original: &str) -> Self {
        let domain = Url::parse(original)
            .ok()
            .and_then(|u| u.host_str().map(|h| truncate(h, MAX_FIELD_CHARS)));
        self.url = Some(UrlInfo {
            original: truncate(original, MAX_URL_CHARS),
            domain,
        });
        self
    }

    /// Placeholder labels (never values). Capped in count and length.
    pub fn credentials<I, S>(mut self, labels: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.ferrowarden.credentials = labels
            .into_iter()
            .take(MAX_CREDENTIAL_LABELS)
            .map(|l| truncate(l.as_ref(), MAX_FIELD_CHARS))
            .collect();
        self
    }

    pub fn duration(mut self, elapsed: Duration) -> Self {
        self.event.duration = Some(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
        self
    }

    /// Add one entry to `ferrowarden.details`. Callers must only pass safe
    /// values: counts, flags, route templates, truncated names.
    pub fn detail(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.ferrowarden
            .details
            .get_or_insert_with(Map::new)
            .insert(key.to_string(), value.into());
        self
    }

    /// [`detail`](Self::detail) for an agent-supplied string: truncated.
    pub fn detail_str(self, key: &str, value: &str) -> Self {
        self.detail(key, truncate(value, MAX_FIELD_CHARS))
    }
}

#[cfg(test)]
mod tests;
