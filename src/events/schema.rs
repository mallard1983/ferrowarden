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
    AuditRead,
    StatusRead,
    VaultUnlock,
    VaultLock,
    VaultSync,
    Startup,
    Shutdown,
    EventsDropped,
}

impl Action {
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
            Action::AuditRead => "audit_read",
            Action::StatusRead => "status_read",
            Action::VaultUnlock => "vault_unlock",
            Action::VaultLock => "vault_lock",
            Action::VaultSync => "vault_sync",
            Action::Startup => "startup",
            Action::Shutdown => "shutdown",
            Action::EventsDropped => "events_dropped",
        }
    }

    /// ECS `event.category`.
    fn category(self) -> &'static str {
        match self {
            Action::Forward
            | Action::CredentialsList
            | Action::RequestRejected
            | Action::AuditRead
            | Action::StatusRead => "web",
            Action::AgentAuth | Action::AdminAuth | Action::VaultUnlock => "authentication",
            Action::RateLimited => "network",
            Action::KeyCreate | Action::KeyRevoke | Action::KeyList => "iam",
            Action::VaultLock
            | Action::VaultSync
            | Action::Startup
            | Action::Shutdown
            | Action::EventsDropped => "configuration",
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
            Action::AuditRead => "audit read",
            Action::StatusRead => "status read",
            Action::VaultUnlock => "vault unlock",
            Action::VaultLock => "vault lock",
            Action::VaultSync => "vault sync",
            Action::Startup => "startup",
            Action::Shutdown => "shutdown",
            Action::EventsDropped => "event delivery",
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
            Action::AuditRead => "audit log read",
            Action::StatusRead => "status read",
            Action::VaultUnlock => "vault unlocked",
            Action::VaultLock => "vault locked",
            Action::VaultSync => "credential cache refreshed",
            Action::Startup => "ferrowarden started",
            Action::Shutdown => "ferrowarden shutting down",
            Action::EventsDropped => "security events were dropped",
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
}

impl Reason {
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
                | Reason::RepromptRequired
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
            Action::CredentialsList | Action::KeyList | Action::AuditRead | Action::StatusRead => {
                vec!["access"]
            }
            Action::AgentAuth | Action::AdminAuth | Action::VaultUnlock => vec!["start"],
            Action::RateLimited | Action::RequestRejected => vec!["denied"],
            Action::KeyCreate => vec!["creation"],
            Action::KeyRevoke => vec!["deletion"],
            Action::VaultLock => vec!["change"],
            Action::VaultSync | Action::EventsDropped => vec!["info"],
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
mod tests {
    use super::*;
    use serde_json::json;

    fn to_json(e: &SecurityEvent) -> Value {
        serde_json::to_value(e).unwrap()
    }

    fn ctx() -> RequestContext {
        RequestContext::new("172.20.0.5".parse().unwrap())
    }

    fn agent() -> AgentKey {
        AgentKey {
            id: "11111111-1111-1111-1111-111111111111".into(),
            name: "monitoring-agent".into(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn forward_failure_matches_documented_shape() {
        let c = ctx();
        let e = SecurityEvent::new(Action::Forward)
            .request(&c)
            .key(&agent())
            .method("POST")
            .url("https://api.example.com/x?token={{vault:t}}")
            .credentials(["t"])
            .duration(Duration::from_nanos(12345678))
            .outcome(Outcome::Failure)
            .reason(Reason::CredentialHostNotAllowed)
            .status(403);
        let v = to_json(&e);

        assert_eq!(v["event"]["kind"], "event");
        assert_eq!(v["event"]["dataset"], "ferrowarden.security");
        assert_eq!(v["event"]["action"], "forward");
        assert_eq!(v["event"]["category"], json!(["web"]));
        assert_eq!(v["event"]["type"], json!(["access", "denied"]));
        assert_eq!(v["event"]["outcome"], "failure");
        assert_eq!(v["event"]["reason"], "credential_host_not_allowed");
        assert_eq!(v["event"]["duration"], 12345678);
        assert_eq!(
            v["message"],
            "forward blocked: credential not bound to target host"
        );
        assert_eq!(v["source"]["ip"], "172.20.0.5");
        assert_eq!(v["http"]["request"]["method"], "POST");
        // A number, not "Some(403)" or "403".
        assert_eq!(v["http"]["response"]["status_code"], 403);
        assert!(v["http"]["response"]["status_code"].is_u64());
        assert_eq!(
            v["url"]["original"],
            "https://api.example.com/x?token={{vault:t}}"
        );
        assert_eq!(v["url"]["domain"], "api.example.com");
        assert_eq!(v["service"]["name"], "ferrowarden");
        assert_eq!(v["ferrowarden"]["schema_version"], 1);
        assert_eq!(v["ferrowarden"]["request_id"], c.request_id.as_str());
        assert_eq!(v["ferrowarden"]["key"]["name"], "monitoring-agent");
        assert_eq!(v["ferrowarden"]["credentials"], json!(["t"]));
    }

    #[test]
    fn inapplicable_fields_are_omitted_not_null() {
        let v = to_json(&SecurityEvent::new(Action::Shutdown));
        let text = v.to_string();
        assert!(!text.contains("null"), "{text}");
        for absent in ["source", "http", "url"] {
            assert!(v.get(absent).is_none(), "{absent} should be omitted");
        }
        assert!(v["event"].get("reason").is_none());
        assert!(v["event"].get("duration").is_none());
        assert!(v["ferrowarden"].get("request_id").is_none());
        assert!(v["ferrowarden"].get("key").is_none());
        assert!(v["ferrowarden"].get("credentials").is_none());
        assert!(v["ferrowarden"].get("details").is_none());
    }

    #[test]
    fn timestamp_is_utc_rfc3339_with_milliseconds() {
        let v = to_json(&SecurityEvent::new(Action::Startup));
        let ts = v["@timestamp"].as_str().unwrap();
        // 2026-11-21T14:03:11.402Z
        assert_eq!(ts.len(), 24, "{ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[19..20], ".");
        assert!(DateTime::parse_from_rfc3339(ts).is_ok());
    }

    #[test]
    fn ecs_category_and_type_follow_the_action_table() {
        let cases = [
            (Action::Forward, "web", vec!["access"]),
            (Action::CredentialsList, "web", vec!["access"]),
            (Action::AgentAuth, "authentication", vec!["start"]),
            (Action::AdminAuth, "authentication", vec!["start"]),
            (Action::RateLimited, "network", vec!["denied"]),
            (Action::RequestRejected, "web", vec!["denied"]),
            (Action::KeyCreate, "iam", vec!["creation"]),
            (Action::KeyRevoke, "iam", vec!["deletion"]),
            (Action::KeyList, "iam", vec!["access"]),
            (Action::AuditRead, "web", vec!["access"]),
            (Action::StatusRead, "web", vec!["access"]),
            (Action::VaultUnlock, "authentication", vec!["start"]),
            (Action::VaultLock, "configuration", vec!["change"]),
            (Action::VaultSync, "configuration", vec!["info"]),
            (Action::Startup, "configuration", vec!["start"]),
            (Action::Shutdown, "configuration", vec!["end"]),
            (Action::EventsDropped, "configuration", vec!["info"]),
        ];
        for (action, category, types) in cases {
            let e = SecurityEvent::new(action);
            assert_eq!(e.event.category, vec![category], "{action:?}");
            assert_eq!(e.event.types, types, "{action:?}");
        }
        // `denied` is added to a forward only when it was blocked.
        let blocked = SecurityEvent::new(Action::Forward)
            .outcome(Outcome::Failure)
            .reason(Reason::TargetBlocked);
        assert_eq!(blocked.event.types, vec!["access", "denied"]);
        let upstream = SecurityEvent::new(Action::Forward)
            .outcome(Outcome::Failure)
            .reason(Reason::UpstreamError);
        assert_eq!(upstream.event.types, vec!["access"]);
    }

    #[test]
    fn failure_only_actions_default_to_failure() {
        for a in [
            Action::AgentAuth,
            Action::AdminAuth,
            Action::RateLimited,
            Action::RequestRejected,
        ] {
            assert_eq!(SecurityEvent::new(a).event.outcome, Outcome::Failure);
        }
        assert_eq!(
            SecurityEvent::new(Action::Forward).event.outcome,
            Outcome::Success
        );
    }

    #[test]
    fn action_names_match_serde_names() {
        for a in [
            Action::Forward,
            Action::CredentialsList,
            Action::AgentAuth,
            Action::AdminAuth,
            Action::RateLimited,
            Action::RequestRejected,
            Action::KeyCreate,
            Action::KeyRevoke,
            Action::KeyList,
            Action::AuditRead,
            Action::StatusRead,
            Action::VaultUnlock,
            Action::VaultLock,
            Action::VaultSync,
            Action::Startup,
            Action::Shutdown,
            Action::EventsDropped,
        ] {
            assert_eq!(serde_json::to_value(a).unwrap(), a.as_str());
        }
    }

    #[test]
    fn every_ferro_error_variant_maps_to_a_reason() {
        // One of each variant. The `From<&FerroError>` match has no catch-all,
        // so a new variant fails to compile until it is mapped; this test pins
        // the actual mapping.
        let cases: Vec<(FerroError, Reason)> = vec![
            (FerroError::VaultLocked, Reason::VaultLocked),
            (FerroError::UnlockFailed("x".into()), Reason::UnlockFailed),
            (
                FerroError::CredentialNotFound("x".into()),
                Reason::UnknownCredential,
            ),
            (FerroError::VaultUnavailable, Reason::UpstreamError),
            (
                FerroError::AmbiguousCredential("x".into()),
                Reason::AmbiguousCredential,
            ),
            (
                FerroError::CredentialHostNotAllowed {
                    name: "n".into(),
                    host: "h".into(),
                    reason: "r".into(),
                },
                Reason::CredentialHostNotAllowed,
            ),
            (FerroError::Unauthorized, Reason::InvalidKey),
            (FerroError::AgentKeyNotFound, Reason::KeyNotFound),
            (FerroError::ForwardFailed("x".into()), Reason::UpstreamError),
            (
                FerroError::InvalidTargetUrl("x".into()),
                Reason::InvalidTargetUrl,
            ),
            (FerroError::TargetBlocked("x".into()), Reason::TargetBlocked),
            (FerroError::ResponseTooLarge(1), Reason::ResponseTooLarge),
            (
                FerroError::UnknownPlaceholder("x".into()),
                Reason::UnknownCredential,
            ),
            (
                FerroError::MalformedPlaceholder("x".into()),
                Reason::MalformedPlaceholder,
            ),
            (
                FerroError::AmbiguousField {
                    item: "i".into(),
                    field: "f".into(),
                },
                Reason::AmbiguousField,
            ),
            (
                FerroError::RepromptRequired("x".into()),
                Reason::RepromptRequired,
            ),
            (FerroError::Config("x".into()), Reason::InternalError),
            (FerroError::UnlockEndpointDisabled, Reason::InvalidRequest),
            (
                FerroError::InvalidRequest("x".into()),
                Reason::InvalidRequest,
            ),
            (FerroError::InvalidJson("x".into()), Reason::InvalidJson),
            (FerroError::Internal("x".into()), Reason::InternalError),
        ];
        for (err, reason) in &cases {
            assert_eq!(Reason::from(err), *reason, "{err}");
        }
    }

    #[test]
    fn reason_codes_are_the_documented_snake_case_list() {
        let all = [
            (Reason::MissingKey, "missing_key"),
            (Reason::InvalidKey, "invalid_key"),
            (Reason::MissingAdminKey, "missing_admin_key"),
            (Reason::InvalidAdminKey, "invalid_admin_key"),
            (Reason::RateLimited, "rate_limited"),
            (Reason::InvalidJson, "invalid_json"),
            (Reason::InvalidRequest, "invalid_request"),
            (Reason::TargetBlocked, "target_blocked"),
            (Reason::InvalidTargetUrl, "invalid_target_url"),
            (
                Reason::CredentialHostNotAllowed,
                "credential_host_not_allowed",
            ),
            (Reason::RepromptRequired, "reprompt_required"),
            (Reason::UnknownCredential, "unknown_credential"),
            (Reason::AmbiguousCredential, "ambiguous_credential"),
            (Reason::AmbiguousField, "ambiguous_field"),
            (Reason::MalformedPlaceholder, "malformed_placeholder"),
            (Reason::VaultLocked, "vault_locked"),
            (Reason::UpstreamError, "upstream_error"),
            (Reason::ResponseTooLarge, "response_too_large"),
            (Reason::KeyNotFound, "key_not_found"),
            (Reason::UnlockFailed, "unlock_failed"),
            (Reason::SyncFailed, "sync_failed"),
            (Reason::InternalError, "internal_error"),
        ];
        for (reason, code) in all {
            assert_eq!(serde_json::to_value(reason).unwrap(), code);
        }
    }

    #[test]
    fn truncation_applies_to_agent_supplied_strings() {
        let long_url = format!("https://h.example/{}", "a".repeat(5000));
        let long = "x".repeat(500);
        let e = SecurityEvent::new(Action::Forward)
            .url(&long_url)
            .method(&long)
            .key(&AgentKey {
                id: long.clone(),
                name: long.clone(),
                created_at: Utc::now(),
            })
            .credentials([long.clone()])
            .detail_str("k", &long);
        assert_eq!(e.url.as_ref().unwrap().original.chars().count(), 2048);
        assert_eq!(e.url.as_ref().unwrap().domain.as_deref(), Some("h.example"));
        let req = e.http.as_ref().unwrap().request.as_ref().unwrap();
        assert_eq!(req.method.chars().count(), 128);
        let key = e.ferrowarden.key.as_ref().unwrap();
        assert_eq!(key.name.chars().count(), 128);
        assert_eq!(key.id.chars().count(), 128);
        assert_eq!(e.ferrowarden.credentials[0].chars().count(), 128);
        assert_eq!(
            e.ferrowarden.details.as_ref().unwrap()["k"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            128
        );
        // Multi-byte characters are cut on character boundaries.
        assert_eq!(truncate("ééé", 2), "éé");
    }

    #[test]
    fn credential_label_count_is_capped() {
        let labels: Vec<String> = (0..500).map(|i| format!("c{i}")).collect();
        let e = SecurityEvent::new(Action::Forward).credentials(&labels);
        assert_eq!(e.ferrowarden.credentials.len(), 64);
    }

    #[test]
    fn hostile_strings_cannot_break_the_json_line() {
        let evil = "GET\n{\"event\":{\"outcome\":\"success\"}}\r\u{0}\"\\";
        let line = serde_json::to_string(
            &SecurityEvent::new(Action::Forward)
                .method(evil)
                .url("https://h.example/\n\"x"),
        )
        .unwrap();
        assert_eq!(line.lines().count(), 1, "event must stay on one line");
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["http"]["request"]["method"], evil);
        assert_eq!(v["event"]["outcome"], "success");
    }

    #[test]
    fn unparseable_url_has_no_domain() {
        let e = SecurityEvent::new(Action::Forward).url("not a url {{vault:x}}");
        assert!(e.url.unwrap().domain.is_none());
    }

    #[test]
    fn builder_details_and_message() {
        let e = SecurityEvent::new(Action::CredentialsList)
            .detail("detail", true)
            .detail("count", 3);
        let v = to_json(&e);
        assert_eq!(
            v["ferrowarden"]["details"],
            json!({"detail": true, "count": 3})
        );
        assert_eq!(v["message"], "credentials listed");

        let e = SecurityEvent::new(Action::AgentAuth).reason(Reason::MissingKey);
        assert_eq!(
            e.message,
            "agent authentication blocked: no agent key presented"
        );
        let e = SecurityEvent::new(Action::VaultSync)
            .outcome(Outcome::Failure)
            .reason(Reason::SyncFailed);
        assert_eq!(e.message, "vault sync failed: credential sync failed");
    }

    #[test]
    fn duration_saturates_instead_of_overflowing() {
        let e = SecurityEvent::new(Action::Forward).duration(Duration::MAX);
        assert_eq!(e.event.duration, Some(u64::MAX));
    }
}
