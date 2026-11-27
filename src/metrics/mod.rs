//! Prometheus metrics (docs/metrics.md).
//!
//! Two sources feed one registry:
//!
//! - **Counters and histograms** come from the security event stream. The
//!   metrics consumer is one more consumer of it, like the push notifier:
//!   [`crate::events::EventLog::emit`] hands each event to a [`Feed`], which
//!   `try_send`s it into a bounded queue read by a single task ([`Consumer`]).
//!   `emit` therefore does a classification-free `try_send` and nothing else:
//!   no lock, no allocation beyond an `Arc` clone, no I/O. When the queue is
//!   full the event is not counted and `ferrowarden_metrics_events_dropped_total`
//!   says so. The consumer owns the cardinality caps (plain `HashSet`s, no
//!   locks), so the one place that grows label sets is one task.
//! - **Gauges** (and the counters kept elsewhere, such as dropped events and
//!   notifications) are read from [`crate::state::AppState`] at scrape time
//!   ([`Snapshot::gather`]) and written into the registry just before it is
//!   encoded.
//!
//! Every label value comes from a fixed enum (`Action`, `Outcome`, `Reason`,
//! a fixed list of limiter, sender and result names) or from a name the
//! operator chose (agent key names; with the opt-in, vault item names).
//! Nothing is taken from a request: no URL, host, IP, header name, placeholder
//! text or value ever reaches a label. The label structs below make that
//! visible in the types: request-derived text has no `String` field to live in.
//!
//! Series are never removed. A revoked agent key keeps its series, because a
//! counter that disappears and comes back looks like a reset.

pub mod server;

use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use prometheus_client::encoding::{text::encode, EncodeLabelSet};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::{Registry, Unit};
use tokio::sync::mpsc;

use crate::config::MetricsConfig;
use crate::events::{Action, EventLog, Outcome, Reason, SecurityEvent};
use crate::sessions::CaptureStatus;
use crate::state::AppState;

/// The `Content-Type` of a scrape: the OpenMetrics text format.
pub const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Events that may wait for the consumer task.
pub const QUEUE_CAPACITY: usize = 4096;
/// Distinct `credential` label values before the rest count as `_other`.
pub const CREDENTIAL_LABEL_CAP: usize = 500;
/// Distinct agent key names as `key` label values before the rest count as
/// `_other`. Far above any real number of keys; a guard, not a limit anyone
/// meets.
pub const KEY_LABEL_CAP: usize = 1000;
/// The label value that stands for everything beyond a cap.
pub const OTHER: &str = "_other";

/// `ferrowarden_forward_duration_seconds` upper bounds, in seconds.
const DURATION_BUCKETS: [f64; 11] = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];

// ── Label sets ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BuildLabels {
    version: &'static str,
    vault_backend: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct EventLabels {
    action: &'static str,
    outcome: &'static str,
    reason: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ForwardLabels {
    outcome: &'static str,
    reason: &'static str,
    /// An agent key name: chosen by the administrator.
    key: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct OutcomeLabels {
    outcome: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RotationLabels {
    stage: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ResultLabels {
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct LimiterLabels {
    limiter: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct KindLabels {
    kind: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct PolicyLabels {
    policy_set: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct NotifyLabels {
    sender: &'static str,
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct CredentialLabels {
    /// A vault item name (opt-in, capped).
    credential: String,
}

/// The values of `ferrowarden_rate_limited_total{limiter}` and
/// `ferrowarden_auth_failures_total{kind}`.
const LIMITERS: [&str; 3] = ["agent", "admin", "notify_test"];
const AUTH_KINDS: [&str; 4] = ["agent", "admin", "ui", "metrics"];
/// `sender` of the notification counters the notifier keeps for all senders.
const ALL_SENDERS: &str = "all";
/// The values of `ferrowarden_session_uses_total{outcome}`.
const SESSION_USE_OUTCOMES: [&str; 3] = ["success", "unknown_session", "session_host_not_allowed"];
/// The values of `ferrowarden_approval_requests_total{outcome}`.
const APPROVAL_OUTCOMES: [&str; 4] = ["granted", "denied", "expired", "limit_reached"];
/// The values of `ferrowarden_credential_creates_total{outcome}`: `created`,
/// or the reason a create request was refused or failed (`other`: any other
/// reason).
const CREATE_OUTCOMES: [&str; 10] = [
    "created",
    "approval_denied",
    "approval_pending",
    "approval_limit_reached",
    "credential_exists",
    "managed_collection_unavailable",
    "credential_create_disabled",
    "credential_create_out_of_scope",
    "vault_write_failed",
    "other",
];
/// The `stage` values of `ferrowarden_credential_rotations_total`.
const ROTATE_STAGES: [&str; 3] = ["start", "commit", "abort"];
/// The `outcome` values of `ferrowarden_credential_rotations_total`:
/// `success`, or the reason a rotation request was refused or failed (`other`:
/// any other reason).
const ROTATE_OUTCOMES: [&str; 14] = [
    "success",
    "approval_denied",
    "approval_pending",
    "approval_limit_reached",
    "credential_rotate_out_of_scope",
    "credential_not_managed",
    "credential_not_rotatable",
    "rotation_in_progress",
    "no_rotation_pending",
    "vault_conflict",
    "vault_write_failed",
    "managed_collection_unavailable",
    "credential_create_disabled",
    "other",
];
/// The values of `ferrowarden_forward_approval_total{result}`: how a request
/// that needed approval ended at the gate.
const FORWARD_APPROVAL_RESULTS: [&str; 4] = [
    "granted_by_grant",
    "approved_while_waiting",
    "pending",
    "denied",
];

fn duration_histogram() -> Histogram {
    Histogram::new(DURATION_BUCKETS)
}

// ── The registry ──────────────────────────────────────────────────────────────

/// Every metric Ferrowarden exports, and the registry that holds them.
pub struct Metrics {
    registry: Registry,
    events: Family<EventLabels, Counter>,
    forward: Family<ForwardLabels, Counter>,
    duration: Family<OutcomeLabels, Histogram, fn() -> Histogram>,
    response_bytes: Histogram,
    rate_limited: Family<LimiterLabels, Counter>,
    auth_failures: Family<KindLabels, Counter>,
    vault_unlocked: Gauge,
    vault_credentials: Gauge,
    vault_excluded: Gauge,
    vault_last_sync: Gauge,
    agent_keys: Family<PolicyLabels, Gauge>,
    events_dropped: Counter,
    metrics_dropped: Counter,
    notifications: Family<NotifyLabels, Counter>,
    ui_sessions: Gauge,
    session_captures: Family<OutcomeLabels, Counter>,
    session_uses: Family<OutcomeLabels, Counter>,
    sessions_active: Gauge,
    approval_requests: Family<OutcomeLabels, Counter>,
    forward_approval: Family<ResultLabels, Counter>,
    credential_creates: Family<OutcomeLabels, Counter>,
    credential_rotations: Family<RotationLabels, Counter>,
    approvals_pending: Gauge,
    approval_grants_active: Gauge,
    /// Only with `metrics.credential_labels = true`.
    credential_uses: Option<Family<CredentialLabels, Counter>>,
}

impl Metrics {
    /// Register every metric family. `credential_labels` adds
    /// `ferrowarden_forward_credential_uses_total`.
    pub fn new(
        version: &'static str,
        vault_backend: &'static str,
        credential_labels: bool,
    ) -> Arc<Self> {
        let mut registry = Registry::with_prefix("ferrowarden");

        let build: Family<BuildLabels, Gauge> = Family::default();
        build
            .get_or_create(&BuildLabels {
                version,
                vault_backend,
            })
            .set(1);
        registry.register(
            "build_info",
            "Build information: the version and the vault backend (always 1)",
            build,
        );

        let m = Self {
            events: Family::default(),
            forward: Family::default(),
            duration: Family::new_with_constructor(duration_histogram as fn() -> Histogram),
            response_bytes: Histogram::new(exponential_buckets(256.0, 2.0, 18)),
            rate_limited: Family::default(),
            auth_failures: Family::default(),
            vault_unlocked: Gauge::default(),
            vault_credentials: Gauge::default(),
            vault_excluded: Gauge::default(),
            vault_last_sync: Gauge::default(),
            agent_keys: Family::default(),
            events_dropped: Counter::default(),
            metrics_dropped: Counter::default(),
            notifications: Family::default(),
            ui_sessions: Gauge::default(),
            session_captures: Family::default(),
            session_uses: Family::default(),
            sessions_active: Gauge::default(),
            approval_requests: Family::default(),
            forward_approval: Family::default(),
            credential_creates: Family::default(),
            credential_rotations: Family::default(),
            approvals_pending: Gauge::default(),
            approval_grants_active: Gauge::default(),
            credential_uses: credential_labels.then(Family::default),
            registry: Registry::default(),
        };

        registry.register(
            "events",
            "Security events by action, outcome and reason (reason is empty when there is none)",
            m.events.clone(),
        );
        registry.register(
            "forward_requests",
            "Forward requests by outcome, reason and agent key name",
            m.forward.clone(),
        );
        registry.register_with_unit(
            "forward_duration",
            "Time to serve a forward request, by outcome",
            Unit::Seconds,
            m.duration.clone(),
        );
        registry.register_with_unit(
            "forward_response",
            "Size of the upstream response body of successful forward requests",
            Unit::Bytes,
            m.response_bytes.clone(),
        );
        registry.register(
            "rate_limited",
            "Requests answered 429 by a rate limiter (limiter: agent, admin or notify_test)",
            m.rate_limited.clone(),
        );
        registry.register(
            "auth_failures",
            "Failed authentications (kind: agent, admin, ui or metrics)",
            m.auth_failures.clone(),
        );
        registry.register(
            "vault_unlocked",
            "1 when the vault is unlocked, 0 when it is locked",
            m.vault_unlocked.clone(),
        );
        registry.register(
            "vault_credentials",
            "Credentials in the cache (item names only; never values)",
            m.vault_credentials.clone(),
        );
        registry.register(
            "vault_excluded_items",
            "Items the native backend left out at its last rebuild because they could not be read safely",
            m.vault_excluded.clone(),
        );
        registry.register_with_unit(
            "vault_last_sync_timestamp",
            "Unix time of the last successful vault sync (0 before the first)",
            Unit::Seconds,
            m.vault_last_sync.clone(),
        );
        registry.register(
            "agent_keys",
            "Agent keys, by whether they have a policy (false means deny-all)",
            m.agent_keys.clone(),
        );
        registry.register(
            "events_dropped",
            "Security events dropped because the sink queue was full",
            m.events_dropped.clone(),
        );
        registry.register(
            "metrics_events_dropped",
            "Security events not counted because the metrics queue was full",
            m.metrics_dropped.clone(),
        );
        registry.register(
            "notifications",
            "Push notifications by sender and result (suppressed and dropped are counted for all senders together, as sender=\"all\")",
            m.notifications.clone(),
        );
        registry.register(
            "ui_sessions",
            "Admin UI sessions that are signed in now (0 when the UI is off)",
            m.ui_sessions.clone(),
        );
        registry.register(
            "session_captures",
            "Capture entries of forward requests by outcome (the capture status: captured, not_found, not_a_string, ambiguous, too_short, too_long, expired or limit_reached)",
            m.session_captures.clone(),
        );
        registry.register(
            "session_uses",
            "Forward requests that used a captured session, by outcome (success, unknown_session or session_host_not_allowed)",
            m.session_uses.clone(),
        );
        registry.register(
            "sessions_active",
            "Captured sessions that are live now, across all agent keys (names and values are never exported)",
            m.sessions_active.clone(),
        );
        registry.register(
            "approval_requests",
            "Approval requests by outcome (granted, denied, expired or limit_reached: an agent key over its limits)",
            m.approval_requests.clone(),
        );
        registry.register(
            "forward_approval",
            "Forward requests that needed approval, by how they ended at the gate (granted_by_grant, approved_while_waiting, pending or denied)",
            m.forward_approval.clone(),
        );
        registry.register(
            "credential_creates",
            "Requests to create a credential, by outcome (created, or the reason it was refused or failed; the generated value is never exported)",
            m.credential_creates.clone(),
        );
        registry.register(
            "credential_rotations",
            "Requests to rotate a credential's password, by stage (start, commit, abort) and outcome (success, or the reason it was refused or failed; the generated value is never exported)",
            m.credential_rotations.clone(),
        );
        registry.register(
            "approvals_pending",
            "Approvals waiting for a human's decision now (names and ids are never exported)",
            m.approvals_pending.clone(),
        );
        registry.register(
            "approval_grants_active",
            "Approval grants that are live now, across all agent keys",
            m.approval_grants_active.clone(),
        );
        if let Some(family) = &m.credential_uses {
            registry.register(
                "forward_credential_uses",
                "Successful forward requests by vault item name (opt-in; names reveal vault contents)",
                family.clone(),
            );
        }

        // Series that exist from the start, so a rate() sees the first
        // increment and a dashboard has something to draw.
        for limiter in LIMITERS {
            let _ = m.rate_limited.get_or_create(&LimiterLabels { limiter });
        }
        for kind in AUTH_KINDS {
            let _ = m.auth_failures.get_or_create(&KindLabels { kind });
        }
        for result in ["suppressed", "dropped"] {
            let _ = m.notifications.get_or_create(&NotifyLabels {
                sender: ALL_SENDERS,
                result,
            });
        }
        for policy_set in ["true", "false"] {
            let _ = m.agent_keys.get_or_create(&PolicyLabels { policy_set });
        }
        for status in CaptureStatus::ALL {
            let _ = m.session_captures.get_or_create(&OutcomeLabels {
                outcome: status.as_str(),
            });
        }
        for outcome in SESSION_USE_OUTCOMES {
            let _ = m.session_uses.get_or_create(&OutcomeLabels { outcome });
        }
        for outcome in APPROVAL_OUTCOMES {
            let _ = m
                .approval_requests
                .get_or_create(&OutcomeLabels { outcome });
        }
        for result in FORWARD_APPROVAL_RESULTS {
            let _ = m.forward_approval.get_or_create(&ResultLabels { result });
        }
        for outcome in CREATE_OUTCOMES {
            let _ = m
                .credential_creates
                .get_or_create(&OutcomeLabels { outcome });
        }
        for stage in ROTATE_STAGES {
            for outcome in ROTATE_OUTCOMES {
                let _ = m
                    .credential_rotations
                    .get_or_create(&RotationLabels { stage, outcome });
            }
        }

        Arc::new(Self { registry, ..m })
    }

    /// A failed scrape authentication, counted at the source (every one, not
    /// only those the rate-limited `metrics_auth` event reports).
    pub fn count_metrics_auth_failure(&self) {
        self.auth_failures
            .get_or_create(&KindLabels { kind: "metrics" })
            .inc();
    }

    /// Write the scrape-time values into the registry and encode it.
    pub fn render(&self, s: &Snapshot) -> Result<String, std::fmt::Error> {
        self.vault_unlocked.set(i64::from(s.unlocked));
        self.vault_credentials
            .set(i64::try_from(s.credentials).unwrap_or(i64::MAX));
        self.vault_excluded
            .set(i64::try_from(s.excluded).unwrap_or(i64::MAX));
        self.vault_last_sync.set(s.last_sync);
        for (policy_set, n) in [
            ("true", s.keys_with_policy),
            ("false", s.keys_without_policy),
        ] {
            self.agent_keys
                .get_or_create(&PolicyLabels { policy_set })
                .set(i64::try_from(n).unwrap_or(i64::MAX));
        }
        self.ui_sessions
            .set(i64::try_from(s.ui_sessions).unwrap_or(i64::MAX));
        self.sessions_active
            .set(i64::try_from(s.sessions_active).unwrap_or(i64::MAX));
        self.approvals_pending
            .set(i64::try_from(s.approvals_pending).unwrap_or(i64::MAX));
        self.approval_grants_active
            .set(i64::try_from(s.approval_grants).unwrap_or(i64::MAX));
        // Counters that the rest of the program keeps: copy their totals.
        self.events_dropped
            .inner()
            .store(s.events_dropped, Ordering::Relaxed);
        let set_notifications = |sender: &'static str, result: &'static str, value: u64| {
            self.notifications
                .get_or_create(&NotifyLabels { sender, result })
                .inner()
                .store(value, Ordering::Relaxed);
        };
        for sender in &s.notify.senders {
            set_notifications(sender.kind, "sent", sender.sent);
            set_notifications(sender.kind, "failed", sender.failed);
        }
        set_notifications(ALL_SENDERS, "suppressed", s.notify.suppressed);
        set_notifications(ALL_SENDERS, "dropped", s.notify.dropped);

        let mut out = String::with_capacity(8 * 1024);
        encode(&mut out, &self.registry)?;
        Ok(out)
    }
}

// ── Scrape-time values ────────────────────────────────────────────────────────

/// What the gauges (and the counters kept elsewhere) show at one scrape.
pub struct Snapshot {
    pub unlocked: bool,
    pub credentials: usize,
    pub excluded: u64,
    pub last_sync: i64,
    pub keys_with_policy: usize,
    pub keys_without_policy: usize,
    pub events_dropped: u64,
    pub notify: crate::notify::Snapshot,
    pub ui_sessions: usize,
    /// Live captured sessions, all keys together.
    pub sessions_active: usize,
    /// Approvals waiting for a decision.
    pub approvals_pending: usize,
    /// Live approval grants, all keys together.
    pub approval_grants: usize,
}

impl Snapshot {
    /// Read the state. `ui` is the admin UI's session count, `None` when the
    /// UI is off.
    pub async fn gather(state: &AppState, ui_sessions: Option<usize>) -> Self {
        let (with, without) = {
            let keys = state.agent_keys.read().await;
            let with = keys.values().filter(|k| k.policy_set).count();
            (with, keys.len() - with)
        };
        let (approvals_pending, approval_grants) = state.approvals.counts(chrono::Utc::now());
        Self {
            unlocked: !state.is_locked().await,
            credentials: state.credentials.read().await.len(),
            excluded: state.sync_stats.excluded(),
            last_sync: state.sync_stats.last_sync_unix(),
            keys_with_policy: with,
            keys_without_policy: without,
            events_dropped: state.events.dropped_total(),
            notify: state.notify.snapshot(),
            ui_sessions: ui_sessions.unwrap_or(0),
            sessions_active: state.sessions.active(chrono::Utc::now()),
            approvals_pending,
            approval_grants,
        }
    }
}

// ── Feed: where events enter ──────────────────────────────────────────────────

/// The consumer's end of the event stream, owned by the `EventLog`.
pub struct Feed {
    tx: mpsc::Sender<Arc<SecurityEvent>>,
    dropped: Counter,
}

impl Feed {
    /// Offer one event. Never blocks and never fails: an event that does not
    /// fit in the queue is counted as dropped.
    pub fn offer(&self, event: &Arc<SecurityEvent>) {
        if self.tx.try_send(event.clone()).is_err() {
            self.dropped.inc();
        }
    }
}

// ── The consumer ──────────────────────────────────────────────────────────────

/// Distinct label values seen so far, up to a cap.
struct Capped {
    seen: HashSet<String>,
    cap: usize,
}

impl Capped {
    fn new(cap: usize) -> Self {
        Self {
            seen: HashSet::new(),
            cap,
        }
    }

    /// `name` itself while it is known or there is room for it, else `_other`.
    fn admit(&mut self, name: &str) -> String {
        if self.seen.contains(name) {
            return name.to_string();
        }
        if self.seen.len() < self.cap {
            self.seen.insert(name.to_string());
            return name.to_string();
        }
        OTHER.to_string()
    }
}

/// Turns events into counter and histogram updates. It runs in one task and
/// does no I/O.
pub struct Consumer {
    m: Arc<Metrics>,
    keys: Capped,
    credentials: Capped,
}

impl Consumer {
    pub fn new(m: Arc<Metrics>) -> Self {
        Self::with_caps(m, KEY_LABEL_CAP, CREDENTIAL_LABEL_CAP)
    }

    pub fn with_caps(m: Arc<Metrics>, key_cap: usize, credential_cap: usize) -> Self {
        Self {
            m,
            keys: Capped::new(key_cap),
            credentials: Capped::new(credential_cap),
        }
    }

    /// Count one event.
    pub fn process(&mut self, e: &SecurityEvent) {
        let info = &e.event;
        let outcome = info.outcome.as_str();
        let reason = info.reason.map_or("", Reason::as_str);
        self.m
            .events
            .get_or_create(&EventLabels {
                action: info.action.as_str(),
                outcome,
                reason,
            })
            .inc();

        let failed = info.outcome == Outcome::Failure;
        match info.action {
            Action::Forward => self.forward(e, outcome, reason),
            Action::RateLimited => {
                let limiter = match detail_str(e, "limiter") {
                    Some("agent") => "agent",
                    Some("admin") => "admin",
                    Some("notify_test") => "notify_test",
                    _ => "other",
                };
                // The event stands for itself and for the 429s that were not
                // reported since the previous event for that client.
                let n = 1 + detail_u64(e, "suppressed").unwrap_or(0);
                self.m
                    .rate_limited
                    .get_or_create(&LimiterLabels { limiter })
                    .inc_by(n);
            }
            Action::AgentAuth if failed => self.auth_failure("agent"),
            Action::AdminAuth if failed => self.auth_failure("admin"),
            // A sign-in over plain HTTP that is refused is not a wrong
            // password.
            Action::UiLogin if failed && info.reason != Some(Reason::InsecureTransport) => {
                self.auth_failure("ui")
            }
            Action::SessionCapture => {
                // The status is one of a fixed set; anything else is not counted.
                if let Some(status) = CaptureStatus::ALL
                    .into_iter()
                    .find(|s| Some(s.as_str()) == detail_str(e, "status"))
                {
                    self.m
                        .session_captures
                        .get_or_create(&OutcomeLabels {
                            outcome: status.as_str(),
                        })
                        .inc();
                }
            }
            Action::SessionUse => {
                let outcome = match info.reason {
                    None => "success",
                    Some(Reason::UnknownSession) => "unknown_session",
                    Some(Reason::SessionHostNotAllowed) => "session_host_not_allowed",
                    // No other reason is recorded on a `session_use` event.
                    Some(_) => return,
                };
                self.m
                    .session_uses
                    .get_or_create(&OutcomeLabels { outcome })
                    .inc();
            }
            // Decisions and expiries count as approval outcomes; a failed
            // attempt to decide (the approval was not pending) does not.
            Action::ApprovalGranted if !failed => self.approval_outcome("granted"),
            Action::ApprovalDenied if !failed => self.approval_outcome("denied"),
            Action::ApprovalExpired => self.approval_outcome("expired"),
            Action::CredentialCreate => {
                let outcome = if failed {
                    CREATE_OUTCOMES
                        .into_iter()
                        .find(|o| *o != "created" && !reason.is_empty() && *o == reason)
                        .unwrap_or("other")
                } else {
                    "created"
                };
                self.m
                    .credential_creates
                    .get_or_create(&OutcomeLabels { outcome })
                    .inc();
            }
            Action::CredentialRotateStart
            | Action::CredentialRotateCommit
            | Action::CredentialRotateAbort => {
                let stage = match e.event.action {
                    Action::CredentialRotateStart => "start",
                    Action::CredentialRotateCommit => "commit",
                    _ => "abort",
                };
                let outcome = if failed {
                    ROTATE_OUTCOMES
                        .into_iter()
                        .find(|o| *o != "success" && !reason.is_empty() && *o == reason)
                        .unwrap_or("other")
                } else {
                    "success"
                };
                self.m
                    .credential_rotations
                    .get_or_create(&RotationLabels { stage, outcome })
                    .inc();
            }
            // `metrics_auth` failures are counted where they happen
            // ([`Metrics::count_metrics_auth_failure`]), all of them.
            _ => {}
        }
    }

    fn approval_outcome(&self, outcome: &'static str) {
        self.m
            .approval_requests
            .get_or_create(&OutcomeLabels { outcome })
            .inc();
    }

    fn auth_failure(&self, kind: &'static str) {
        self.m
            .auth_failures
            .get_or_create(&KindLabels { kind })
            .inc();
    }

    fn forward(&mut self, e: &SecurityEvent, outcome: &'static str, reason: &'static str) {
        // The approval gate: how the request ended there. The detail is one of
        // a fixed set; anything else is not counted.
        if let Some(result) = FORWARD_APPROVAL_RESULTS
            .into_iter()
            .find(|r| Some(*r) == detail_str(e, "approval"))
        {
            self.m
                .forward_approval
                .get_or_create(&ResultLabels { result })
                .inc();
        }
        if e.event.reason == Some(Reason::ApprovalLimitReached) {
            self.approval_outcome("limit_reached");
        }
        let key = match &e.ferrowarden.key {
            Some(key) => self.keys.admit(&key.name),
            None => String::new(),
        };
        self.m
            .forward
            .get_or_create(&ForwardLabels {
                outcome,
                reason,
                key,
            })
            .inc();
        if let Some(nanos) = e.event.duration {
            // Precision beyond f64 is irrelevant for a latency.
            self.m
                .duration
                .get_or_create(&OutcomeLabels { outcome })
                .observe(nanos as f64 / 1e9);
        }
        if e.event.outcome != Outcome::Success {
            return;
        }
        let bytes = e
            .http
            .as_ref()
            .and_then(|h| h.response.as_ref())
            .and_then(|r| r.body.as_ref())
            .map(|b| b.bytes);
        if let Some(bytes) = bytes {
            self.m.response_bytes.observe(bytes as f64);
        }
        // Only a forward that succeeded has item names that exist in the
        // vault: an unknown name in a refused request is the agent's text.
        if let Some(family) = &self.m.credential_uses {
            let distinct: HashSet<&str> = e.items.iter().map(String::as_str).collect();
            for item in distinct {
                let credential = self.credentials.admit(item);
                family.get_or_create(&CredentialLabels { credential }).inc();
            }
        }
    }
}

fn detail_str<'a>(e: &'a SecurityEvent, key: &str) -> Option<&'a str> {
    e.ferrowarden.details.as_ref()?.get(key)?.as_str()
}

fn detail_u64(e: &SecurityEvent, key: &str) -> Option<u64> {
    e.ferrowarden.details.as_ref()?.get(key)?.as_u64()
}

/// The consumer task: drains the queue until every sender is gone.
async fn run(mut rx: mpsc::Receiver<Arc<SecurityEvent>>, mut consumer: Consumer) {
    while let Some(event) = rx.recv().await {
        consumer.process(&event);
    }
}

// ── Start-up ──────────────────────────────────────────────────────────────────

/// Build the registry, start the consumer and attach it to the event log.
/// `None` when metrics are off. Must run inside a Tokio runtime.
pub fn start(
    cfg: &MetricsConfig,
    vault_backend: &'static str,
    events: &Arc<EventLog>,
) -> Option<Arc<Metrics>> {
    if !cfg.enabled() {
        return None;
    }
    let metrics = Metrics::new(
        env!("CARGO_PKG_VERSION"),
        vault_backend,
        cfg.credential_labels,
    );
    let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
    tokio::spawn(run(rx, Consumer::new(metrics.clone())));
    events.attach_metrics(Feed {
        tx,
        dropped: metrics.metrics_dropped.clone(),
    });
    Some(metrics)
}

#[cfg(test)]
mod tests;
