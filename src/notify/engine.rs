//! Which events notify, and how often.
//!
//! [`classify`] is the stateless half: the table of actions, outcomes and
//! reason codes that can produce a notification. [`Engine`] is the stateful
//! half: failure counting per source address, the per-subject rate limit with
//! its "and N more" summaries, the hourly cap, and the bounded tables behind
//! them. The engine does no I/O and takes the clock as an argument, so every
//! rule is tested without waiting.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use super::content::{EventFields, Kind, Notification};
use super::{Category, CategorySet, Stats};
use crate::events::{Action, Outcome, Reason, SecurityEvent};

/// Subjects remembered for the per-subject rate limit.
const MAX_SUBJECTS: usize = 1024;
/// Source addresses whose failures are being counted.
const MAX_AUTH_IPS: usize = 4096;
/// Failures remembered per address.
const MAX_FAILS_PER_IP: usize = 1024;
/// A subject that has suppressed occurrences is kept at least this long, so
/// the summary is still there when the next notification for it is due.
const SUBJECT_RETENTION: Duration = Duration::from_secs(3600);
const HOUR: Duration = Duration::from_secs(3600);
/// How often expired entries are swept out.
const PRUNE_EVERY: Duration = Duration::from_secs(30);

// ── Classification ────────────────────────────────────────────────────────────

/// Where a failed authentication came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSource {
    Agent,
    Admin,
    Ui,
}

/// What an event is, as far as notifications go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Blocked,
    /// One failed authentication; notifies only once repeated.
    Auth(AuthSource),
    LockedOut,
    VaultLock,
    VaultUnlockFailed,
    VaultSyncFailed,
    /// The vault unlocked; a recovery notice if a lock was notified.
    VaultUnlockOk,
    KeyCreate,
    KeyRevoke,
    KeyPolicyChange,
    UiLoginOk,
    EventsDropped,
    /// A request is waiting for a human to approve it.
    ApprovalRequested,
}

impl Class {
    pub fn category(self) -> Category {
        match self {
            Class::Blocked => Category::Blocked,
            Class::Auth(_) | Class::LockedOut => Category::AuthFailure,
            Class::VaultLock
            | Class::VaultUnlockFailed
            | Class::VaultSyncFailed
            | Class::VaultUnlockOk => Category::Vault,
            Class::KeyCreate | Class::KeyRevoke | Class::KeyPolicyChange | Class::UiLoginOk => {
                Category::Admin
            }
            Class::EventsDropped => Category::System,
            Class::ApprovalRequested => Category::Approval,
        }
    }
}

/// The table of events that can notify. Everything not listed is ignored.
pub fn classify(event: &SecurityEvent) -> Option<Class> {
    let e = &event.event;
    let failed = e.outcome == Outcome::Failure;
    match e.action {
        Action::Forward if failed => match e.reason? {
            Reason::CredentialHostNotAllowed
            | Reason::SessionHostNotAllowed
            | Reason::TargetBlocked
            | Reason::CredentialOutOfScope
            | Reason::MethodNotAllowed
            | Reason::RepromptRequired => Some(Class::Blocked),
            _ => None,
        },
        Action::AgentAuth if failed => Some(Class::Auth(AuthSource::Agent)),
        Action::AdminAuth if failed => Some(Class::Auth(AuthSource::Admin)),
        Action::UiLogin => match (e.outcome, e.reason) {
            (Outcome::Failure, Some(Reason::LoginLockedOut)) => Some(Class::LockedOut),
            (Outcome::Failure, Some(Reason::InvalidCredentials | Reason::TwoFactorFailed)) => {
                Some(Class::Auth(AuthSource::Ui))
            }
            (Outcome::Success, _) => Some(Class::UiLoginOk),
            _ => None,
        },
        Action::VaultLock => Some(Class::VaultLock),
        Action::VaultUnlock => match e.outcome {
            Outcome::Failure => Some(Class::VaultUnlockFailed),
            Outcome::Success => Some(Class::VaultUnlockOk),
            Outcome::Unknown => None,
        },
        Action::VaultSync if failed => Some(Class::VaultSyncFailed),
        Action::KeyCreate if e.outcome == Outcome::Success => Some(Class::KeyCreate),
        Action::KeyRevoke if e.outcome == Outcome::Success => Some(Class::KeyRevoke),
        Action::KeyPolicyChange if e.outcome == Outcome::Success => Some(Class::KeyPolicyChange),
        Action::EventsDropped => Some(Class::EventsDropped),
        Action::ApprovalRequested if e.outcome == Outcome::Success => {
            Some(Class::ApprovalRequested)
        }
        _ => None,
    }
}

// ── Engine ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Settings {
    pub categories: CategorySet,
    pub min_interval: Duration,
    pub max_per_hour: u32,
    pub auth_threshold: u32,
    pub auth_window: Duration,
}

/// Rate-limit state of one `(category, subject)`.
struct Subject {
    last_sent: Instant,
    suppressed: u64,
    /// When the first held-back occurrence happened.
    since: Option<DateTime<Utc>>,
}

#[derive(Default)]
struct AuthTrack {
    fails: VecDeque<(Instant, AuthSource)>,
}

struct Hour {
    start: Instant,
    sent: u32,
    suppressed: u64,
    paused: bool,
}

/// A notification waiting for the rate limits.
struct Candidate {
    category: Category,
    subject: String,
    kind: Kind,
    fields: EventFields,
    /// Occurrences it stands for.
    count: u64,
    /// Skips the per-subject limit and leaves its state alone (recovery
    /// notices: the operator must hear that the problem is over).
    bypass: bool,
}

pub struct Engine {
    s: Settings,
    subjects: HashMap<(Category, String), Subject>,
    auth: HashMap<IpAddr, AuthTrack>,
    /// A `vault_lock` notification went out and no recovery has yet.
    lock_notified: bool,
    hour: Hour,
    last_prune: Instant,
    stats: Arc<Stats>,
}

impl Engine {
    pub fn new(settings: Settings, stats: Arc<Stats>) -> Self {
        let now = Instant::now();
        Self {
            s: settings,
            subjects: HashMap::new(),
            auth: HashMap::new(),
            lock_notified: false,
            hour: Hour {
                start: now,
                sent: 0,
                suppressed: 0,
                paused: false,
            },
            last_prune: now,
            stats,
        }
    }

    #[cfg(test)]
    pub fn table_sizes(&self) -> (usize, usize) {
        (self.subjects.len(), self.auth.len())
    }

    /// Decide what `event` turns into at `now`: usually nothing, sometimes one
    /// notification (or the "paused" notice).
    pub fn process(&mut self, now: Instant, event: &SecurityEvent) -> Vec<Notification> {
        let Some(class) = classify(event) else {
            return Vec::new();
        };
        let category = class.category();
        if !self.s.categories.contains(category) {
            return Vec::new();
        }
        self.prune(now);
        let ip = event.source.as_ref().map(|s| s.ip);
        let key_subject = event
            .ferrowarden
            .key
            .as_ref()
            .map(|k| k.id.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let (subject, kind, count, bypass) = match class {
            Class::Blocked => (key_subject, Kind::Blocked, 1, false),
            Class::Auth(source) => {
                // Without a source address there is nothing to count by.
                let Some(ip) = ip else {
                    return Vec::new();
                };
                let (agent, admin, ui) = self.track_failure(now, ip, source);
                let total = u64::from(agent) + u64::from(admin) + u64::from(ui);
                if total < u64::from(self.s.auth_threshold) {
                    return Vec::new();
                }
                (
                    ip.to_string(),
                    Kind::AuthFailures {
                        agent,
                        admin,
                        ui,
                        window_secs: self.s.auth_window.as_secs(),
                    },
                    total,
                    false,
                )
            }
            Class::LockedOut => (
                ip.map_or_else(|| "lockout".to_string(), |ip| format!("lockout:{ip}")),
                Kind::LockedOut,
                1,
                false,
            ),
            Class::VaultLock => ("vault".to_string(), Kind::VaultLocked, 1, false),
            Class::VaultUnlockFailed => ("vault".to_string(), Kind::VaultUnlockFailed, 1, false),
            Class::VaultSyncFailed => ("vault".to_string(), Kind::VaultSyncFailed, 1, false),
            Class::VaultUnlockOk => {
                if !self.lock_notified {
                    return Vec::new();
                }
                ("vault".to_string(), Kind::VaultRecovered, 1, true)
            }
            Class::KeyCreate => (key_subject, Kind::KeyCreated, 1, false),
            Class::KeyRevoke => (key_subject, Kind::KeyRevoked, 1, false),
            Class::KeyPolicyChange => (key_subject, Kind::KeyPolicyChanged, 1, false),
            Class::UiLoginOk => ("ui_login".to_string(), Kind::UiSignIn, 1, false),
            Class::EventsDropped => (
                "system".to_string(),
                Kind::EventsDropped,
                dropped_count(event),
                false,
            ),
            // One prompt per approval: the subject is the approval itself, so
            // the per-subject limit never holds one back.
            Class::ApprovalRequested => (
                event
                    .ferrowarden
                    .details
                    .as_ref()
                    .and_then(|d| d.get("approval_id"))
                    .and_then(|v| v.as_str())
                    .map_or_else(|| key_subject, |id| format!("approval:{id}")),
                Kind::ApprovalRequest,
                1,
                false,
            ),
        };
        // `count` is what the notification stands for; for a failure burst it
        // is the number of failures in the window, which the message states.
        let fields = EventFields::from_event(category, event, count);
        // What the rate limiter counts as suppressed: one occurrence, except
        // for events that carry a number of their own.
        let weight = match class {
            Class::EventsDropped => count,
            _ => 1,
        };
        self.submit(
            now,
            event.timestamp,
            Candidate {
                category,
                subject,
                kind,
                fields,
                count: weight,
                bypass,
            },
        )
    }

    /// `n` notifications or events did not fit in a queue: a system notice.
    pub fn notifications_dropped(&mut self, now: Instant, n: u64) -> Vec<Notification> {
        if n == 0 || !self.s.categories.contains(Category::System) {
            return Vec::new();
        }
        let wall = Utc::now();
        let fields = EventFields::internal(
            Category::System,
            "notifications_dropped",
            Outcome::Unknown,
            n,
            wall,
        );
        self.submit(
            now,
            wall,
            Candidate {
                category: Category::System,
                subject: "system".to_string(),
                kind: Kind::NotificationsDropped,
                fields,
                count: n,
                bypass: false,
            },
        )
    }

    // ── rate limits ──────────────────────────────────────────────────────────

    fn submit(&mut self, now: Instant, wall: DateTime<Utc>, cand: Candidate) -> Vec<Notification> {
        let key = (cand.category, cand.subject.clone());

        // At most one per subject per interval; the rest are counted.
        if !cand.bypass {
            if let Some(st) = self.subjects.get_mut(&key) {
                if now.saturating_duration_since(st.last_sent) < self.s.min_interval {
                    st.suppressed += cand.count;
                    st.since.get_or_insert(wall);
                    self.stats
                        .suppressed
                        .fetch_add(cand.count, Ordering::Relaxed);
                    return Vec::new();
                }
            }
        }

        // At most `max_per_hour` in total.
        if now.saturating_duration_since(self.hour.start) >= HOUR {
            self.hour = Hour {
                start: now,
                sent: 0,
                suppressed: 0,
                paused: false,
            };
        }
        // An approval prompt is never held back by the hourly cap: a request
        // is waiting for it, and approvals are limited per agent key already
        // (`approval.max_requests_per_key_per_hour`).
        if self.hour.sent >= self.s.max_per_hour && !matches!(cand.kind, Kind::ApprovalRequest) {
            self.hour.suppressed += cand.count;
            self.stats
                .suppressed
                .fetch_add(cand.count, Ordering::Relaxed);
            if matches!(cand.kind, Kind::VaultRecovered) {
                self.lock_notified = false;
            }
            if self.hour.paused {
                return Vec::new();
            }
            // One notice, then silence until the hour rolls over.
            self.hour.paused = true;
            let fields = EventFields::internal(
                Category::System,
                "notifications_paused",
                Outcome::Unknown,
                self.hour.suppressed,
                wall,
            );
            return vec![Notification::render(
                Category::System,
                &Kind::Paused {
                    limit: self.s.max_per_hour,
                },
                fields,
                0,
                None,
            )];
        }
        self.hour.sent += 1;

        let (suppressed, since) = if cand.bypass {
            (0, None)
        } else {
            if !self.subjects.contains_key(&key) && self.subjects.len() >= MAX_SUBJECTS {
                self.prune_subjects(now);
            }
            let st = self.subjects.entry(key).or_insert(Subject {
                last_sent: now,
                suppressed: 0,
                since: None,
            });
            st.last_sent = now;
            (std::mem::take(&mut st.suppressed), st.since.take())
        };
        match cand.kind {
            Kind::VaultLocked => self.lock_notified = true,
            Kind::VaultRecovered => self.lock_notified = false,
            _ => {}
        }
        vec![Notification::render(
            cand.category,
            &cand.kind,
            cand.fields,
            suppressed,
            since,
        )]
    }

    // ── failure counting ─────────────────────────────────────────────────────

    /// Record one failure from `ip` and return the failures in the window,
    /// by source.
    fn track_failure(&mut self, now: Instant, ip: IpAddr, source: AuthSource) -> (u32, u32, u32) {
        if !self.auth.contains_key(&ip) && self.auth.len() >= MAX_AUTH_IPS {
            self.prune_auth(now);
        }
        let window = self.s.auth_window;
        let track = self.auth.entry(ip).or_default();
        trim(track, now, window);
        if track.fails.len() >= MAX_FAILS_PER_IP {
            track.fails.pop_front();
        }
        track.fails.push_back((now, source));
        let mut counts = (0u32, 0u32, 0u32);
        for (_, src) in &track.fails {
            match src {
                AuthSource::Agent => counts.0 += 1,
                AuthSource::Admin => counts.1 += 1,
                AuthSource::Ui => counts.2 += 1,
            }
        }
        counts
    }

    // ── bounded memory ───────────────────────────────────────────────────────

    fn prune(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_prune) < PRUNE_EVERY {
            return;
        }
        self.last_prune = now;
        self.prune_subjects(now);
        self.prune_auth(now);
    }

    /// Drop subjects that are past their interval and hold nothing to report
    /// (or have held it for an hour); if the table is still full, the oldest.
    fn prune_subjects(&mut self, now: Instant) {
        let interval = self.s.min_interval;
        self.subjects.retain(|_, st| {
            let age = now.saturating_duration_since(st.last_sent);
            if st.suppressed > 0 {
                age < interval.max(SUBJECT_RETENTION)
            } else {
                age < interval
            }
        });
        evict_oldest(&mut self.subjects, MAX_SUBJECTS, |st| st.last_sent);
    }

    fn prune_auth(&mut self, now: Instant) {
        let window = self.s.auth_window;
        self.auth.retain(|_, track| {
            trim(track, now, window);
            !track.fails.is_empty()
        });
        evict_oldest(&mut self.auth, MAX_AUTH_IPS, |t| {
            t.fails.back().map_or(now, |(at, _)| *at)
        });
    }
}

/// Forget failures older than the window.
fn trim(track: &mut AuthTrack, now: Instant, window: Duration) {
    while track
        .fails
        .front()
        .is_some_and(|(at, _)| now.saturating_duration_since(*at) > window)
    {
        track.fails.pop_front();
    }
}

/// Keep at most `max` entries: remove the ones `age_key` says are oldest, and
/// a tenth more so that the next insert does not sort again.
fn evict_oldest<K: Clone + Eq + std::hash::Hash, V>(
    map: &mut HashMap<K, V>,
    max: usize,
    age_key: impl Fn(&V) -> Instant,
) {
    if map.len() < max {
        return;
    }
    let mut by_age: Vec<(Instant, K)> = map.iter().map(|(k, v)| (age_key(v), k.clone())).collect();
    by_age.sort_by_key(|(at, _)| *at);
    let remove = map.len() - max + max / 10 + 1;
    for (_, k) in by_age.into_iter().take(remove) {
        map.remove(&k);
    }
}

/// The number an `events_dropped` event reports (at least 1).
fn dropped_count(event: &SecurityEvent) -> u64 {
    event
        .ferrowarden
        .details
        .as_ref()
        .and_then(|d| d.get("dropped"))
        .and_then(|v| v.as_u64())
        .unwrap_or(1)
        .max(1)
}
