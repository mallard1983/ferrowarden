//! Push notifications for security events (docs/notifications.md).
//!
//! The notifier is one more consumer of the security event stream; no handler
//! knows it exists. [`crate::events::EventLog`] hands every event that could
//! matter to a [`Feed`], which `try_send`s it into a bounded queue read by one
//! task. That task classifies the event, applies the rate limits
//! ([`engine::Engine`]), renders a message from an allow-list of event fields
//! ([`content`]) and queues it for each enabled sender ([`senders`]), each of
//! which has its own worker, timeout and retries.
//!
//! Nothing in this chain can make a request, an event or another sink wait: a
//! full queue drops the event and counts it, a slow notifier only fills its
//! own queue, and every failure ends in a counter and a rate-limited log line.

pub mod content;
pub mod engine;
pub mod senders;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::mpsc;

use crate::config::NotifyConfig;
use crate::error::FerroResult;
use crate::events::{EventLog, SecurityEvent};
use content::Notification;
use engine::{Engine, Settings};
use senders::{SendOptions, Sender};

/// Events that may wait for the notifier task.
pub const QUEUE_CAPACITY: usize = 1000;
/// Notifications that may wait for one sender's worker.
pub const SENDER_QUEUE: usize = 100;
/// The test notification may be sent at most this often.
pub const TEST_INTERVAL: Duration = Duration::from_secs(10);

// ── Categories ────────────────────────────────────────────────────────────────

/// What a notification is about; `notify.events` selects them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    /// A forwarded request was refused by a policy.
    Blocked,
    /// Repeated authentication failures from one address, or a lockout.
    AuthFailure,
    /// The vault locked, or could not be unlocked or synced.
    Vault,
    /// Key and sign-in changes (opt-in).
    Admin,
    /// Dropped events or notifications.
    System,
}

impl Category {
    pub const ALL: [Category; 5] = [
        Category::Blocked,
        Category::AuthFailure,
        Category::Vault,
        Category::Admin,
        Category::System,
    ];
    /// Enabled when `notify.events` is not set.
    pub const DEFAULT: [Category; 4] = [
        Category::Blocked,
        Category::AuthFailure,
        Category::Vault,
        Category::System,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Category::Blocked => "blocked",
            Category::AuthFailure => "auth_failure",
            Category::Vault => "vault",
            Category::Admin => "admin",
            Category::System => "system",
        }
    }

    pub fn parse(name: &str) -> Option<Category> {
        Category::ALL.into_iter().find(|c| c.as_str() == name)
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// A set of [`Category`] values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CategorySet(u8);

impl CategorySet {
    pub fn of(categories: &[Category]) -> Self {
        Self(categories.iter().fold(0, |acc, c| acc | c.bit()))
    }

    /// Parse category names; any unknown name is an error.
    pub fn from_names(names: &[String]) -> Result<Self, ()> {
        let mut set = 0;
        for name in names {
            set |= Category::parse(name.trim()).ok_or(())?.bit();
        }
        Ok(Self(set))
    }

    pub fn contains(self, c: Category) -> bool {
        self.0 & c.bit() != 0
    }

    pub fn names(self) -> Vec<&'static str> {
        Category::ALL
            .into_iter()
            .filter(|c| self.contains(*c))
            .map(Category::as_str)
            .collect()
    }
}

// ── Counters ──────────────────────────────────────────────────────────────────

/// Counters shared by the feed, the engine and the admin UI.
#[derive(Default)]
pub struct Stats {
    /// Occurrences folded into a summary or left out by the hourly cap.
    pub suppressed: AtomicU64,
    /// Events or notifications dropped because a queue was full.
    pub dropped: AtomicU64,
}

// ── Feed: where events enter ──────────────────────────────────────────────────

/// The notifier's end of the event stream, owned by the `EventLog`.
pub struct Feed {
    tx: mpsc::Sender<Arc<SecurityEvent>>,
    categories: CategorySet,
    /// Events dropped since the notifier task last looked.
    pending_dropped: Arc<AtomicU64>,
    stats: Arc<Stats>,
}

impl Feed {
    /// Offer one event. Never blocks and never fails: an event that is of no
    /// interest is ignored, one that does not fit in the queue is counted.
    pub fn offer(&self, event: &Arc<SecurityEvent>) {
        let Some(class) = engine::classify(event) else {
            return;
        };
        if !self.categories.contains(class.category()) {
            return;
        }
        if self.tx.try_send(event.clone()).is_err() {
            self.pending_dropped.fetch_add(1, Ordering::Relaxed);
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ── The handle the rest of the program holds ──────────────────────────────────

/// Result of one sender in a test notification.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TestResult {
    pub sender: &'static str,
    pub ok: bool,
    /// The HTTP status the notifier answered with, when it answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// What went wrong, in fixed words: no URL, path or token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One sender as the admin UI shows it: type and host only.
#[derive(Debug, Clone, PartialEq)]
pub struct SenderInfo {
    pub kind: &'static str,
    pub host: String,
    pub sent: u64,
    pub failed: u64,
}

/// What the status page shows.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub senders: Vec<SenderInfo>,
    pub categories: Vec<&'static str>,
    pub suppressed: u64,
    pub dropped: u64,
}

impl Snapshot {
    pub fn enabled(&self) -> bool {
        !self.senders.is_empty()
    }
    pub fn sent(&self) -> u64 {
        self.senders.iter().map(|s| s.sent).sum()
    }
    pub fn failed(&self) -> u64 {
        self.senders.iter().map(|s| s.failed).sum()
    }
}

/// The notifier as seen by the API and the UI: what is enabled, the counters,
/// and the test notification.
pub struct NotifyHandle {
    senders: Vec<Arc<Sender>>,
    categories: CategorySet,
    stats: Arc<Stats>,
    last_test: Mutex<Option<Instant>>,
}

impl Default for NotifyHandle {
    fn default() -> Self {
        Self::disabled(CategorySet::of(&Category::DEFAULT))
    }
}

impl NotifyHandle {
    /// No sender: nothing is sent, the test endpoint reports an empty list.
    pub fn disabled(categories: CategorySet) -> Self {
        Self {
            senders: Vec::new(),
            categories,
            stats: Arc::new(Stats::default()),
            last_test: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub fn enabled(&self) -> bool {
        !self.senders.is_empty()
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            senders: self
                .senders
                .iter()
                .map(|s| SenderInfo {
                    kind: s.name(),
                    host: s.host().to_string(),
                    sent: s.sent.load(Ordering::Relaxed),
                    failed: s.failed.load(Ordering::Relaxed),
                })
                .collect(),
            categories: self.categories.names(),
            suppressed: self.stats.suppressed.load(Ordering::Relaxed),
            dropped: self.stats.dropped.load(Ordering::Relaxed),
        }
    }

    /// Send one test notification to every enabled sender, now, each with the
    /// client's timeout and without retries, and report each result. The rate
    /// limits do not apply to it, except that it can be sent only once per
    /// [`TEST_INTERVAL`]: `Err(seconds)` says how long to wait.
    pub async fn send_test(&self) -> Result<Vec<TestResult>, u64> {
        {
            let mut last = self.last_test.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            if let Some(at) = *last {
                let since = now.saturating_duration_since(at);
                if since < TEST_INTERVAL {
                    return Err((TEST_INTERVAL - since).as_secs_f64().ceil() as u64);
                }
            }
            *last = Some(now);
        }
        let notification = Arc::new(Notification::test());
        let mut set = tokio::task::JoinSet::new();
        for (i, sender) in self.senders.iter().enumerate() {
            let (sender, notification) = (sender.clone(), notification.clone());
            set.spawn(async move {
                let result = match sender.deliver(&notification, false).await {
                    Ok(status) => TestResult {
                        sender: sender.name(),
                        ok: true,
                        status: Some(status),
                        error: None,
                    },
                    Err(e) => TestResult {
                        sender: sender.name(),
                        ok: false,
                        status: e.status(),
                        error: Some(e.to_string()),
                    },
                };
                (i, result)
            });
        }
        let mut results = Vec::new();
        while let Some(joined) = set.join_next().await {
            if let Ok(pair) = joined {
                results.push(pair);
            }
        }
        results.sort_by_key(|(i, _)| *i);
        Ok(results.into_iter().map(|(_, r)| r).collect())
    }
}

// ── Start-up ──────────────────────────────────────────────────────────────────

/// Build the senders, start the notifier task and attach it to the event log.
/// Without a configured sender nothing is started. Must run inside a Tokio
/// runtime.
pub fn start(cfg: &NotifyConfig, events: &Arc<EventLog>) -> FerroResult<Arc<NotifyHandle>> {
    start_with(cfg, events, SendOptions::default())
}

/// [`start`] with the senders' timeout and retry delays given (tests).
pub fn start_with(
    cfg: &NotifyConfig,
    events: &Arc<EventLog>,
    options: SendOptions,
) -> FerroResult<Arc<NotifyHandle>> {
    let categories = cfg.categories();
    if !cfg.enabled() {
        return Ok(Arc::new(NotifyHandle::disabled(categories)));
    }
    let senders = senders::build(cfg, &options)?;
    let stats = Arc::new(Stats::default());
    let handle = Arc::new(NotifyHandle {
        senders: senders.clone(),
        categories,
        stats: stats.clone(),
        last_test: Mutex::new(None),
    });

    let workers: Vec<mpsc::Sender<Arc<Notification>>> = senders
        .into_iter()
        .map(|sender| {
            let (tx, rx) = mpsc::channel(SENDER_QUEUE);
            tokio::spawn(senders::run_worker(sender, rx));
            tx
        })
        .collect();

    let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
    let pending_dropped = Arc::new(AtomicU64::new(0));
    let engine = Engine::new(
        Settings {
            categories,
            min_interval: Duration::from_secs(cfg.min_interval_secs),
            max_per_hour: cfg.max_per_hour,
            auth_threshold: cfg.auth_failure_threshold,
            auth_window: Duration::from_secs(cfg.auth_failure_window_secs),
        },
        stats.clone(),
    );
    tokio::spawn(run(
        rx,
        engine,
        pending_dropped.clone(),
        workers,
        stats.clone(),
    ));
    events.attach_notifier(Feed {
        tx,
        categories,
        pending_dropped,
        stats,
    });
    Ok(handle)
}

/// The notifier task. Wakes for each event and every few seconds (to report
/// events that did not fit in the queue).
async fn run(
    mut rx: mpsc::Receiver<Arc<SecurityEvent>>,
    mut engine: Engine,
    pending_dropped: Arc<AtomicU64>,
    workers: Vec<mpsc::Sender<Arc<Notification>>>,
    stats: Arc<Stats>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut warned: Option<Instant> = None;
    loop {
        let mut out = Vec::new();
        tokio::select! {
            event = rx.recv() => match event {
                Some(event) => out.extend(engine.process(Instant::now(), &event)),
                None => break,
            },
            _ = tick.tick() => {}
        }
        let dropped = pending_dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            out.extend(engine.notifications_dropped(Instant::now(), dropped));
        }
        for notification in out {
            let notification = Arc::new(notification);
            for worker in &workers {
                if worker.try_send(notification.clone()).is_err() {
                    // That sender is behind: count it, say so now and then.
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                    if warned.is_none_or(|w| w.elapsed() > Duration::from_secs(60)) {
                        warned = Some(Instant::now());
                        tracing::warn!("a notifier is not keeping up; notifications are dropped");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
