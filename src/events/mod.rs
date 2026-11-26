//! The security event stream.
//!
//! [`EventLog::emit`] is the one emitter. It is synchronous and never blocks:
//! the event goes into the in-memory ring buffer (behind
//! `GET /v1/admin/audit`) and is queued, with `try_send`, for a single writer
//! task that serializes it once and writes it to every enabled sink. When the
//! queue is full the event is counted as dropped instead of waiting; the
//! writer later reports the loss with an `events_dropped` event. The push
//! notifier and the metrics consumer each get the event through their own
//! bounded queue with `try_send`, so neither can hold `emit` up.

pub mod schema;
pub mod sinks;

use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

pub use schema::{truncate, Action, Outcome, Reason, SecurityEvent, MAX_ERROR_CHARS};
use sinks::Sink;

use crate::config::EventsConfig;
use crate::error::{FerroError, FerroResult};
use crate::middleware::request_context::RequestContext;
use crate::notify::Feed;
use crate::state::AgentKey;

/// Events written per sink flush.
const BATCH: usize = 256;

enum Msg {
    Event(Arc<SecurityEvent>),
    Flush(oneshot::Sender<()>),
}

struct Shared {
    buffer: Mutex<VecDeque<Arc<SecurityEvent>>>,
    capacity: usize,
    /// Events dropped because the sink queue was full, not yet reported.
    dropped: AtomicU64,
    /// Events dropped since start (never reset); shown on the admin UI.
    dropped_total: AtomicU64,
    /// The push notifier's queue, once one is attached. Offering an event to
    /// it is a classification and a `try_send`: it cannot block.
    notify: OnceLock<Feed>,
    /// The metrics consumer's queue, once metrics are on. `offer` is a
    /// `try_send`: it cannot block either.
    metrics: OnceLock<crate::metrics::Feed>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, VecDeque<Arc<SecurityEvent>>> {
        // A poisoned lock only means another thread panicked mid-push; the
        // buffer is still structurally valid and logging must never fail.
        self.buffer.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn push(&self, event: Arc<SecurityEvent>) {
        let mut buf = self.lock();
        if buf.len() >= self.capacity {
            buf.pop_front();
        }
        buf.push_back(event);
    }
}

pub struct EventLog {
    shared: Arc<Shared>,
    tx: Option<mpsc::Sender<Msg>>,
}

impl EventLog {
    /// Ring buffer only, no sinks (unit tests, and the default for state
    /// built without configuration).
    pub fn buffer_only(capacity: usize) -> Self {
        Self {
            shared: Arc::new(Shared {
                buffer: Mutex::new(VecDeque::with_capacity(capacity.min(4096))),
                capacity: capacity.max(1),
                dropped: AtomicU64::new(0),
                dropped_total: AtomicU64::new(0),
                notify: OnceLock::new(),
                metrics: OnceLock::new(),
            }),
            tx: None,
        }
    }

    /// Start the event log with the sinks enabled in `cfg`. Must be called
    /// inside a Tokio runtime (it spawns the writer task).
    pub fn start(cfg: &EventsConfig) -> FerroResult<Arc<Self>> {
        let sinks = Sink::from_config(cfg)?;
        Ok(Arc::new(Self::with_sinks(
            cfg.buffer_size,
            cfg.queue_size,
            sinks,
        )))
    }

    pub fn with_sinks(buffer_size: usize, queue_size: usize, sinks: Vec<Sink>) -> Self {
        let mut log = Self::buffer_only(buffer_size);
        let (tx, rx) = mpsc::channel(queue_size.max(1));
        tokio::spawn(run_writer(rx, sinks, log.shared.clone()));
        log.tx = Some(tx);
        log
    }

    /// Connect the push notifier (docs/notifications.md). Only the first call
    /// has an effect.
    pub fn attach_notifier(&self, feed: Feed) {
        let _ = self.shared.notify.set(feed);
    }

    /// Connect the metrics consumer (docs/metrics.md). Only the first call
    /// has an effect.
    pub fn attach_metrics(&self, feed: crate::metrics::Feed) {
        let _ = self.shared.metrics.set(feed);
    }

    /// Record an event. Never blocks, never fails.
    pub fn emit(&self, event: SecurityEvent) {
        let event = Arc::new(event);
        self.shared.push(event.clone());
        // The notifier has its own queue: a stalled sink cannot hold it up,
        // and it cannot hold up the sinks.
        if let Some(feed) = self.shared.notify.get() {
            feed.offer(&event);
        }
        if let Some(feed) = self.shared.metrics.get() {
            feed.offer(&event);
        }
        let Some(tx) = &self.tx else { return };
        if tx.try_send(Msg::Event(event)).is_err() {
            // Queue full (or the writer is gone). Count it; the writer reports
            // the total when it has room. Say so on stderr right away, once
            // per overflow episode, so a flood cannot also flood stderr.
            self.shared.dropped_total.fetch_add(1, Ordering::Relaxed);
            if self.shared.dropped.fetch_add(1, Ordering::Relaxed) == 0 {
                let _ = writeln!(
                    std::io::stderr(),
                    "ferrowarden: security event queue is full; dropping events"
                );
            }
        }
    }

    /// Wait (bounded) until everything emitted so far has been written to the
    /// sinks and flushed. Used at shutdown.
    pub async fn flush(&self) {
        let Some(tx) = &self.tx else { return };
        let (ack, done) = oneshot::channel();
        let sent = tokio::time::timeout(Duration::from_secs(5), tx.send(Msg::Flush(ack))).await;
        if matches!(sent, Ok(Ok(()))) {
            let _ = tokio::time::timeout(Duration::from_secs(10), done).await;
        }
    }

    /// The newest `limit` events, newest first.
    pub fn recent(&self, limit: usize) -> Vec<Arc<SecurityEvent>> {
        self.shared
            .lock()
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Events that could not be queued for the sinks since start.
    pub fn dropped_total(&self) -> u64 {
        self.shared.dropped_total.load(Ordering::Relaxed)
    }

    /// Ring buffer capacity (the largest useful `limit`).
    pub fn capacity(&self) -> usize {
        self.shared.capacity
    }

    /// Events dropped and not yet reported (tests, diagnostics).
    #[cfg(test)]
    pub fn pending_dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }
}

/// Serialize once, write to every sink.
async fn write_event(sinks: &mut [Sink], event: &SecurityEvent) {
    let mut line = match serde_json::to_vec(event) {
        Ok(line) => line,
        Err(e) => {
            tracing::warn!(error = %e, "failed to serialize a security event");
            return;
        }
    };
    line.push(b'\n');
    for sink in sinks.iter_mut() {
        sink.write(event, &line).await;
    }
}

async fn run_writer(mut rx: mpsc::Receiver<Msg>, mut sinks: Vec<Sink>, shared: Arc<Shared>) {
    let mut batch: Vec<Msg> = Vec::with_capacity(BATCH);
    loop {
        let Some(first) = rx.recv().await else { break };
        batch.push(first);
        while batch.len() < BATCH {
            match rx.try_recv() {
                Ok(msg) => batch.push(msg),
                Err(_) => break,
            }
        }

        let mut acks = Vec::new();
        for msg in batch.drain(..) {
            match msg {
                Msg::Event(event) => write_event(&mut sinks, &event).await,
                Msg::Flush(ack) => acks.push(ack),
            }
        }

        // The queue has room again: report what overflowed meanwhile.
        let dropped = shared.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            let event = Arc::new(
                SecurityEvent::new(Action::EventsDropped)
                    .outcome(Outcome::Unknown)
                    .detail("dropped", dropped),
            );
            shared.push(event.clone());
            if let Some(feed) = shared.notify.get() {
                feed.offer(&event);
            }
            if let Some(feed) = shared.metrics.get() {
                feed.offer(&event);
            }
            write_event(&mut sinks, &event).await;
        }

        for sink in sinks.iter_mut() {
            sink.flush();
        }
        for ack in acks {
            let _ = ack.send(());
        }
    }
    for sink in sinks.iter_mut() {
        sink.flush();
    }
}

/// Emit `request_rejected` for a body or query that failed parsing. `error`
/// is the same sanitized message the client receives.
pub fn emit_rejected(
    events: &EventLog,
    ctx: &RequestContext,
    key: Option<&AgentKey>,
    endpoint: &'static str,
    error: &FerroError,
) {
    let mut event = SecurityEvent::new(Action::RequestRejected)
        .request(ctx)
        .reason(Reason::from(error))
        .status(error.status_code().as_u16())
        .detail("endpoint", endpoint)
        .detail("error", truncate(&error.to_string(), MAX_ERROR_CHARS));
    if let Some(key) = key {
        event = event.key(key);
    }
    events.emit(event);
}

#[cfg(test)]
mod tests;
