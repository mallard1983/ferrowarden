//! The security event stream.
//!
//! [`EventLog::emit`] is the one emitter. It is synchronous and never blocks:
//! the event goes into the in-memory ring buffer (behind
//! `GET /v1/admin/audit`) and is queued, with `try_send`, for a single writer
//! task that serializes it once and writes it to every enabled sink. When the
//! queue is full the event is counted as dropped instead of waiting; the
//! writer later reports the loss with an `events_dropped` event.

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

    /// Record an event. Never blocks, never fails.
    pub fn emit(&self, event: SecurityEvent) {
        let event = Arc::new(event);
        self.shared.push(event.clone());
        // The notifier has its own queue: a stalled sink cannot hold it up,
        // and it cannot hold up the sinks.
        if let Some(feed) = self.shared.notify.get() {
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
mod tests {
    use super::*;
    use sinks::SinkKind;

    fn ev(n: u64) -> SecurityEvent {
        SecurityEvent::new(Action::Forward).detail("n", n)
    }

    fn n_of(e: &SecurityEvent) -> u64 {
        e.ferrowarden.details.as_ref().unwrap()["n"]
            .as_u64()
            .unwrap()
    }

    fn memory_sink() -> (Sink, Arc<Mutex<Vec<String>>>) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        (Sink::new("memory", SinkKind::Memory(lines.clone())), lines)
    }

    #[test]
    fn ring_buffer_returns_newest_first_and_respects_limit() {
        let log = EventLog::buffer_only(10);
        for n in 0..5 {
            log.emit(ev(n));
        }
        let recent = log.recent(3);
        assert_eq!(
            recent.iter().map(|e| n_of(e)).collect::<Vec<_>>(),
            [4, 3, 2]
        );
        assert_eq!(log.recent(100).len(), 5);
    }

    #[test]
    fn ring_buffer_evicts_oldest_at_capacity() {
        let log = EventLog::buffer_only(3);
        for n in 0..5 {
            log.emit(ev(n));
        }
        let recent = log.recent(10);
        assert_eq!(
            recent.iter().map(|e| n_of(e)).collect::<Vec<_>>(),
            [4, 3, 2]
        );
        assert_eq!(log.capacity(), 3);
    }

    #[tokio::test]
    async fn writer_serializes_once_and_writes_to_every_sink() {
        let (a, a_lines) = memory_sink();
        let (b, b_lines) = memory_sink();
        let log = EventLog::with_sinks(10, 100, vec![a, b]);
        for n in 0..3 {
            log.emit(ev(n));
        }
        log.flush().await;

        let a = a_lines.lock().unwrap().clone();
        let b = b_lines.lock().unwrap().clone();
        assert_eq!(a.len(), 3);
        assert_eq!(a, b, "every sink gets identical lines");
        let first: serde_json::Value = serde_json::from_str(&a[0]).unwrap();
        assert_eq!(first["event"]["dataset"], "ferrowarden.security");
        assert_eq!(first["ferrowarden"]["details"]["n"], 0);
    }

    #[tokio::test]
    async fn queue_overflow_counts_drops_then_reports_events_dropped() {
        let (sink, lines) = memory_sink();
        // Current-thread runtime: the writer cannot run until we await, so the
        // queue (capacity 2) overflows deterministically.
        let log = EventLog::with_sinks(100, 2, vec![sink]);
        for n in 0..5 {
            log.emit(ev(n));
        }
        assert_eq!(log.pending_dropped(), 3);
        // The ring buffer still has everything.
        assert_eq!(log.recent(100).len(), 5);

        log.flush().await;
        assert_eq!(log.pending_dropped(), 0);

        let lines = lines.lock().unwrap().clone();
        let events: Vec<serde_json::Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let written_forward = events
            .iter()
            .filter(|e| e["event"]["action"] == "forward")
            .count();
        assert_eq!(written_forward, 2, "only the queued events were written");
        let report = events
            .iter()
            .find(|e| e["event"]["action"] == "events_dropped")
            .expect("events_dropped must be emitted");
        assert_eq!(report["ferrowarden"]["details"]["dropped"], 3);
        // ... and it is visible through the audit endpoint's buffer too.
        assert!(log
            .recent(100)
            .iter()
            .any(|e| e.event.action == Action::EventsDropped));
    }

    #[tokio::test]
    async fn emit_does_not_block_when_the_queue_is_full() {
        let (sink, _lines) = memory_sink();
        let log = EventLog::with_sinks(10, 1, vec![sink]);
        // Would hang the test forever if emit awaited queue space.
        for n in 0..1000 {
            log.emit(ev(n));
        }
        assert_eq!(log.pending_dropped(), 999);
    }

    #[test]
    fn emit_rejected_records_the_client_visible_error_only() {
        let log = EventLog::buffer_only(10);
        let ctx = RequestContext::new("10.1.2.3".parse().unwrap());
        emit_rejected(
            &log,
            &ctx,
            None,
            "/v1/forward",
            &FerroError::InvalidJson("duplicate key at depth 2".into()),
        );
        let e = &log.recent(1)[0];
        let v = serde_json::to_value(&**e).unwrap();
        assert_eq!(v["event"]["action"], "request_rejected");
        assert_eq!(v["event"]["reason"], "invalid_json");
        assert_eq!(v["http"]["response"]["status_code"], 400);
        assert_eq!(v["ferrowarden"]["details"]["endpoint"], "/v1/forward");
        assert_eq!(
            v["ferrowarden"]["details"]["error"],
            "Invalid JSON: duplicate key at depth 2"
        );
    }
}
