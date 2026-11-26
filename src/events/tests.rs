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
