//! Tests of the notifier: classification, rate limits, the content allow-list,
//! the senders against an in-process receiver, and the queues.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Router,
};
use serde_json::Value;
use zeroize::Zeroizing;

use super::content::{EventFields, Kind, Notification, Severity};
use super::engine::{classify, AuthSource, Class, Engine, Settings};
use super::senders::{self, SendError, SendOptions};
use super::*;
use crate::config::{NotifyConfig, NotifyTokens};
use crate::events::{Action, EventLog, Outcome, Reason, SecurityEvent};
use crate::middleware::request_context::RequestContext;
use crate::state::AgentKey;

const SEEDED_SECRET: &str = "sk_live_SEEDED_9f8e7d6c5b4a";
const GOTIFY_TOKEN: &str = "gotify-token-AAAA1111";
const NTFY_TOKEN: &str = "ntfy-token-BBBB2222";
const WEBHOOK_TOKEN: &str = "webhook-token-CCCC3333";

// ── Builders ──────────────────────────────────────────────────────────────────

fn ctx_from(ip: &str) -> RequestContext {
    RequestContext::new(ip.parse().unwrap())
}

fn agent(name: &str, id: &str) -> AgentKey {
    AgentKey {
        id: id.into(),
        name: name.into(),
        created_at: chrono::Utc::now(),
        policy: Default::default(),
        policy_set: true,
    }
}

fn monitoring_agent() -> AgentKey {
    agent("monitoring-agent", "11111111-1111-1111-1111-111111111111")
}

fn blocked(reason: Reason) -> SecurityEvent {
    SecurityEvent::new(Action::Forward)
        .request(&ctx_from("172.20.0.5"))
        .key(&monitoring_agent())
        .method("POST")
        .url("https://api.example.com/v1/things?token={{vault:grafana_service_account}}")
        .credentials(["grafana_service_account"])
        .outcome(Outcome::Failure)
        .reason(reason)
        .status(403)
}

fn auth_failure(action: Action, ip: &str) -> SecurityEvent {
    let reason = match action {
        Action::AdminAuth => Reason::InvalidAdminKey,
        _ => Reason::InvalidKey,
    };
    SecurityEvent::new(action)
        .request(&ctx_from(ip))
        .reason(reason)
        .status(401)
}

fn ui_login(outcome: Outcome, reason: Option<Reason>, ip: &str) -> SecurityEvent {
    let mut e = SecurityEvent::new(Action::UiLogin)
        .request(&ctx_from(ip))
        .outcome(outcome);
    if let Some(r) = reason {
        e = e.reason(r);
    }
    e
}

fn vault(action: Action, outcome: Outcome) -> SecurityEvent {
    SecurityEvent::new(action).outcome(outcome)
}

fn settings(categories: &[Category]) -> Settings {
    Settings {
        categories: CategorySet::of(categories),
        min_interval: Duration::from_secs(60),
        max_per_hour: 60,
        auth_threshold: 5,
        auth_window: Duration::from_secs(300),
    }
}

fn engine_with(s: Settings) -> (Engine, Arc<Stats>) {
    let stats = Arc::new(Stats::default());
    (Engine::new(s, stats.clone()), stats)
}

fn engine() -> (Engine, Arc<Stats>) {
    engine_with(settings(&Category::DEFAULT))
}

fn at(base: Instant, secs: u64) -> Instant {
    base + Duration::from_secs(secs)
}

// ── Classification ────────────────────────────────────────────────────────────

/// The documented table, written out per (action, outcome, reason).
fn expected_class(action: Action, outcome: Outcome, reason: Option<Reason>) -> Option<Class> {
    use Action::*;
    let failed = outcome == Outcome::Failure;
    let ok = outcome == Outcome::Success;
    match action {
        Forward if failed => matches!(
            reason,
            Some(
                Reason::CredentialHostNotAllowed
                    | Reason::SessionHostNotAllowed
                    | Reason::TargetBlocked
                    | Reason::CredentialOutOfScope
                    | Reason::MethodNotAllowed
                    | Reason::RepromptRequired
            )
        )
        .then_some(Class::Blocked),
        AgentAuth if failed => Some(Class::Auth(AuthSource::Agent)),
        AdminAuth if failed => Some(Class::Auth(AuthSource::Admin)),
        UiLogin if failed && reason == Some(Reason::LoginLockedOut) => Some(Class::LockedOut),
        UiLogin
            if failed
                && matches!(
                    reason,
                    Some(Reason::InvalidCredentials | Reason::TwoFactorFailed)
                ) =>
        {
            Some(Class::Auth(AuthSource::Ui))
        }
        UiLogin if ok => Some(Class::UiLoginOk),
        VaultLock => Some(Class::VaultLock),
        VaultUnlock if failed => Some(Class::VaultUnlockFailed),
        VaultUnlock if ok => Some(Class::VaultUnlockOk),
        VaultSync if failed => Some(Class::VaultSyncFailed),
        KeyCreate if ok => Some(Class::KeyCreate),
        KeyRevoke if ok => Some(Class::KeyRevoke),
        KeyPolicyChange if ok => Some(Class::KeyPolicyChange),
        CredentialCreate if ok => Some(Class::CredentialCreated),
        EventsDropped => Some(Class::EventsDropped),
        ApprovalRequested if ok => Some(Class::ApprovalRequested),
        _ => None,
    }
}

#[test]
fn every_action_outcome_and_reason_is_classified_as_documented() {
    let mut reasons: Vec<Option<Reason>> = vec![None];
    reasons.extend(Reason::ALL.into_iter().map(Some));
    let mut classified = 0;
    for action in Action::ALL {
        for outcome in [Outcome::Success, Outcome::Failure, Outcome::Unknown] {
            for reason in &reasons {
                let mut e = SecurityEvent::new(action).outcome(outcome);
                if let Some(r) = reason {
                    e = e.reason(*r);
                }
                let got = classify(&e);
                assert_eq!(
                    got,
                    expected_class(action, outcome, *reason),
                    "{action:?} {outcome:?} {reason:?}"
                );
                classified += got.is_some() as usize;
            }
        }
    }
    assert!(classified > 0);
}

#[test]
fn the_documented_examples_classify_and_the_rest_are_ignored() {
    let c = |e: SecurityEvent| classify(&e);
    for reason in [
        Reason::CredentialHostNotAllowed,
        Reason::SessionHostNotAllowed,
        Reason::TargetBlocked,
        Reason::CredentialOutOfScope,
        Reason::MethodNotAllowed,
        Reason::RepromptRequired,
    ] {
        assert_eq!(c(blocked(reason)), Some(Class::Blocked), "{reason:?}");
    }
    // A forward that failed for another reason, or succeeded, is not a block.
    for reason in [
        Reason::UpstreamError,
        Reason::UnknownCredential,
        Reason::VaultLocked,
        Reason::InvalidTargetUrl,
        Reason::MalformedPlaceholder,
        Reason::ResponseTooLarge,
    ] {
        assert_eq!(c(blocked(reason)), None, "{reason:?}");
    }
    assert_eq!(c(SecurityEvent::new(Action::Forward)), None);
    // Never notified: reads, rate limiting, lifecycle, UI housekeeping.
    for action in [
        Action::CredentialsList,
        Action::RateLimited,
        Action::RequestRejected,
        Action::KeyList,
        Action::PolicyPreview,
        Action::AuditRead,
        Action::StatusRead,
        Action::OpenapiRead,
        Action::Startup,
        Action::Shutdown,
        Action::UiLogout,
        Action::UiSessionExpired,
        Action::UiTwoFactorEmailSent,
        Action::NotifyTest,
    ] {
        assert_eq!(c(SecurityEvent::new(action)), None, "{action:?}");
        assert_eq!(
            c(SecurityEvent::new(action).outcome(Outcome::Failure)),
            None,
            "{action:?}"
        );
    }
    // Second-factor pending, an unreachable Vaultwarden and insecure
    // transport are not authentication failures.
    assert_eq!(
        c(ui_login(
            Outcome::Unknown,
            Some(Reason::TwoFactorRequired),
            "1.2.3.4"
        )),
        None
    );
    assert_eq!(
        c(ui_login(
            Outcome::Failure,
            Some(Reason::UpstreamError),
            "1.2.3.4"
        )),
        None
    );
    assert_eq!(
        c(ui_login(
            Outcome::Failure,
            Some(Reason::InsecureTransport),
            "1.2.3.4"
        )),
        None
    );
    // A successful agent_auth does not exist, but would not notify either.
    assert_eq!(
        c(SecurityEvent::new(Action::AgentAuth).outcome(Outcome::Success)),
        None
    );
    // A failed key creation is not an admin notification.
    assert_eq!(
        c(SecurityEvent::new(Action::KeyCreate).outcome(Outcome::Failure)),
        None
    );
}

#[test]
fn categories_parse_and_default_to_everything_but_admin() {
    assert_eq!(
        CategorySet::from_names(&["blocked".into(), "vault".into()])
            .unwrap()
            .names(),
        ["blocked", "vault"]
    );
    assert!(CategorySet::from_names(&["nope".into()]).is_err());
    assert!(CategorySet::from_names(&["Blocked".into()]).is_err());
    let d = CategorySet::of(&Category::DEFAULT);
    assert!(!d.contains(Category::Admin));
    for c in [
        Category::Blocked,
        Category::AuthFailure,
        Category::Vault,
        Category::System,
    ] {
        assert!(d.contains(c));
    }
    assert_eq!(NotifyConfig::default().categories(), d);
}

#[test]
fn events_outside_the_enabled_categories_are_ignored() {
    let (mut e, _) = engine();
    let t0 = Instant::now();
    for ev in [
        SecurityEvent::new(Action::KeyCreate)
            .request(&ctx_from("10.0.0.1"))
            .key(&monitoring_agent()),
        ui_login(Outcome::Success, None, "10.0.0.1"),
    ] {
        assert!(e.process(t0, &ev).is_empty());
    }
    // Admin enabled: both notify.
    let (mut e, _) = engine_with(settings(&Category::ALL));
    let out = e.process(
        t0,
        &SecurityEvent::new(Action::KeyCreate)
            .request(&ctx_from("10.0.0.1"))
            .key(&monitoring_agent()),
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].severity, Severity::Normal);
    assert_eq!(out[0].category, Category::Admin);
    assert_eq!(
        e.process(t0, &ui_login(Outcome::Success, None, "10.0.0.1"))
            .len(),
        1
    );
}

// ── Auth failures ─────────────────────────────────────────────────────────────

#[test]
fn auth_failures_notify_at_the_threshold_per_source_address() {
    let (mut e, _) = engine();
    let t0 = Instant::now();
    for i in 0..4 {
        assert!(
            e.process(at(t0, i), &auth_failure(Action::AgentAuth, "203.0.113.9"))
                .is_empty(),
            "failure {i}"
        );
    }
    // Another address has its own count.
    assert!(e
        .process(at(t0, 4), &auth_failure(Action::AgentAuth, "203.0.113.10"))
        .is_empty());
    let out = e.process(at(t0, 5), &auth_failure(Action::AgentAuth, "203.0.113.9"));
    assert_eq!(out.len(), 1);
    let n = &out[0];
    assert_eq!(n.category, Category::AuthFailure);
    assert_eq!(n.severity, Severity::High);
    assert_eq!(n.event.count, 5);
    assert_eq!(n.event.source_ip.as_deref(), Some("203.0.113.9"));
    assert!(n.message.starts_with("5 failed authentication attempts from 203.0.113.9 in the last 5 minutes (agent key 5)."), "{}", n.message);
}

#[test]
fn auth_failures_count_agent_admin_and_ui_together_within_the_window() {
    let (mut e, _) = engine();
    let t0 = Instant::now();
    let ip = "198.51.100.7";
    assert!(e
        .process(at(t0, 0), &auth_failure(Action::AgentAuth, ip))
        .is_empty());
    assert!(e
        .process(at(t0, 1), &auth_failure(Action::AdminAuth, ip))
        .is_empty());
    assert!(e
        .process(
            at(t0, 2),
            &ui_login(Outcome::Failure, Some(Reason::InvalidCredentials), ip)
        )
        .is_empty());
    assert!(e
        .process(
            at(t0, 3),
            &ui_login(Outcome::Failure, Some(Reason::TwoFactorFailed), ip)
        )
        .is_empty());
    let out = e.process(at(t0, 4), &auth_failure(Action::AgentAuth, ip));
    assert_eq!(out.len(), 1);
    assert!(
        out[0]
            .message
            .contains("(agent key 2, admin key 1, admin UI 2)"),
        "{}",
        out[0].message
    );
}

#[test]
fn failures_outside_the_window_do_not_add_up() {
    let (mut e, _) = engine();
    let t0 = Instant::now();
    // One failure every 100 s: at most 4 fit in 300 s... never 5.
    for i in 0..30 {
        assert!(
            e.process(
                at(t0, i * 100),
                &auth_failure(Action::AgentAuth, "192.0.2.1")
            )
            .is_empty(),
            "failure {i}"
        );
    }
}

#[test]
fn the_threshold_and_window_are_configurable() {
    let mut s = settings(&Category::DEFAULT);
    s.auth_threshold = 2;
    s.auth_window = Duration::from_secs(10);
    let (mut e, _) = engine_with(s);
    let t0 = Instant::now();
    assert!(e
        .process(at(t0, 0), &auth_failure(Action::AdminAuth, "192.0.2.1"))
        .is_empty());
    assert_eq!(
        e.process(at(t0, 9), &auth_failure(Action::AdminAuth, "192.0.2.1"))
            .len(),
        1
    );
    // Further failures within the interval are folded into the next notice.
    let (mut e, _) = engine_with({
        let mut s = settings(&Category::DEFAULT);
        s.auth_threshold = 2;
        s.auth_window = Duration::from_secs(10);
        s
    });
    assert!(e
        .process(at(t0, 0), &auth_failure(Action::AdminAuth, "192.0.2.1"))
        .is_empty());
    assert!(
        e.process(at(t0, 11), &auth_failure(Action::AdminAuth, "192.0.2.1"))
            .is_empty(),
        "the first one left the window"
    );
}

#[test]
fn a_failure_without_a_source_address_is_ignored() {
    let (mut e, _) = engine_with({
        let mut s = settings(&Category::DEFAULT);
        s.auth_threshold = 1;
        s
    });
    let ev = SecurityEvent::new(Action::AgentAuth).reason(Reason::InvalidKey);
    assert!(e.process(Instant::now(), &ev).is_empty());
}

#[test]
fn a_lockout_notifies_immediately_and_is_rate_limited_on_its_own() {
    let (mut e, _) = engine();
    let t0 = Instant::now();
    let ev = ui_login(
        Outcome::Failure,
        Some(Reason::LoginLockedOut),
        "203.0.113.50",
    );
    let out = e.process(t0, &ev);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].title, "Ferrowarden: sign-in locked out");
    assert_eq!(out[0].severity, Severity::High);
    assert!(out[0].message.contains("203.0.113.50"));
    assert!(
        e.process(at(t0, 5), &ev).is_empty(),
        "same address, within the interval"
    );
    let other = ui_login(
        Outcome::Failure,
        Some(Reason::LoginLockedOut),
        "203.0.113.51",
    );
    assert_eq!(e.process(at(t0, 5), &other).len(), 1);
    let again = e.process(at(t0, 61), &ev);
    assert_eq!(again.len(), 1);
    assert!(
        again[0].message.contains("And 1 more since"),
        "{}",
        again[0].message
    );
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

#[test]
fn one_notification_per_subject_per_interval_with_a_summary_of_the_rest() {
    let (mut e, stats) = engine();
    let t0 = Instant::now();
    let ev = blocked(Reason::CredentialHostNotAllowed);
    assert_eq!(e.process(at(t0, 0), &ev).len(), 1);
    for i in 1..=14 {
        assert!(e.process(at(t0, i), &ev).is_empty());
    }
    assert_eq!(stats.suppressed.load(Ordering::Relaxed), 14);
    // A different key is a different subject.
    let other = blocked(Reason::TargetBlocked).key(&agent(
        "other-agent",
        "22222222-2222-2222-2222-222222222222",
    ));
    assert_eq!(e.process(at(t0, 20), &other).len(), 1);

    let out = e.process(at(t0, 60), &ev);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].suppressed, 14);
    assert!(
        out[0].message.contains(" And 14 more since "),
        "{}",
        out[0].message
    );
    assert!(
        out[0].message.trim_end_matches('.').ends_with(" UTC"),
        "{}",
        out[0].message
    );
    // The summary was consumed.
    assert!(e.process(at(t0, 119), &ev).is_empty());
    let out = e.process(at(t0, 121), &ev);
    assert_eq!(out[0].suppressed, 1);
}

#[test]
fn the_interval_is_configurable_and_zero_disables_it() {
    let mut s = settings(&Category::DEFAULT);
    s.min_interval = Duration::ZERO;
    let (mut e, _) = engine_with(s);
    let t0 = Instant::now();
    for _ in 0..5 {
        assert_eq!(e.process(t0, &blocked(Reason::TargetBlocked)).len(), 1);
    }
}

#[test]
fn the_hourly_cap_pauses_once_and_resumes_when_the_hour_rolls_over() {
    let mut s = settings(&Category::DEFAULT);
    s.min_interval = Duration::ZERO;
    s.max_per_hour = 3;
    let (mut e, stats) = engine_with(s);
    let t0 = Instant::now();
    for i in 0..3 {
        assert_eq!(
            e.process(at(t0, i), &blocked(Reason::TargetBlocked)).len(),
            1
        );
    }
    let paused = e.process(at(t0, 10), &blocked(Reason::TargetBlocked));
    assert_eq!(paused.len(), 1, "one notice");
    assert_eq!(paused[0].category, Category::System);
    assert_eq!(paused[0].title, "Ferrowarden: notifications paused");
    assert!(
        paused[0].message.contains("3 per hour")
            && paused[0].message.contains("1 suppressed so far"),
        "{}",
        paused[0].message
    );
    assert_eq!(paused[0].severity, Severity::High);
    // Then silence.
    for i in 11..40 {
        assert!(e
            .process(at(t0, i), &blocked(Reason::TargetBlocked))
            .is_empty());
    }
    assert_eq!(stats.suppressed.load(Ordering::Relaxed), 30);
    // The hour rolls over.
    assert_eq!(
        e.process(at(t0, 3601), &blocked(Reason::TargetBlocked))
            .len(),
        1
    );
}

#[test]
fn the_per_subject_tables_are_bounded() {
    let mut s = settings(&Category::DEFAULT);
    s.max_per_hour = u32::MAX;
    s.auth_threshold = 1_000_000;
    let (mut e, _) = engine_with(s);
    let t0 = Instant::now();
    for i in 0..5000u32 {
        let key = agent("k", &format!("{i:08x}-0000-0000-0000-000000000000"));
        e.process(at(t0, 0), &blocked(Reason::TargetBlocked).key(&key));
        let ip = format!("10.{}.{}.{}", (i >> 16) & 255, (i >> 8) & 255, i & 255);
        e.process(at(t0, 0), &auth_failure(Action::AgentAuth, &ip));
    }
    let (subjects, ips) = e.table_sizes();
    assert!(subjects <= 1024, "{subjects}");
    assert!(ips <= 4096, "{ips}");
    // Expired entries are pruned.
    e.process(at(t0, 4000), &blocked(Reason::TargetBlocked));
    let (subjects, ips) = e.table_sizes();
    assert!(subjects <= 2, "{subjects}");
    assert!(ips <= 1, "{ips}");
}

// ── Vault ─────────────────────────────────────────────────────────────────────

#[test]
fn vault_events_and_the_recovery_notice() {
    let (mut e, _) = engine();
    let t0 = Instant::now();

    // An unlock with no notified lock before it is not news.
    assert!(e
        .process(at(t0, 0), &vault(Action::VaultUnlock, Outcome::Success))
        .is_empty());

    let lock = e.process(at(t0, 1), &vault(Action::VaultLock, Outcome::Success));
    assert_eq!(lock.len(), 1);
    assert_eq!(lock[0].title, "Ferrowarden: vault locked");
    assert_eq!(lock[0].severity, Severity::High);

    // The recovery goes out even inside the interval, at normal priority.
    let rec = e.process(at(t0, 2), &vault(Action::VaultUnlock, Outcome::Success));
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0].title, "Ferrowarden: vault unlocked");
    assert_eq!(rec[0].severity, Severity::Normal);
    // Only once.
    assert!(e
        .process(at(t0, 3), &vault(Action::VaultUnlock, Outcome::Success))
        .is_empty());

    // Failures, after the interval.
    let fail = e.process(
        at(t0, 100),
        &vault(Action::VaultUnlock, Outcome::Failure).reason(Reason::UnlockFailed),
    );
    assert_eq!(fail[0].title, "Ferrowarden: vault unlock failed");
    assert_eq!(fail[0].severity, Severity::High);
    let sync = e.process(
        at(t0, 200),
        &vault(Action::VaultSync, Outcome::Failure).reason(Reason::SyncFailed),
    );
    assert_eq!(sync[0].title, "Ferrowarden: vault sync failed");
    assert_eq!(sync[0].severity, Severity::High);
    // A successful sync is not an event for the notifier.
    assert!(e
        .process(at(t0, 300), &vault(Action::VaultSync, Outcome::Success))
        .is_empty());
}

#[test]
fn a_rate_limited_lock_still_leads_to_a_recovery_notice() {
    let (mut e, _) = engine();
    let t0 = Instant::now();
    assert_eq!(
        e.process(at(t0, 0), &vault(Action::VaultLock, Outcome::Success))
            .len(),
        1
    );
    assert!(e
        .process(at(t0, 1), &vault(Action::VaultLock, Outcome::Success))
        .is_empty());
    assert_eq!(
        e.process(at(t0, 2), &vault(Action::VaultUnlock, Outcome::Success))
            .len(),
        1
    );
}

#[test]
fn system_notices_for_dropped_events_and_notifications() {
    let (mut e, _) = engine();
    let t0 = Instant::now();
    let dropped = SecurityEvent::new(Action::EventsDropped)
        .outcome(Outcome::Unknown)
        .detail("dropped", 7u64);
    let out = e.process(at(t0, 0), &dropped);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].category, Category::System);
    assert!(
        out[0].message.starts_with("7 security events were dropped"),
        "{}",
        out[0].message
    );
    assert_eq!(out[0].severity, Severity::High);

    let n = e.notifications_dropped(at(t0, 100), 3);
    assert_eq!(n.len(), 1);
    assert!(
        n[0].message.starts_with("3 notifications were dropped"),
        "{}",
        n[0].message
    );
    // System notices share one subject, so the count is summarised.
    assert!(e.notifications_dropped(at(t0, 101), 2).is_empty());
    let n = e.notifications_dropped(at(t0, 161), 1);
    assert_eq!(n[0].suppressed, 2);

    // Not enabled: nothing.
    let (mut e, _) = engine_with(settings(&[Category::Blocked]));
    assert!(e.notifications_dropped(t0, 5).is_empty());
    assert!(e.process(t0, &dropped).is_empty());
}

// ── Content ───────────────────────────────────────────────────────────────────

#[test]
fn a_blocked_request_reads_like_the_documented_example() {
    let (mut e, _) = engine();
    let out = e.process(Instant::now(), &blocked(Reason::CredentialHostNotAllowed));
    let n = &out[0];
    assert_eq!(n.title, "Ferrowarden: request blocked");
    assert_eq!(n.severity, Severity::High);
    assert!(
        n.message.starts_with(
            "Key \"monitoring-agent\" (id 11111111) tried to send grafana_service_account to api.example.com. Blocked: credential not bound to that host. Source 172.20.0.5, request "
        ),
        "{}",
        n.message
    );
    assert!(
        n.message
            .ends_with('\u{2026}'.to_string().as_str().to_owned().as_str())
            || n.message.ends_with("\u{2026}."),
        "{}",
        n.message
    );
    assert_eq!(n.event.target_host.as_deref(), Some("api.example.com"));
    assert_eq!(n.event.key_name.as_deref(), Some("monitoring-agent"));
    assert_eq!(n.event.key_id.as_deref(), Some("11111111"));
    assert_eq!(n.event.credentials, ["grafana_service_account"]);
}

#[test]
fn names_are_reduced_to_a_safe_character_set() {
    let hostile_key = agent(
        "evil\"\n{{vault:x}}/../name\u{202e}?q=1",
        "id/with\nnewline-and-more-chars-than-eight",
    );
    let ev = blocked(Reason::CredentialOutOfScope)
        .key(&hostile_key)
        .credentials([
            "ok_name",
            "a{{vault:b}}\n/etc/passwd?x=1",
            "third",
            "fourth",
            "fifth",
        ]);
    let f = EventFields::from_event(Category::Blocked, &ev, 1);
    for text in [f.key_name.clone().unwrap(), f.key_id.clone().unwrap()]
        .into_iter()
        .chain(f.credentials.clone())
    {
        assert!(
            !text.contains(['{', '}', '\n', '/', '"', '\u{202e}']),
            "{text:?}"
        );
    }
    assert_eq!(f.key_id.as_deref(), Some("idwithne"));
    // At most three names are spelled out.
    let n = Notification::render(Category::Blocked, &Kind::Blocked, f, 0, None);
    assert!(n.message.contains("ok_name, a?"), "{}", n.message);
    assert!(
        n.message.contains(" and 2 more to api.example.com"),
        "{}",
        n.message
    );
}

#[test]
fn the_target_is_the_host_only() {
    for (url, host) in [
        ("https://api.example.com/a/b?c=d#e", Some("api.example.com")),
        (
            "https://user:pw@API.Example.com:8443/x",
            Some("api.example.com"),
        ),
        ("http://[2001:db8::1]:9/x", Some("[2001:db8::1]")),
        ("http://192.0.2.5/x?y", Some("192.0.2.5")),
        ("not a url at all", None),
    ] {
        let ev = blocked(Reason::TargetBlocked).url(url);
        let f = EventFields::from_event(Category::Blocked, &ev, 1);
        assert_eq!(f.target_host.as_deref(), host, "{url}");
    }
    // A host with anything but host characters is not shown.
    let mut ev = blocked(Reason::TargetBlocked).url("https://api.example.com/");
    ev.url.as_mut().unwrap().domain = Some("evil.example.com/path?x=1".to_string());
    assert_eq!(
        EventFields::from_event(Category::Blocked, &ev, 1).target_host,
        None
    );
}

/// One hostile event per kind of notification: the URL carries userinfo, port,
/// path, query, fragment and a placeholder, `details` carries header text, a
/// body, an error message and a secret-looking value.
fn hostile(e: SecurityEvent) -> SecurityEvent {
    e.url(&format!(
        "https://user:{SEEDED_SECRET}@api.example.com:8443/k7f3q9/v1/secret/path?token={SEEDED_SECRET}&k={{{{vault:grafana_token}}}}#frag"
    ))
    .detail("headers", format!("Authorization: Bearer {SEEDED_SECRET}"))
    .detail("body", format!("{{\"password\":\"{SEEDED_SECRET}\"}}"))
    .detail("error", format!("Vaultwarden said: bad password {SEEDED_SECRET}"))
    .detail("cause", format!("password={SEEDED_SECRET}"))
    .detail("endpoint", "/k7f3q9/v1/forward")
    .credentials(["grafana_service_account", "evil {{vault:inner}}/../x?y=z"])
}

/// An approval prompt as the gate records it: the path has no query, the
/// credentials are names.
fn approval_requested() -> SecurityEvent {
    SecurityEvent::new(Action::ApprovalRequested)
        .request(&ctx_from("172.20.0.5"))
        .key(&monitoring_agent())
        .method("get")
        .credentials(["grafana_service_account"])
        .detail("approval_id", "Zm9vYmFyMTIzNDU2Nzg5MA")
        .detail("host", "api.example.com:8443")
        .detail("path", "/api2/json/nodes")
        .detail("expires_at", "2026-11-26T12:10:00Z")
        .detail(
            "link",
            "https://fw.example.com/approvals/Zm9vYmFyMTIzNDU2Nzg5MA",
        )
}

fn hostile_events() -> Vec<SecurityEvent> {
    let key = monitoring_agent();
    let ctx = ctx_from("172.20.0.5");
    let mut events = vec![
        hostile(blocked(Reason::CredentialHostNotAllowed)),
        hostile(blocked(Reason::TargetBlocked)),
        hostile(blocked(Reason::CredentialOutOfScope)),
        hostile(blocked(Reason::MethodNotAllowed)),
        hostile(blocked(Reason::RepromptRequired)),
        hostile(auth_failure(Action::AgentAuth, "203.0.113.9")),
        hostile(auth_failure(Action::AdminAuth, "203.0.113.9")),
        hostile(ui_login(
            Outcome::Failure,
            Some(Reason::InvalidCredentials),
            "203.0.113.9",
        )),
        hostile(ui_login(
            Outcome::Failure,
            Some(Reason::LoginLockedOut),
            "203.0.113.9",
        )),
        hostile(vault(Action::VaultLock, Outcome::Success)),
        hostile(vault(Action::VaultUnlock, Outcome::Failure).reason(Reason::UnlockFailed)),
        hostile(vault(Action::VaultSync, Outcome::Failure).reason(Reason::SyncFailed)),
        hostile(vault(Action::VaultUnlock, Outcome::Success)),
        hostile(
            SecurityEvent::new(Action::KeyCreate)
                .request(&ctx)
                .key(&key),
        ),
        hostile(
            SecurityEvent::new(Action::KeyRevoke)
                .request(&ctx)
                .key(&key),
        ),
        hostile(
            SecurityEvent::new(Action::KeyPolicyChange)
                .request(&ctx)
                .key(&key),
        ),
        hostile(ui_login(Outcome::Success, None, "203.0.113.9")),
        hostile(approval_requested()),
    ];
    events.push(hostile(
        SecurityEvent::new(Action::EventsDropped)
            .outcome(Outcome::Unknown)
            .detail("dropped", 4u64),
    ));
    events
}

/// Every notification the hostile events can produce, with every category on,
/// no rate limiting and a failure threshold of one.
fn hostile_notifications() -> Vec<Notification> {
    let (mut e, _) = engine_with(Settings {
        categories: CategorySet::of(&Category::ALL),
        min_interval: Duration::ZERO,
        max_per_hour: 1000,
        auth_threshold: 1,
        auth_window: Duration::from_secs(300),
    });
    let t0 = Instant::now();
    let mut out = Vec::new();
    for ev in hostile_events() {
        out.extend(e.process(t0, &ev));
    }
    out.extend(e.notifications_dropped(t0, 3));
    out.push(Notification::test());
    // The paused notice.
    let (mut capped, _) = engine_with(Settings {
        categories: CategorySet::of(&Category::ALL),
        min_interval: Duration::ZERO,
        max_per_hour: 1,
        auth_threshold: 1,
        auth_window: Duration::from_secs(300),
    });
    capped.process(t0, &hostile(blocked(Reason::TargetBlocked)));
    out.extend(capped.process(t0, &hostile(blocked(Reason::TargetBlocked))));
    out
}

fn all_senders() -> Vec<Arc<senders::Sender>> {
    let cfg = NotifyConfig {
        gotify_url: "https://gotify.example.com/base".into(),
        ntfy_url: "https://ntfy.example.com/ferrowarden".into(),
        webhook_url: "https://hooks.example.com/ferrowarden".into(),
        tokens: NotifyTokens {
            gotify: Some(Zeroizing::new(GOTIFY_TOKEN.into())),
            ntfy: Some(Zeroizing::new(NTFY_TOKEN.into())),
            webhook: Some(Zeroizing::new(WEBHOOK_TOKEN.into())),
        },
        ..NotifyConfig::default()
    };
    senders::build(&cfg, &SendOptions::default()).unwrap()
}

/// Everything a sender puts on the wire except the credential header.
fn wire_text(sender: &senders::Sender, n: &Notification) -> String {
    let req = sender.build_request(n).build().unwrap();
    let mut text = req.url().to_string();
    for (name, value) in req.headers() {
        if name == "authorization" || name == "x-gotify-key" {
            continue;
        }
        text.push_str(&format!("\n{name}: {}", value.to_str().unwrap()));
    }
    if let Some(body) = req.body().and_then(|b| b.as_bytes()) {
        text.push('\n');
        text.push_str(&String::from_utf8_lossy(body));
    }
    text
}

#[test]
fn payloads_contain_only_allow_listed_content_for_every_category_and_sender() {
    let notifications = hostile_notifications();
    let categories: BTreeSet<&str> = notifications.iter().map(|n| n.category.as_str()).collect();
    assert_eq!(
        categories,
        Category::ALL
            .iter()
            .map(|c| c.as_str())
            .collect::<BTreeSet<_>>(),
        "the table must exercise every category"
    );
    let titles: BTreeSet<&str> = notifications.iter().map(|n| n.title.as_str()).collect();
    assert!(titles.len() >= 14, "every kind of notification: {titles:?}");

    let forbidden = [
        SEEDED_SECRET,
        "{{",
        "k7f3q9",
        "secret/path",
        "/v1/",
        "token=",
        "#frag",
        "user:",
        "@api",
        "Authorization",
        "Bearer",
        "Vaultwarden said",
        "bad password",
        "password=",
        "\\\"password\\\"",
        "grafana_token",
        "/etc",
        "../",
        GOTIFY_TOKEN,
        NTFY_TOKEN,
        WEBHOOK_TOKEN,
    ];
    let senders = all_senders();
    assert_eq!(senders.len(), 3);
    for n in &notifications {
        for sender in &senders {
            let text = wire_text(sender, n);
            for bad in forbidden {
                assert!(
                    !text.contains(bad),
                    "{} payload of {:?} contains {bad:?}:\n{text}",
                    sender.name(),
                    n.title
                );
            }
        }
        // The same for the title and the message themselves.
        for bad in forbidden {
            assert!(
                !n.title.contains(bad) && !n.message.contains(bad),
                "{bad:?} in {:?}",
                n.title
            );
        }
    }
}

#[test]
fn the_webhook_event_carries_exactly_the_allow_listed_keys() {
    const ALLOWED: [&str; 13] = [
        "category",
        "action",
        "outcome",
        "reason",
        "key_name",
        "key_id",
        "credentials",
        "target_host",
        "source_ip",
        "request_id",
        "timestamp",
        "count",
        "approval",
    ];
    const TOP: [&str; 8] = [
        "source",
        "schema_version",
        "category",
        "severity",
        "title",
        "message",
        "event",
        "suppressed",
    ];
    let mut seen = BTreeSet::new();
    for n in hostile_notifications() {
        let body = n.webhook_body();
        let top: BTreeSet<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(top, TOP.into_iter().collect(), "{}", n.title);
        assert_eq!(body["source"], "ferrowarden");
        assert_eq!(body["schema_version"], 1);
        assert_eq!(body["category"], n.category.as_str());
        assert!(body["severity"] == "high" || body["severity"] == "normal");
        for key in body["event"].as_object().unwrap().keys() {
            assert!(ALLOWED.contains(&key.as_str()), "{key} is not allow-listed");
            seen.insert(key.clone());
        }
        assert!(body["event"]["timestamp"].as_str().unwrap().ends_with('Z'));
    }
    // ... and the fields are really used.
    for key in ALLOWED {
        assert!(seen.contains(key), "{key} never appears");
    }
}

#[test]
fn severity_and_priorities_follow_the_mapping() {
    let by_title: HashMap<String, Severity> = hostile_notifications()
        .into_iter()
        .map(|n| (n.title, n.severity))
        .collect();
    for (title, sev) in [
        ("Ferrowarden: request blocked", Severity::High),
        (
            "Ferrowarden: repeated authentication failures",
            Severity::High,
        ),
        ("Ferrowarden: sign-in locked out", Severity::High),
        ("Ferrowarden: vault locked", Severity::High),
        ("Ferrowarden: vault unlock failed", Severity::High),
        ("Ferrowarden: vault sync failed", Severity::High),
        ("Ferrowarden: vault unlocked", Severity::Normal),
        ("Ferrowarden: agent key created", Severity::Normal),
        ("Ferrowarden: agent key revoked", Severity::Normal),
        ("Ferrowarden: agent key policy changed", Severity::Normal),
        ("Ferrowarden: admin UI sign-in", Severity::Normal),
        ("Ferrowarden: approval needed", Severity::High),
        ("Ferrowarden: security events dropped", Severity::High),
        ("Ferrowarden: notifications dropped", Severity::High),
        ("Ferrowarden: notifications paused", Severity::High),
        ("Ferrowarden: test notification", Severity::Normal),
    ] {
        assert_eq!(by_title.get(title), Some(&sev), "{title}");
    }
    assert_eq!(Severity::High.gotify_priority(), 8);
    assert_eq!(Severity::Normal.gotify_priority(), 4);
    assert_eq!(Severity::High.ntfy_priority(), "high");
    assert_eq!(Severity::Normal.ntfy_priority(), "default");
}

#[test]
fn titles_are_plain_ascii_so_they_can_be_header_values() {
    for n in hostile_notifications() {
        assert!(n.title.is_ascii(), "{}", n.title);
        assert!(n.title.starts_with("Ferrowarden: "));
    }
}

// ── Queues: the notifier never blocks emit ────────────────────────────────────

fn blocked_with_key(i: usize) -> SecurityEvent {
    blocked(Reason::TargetBlocked).key(&agent("k", &format!("{i:08}-0000-0000-0000-000000000000")))
}

#[test]
fn a_stalled_notifier_queue_never_blocks_emit_and_drops_are_counted() {
    let log = EventLog::buffer_only(10);
    let (tx, _rx_never_read) = mpsc::channel(2);
    let stats = Arc::new(Stats::default());
    let pending = Arc::new(AtomicU64::new(0));
    log.attach_notifier(Feed {
        tx,
        categories: CategorySet::of(&Category::DEFAULT),
        pending_dropped: pending.clone(),
        stats: stats.clone(),
    });
    let started = Instant::now();
    for i in 0..10_000 {
        log.emit(blocked_with_key(i));
    }
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(pending.load(Ordering::Relaxed), 9_998);
    assert_eq!(stats.dropped.load(Ordering::Relaxed), 9_998);
    // The ring buffer still got every event.
    assert_eq!(log.recent(100).len(), 10);
    // Events of no interest are not even counted.
    log.emit(SecurityEvent::new(Action::StatusRead));
    assert_eq!(pending.load(Ordering::Relaxed), 9_998);
}

#[tokio::test]
async fn overflow_is_reported_in_a_notification_and_other_sinks_are_unaffected() {
    let recv = receiver(vec![], Duration::ZERO).await;
    let cfg = NotifyConfig {
        webhook_url: format!("{}/hook", recv.url),
        allow_http: true,
        min_interval_secs: 60,
        tokens: NotifyTokens::default(),
        ..NotifyConfig::default()
    };
    let lines = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::new(EventLog::with_sinks(
        100,
        100_000,
        vec![crate::events::sinks::Sink::new(
            "memory",
            crate::events::sinks::SinkKind::Memory(lines.clone()),
        )],
    ));
    let handle = start_with(&cfg, &log, fast()).unwrap();

    // The current-thread runtime cannot run the notifier task until we await:
    // the queue (1000) overflows deterministically.
    let key = monitoring_agent();
    for _ in 0..1500 {
        log.emit(blocked(Reason::TargetBlocked).key(&key));
    }
    assert_eq!(handle.snapshot().dropped, 500);
    log.flush().await;
    assert_eq!(
        lines.lock().unwrap().len(),
        1500,
        "the other sink got everything"
    );

    // One blocked notification (the first for the key) and one "dropped" notice.
    let bodies = recv.wait_for(2).await;
    let messages: Vec<String> = bodies
        .iter()
        .map(|g| {
            serde_json::from_str::<Value>(&g.body).unwrap()["message"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("Blocked: target not allowed")),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.starts_with("500 notifications were dropped")),
        "{messages:?}"
    );
}

#[tokio::test]
async fn a_stalled_sender_delays_nothing_but_itself() {
    // The receiver never answers within the test; the sender's worker waits,
    // the queue behind it fills, and emit keeps returning at once.
    let recv = receiver(vec![], Duration::from_secs(30)).await;
    let cfg = NotifyConfig {
        webhook_url: format!("{}/hook", recv.url),
        allow_http: true,
        min_interval_secs: 0,
        max_per_hour: 1_000_000,
        ..NotifyConfig::default()
    };
    let log = Arc::new(EventLog::buffer_only(10));
    let handle = start_with(
        &cfg,
        &log,
        SendOptions {
            timeout: Duration::from_secs(60),
            retry_delays: vec![],
        },
    )
    .unwrap();
    let started = Instant::now();
    for i in 0..400 {
        log.emit(blocked_with_key(i));
        if i % 50 == 0 {
            tokio::task::yield_now().await;
        }
    }
    assert!(started.elapsed() < Duration::from_secs(5));
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The sender's own queue (100) filled; the overflow was counted.
    assert!(handle.snapshot().dropped > 0);
}

#[tokio::test]
async fn the_notifier_task_reports_events_that_did_not_fit() {
    let (tx, rx) = mpsc::channel(2);
    let stats = Arc::new(Stats::default());
    let pending = Arc::new(AtomicU64::new(0));
    let feed = Feed {
        tx,
        categories: CategorySet::of(&Category::DEFAULT),
        pending_dropped: pending.clone(),
        stats: stats.clone(),
    };
    for i in 0..5 {
        feed.offer(&Arc::new(blocked_with_key(i)));
    }
    let (wtx, mut wrx) = mpsc::channel(100);
    let (engine, _) = engine();
    tokio::spawn(run(rx, engine, pending, vec![wtx], stats));
    let mut messages = Vec::new();
    while messages.len() < 3 {
        let n = tokio::time::timeout(Duration::from_secs(2), wrx.recv())
            .await
            .unwrap()
            .unwrap();
        messages.push(n.message.clone());
    }
    assert!(
        messages
            .iter()
            .any(|m| m.starts_with("3 notifications were dropped")),
        "{messages:?}"
    );
}

// ── Senders against an in-process receiver ────────────────────────────────────

#[derive(Clone, Debug)]
pub(crate) struct Got {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: String,
}

pub(crate) struct Receiver {
    pub(crate) url: String,
    got: Arc<Mutex<Vec<Got>>>,
}

impl Receiver {
    pub(crate) fn requests(&self) -> Vec<Got> {
        self.got.lock().unwrap().clone()
    }

    pub(crate) async fn wait_for(&self, n: usize) -> Vec<Got> {
        for _ in 0..200 {
            if self.requests().len() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let got = self.requests();
        assert!(got.len() >= n, "expected {n} requests, got {got:?}");
        got
    }
}

#[derive(Clone)]
struct ReceiverState {
    got: Arc<Mutex<Vec<Got>>>,
    script: Arc<Mutex<VecDeque<u16>>>,
    delay: Duration,
}

async fn receive(
    State(st): State<ReceiverState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: String,
) -> Response {
    st.got.lock().unwrap().push(Got {
        method: method.to_string(),
        path: uri.path().to_string(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect(),
        body,
    });
    if !st.delay.is_zero() {
        tokio::time::sleep(st.delay).await;
    }
    if uri.path() == "/redirect" {
        return (StatusCode::FOUND, [("location", "/landed")], "").into_response();
    }
    let status = st.script.lock().unwrap().pop_front().unwrap_or(200);
    (StatusCode::from_u16(status).unwrap(), "{}").into_response()
}

/// A receiver on a loopback port that answers with `statuses` in turn, then 200.
pub(crate) async fn receiver(statuses: Vec<u16>, delay: Duration) -> Receiver {
    let got = Arc::new(Mutex::new(Vec::new()));
    let state = ReceiverState {
        got: got.clone(),
        script: Arc::new(Mutex::new(statuses.into())),
        delay,
    };
    let app = Router::new().fallback(receive).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Receiver {
        url: format!("http://{addr}"),
        got,
    }
}

fn fast() -> SendOptions {
    SendOptions {
        timeout: Duration::from_secs(2),
        retry_delays: vec![Duration::from_millis(10), Duration::from_millis(10)],
    }
}

fn config_for(base: &str) -> NotifyConfig {
    NotifyConfig {
        gotify_url: format!("{base}/gotify/"),
        ntfy_url: format!("{base}/topic"),
        webhook_url: format!("{base}/hook"),
        allow_http: true,
        tokens: NotifyTokens {
            gotify: Some(Zeroizing::new(GOTIFY_TOKEN.into())),
            ntfy: Some(Zeroizing::new(NTFY_TOKEN.into())),
            webhook: Some(Zeroizing::new(WEBHOOK_TOKEN.into())),
        },
        ..NotifyConfig::default()
    }
}

fn sample() -> Notification {
    let (mut e, _) = engine();
    e.process(Instant::now(), &blocked(Reason::CredentialHostNotAllowed))
        .remove(0)
}

#[tokio::test]
async fn gotify_posts_json_with_the_key_header() {
    let r = receiver(vec![], Duration::ZERO).await;
    let senders = senders::build(&config_for(&r.url), &fast()).unwrap();
    let gotify = senders.iter().find(|s| s.name() == "gotify").unwrap();
    let n = sample();
    assert_eq!(gotify.deliver(&n, true).await, Ok(200));
    let got = &r.requests()[0];
    assert_eq!(got.method, "POST");
    assert_eq!(got.path, "/gotify/message");
    assert_eq!(got.headers["x-gotify-key"], GOTIFY_TOKEN);
    assert!(got.headers["content-type"].starts_with("application/json"));
    assert!(!got.headers.contains_key("authorization"));
    let body: Value = serde_json::from_str(&got.body).unwrap();
    assert_eq!(body["title"], n.title);
    assert_eq!(body["message"], n.message);
    assert_eq!(body["priority"], 8);
    assert_eq!(body.as_object().unwrap().len(), 3);
}

#[tokio::test]
async fn gotify_uses_priority_four_for_normal_notifications() {
    let r = receiver(vec![], Duration::ZERO).await;
    let senders = senders::build(&config_for(&r.url), &fast()).unwrap();
    let gotify = senders.iter().find(|s| s.name() == "gotify").unwrap();
    gotify.deliver(&Notification::test(), true).await.unwrap();
    let body: Value = serde_json::from_str(&r.requests()[0].body).unwrap();
    assert_eq!(body["priority"], 4);
}

#[tokio::test]
async fn ntfy_posts_the_message_as_the_body_with_headers() {
    let r = receiver(vec![], Duration::ZERO).await;
    let senders = senders::build(&config_for(&r.url), &fast()).unwrap();
    let ntfy = senders.iter().find(|s| s.name() == "ntfy").unwrap();
    let n = sample();
    assert_eq!(ntfy.deliver(&n, true).await, Ok(200));
    let got = &r.requests()[0];
    assert_eq!(got.method, "POST");
    assert_eq!(got.path, "/topic");
    assert_eq!(got.body, n.message);
    assert_eq!(got.headers["title"], n.title);
    assert_eq!(got.headers["priority"], "high");
    assert_eq!(got.headers["tags"], "warning");
    assert_eq!(got.headers["authorization"], format!("Bearer {NTFY_TOKEN}"));
    assert!(got.headers["content-type"].starts_with("text/plain"));
}

#[tokio::test]
async fn ntfy_without_a_token_sends_no_authorization() {
    let r = receiver(vec![], Duration::ZERO).await;
    let mut cfg = config_for(&r.url);
    cfg.tokens.ntfy = None;
    let senders = senders::build(&cfg, &fast()).unwrap();
    let ntfy = senders.iter().find(|s| s.name() == "ntfy").unwrap();
    ntfy.deliver(&Notification::test(), true).await.unwrap();
    let got = &r.requests()[0];
    assert!(!got.headers.contains_key("authorization"));
    assert_eq!(got.headers["priority"], "default");
}

#[tokio::test]
async fn the_webhook_posts_the_documented_json_with_a_bearer_token() {
    let r = receiver(vec![], Duration::ZERO).await;
    let senders = senders::build(&config_for(&r.url), &fast()).unwrap();
    let hook = senders.iter().find(|s| s.name() == "webhook").unwrap();
    let n = sample();
    assert_eq!(hook.deliver(&n, true).await, Ok(200));
    let got = &r.requests()[0];
    assert_eq!(got.path, "/hook");
    assert_eq!(
        got.headers["authorization"],
        format!("Bearer {WEBHOOK_TOKEN}")
    );
    let body: Value = serde_json::from_str(&got.body).unwrap();
    assert_eq!(body["source"], "ferrowarden");
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["category"], "blocked");
    assert_eq!(body["severity"], "high");
    assert_eq!(body["title"], n.title);
    assert_eq!(body["message"], n.message);
    assert_eq!(body["suppressed"], 0);
    assert_eq!(body["event"]["action"], "forward");
    assert_eq!(body["event"]["outcome"], "failure");
    assert_eq!(body["event"]["reason"], "credential_host_not_allowed");
    assert_eq!(body["event"]["key_name"], "monitoring-agent");
    assert_eq!(body["event"]["target_host"], "api.example.com");
    assert_eq!(
        body["event"]["credentials"],
        serde_json::json!(["grafana_service_account"])
    );
    assert_eq!(body["event"]["source_ip"], "172.20.0.5");
}

#[tokio::test]
async fn server_errors_are_retried_twice_then_given_up() {
    let r = receiver(vec![500, 503, 502], Duration::ZERO).await;
    let senders = senders::build(&config_for(&r.url), &fast()).unwrap();
    let hook = senders.iter().find(|s| s.name() == "webhook").unwrap();
    assert_eq!(
        hook.deliver(&Notification::test(), true).await,
        Err(SendError::Status(502))
    );
    assert_eq!(r.requests().len(), 3, "one try and two retries");

    // A success on the second try ends it.
    let r = receiver(vec![500], Duration::ZERO).await;
    let senders = senders::build(&config_for(&r.url), &fast()).unwrap();
    let hook = senders.iter().find(|s| s.name() == "webhook").unwrap();
    assert_eq!(hook.deliver(&Notification::test(), true).await, Ok(200));
    assert_eq!(r.requests().len(), 2);
}

#[tokio::test]
async fn client_errors_are_not_retried() {
    for status in [400u16, 401, 403, 404, 429] {
        let r = receiver(vec![status, status, status], Duration::ZERO).await;
        let senders = senders::build(&config_for(&r.url), &fast()).unwrap();
        let hook = senders.iter().find(|s| s.name() == "webhook").unwrap();
        assert_eq!(
            hook.deliver(&Notification::test(), true).await,
            Err(SendError::Status(status))
        );
        assert_eq!(r.requests().len(), 1, "{status}");
    }
}

#[tokio::test]
async fn a_test_notification_is_sent_once_without_retries() {
    let r = receiver(vec![500, 500, 500], Duration::ZERO).await;
    let senders = senders::build(&config_for(&r.url), &fast()).unwrap();
    let hook = senders.iter().find(|s| s.name() == "webhook").unwrap();
    assert_eq!(
        hook.deliver(&Notification::test(), false).await,
        Err(SendError::Status(500))
    );
    assert_eq!(r.requests().len(), 1);
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let r = receiver(vec![], Duration::ZERO).await;
    let mut cfg = config_for(&r.url);
    cfg.webhook_url = format!("{}/redirect", r.url);
    let senders = senders::build(&cfg, &fast()).unwrap();
    let hook = senders.iter().find(|s| s.name() == "webhook").unwrap();
    assert_eq!(
        hook.deliver(&Notification::test(), true).await,
        Err(SendError::Status(302))
    );
    let got = r.requests();
    assert_eq!(got.len(), 1, "no retry on a 3xx either");
    assert!(got.iter().all(|g| g.path != "/landed"));
}

#[tokio::test]
async fn a_slow_notifier_times_out() {
    let r = receiver(vec![], Duration::from_secs(5)).await;
    let mut cfg = config_for(&r.url);
    cfg.gotify_url.clear();
    cfg.ntfy_url.clear();
    let opts = SendOptions {
        timeout: Duration::from_millis(200),
        retry_delays: vec![],
    };
    let senders = senders::build(&cfg, &opts).unwrap();
    let started = Instant::now();
    assert_eq!(
        senders[0].deliver(&Notification::test(), true).await,
        Err(SendError::Timeout)
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn an_unreachable_notifier_is_a_connect_error_without_url_or_token() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let cfg = NotifyConfig {
        webhook_url: format!("http://127.0.0.1:{port}/secret-path"),
        allow_http: true,
        tokens: NotifyTokens {
            webhook: Some(Zeroizing::new(WEBHOOK_TOKEN.into())),
            ..Default::default()
        },
        ..NotifyConfig::default()
    };
    // Windows takes a couple of seconds to give up on a closed loopback port.
    let patient = SendOptions {
        timeout: Duration::from_secs(10),
        ..fast()
    };
    let senders = senders::build(&cfg, &patient).unwrap();
    let err = senders[0]
        .deliver(&Notification::test(), true)
        .await
        .unwrap_err();
    assert_eq!(err, SendError::Connect);
    let text = err.to_string();
    assert!(
        !text.contains("secret-path")
            && !text.contains("127.0.0.1")
            && !text.contains(WEBHOOK_TOKEN),
        "{text}"
    );
}

#[tokio::test]
async fn the_token_header_is_marked_sensitive_and_the_sender_never_prints_it() {
    let senders = all_senders();
    for s in &senders {
        let req = s.build_request(&Notification::test()).build().unwrap();
        let header = req
            .headers()
            .get("authorization")
            .or_else(|| req.headers().get("x-gotify-key"))
            .unwrap();
        assert!(header.is_sensitive(), "{}", s.name());
        assert!(!format!("{req:?}").contains(GOTIFY_TOKEN));
        assert!(!format!("{req:?}").contains(NTFY_TOKEN));
        assert!(!format!("{req:?}").contains(WEBHOOK_TOKEN));
    }
}

// ── End to end: events in, notifications out ──────────────────────────────────

#[tokio::test]
async fn an_emitted_event_reaches_every_sender_and_is_counted() {
    let r = receiver(vec![], Duration::ZERO).await;
    let log = Arc::new(EventLog::buffer_only(10));
    let handle = start_with(&config_for(&r.url), &log, fast()).unwrap();
    assert!(handle.enabled());
    log.emit(blocked(Reason::CredentialHostNotAllowed));
    let got = r.wait_for(3).await;
    let paths: BTreeSet<&str> = got.iter().map(|g| g.path.as_str()).collect();
    assert_eq!(
        paths,
        ["/gotify/message", "/hook", "/topic"].into_iter().collect()
    );
    // Counters are updated after the response, so wait a moment.
    for _ in 0..100 {
        if handle.snapshot().sent() == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let snap = handle.snapshot();
    assert_eq!(snap.sent(), 3);
    assert_eq!(snap.failed(), 0);
    assert_eq!(
        snap.categories,
        ["blocked", "auth_failure", "vault", "system", "approval"]
    );
    assert_eq!(
        snap.senders
            .iter()
            .map(|s| (s.kind, s.host.as_str()))
            .collect::<Vec<_>>(),
        [
            ("gotify", "127.0.0.1"),
            ("ntfy", "127.0.0.1"),
            ("webhook", "127.0.0.1")
        ]
    );
}

#[tokio::test]
async fn failed_deliveries_are_counted_not_retried_forever() {
    let r = receiver(vec![500; 20], Duration::ZERO).await;
    let mut cfg = config_for(&r.url);
    cfg.gotify_url.clear();
    cfg.ntfy_url.clear();
    let log = Arc::new(EventLog::buffer_only(10));
    let handle = start_with(&cfg, &log, fast()).unwrap();
    log.emit(blocked(Reason::TargetBlocked));
    for _ in 0..200 {
        if handle.snapshot().failed() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(handle.snapshot().failed(), 1);
    assert_eq!(r.requests().len(), 3);
}

#[tokio::test]
async fn nothing_starts_without_a_configured_sender() {
    let log = Arc::new(EventLog::buffer_only(10));
    let handle = start(&NotifyConfig::default(), &log).unwrap();
    assert!(!handle.enabled());
    log.emit(blocked(Reason::TargetBlocked));
    assert!(handle.snapshot().senders.is_empty());
    assert_eq!(handle.send_test().await, Ok(vec![]));
}

#[tokio::test]
async fn the_test_notification_reports_each_sender_and_is_limited_to_one_per_ten_seconds() {
    let r = receiver(vec![], Duration::ZERO).await;
    let log = Arc::new(EventLog::buffer_only(10));
    // The webhook refuses: 403.
    let mut cfg = config_for(&r.url);
    cfg.webhook_url = format!("{}/hook", r.url);
    let handle = start_with(&cfg, &log, fast()).unwrap();
    // Make the webhook fail by pointing a fourth path... use a script: the
    // receiver answers in order, so use a fresh one for the failing case below.
    let results = handle.send_test().await.unwrap();
    assert_eq!(results.len(), 3);
    assert!(
        results
            .iter()
            .all(|r| r.ok && r.status == Some(200) && r.error.is_none()),
        "{results:?}"
    );
    assert_eq!(
        results.iter().map(|r| r.sender).collect::<Vec<_>>(),
        ["gotify", "ntfy", "webhook"]
    );
    let wait = handle.send_test().await.unwrap_err();
    assert!((1..=10).contains(&wait), "{wait}");
    // The test did not count as a notification.
    assert_eq!(handle.snapshot().sent(), 0);
    assert_eq!(r.requests().len(), 3);
    for got in r.requests() {
        assert!(
            got.body.contains("test notification")
                || got.headers.get("title").is_some_and(|t| t.contains("test")),
            "{got:?}"
        );
    }
}

#[tokio::test]
async fn a_failing_sender_in_a_test_is_reported_without_url_or_token() {
    let r = receiver(vec![403], Duration::ZERO).await;
    let mut cfg = config_for(&r.url);
    cfg.gotify_url.clear();
    cfg.ntfy_url.clear();
    cfg.webhook_url = format!("{}/secret-path/with-token-in-it", r.url);
    let log = Arc::new(EventLog::buffer_only(10));
    let handle = start_with(&cfg, &log, fast()).unwrap();
    let results = handle.send_test().await.unwrap();
    assert_eq!(results.len(), 1);
    assert!(!results[0].ok);
    assert_eq!(results[0].status, Some(403));
    let json = serde_json::to_string(&results).unwrap();
    assert!(json.contains("the notifier answered HTTP 403"), "{json}");
    for bad in ["secret-path", "with-token", "127.0.0.1", WEBHOOK_TOKEN] {
        assert!(!json.contains(bad), "{bad} in {json}");
    }
    assert_eq!(r.requests().len(), 1, "no retry for a test");
}

#[test]
fn the_default_handle_is_disabled() {
    let h = NotifyHandle::default();
    assert!(!h.enabled());
    let s = h.snapshot();
    assert!(!s.enabled());
    assert_eq!(
        (s.sent(), s.failed(), s.suppressed, s.dropped),
        (0, 0, 0, 0)
    );
}

// ── Approval prompts ──────────────────────────────────────────────────────────

fn pending_view(url: &str) -> crate::approvals::PendingView {
    use crate::approvals::{ApprovalNeed, PendingView, Reasons};
    let now = chrono::DateTime::parse_from_rfc3339("2026-11-26T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    PendingView {
        id: "Zm9vYmFyMTIzNDU2Nzg5MA".into(),
        kind: crate::approvals::ApprovalKind::Forward,
        create: None,
        key_id: "11111111-1111-1111-1111-111111111111".into(),
        key_name: "monitoring-agent".into(),
        items: vec![
            ApprovalNeed {
                item: "proxmox_root".into(),
                reasons: Reasons {
                    vault_field: true,
                    key_policy: false,
                },
            },
            ApprovalNeed {
                item: "nas_admin".into(),
                reasons: Reasons {
                    vault_field: false,
                    key_policy: true,
                },
            },
        ],
        method: "DELETE".into(),
        scheme: "https".into(),
        host: "pve.example.com:8006".into(),
        port: 8006,
        url: url.into(),
        request_id: "0193abcd-0000-7000-8000-000000000001".into(),
        created: now,
        expires: now + chrono::Duration::minutes(10),
    }
}

fn prompt(url: &str, link: Option<&str>) -> Notification {
    let ev = crate::approvals::requested_event(
        &ctx_from("172.20.0.5"),
        &pending_view(url),
        link.map(str::to_string),
    );
    let (mut e, _) = engine();
    let mut out = e.process(Instant::now(), &ev);
    assert_eq!(out.len(), 1, "one prompt per new approval");
    out.remove(0)
}

fn approval_path(n: &Notification) -> String {
    n.webhook_body()["event"]["approval"]["path"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn an_approval_prompt_says_who_what_where_and_how_to_decide() {
    let link = "https://fw.example.com/approvals/Zm9vYmFyMTIzNDU2Nzg5MA";
    let n = prompt(
        "https://pve.example.com:8006/api2/json/nodes?ticket=SEEDED#frag",
        Some(link),
    );
    assert_eq!(n.category, Category::Approval);
    assert_eq!(n.title, "Ferrowarden: approval needed");
    assert_eq!(n.severity, Severity::High);
    let m = &n.message;
    assert!(m.contains("Key \"monitoring-agent\" (id 11111111)"), "{m}");
    assert!(m.contains("proxmox_root and nas_admin"), "{m}");
    assert!(
        m.contains("DELETE pve.example.com:8006/api2/json/nodes"),
        "{m}"
    );
    assert!(m.contains(&format!("Approve or deny: {link}")), "{m}");
    assert!(m.contains("Approval Zm9vYmFyMTIzNDU2Nzg5MA"), "{m}");
    assert!(m.contains("open until 12:10 UTC"), "{m}");
    // The query string and the fragment are not in it, anywhere.
    let wire = serde_json::to_string(&n.webhook_body()).unwrap();
    for bad in ["ticket", "SEEDED", "frag", "?"] {
        assert!(
            !m.contains(bad) && !wire.contains(bad),
            "{bad:?} in {m}\n{wire}"
        );
    }
    // The webhook event carries the approval fields.
    let a = &n.webhook_body()["event"]["approval"];
    assert_eq!(a["id"], "Zm9vYmFyMTIzNDU2Nzg5MA");
    assert_eq!(a["method"], "DELETE");
    assert_eq!(a["target"], "pve.example.com:8006");
    assert_eq!(a["path"], "/api2/json/nodes");
    assert_eq!(a["expires_at"], "2026-11-26T12:10:00Z");
    assert_eq!(a["link"], link);
    assert_eq!(
        n.webhook_body()["event"]["credentials"],
        serde_json::json!(["proxmox_root", "nas_admin"])
    );
}

#[test]
fn without_a_public_url_the_prompt_points_at_the_approvals_page() {
    let n = prompt("https://pve.example.com:8006/x", None);
    assert!(
        n.message
            .contains("Open the Approvals page of the Ferrowarden admin UI"),
        "{}",
        n.message
    );
    assert!(!n.message.contains("http"), "{}", n.message);
    assert!(n.webhook_body()["event"]["approval"].get("link").is_none());
}

#[test]
fn the_path_is_cut_to_200_characters_and_made_printable() {
    let n = prompt(
        &format!("https://pve.example.com:8006/{}", "a".repeat(500)),
        None,
    );
    assert_eq!(approval_path(&n).chars().count(), 200);
    // Control characters, non-ASCII text and an embedded query never get through.
    let n = prompt("https://pve.example.com:8006/a\nb/\u{202e}c/d e?x=y", None);
    // Each unprintable character is shown as `?`; the real query is gone.
    assert_eq!(approval_path(&n), "/a?b/?c/d?e");
    // Placeholders are shown as written: names, never values.
    let n = prompt(
        "https://pve.example.com:8006/api/{{vault:nas_admin:username}}/x?k={{vault:y}}",
        None,
    );
    assert_eq!(approval_path(&n), "/api/{{vault:nas_admin:username}}/x");
}

#[test]
fn a_forged_link_in_an_event_is_not_shown() {
    let with_link = |link: &str| {
        let ev = crate::approvals::requested_event(
            &ctx_from("172.20.0.5"),
            &pending_view("https://pve.example.com:8006/x"),
            Some(link.to_string()),
        );
        EventFields::from_event(Category::Approval, &ev, 1)
            .approval
            .unwrap()
            .link
    };
    assert_eq!(with_link("javascript:alert(1)"), None);
    assert_eq!(with_link("https://fw.example.com/approvals/x y\nz"), None);
    assert_eq!(
        with_link("https://fw.example.com/approvals/x").as_deref(),
        Some("https://fw.example.com/approvals/x")
    );
    // Only an approval request has the approval fields.
    let ev = blocked(Reason::TargetBlocked)
        .detail("approval_id", "x")
        .detail("path", "/p");
    assert!(EventFields::from_event(Category::Blocked, &ev, 1)
        .approval
        .is_none());
}

#[test]
fn every_new_approval_is_notified_once_and_is_not_held_back_by_the_limits() {
    let ev = |id: &str| {
        let mut v = pending_view("https://pve.example.com:8006/x");
        v.id = id.to_string();
        crate::approvals::requested_event(&ctx_from("172.20.0.5"), &v, None)
    };
    // Same key, an interval of 60 s: two approvals, two prompts.
    let (mut e, stats) = engine();
    let t0 = Instant::now();
    assert_eq!(e.process(t0, &ev("A1111111111111111111111")).len(), 1);
    assert_eq!(
        e.process(at(t0, 1), &ev("B2222222222222222222222")).len(),
        1
    );
    assert_eq!(
        stats.suppressed.load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    // Even when the hourly cap is used up by other notifications.
    let (mut capped, _) = engine_with(Settings {
        max_per_hour: 1,
        ..settings(&Category::DEFAULT)
    });
    assert_eq!(
        capped
            .process(t0, &hostile(blocked(Reason::TargetBlocked)))
            .len(),
        1
    );
    // The cap pauses the others (one notice)...
    let paused = capped.process(at(t0, 100), &hostile(blocked(Reason::MethodNotAllowed)));
    assert!(paused.iter().all(|n| n.category == Category::System));
    // ...but not an approval prompt.
    let out = capped.process(at(t0, 101), &ev("C3333333333333333333333"));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].category, Category::Approval);

    // With the category off, nothing is sent.
    let (mut off, _) = engine_with(settings(&[Category::Blocked]));
    assert!(off.process(t0, &ev("D4444444444444444444444")).is_empty());
}

#[test]
fn only_a_successful_approval_request_event_is_a_prompt() {
    let base = SecurityEvent::new(Action::ApprovalRequested);
    assert_eq!(classify(&base), Some(Class::ApprovalRequested));
    assert_eq!(Class::ApprovalRequested.category(), Category::Approval);
    // Decisions and expiries are events, not prompts.
    for action in [
        Action::ApprovalGranted,
        Action::ApprovalDenied,
        Action::ApprovalExpired,
        Action::GrantRevoked,
        Action::GrantExpired,
    ] {
        assert_eq!(classify(&SecurityEvent::new(action)), None, "{action:?}");
    }
    // The refusals of the gate are not "blocked" notifications either.
    for reason in [
        Reason::ApprovalPending,
        Reason::ApprovalDenied,
        Reason::ApprovalLimitReached,
    ] {
        assert_eq!(classify(&blocked(reason)), None, "{reason:?}");
    }
}

#[test]
fn the_approval_category_is_part_of_the_category_set() {
    assert_eq!(Category::parse("approval"), Some(Category::Approval));
    assert!(CategorySet::of(&Category::DEFAULT).contains(Category::Approval));
    assert!(!CategorySet::of(&[Category::Blocked]).contains(Category::Approval));
    let set = CategorySet::from_names(&["approval".into(), "vault".into()]).unwrap();
    assert_eq!(set.names(), ["vault", "approval"]);
}

#[test]
fn an_approval_id_keeps_its_url_safe_characters() {
    let mut v = pending_view("https://pve.example.com:8006/x");
    v.id = "Ab-_9zZ-_Q0123456789abcd".into();
    let ev = crate::approvals::requested_event(&ctx_from("172.20.0.5"), &v, None);
    let f = EventFields::from_event(Category::Approval, &ev, 1);
    assert_eq!(f.approval.unwrap().id, "Ab-_9zZ-_Q0123456789abcd");
}

// ── Create prompts and the creation notice ────────────────────────────────────

fn create_view() -> crate::approvals::PendingView {
    use crate::approvals::{ApprovalKind, ApprovalNeed, CreateDetail, PendingView, Reasons};
    let now = chrono::DateTime::parse_from_rfc3339("2026-11-26T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    PendingView {
        id: "Y3JlYXRlYXBwcm92YWwxMg".into(),
        kind: ApprovalKind::Create,
        key_id: "11111111-1111-1111-1111-111111111111".into(),
        key_name: "homelab-claude".into(),
        items: vec![ApprovalNeed {
            item: "agent_keycloak_admin".into(),
            reasons: Reasons::default(),
        }],
        create: Some(CreateDetail {
            name: "agent_keycloak_admin".into(),
            username: Some("admin".into()),
            uris: vec![
                "https://keycloak.example.com".into(),
                "https://sso.example.com:8443".into(),
            ],
            charset: "ascii".into(),
            length: 48,
            approval_required: true,
            collection: "Ferrowarden managed".into(),
        }),
        method: String::new(),
        scheme: String::new(),
        host: String::new(),
        port: 0,
        url: String::new(),
        request_id: "0193abcd-0000-7000-8000-000000000002".into(),
        created: now,
        expires: now + chrono::Duration::minutes(10),
    }
}

fn create_prompt(view: &crate::approvals::PendingView, link: Option<&str>) -> Notification {
    let ev =
        crate::approvals::requested_event(&ctx_from("172.20.0.5"), view, link.map(str::to_string));
    let (mut e, _) = engine();
    let mut out = e.process(Instant::now(), &ev);
    assert_eq!(out.len(), 1, "one prompt per new approval");
    out.remove(0)
}

#[test]
fn a_create_prompt_says_what_will_be_made_and_that_the_agent_never_sees_it() {
    let link = "https://fw.example.com/approvals/Y3JlYXRlYXBwcm92YWwxMg";
    let n = create_prompt(&create_view(), Some(link));
    assert_eq!(n.category, Category::Approval);
    assert_eq!(n.title, "Ferrowarden: approval needed");
    assert_eq!(n.severity, Severity::High);
    let m = &n.message;
    assert!(m.contains("Key \"homelab-claude\" (id 11111111)"), "{m}");
    assert!(
        m.contains("create the credential agent_keycloak_admin"),
        "{m}"
    );
    assert!(m.contains("with username admin"), "{m}");
    assert!(
        m.contains("https://keycloak.example.com and https://sso.example.com:8443"),
        "{m}"
    );
    assert!(m.contains("collection Ferrowarden managed"), "{m}");
    assert!(m.contains("48-character ascii password"), "{m}");
    assert!(m.contains("the agent never sees"), "{m}");
    assert!(m.contains("Using it will need approval too."), "{m}");
    assert!(m.contains(&format!("Approve or deny: {link}")), "{m}");
    assert!(m.contains("Approval Y3JlYXRlYXBwcm92YWwxMg"), "{m}");
    assert!(m.contains("open until 12:10 UTC"), "{m}");

    // The webhook event carries the kind and the create fields.
    let a = &n.webhook_body()["event"]["approval"];
    assert_eq!(a["kind"], "create");
    assert_eq!(a["id"], "Y3JlYXRlYXBwcm92YWwxMg");
    assert_eq!(a["create"]["name"], "agent_keycloak_admin");
    assert_eq!(a["create"]["username"], "admin");
    assert_eq!(a["create"]["length"], 48);
    assert_eq!(a["create"]["charset"], "ascii");
    assert_eq!(a["create"]["approval_required"], true);
    assert_eq!(a["create"]["collection"], "Ferrowarden managed");
    assert_eq!(a["create"]["uris"][1], "https://sso.example.com:8443");
    assert!(a.get("link").is_some());
}

#[test]
fn a_create_prompt_without_a_username_or_flag_leaves_them_out() {
    let mut v = create_view();
    let c = v.create.as_mut().unwrap();
    c.username = None;
    c.approval_required = false;
    let n = create_prompt(&v, None);
    assert!(!n.message.contains("with username"), "{}", n.message);
    assert!(!n.message.contains("need approval too"), "{}", n.message);
    assert!(
        n.message.contains("Open the Approvals page"),
        "{}",
        n.message
    );
    let a = &n.webhook_body()["event"]["approval"];
    assert!(a["create"].get("username").is_none());
}

#[test]
fn a_create_prompt_cleans_what_an_agent_chose() {
    let mut v = create_view();
    let c = v.create.as_mut().unwrap();
    c.name = "evil\n{{vault:x}}<b>".into();
    c.username = Some("a\u{202e}b\n".into());
    c.uris = vec!["https://h.example/\n\u{202e}x".into()];
    let n = create_prompt(&v, None);
    let wire = serde_json::to_string(&n.webhook_body()).unwrap();
    for bad in ["\n", "\u{202e}", "{{", "<b>"] {
        assert!(!n.message.contains(bad), "{bad:?} in {}", n.message);
        assert!(!wire.contains(bad), "{bad:?} in {wire}");
    }
}

#[test]
fn a_created_credential_is_an_admin_notice_with_no_value() {
    let ev = SecurityEvent::new(Action::CredentialCreate)
        .request(&ctx_from("172.20.0.5"))
        .key_named("11111111-1111-1111-1111-111111111111", "homelab-claude")
        .credentials(["agent_keycloak_admin"])
        .detail("collection_id", "6c0d7f0e-52d0-4b5b-8a39-0e8a7f6d5c4b");
    assert_eq!(classify(&ev), Some(Class::CredentialCreated));
    assert_eq!(Class::CredentialCreated.category(), Category::Admin);
    // Opt-in: `admin` is not among the default categories.
    assert!(!Category::DEFAULT.contains(&Category::Admin));

    let (mut e, _) = engine_with(settings(&[Category::Admin]));
    let out = e.process(Instant::now(), &ev);
    assert_eq!(out.len(), 1);
    let n = &out[0];
    assert_eq!(n.title, "Ferrowarden: credential created");
    assert_eq!(n.severity, Severity::Normal);
    assert!(
        n.message.contains("agent_keycloak_admin was created by"),
        "{}",
        n.message
    );
    assert!(n.message.contains("homelab-claude"), "{}", n.message);
    assert!(n.message.contains("no one has seen it"), "{}", n.message);
    // A failed create is not announced.
    let failed = ev
        .clone()
        .outcome(Outcome::Failure)
        .reason(Reason::CredentialExists);
    assert_eq!(classify(&failed), None);
}
