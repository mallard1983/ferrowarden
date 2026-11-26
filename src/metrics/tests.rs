use super::*;
use crate::middleware::request_context::RequestContext;
use crate::notify::{SenderInfo, Snapshot as NotifySnapshot};
use crate::state::AgentKey;
use std::collections::BTreeMap;
use std::time::Duration;

const VERSION: &str = "9.9.9-test";

fn metrics(credential_labels: bool) -> Arc<Metrics> {
    Metrics::new(VERSION, "bw-serve", credential_labels)
}

fn key(name: &str) -> AgentKey {
    AgentKey {
        id: "11111111-1111-1111-1111-111111111111".into(),
        name: name.into(),
        created_at: chrono::Utc::now(),
        policy: Default::default(),
        policy_set: true,
    }
}

fn ctx() -> RequestContext {
    RequestContext::new("172.20.0.5".parse().unwrap())
}

fn snapshot() -> Snapshot {
    Snapshot {
        unlocked: true,
        credentials: 7,
        excluded: 2,
        last_sync: 1_700_000_000,
        keys_with_policy: 3,
        keys_without_policy: 1,
        events_dropped: 4,
        notify: NotifySnapshot {
            senders: vec![SenderInfo {
                kind: "webhook",
                host: "notify.example".into(),
                sent: 5,
                failed: 2,
            }],
            categories: vec![],
            suppressed: 6,
            dropped: 1,
        },
        ui_sessions: 2,
    }
}

fn render(m: &Metrics) -> String {
    m.render(&snapshot()).unwrap()
}

/// A successful forward by `key_name`.
fn forward_ok(key_name: &str) -> SecurityEvent {
    SecurityEvent::new(Action::Forward)
        .request(&ctx())
        .key(&key(key_name))
        .method("GET")
        .url("https://api.example.com/v1/things?x=1")
        .credentials(["grafana_token"])
        .items(["grafana_token"])
        .response_bytes(1500)
        .status(200)
        .duration(Duration::from_millis(40))
}

/// `# TYPE` lines: family name -> type.
fn types(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| l.strip_prefix("# TYPE "))
        .filter_map(|l| l.split_once(' '))
        .map(|(n, t)| (n.to_string(), t.to_string()))
        .collect()
}

/// The sample lines of one series name (`name{...} value` or `name value`).
fn samples<'a>(text: &'a str, name: &str) -> Vec<&'a str> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter(|l| {
            l.strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('{') || rest.starts_with(' '))
        })
        .collect()
}

/// The value of the one sample that starts with `series` (name and labels).
fn value(text: &str, series: &str) -> Option<f64> {
    text.lines()
        .find_map(|l| l.strip_prefix(series)?.strip_prefix(' '))
        .and_then(|v| v.parse().ok())
}

/// The label names used by the samples of `name`.
fn label_names(text: &str, name: &str) -> Vec<String> {
    let mut names = std::collections::BTreeSet::new();
    for line in samples(text, name) {
        let Some(open) = line.find('{') else { continue };
        let close = line.rfind('}').unwrap();
        for pair in split_labels(&line[open + 1..close]) {
            names.insert(pair.split('=').next().unwrap().to_string());
        }
    }
    names.into_iter().collect()
}

/// Split `a="x",b="y,z"` on the commas outside quotes.
fn split_labels(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted, mut escaped) = (Vec::new(), String::new(), false, false);
    for c in s.chars() {
        match c {
            '\\' if quoted && !escaped => {
                escaped = true;
                cur.push(c);
                continue;
            }
            '"' if !escaped => quoted = !quoted,
            ',' if !quoted => {
                out.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        escaped = false;
        cur.push(c);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

// ── The registry ──────────────────────────────────────────────────────────────

#[test]
fn every_family_is_registered_with_the_right_type() {
    let m = metrics(true);
    let mut c = Consumer::new(m.clone());
    c.process(&forward_ok("agent-a"));
    let text = render(&m);

    let want: BTreeMap<&str, &str> = BTreeMap::from([
        ("ferrowarden_build_info", "gauge"),
        ("ferrowarden_events", "counter"),
        ("ferrowarden_forward_requests", "counter"),
        ("ferrowarden_forward_duration_seconds", "histogram"),
        ("ferrowarden_forward_response_bytes", "histogram"),
        ("ferrowarden_rate_limited", "counter"),
        ("ferrowarden_auth_failures", "counter"),
        ("ferrowarden_vault_unlocked", "gauge"),
        ("ferrowarden_vault_credentials", "gauge"),
        ("ferrowarden_vault_excluded_items", "gauge"),
        ("ferrowarden_vault_last_sync_timestamp_seconds", "gauge"),
        ("ferrowarden_agent_keys", "gauge"),
        ("ferrowarden_events_dropped", "counter"),
        ("ferrowarden_metrics_events_dropped", "counter"),
        ("ferrowarden_notifications", "counter"),
        ("ferrowarden_ui_sessions", "gauge"),
        ("ferrowarden_forward_credential_uses", "counter"),
    ]);
    let got = types(&text);
    let got: BTreeMap<&str, &str> = got.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    assert_eq!(got, want);
    assert!(text.ends_with("# EOF\n"), "OpenMetrics ends with # EOF");
}

#[test]
fn credential_uses_exist_only_with_the_opt_in() {
    let m = metrics(false);
    Consumer::new(m.clone()).process(&forward_ok("agent-a"));
    let text = render(&m);
    assert!(!text.contains("credential_uses"));
    assert!(!text.contains("grafana_token"));
}

#[test]
fn series_carry_exactly_the_documented_labels() {
    let m = metrics(true);
    let mut c = Consumer::new(m.clone());
    c.process(&forward_ok("agent-a"));
    c.process(
        &SecurityEvent::new(Action::RateLimited)
            .reason(Reason::RateLimited)
            .detail("limiter", "agent"),
    );
    let text = render(&m);
    let labels = |name: &str| label_names(&text, name);
    assert_eq!(
        labels("ferrowarden_build_info"),
        ["vault_backend", "version"]
    );
    assert_eq!(
        labels("ferrowarden_events_total"),
        ["action", "outcome", "reason"]
    );
    assert_eq!(
        labels("ferrowarden_forward_requests_total"),
        ["key", "outcome", "reason"]
    );
    assert_eq!(
        labels("ferrowarden_forward_duration_seconds_bucket"),
        ["le", "outcome"]
    );
    assert_eq!(labels("ferrowarden_forward_response_bytes_bucket"), ["le"]);
    assert_eq!(labels("ferrowarden_rate_limited_total"), ["limiter"]);
    assert_eq!(labels("ferrowarden_auth_failures_total"), ["kind"]);
    assert_eq!(labels("ferrowarden_agent_keys"), ["policy_set"]);
    assert_eq!(
        labels("ferrowarden_notifications_total"),
        ["result", "sender"]
    );
    assert_eq!(
        labels("ferrowarden_forward_credential_uses_total"),
        ["credential"]
    );
    for unlabelled in [
        "ferrowarden_vault_unlocked",
        "ferrowarden_vault_credentials",
        "ferrowarden_vault_excluded_items",
        "ferrowarden_vault_last_sync_timestamp_seconds",
        "ferrowarden_events_dropped_total",
        "ferrowarden_metrics_events_dropped_total",
        "ferrowarden_ui_sessions",
    ] {
        assert!(labels(unlabelled).is_empty(), "{unlabelled}");
    }
}

#[test]
fn bucket_boundaries_are_the_documented_ones() {
    let m = metrics(false);
    Consumer::new(m.clone()).process(&forward_ok("a"));
    let text = render(&m);
    let les = |name: &str| -> Vec<String> {
        samples(&text, name)
            .iter()
            .filter_map(|l| l.split("le=\"").nth(1))
            .map(|r| r.split('"').next().unwrap().to_string())
            .collect()
    };
    assert_eq!(
        les("ferrowarden_forward_duration_seconds_bucket"),
        [
            "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1.0", "2.5", "5.0", "10.0", "30.0",
            "+Inf"
        ]
    );
    let bytes = les("ferrowarden_forward_response_bytes_bucket");
    assert_eq!(bytes.first().map(String::as_str), Some("256.0"));
    assert_eq!(bytes[bytes.len() - 2], "33554432.0", "32 MiB");
    assert_eq!(bytes.last().map(String::as_str), Some("+Inf"));
}

#[test]
fn scrape_time_values_come_from_the_snapshot() {
    let m = metrics(false);
    let text = render(&m);
    assert_eq!(value(&text, "ferrowarden_vault_unlocked"), Some(1.0));
    assert_eq!(value(&text, "ferrowarden_vault_credentials"), Some(7.0));
    assert_eq!(value(&text, "ferrowarden_vault_excluded_items"), Some(2.0));
    assert_eq!(
        value(&text, "ferrowarden_vault_last_sync_timestamp_seconds"),
        Some(1_700_000_000.0)
    );
    assert_eq!(
        value(&text, "ferrowarden_agent_keys{policy_set=\"true\"}"),
        Some(3.0)
    );
    assert_eq!(
        value(&text, "ferrowarden_agent_keys{policy_set=\"false\"}"),
        Some(1.0)
    );
    assert_eq!(value(&text, "ferrowarden_events_dropped_total"), Some(4.0));
    assert_eq!(value(&text, "ferrowarden_ui_sessions"), Some(2.0));
    for (series, want) in [
        ("sender=\"webhook\",result=\"sent\"", 5.0),
        ("sender=\"webhook\",result=\"failed\"", 2.0),
        ("sender=\"all\",result=\"suppressed\"", 6.0),
        ("sender=\"all\",result=\"dropped\"", 1.0),
    ] {
        let name = format!("ferrowarden_notifications_total{{{series}}}");
        assert_eq!(value(&text, &name), Some(want), "{series}");
    }
    assert_eq!(
        value(
            &text,
            &format!("ferrowarden_build_info{{version=\"{VERSION}\",vault_backend=\"bw-serve\"}}")
        ),
        Some(1.0)
    );

    // A locked vault and a later scrape: gauges follow, counters never go back.
    let mut locked = snapshot();
    locked.unlocked = false;
    locked.keys_without_policy = 0;
    let text = m.render(&locked).unwrap();
    assert_eq!(value(&text, "ferrowarden_vault_unlocked"), Some(0.0));
    assert_eq!(
        value(&text, "ferrowarden_agent_keys{policy_set=\"false\"}"),
        Some(0.0)
    );
}

#[test]
fn the_fixed_series_exist_before_any_event() {
    let text = render(&metrics(false));
    for kind in ["agent", "admin", "ui", "metrics"] {
        let series = format!("ferrowarden_auth_failures_total{{kind=\"{kind}\"}}");
        assert_eq!(value(&text, &series), Some(0.0), "{series}");
    }
    for limiter in ["agent", "admin", "notify_test"] {
        let series = format!("ferrowarden_rate_limited_total{{limiter=\"{limiter}\"}}");
        assert_eq!(value(&text, &series), Some(0.0), "{series}");
    }
}

// ── Events into counters and histograms ───────────────────────────────────────

#[test]
fn a_forward_is_counted_timed_and_sized() {
    let m = metrics(false);
    let mut c = Consumer::new(m.clone());
    c.process(&forward_ok("agent-a"));
    c.process(&forward_ok("agent-a"));
    c.process(
        &SecurityEvent::new(Action::Forward)
            .request(&ctx())
            .key(&key("agent-b"))
            .reason(Reason::TargetBlocked)
            .outcome(Outcome::Failure)
            .status(403)
            .duration(Duration::from_millis(2)),
    );
    let text = render(&m);
    assert_eq!(
        value(
            &text,
            "ferrowarden_forward_requests_total{outcome=\"success\",reason=\"\",key=\"agent-a\"}"
        ),
        Some(2.0)
    );
    assert_eq!(
        value(
            &text,
            "ferrowarden_forward_requests_total{outcome=\"failure\",reason=\"target_blocked\",key=\"agent-b\"}"
        ),
        Some(1.0)
    );
    assert_eq!(
        value(
            &text,
            "ferrowarden_forward_duration_seconds_count{outcome=\"success\"}"
        ),
        Some(2.0)
    );
    assert_eq!(
        value(
            &text,
            "ferrowarden_forward_duration_seconds_count{outcome=\"failure\"}"
        ),
        Some(1.0)
    );
    // Only successful forwards have a response size.
    assert_eq!(
        value(&text, "ferrowarden_forward_response_bytes_count"),
        Some(2.0)
    );
    assert_eq!(
        value(&text, "ferrowarden_forward_response_bytes_sum"),
        Some(3000.0)
    );
}

#[test]
fn rate_limited_counts_the_suppressed_429s_too() {
    let m = metrics(false);
    let mut c = Consumer::new(m.clone());
    let limited = |limiter: &str, suppressed: u64| {
        SecurityEvent::new(Action::RateLimited)
            .reason(Reason::RateLimited)
            .detail("limiter", limiter)
            .detail("suppressed", suppressed)
    };
    c.process(&limited("agent", 0));
    c.process(&limited("agent", 41));
    c.process(&limited("admin", 2));
    // The notify test limiter's event has no `suppressed` detail.
    c.process(
        &SecurityEvent::new(Action::RateLimited)
            .reason(Reason::RateLimited)
            .detail("limiter", "notify_test"),
    );
    let text = render(&m);
    for (limiter, want) in [("agent", 43.0), ("admin", 3.0), ("notify_test", 1.0)] {
        let series = format!("ferrowarden_rate_limited_total{{limiter=\"{limiter}\"}}");
        assert_eq!(value(&text, &series), Some(want), "{limiter}");
    }
}

#[test]
fn an_unknown_limiter_name_never_becomes_a_label() {
    let m = metrics(false);
    Consumer::new(m.clone()).process(
        &SecurityEvent::new(Action::RateLimited)
            .detail("limiter", "evil\"label{injection}")
            .detail("suppressed", 0),
    );
    let text = render(&m);
    assert!(!text.contains("injection"));
    assert_eq!(
        value(&text, "ferrowarden_rate_limited_total{limiter=\"other\"}"),
        Some(1.0)
    );
}

/// Which `auth_failures_total{kind}` an event raises, from a counter reading
/// before and after.
fn auth_kinds_raised(event: SecurityEvent) -> Vec<&'static str> {
    let m = metrics(false);
    Consumer::new(m.clone()).process(&event);
    let text = render(&m);
    AUTH_KINDS
        .into_iter()
        .filter(|kind| {
            let series = format!("ferrowarden_auth_failures_total{{kind=\"{kind}\"}}");
            value(&text, &series).unwrap() > 0.0
        })
        .collect()
}

#[test]
fn auth_failures_are_counted_by_kind() {
    let fail = |a: Action, r: Reason| SecurityEvent::new(a).reason(r);
    assert_eq!(
        auth_kinds_raised(fail(Action::AgentAuth, Reason::InvalidKey)),
        ["agent"]
    );
    assert_eq!(
        auth_kinds_raised(fail(Action::AdminAuth, Reason::MissingAdminKey)),
        ["admin"]
    );
    for reason in [
        Reason::InvalidCredentials,
        Reason::TwoFactorFailed,
        Reason::LoginLockedOut,
    ] {
        assert_eq!(
            auth_kinds_raised(fail(Action::UiLogin, reason).outcome(Outcome::Failure)),
            ["ui"],
            "{reason:?}"
        );
    }
    // Not failures of authentication: successes, the first of two steps, and
    // a sign-in refused for arriving over plain HTTP.
    assert!(auth_kinds_raised(SecurityEvent::new(Action::UiLogin)).is_empty());
    assert!(auth_kinds_raised(
        fail(Action::UiLogin, Reason::TwoFactorRequired).outcome(Outcome::Unknown)
    )
    .is_empty());
    assert!(auth_kinds_raised(
        fail(Action::UiLogin, Reason::InsecureTransport).outcome(Outcome::Failure)
    )
    .is_empty());
    assert!(
        auth_kinds_raised(SecurityEvent::new(Action::AgentAuth).outcome(Outcome::Success))
            .is_empty()
    );
    // `metrics_auth` is counted where it happens, not from the event, so the
    // consumer must not count it a second time.
    assert!(auth_kinds_raised(fail(Action::MetricsAuth, Reason::InvalidMetricsToken)).is_empty());
}

#[test]
fn metrics_auth_failures_are_counted_at_the_source() {
    let m = metrics(false);
    for _ in 0..5 {
        m.count_metrics_auth_failure();
    }
    assert_eq!(
        value(
            &render(&m),
            "ferrowarden_auth_failures_total{kind=\"metrics\"}"
        ),
        Some(5.0)
    );
}

/// Every action, every outcome and every reason (and none): each event is
/// counted once under exactly its own wire names, whatever else it does.
#[test]
fn every_event_is_counted_under_its_own_names() {
    let outcomes = [Outcome::Success, Outcome::Failure, Outcome::Unknown];
    let reasons: Vec<Option<Reason>> = std::iter::once(None)
        .chain(Reason::ALL.into_iter().map(Some))
        .collect();
    let m = metrics(true);
    let mut c = Consumer::new(m.clone());
    let mut expected = 0usize;
    for action in Action::ALL {
        for outcome in outcomes {
            for reason in &reasons {
                let mut e = SecurityEvent::new(action).outcome(outcome);
                if let Some(r) = reason {
                    e = e.reason(*r);
                }
                c.process(&e);
                expected += 1;
            }
        }
    }
    let text = render(&m);
    let lines = samples(&text, "ferrowarden_events_total");
    assert_eq!(lines.len(), expected, "one series per combination");
    for line in &lines {
        assert!(line.ends_with(" 1"), "{line}");
    }
    for action in Action::ALL {
        for outcome in outcomes {
            for reason in &reasons {
                let series = format!(
                    "ferrowarden_events_total{{action=\"{}\",outcome=\"{}\",reason=\"{}\"}}",
                    action.as_str(),
                    outcome.as_str(),
                    reason.map_or("", Reason::as_str)
                );
                assert_eq!(value(&text, &series), Some(1.0), "{series}");
            }
        }
    }
}

/// The side effects of an event are the same table whatever its reason: only
/// the actions and outcomes below move any other counter.
#[test]
fn only_the_documented_events_move_the_other_counters() {
    let outcomes = [Outcome::Success, Outcome::Failure, Outcome::Unknown];
    for action in Action::ALL {
        for outcome in outcomes {
            for reason in std::iter::once(None).chain(Reason::ALL.into_iter().map(Some)) {
                let m = metrics(true);
                let mut e = SecurityEvent::new(action).outcome(outcome);
                if let Some(r) = reason {
                    e = e.reason(r);
                }
                Consumer::new(m.clone()).process(&e);
                let text = render(&m);
                let forwarded = !samples(&text, "ferrowarden_forward_requests_total").is_empty();
                assert_eq!(forwarded, action == Action::Forward, "{action:?}");
                let raised = {
                    let mut n = auth_kinds_raised(e.clone());
                    n.sort();
                    n
                };
                let want: &[&str] = match (action, outcome, reason) {
                    (Action::AgentAuth, Outcome::Failure, _) => &["agent"],
                    (Action::AdminAuth, Outcome::Failure, _) => &["admin"],
                    (Action::UiLogin, Outcome::Failure, Some(Reason::InsecureTransport)) => &[],
                    (Action::UiLogin, Outcome::Failure, _) => &["ui"],
                    _ => &[],
                };
                assert_eq!(raised, want, "{action:?} {outcome:?} {reason:?}");
                // The `other` limiter is how a rate_limited event without a
                // known limiter is counted.
                let limited = value(&text, "ferrowarden_rate_limited_total{limiter=\"other\"}");
                assert_eq!(
                    limited.is_some(),
                    action == Action::RateLimited,
                    "{action:?}"
                );
            }
        }
    }
}

// ── Label values ──────────────────────────────────────────────────────────────

/// Strings that must never reach the output: request data and secret-looking
/// values, put in every place an event can carry free text.
const HOSTILE: [&str; 9] = [
    "evil-host.attacker.example",
    "/secret/path/segment",
    "token=SUPERSECRETVALUE123",
    "Authorization: Bearer abcdef0123456789",
    "{{vault:StolenItem:password}}",
    "X-Hostile-Header",
    "198.51.100.77",
    "ssh-rsa AAAAB3NzaC1yc2EHOSTILE",
    "injection\"} 1\nferrowarden_fake_total 99",
];

fn hostile_event(action: Action, outcome: Outcome, reason: Option<Reason>) -> SecurityEvent {
    let mut e = SecurityEvent::new(action)
        .outcome(outcome)
        .request(&RequestContext::new("198.51.100.77".parse().unwrap()))
        .method("X-Hostile-Header")
        .url("https://evil-host.attacker.example/secret/path/segment?token=SUPERSECRETVALUE123")
        .credentials([
            "{{vault:StolenItem:password}}",
            "'Hostile (prod)':field:ssh-rsa AAAAB3NzaC1yc2EHOSTILE",
        ])
        .items(["{{vault:StolenItem:password}}", "X-Hostile-Header"])
        .response_bytes(10)
        .status(200)
        .duration(Duration::from_millis(5))
        .detail("endpoint", "/secret/path/segment")
        .detail("host", "evil-host.attacker.example")
        .detail("error", "Authorization: Bearer abcdef0123456789")
        .detail("limiter", HOSTILE[8])
        .detail("suppressed", 1)
        .detail("provider", "token=SUPERSECRETVALUE123");
    if let Some(r) = reason {
        e = e.reason(r);
    }
    e
}

#[test]
fn request_data_never_reaches_the_output() {
    // Even with the credential-name opt-in on: failures and refusals carry
    // names the agent typed, which are never counted.
    for credential_labels in [false, true] {
        let m = metrics(credential_labels);
        let mut c = Consumer::new(m.clone());
        for action in Action::ALL {
            for outcome in [Outcome::Success, Outcome::Failure, Outcome::Unknown] {
                for reason in [
                    None,
                    Some(Reason::TargetBlocked),
                    Some(Reason::UnknownCredential),
                ] {
                    let e = hostile_event(action, outcome, reason);
                    if credential_labels && action == Action::Forward && outcome == Outcome::Success
                    {
                        // The one place item names are used. These two are
                        // checked below; skip them here.
                        continue;
                    }
                    c.process(&e);
                }
            }
        }
        let text = render(&m);
        for hostile in HOSTILE {
            assert!(!text.contains(hostile), "{hostile:?} reached the output");
        }
        assert!(!text.contains("ferrowarden_fake_total"));
        // And the hostile text is not a key name either: events without a
        // key have an empty `key` label.
        assert!(text.contains("key=\"\""));
    }
}

#[test]
fn credential_names_are_counted_only_for_successful_forwards() {
    let m = metrics(true);
    let mut c = Consumer::new(m.clone());
    c.process(&forward_ok("agent-a").items(["Grafana", "Grafana", "Proxmox (prod)"]));
    // A refused forward names whatever the agent typed.
    c.process(
        &SecurityEvent::new(Action::Forward)
            .key(&key("agent-a"))
            .items(["TypedByTheAgent"])
            .reason(Reason::UnknownCredential)
            .outcome(Outcome::Failure),
    );
    let text = render(&m);
    assert_eq!(
        value(
            &text,
            "ferrowarden_forward_credential_uses_total{credential=\"Grafana\"}"
        ),
        Some(1.0),
        "a name used twice in one request counts once"
    );
    assert_eq!(
        value(
            &text,
            "ferrowarden_forward_credential_uses_total{credential=\"Proxmox (prod)\"}"
        ),
        Some(1.0)
    );
    assert!(!text.contains("TypedByTheAgent"));
}

#[test]
fn credential_labels_are_capped() {
    let m = metrics(true);
    let mut c = Consumer::new(m.clone());
    let total = CREDENTIAL_LABEL_CAP + 25;
    for i in 0..total {
        c.process(&forward_ok("agent-a").items([format!("item-{i}")]));
    }
    // A name seen before the cap keeps counting under its own name.
    c.process(&forward_ok("agent-a").items(["item-0"]));
    let text = render(&m);
    let lines = samples(&text, "ferrowarden_forward_credential_uses_total");
    assert_eq!(lines.len(), CREDENTIAL_LABEL_CAP + 1, "cap + `_other`");
    assert_eq!(
        value(
            &text,
            "ferrowarden_forward_credential_uses_total{credential=\"_other\"}"
        ),
        Some(25.0)
    );
    assert_eq!(
        value(
            &text,
            "ferrowarden_forward_credential_uses_total{credential=\"item-0\"}"
        ),
        Some(2.0)
    );
    assert!(!text.contains(&format!("item-{}\"", total - 1)));
}

#[test]
fn key_names_are_bounded_too() {
    let m = metrics(false);
    let mut c = Consumer::with_caps(m.clone(), 3, 3);
    for name in ["a", "b", "c", "d", "e", "a"] {
        c.process(&forward_ok(name));
    }
    let text = render(&m);
    let series = |k: &str| {
        value(
            &text,
            &format!(
                "ferrowarden_forward_requests_total{{outcome=\"success\",reason=\"\",key=\"{k}\"}}"
            ),
        )
    };
    assert_eq!(series("a"), Some(2.0));
    assert_eq!(series("_other"), Some(2.0));
    assert_eq!(series("d"), None);
}

#[test]
fn a_key_name_is_escaped_in_the_output() {
    let m = metrics(false);
    Consumer::new(m.clone()).process(&forward_ok("na\"me\\with\nnewline"));
    let text = render(&m);
    assert!(text.contains(r#"key="na\"me\\with\nnewline""#), "{text}");
    // Still one sample per line.
    assert!(text
        .lines()
        .all(|l| l.starts_with('#') || l.is_empty() || l.starts_with("ferrowarden_")));
}

#[test]
fn revoked_key_series_stay() {
    let m = metrics(false);
    let mut c = Consumer::new(m.clone());
    c.process(&forward_ok("gone-agent"));
    // Nothing removes a series: the key store shrinking changes no counter.
    let mut after = snapshot();
    after.keys_with_policy = 0;
    after.keys_without_policy = 0;
    let text = m.render(&after).unwrap();
    assert_eq!(
        value(
            &text,
            "ferrowarden_forward_requests_total{outcome=\"success\",reason=\"\",key=\"gone-agent\"}"
        ),
        Some(1.0)
    );
}

// ── Never blocking ────────────────────────────────────────────────────────────

#[test]
fn offering_to_a_full_queue_counts_a_drop_and_returns() {
    let m = metrics(false);
    let (tx, mut rx) = mpsc::channel(2);
    let feed = Feed {
        tx,
        dropped: m.metrics_dropped.clone(),
    };
    let event = Arc::new(SecurityEvent::new(Action::Startup));
    for _ in 0..10 {
        feed.offer(&event);
    }
    assert_eq!(m.metrics_dropped.get(), 8, "10 offered, 2 fit");
    assert!(rx.try_recv().is_ok());
    assert_eq!(
        value(&render(&m), "ferrowarden_metrics_events_dropped_total"),
        Some(8.0)
    );
}

/// `emit` with a consumer that never reads, from a plain thread: it must
/// finish, however many events there are.
#[test]
fn a_stalled_consumer_cannot_block_emit() {
    let m = metrics(false);
    let (tx, _rx_never_read) = mpsc::channel(4);
    let log = Arc::new(EventLog::buffer_only(16));
    log.attach_metrics(Feed {
        tx,
        dropped: m.metrics_dropped.clone(),
    });
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = log.clone();
    std::thread::spawn(move || {
        for _ in 0..50_000 {
            worker.emit(SecurityEvent::new(Action::Startup));
        }
        let _ = done_tx.send(());
    });
    done_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("emit must not wait for the metrics consumer");
    assert_eq!(m.metrics_dropped.get(), 50_000 - 4);
    assert_eq!(log.recent(1).len(), 1, "the ring buffer still got them");
}

#[tokio::test]
async fn the_started_consumer_counts_what_the_log_emits() {
    let cfg = MetricsConfig {
        bind: "127.0.0.1:0".into(),
        ..Default::default()
    };
    let log = Arc::new(EventLog::buffer_only(16));
    let m = start(&cfg, "native", &log).expect("metrics are on");
    log.emit(forward_ok("agent-a"));
    // The consumer is another task: wait for it.
    let mut text = String::new();
    for _ in 0..200 {
        text = render(&m);
        if text.contains("ferrowarden_forward_requests_total{") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        value(
            &text,
            "ferrowarden_events_total{action=\"forward\",outcome=\"success\",reason=\"\"}"
        ),
        Some(1.0)
    );
}

#[tokio::test]
async fn metrics_off_starts_nothing() {
    let log = Arc::new(EventLog::buffer_only(16));
    assert!(start(&MetricsConfig::default(), "bw-serve", &log).is_none());
}
