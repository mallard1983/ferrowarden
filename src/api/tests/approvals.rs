//! Human approval through the real router: the hold, the three outcomes, the
//! grants, the limits, the clearing, and the admin routes that decide.
//!
//! The vault is the in-memory fake, which counts the value reads: a test that
//! says "no value was fetched" asserts that count is zero, and one that says
//! "nothing was sent" asserts the upstream saw no request.

use super::*;
use crate::approvals::PendingView;
use crate::vault::fake::FakeVault;
use std::time::Duration;

const SENSITIVE_VALUE: &str = "SENSITIVE-VALUE-0001";
const ORDINARY_VALUE: &str = "ordinary-value-0002";
const POLICY_VALUE: &str = "policy-value-0003";

/// The tests that must not be held configure `wait_secs = 20` (or 30); half of
/// that is the proof. (Not a tighter bound: resolving the vault host for the
/// outbound policy can itself take seconds on some machines.)
const HELD_FOR_20: Duration = Duration::from_secs(10);

fn fake(state: &AppState) -> &FakeVault {
    match &*state.vault {
        crate::vault::ActiveVault::Fake(f) => f,
        _ => unreachable!("the test state uses the fake vault"),
    }
}

struct Setup {
    app: Router,
    state: Arc<AppState>,
    up: Upstream,
}

impl Setup {
    /// `{base}/x`, with the vault item `item` as a bearer token.
    fn payload(&self, item: &str) -> serde_json::Value {
        self.payload_at(item, "/x")
    }

    fn payload_at(&self, item: &str, path: &str) -> serde_json::Value {
        json!({"request": {
            "method": "GET",
            "url": format!("{}{path}", self.up.base()),
            "headers": {"Authorization": format!("Bearer {{{{vault:{item}}}}}")}
        }})
    }

    async fn key(&self, name: &str, approval: &str) -> (String, String) {
        let (s, _, body) = call(
            &self.app,
            "POST",
            "/v1/admin/keys",
            &[("x-admin-key", ADMIN_KEY)],
            Some(&format!(
                r#"{{"name":"{name}","credentials":["*"],"methods":["*"],"approval":{approval}}}"#
            )),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{body}");
        (
            body["id"].as_str().unwrap().to_string(),
            body["token"].as_str().unwrap().to_string(),
        )
    }

    fn pending(&self) -> Vec<PendingView> {
        self.state.approvals.list(chrono::Utc::now()).0
    }

    /// Wait (briefly) until `n` approvals are open.
    async fn wait_for_pending(&self, n: usize) -> Vec<PendingView> {
        for _ in 0..200 {
            let p = self.pending();
            if p.len() >= n {
                return p;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no approval was opened");
    }

    async fn decide(
        &self,
        id: &str,
        action: &str,
        body: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        admin(
            &self.app,
            "POST",
            &format!("/v1/admin/approvals/{id}/{action}"),
            body,
        )
        .await
    }

    async fn approve(&self, id: &str, minutes: u32) -> (StatusCode, serde_json::Value) {
        self.decide(id, "approve", Some(&format!(r#"{{"minutes":{minutes}}}"#)))
            .await
    }

    fn sent_values(&self) -> usize {
        self.up
            .requests()
            .iter()
            .filter(|r| r.contains(SENSITIVE_VALUE) || r.contains(POLICY_VALUE))
            .count()
    }
}

async fn setup(tweak: impl FnOnce(&mut Config)) -> Setup {
    let up = upstream(|_, _| http(200, &[], r#"{"ok":true}"#)).await;
    let (app, state) = local_app(|c| {
        c.approval.wait_secs = 1;
        c.approval.pending_ttl_secs = 30;
        tweak(c);
    })
    .await;
    let base = up.base();
    let mut creds = state.credentials.write().await;
    // `sensitive`: the vault item itself asks for approval.
    let mut sensitive = CredentialEntry::login("s1", &[&base]);
    sensitive.approval_required = true;
    sensitive.has_username = true;
    creds.insert("sensitive".into(), vec![sensitive]);
    // Two plain items; one of them is made sensitive by a key policy.
    creds.insert(
        "ordinary".into(),
        vec![CredentialEntry::login("o1", &[&base])],
    );
    creds.insert(
        "policy_item".into(),
        vec![CredentialEntry::login("p1", &[&base])],
    );
    for n in ["a", "b", "c", "d"] {
        creds.insert(
            format!("lim_{n}"),
            vec![CredentialEntry::login(&format!("l_{n}"), &[&base])],
        );
    }
    drop(creds);
    fake(&state).set_password("s1", SENSITIVE_VALUE);
    fake(&state).set_password("o1", ORDINARY_VALUE);
    fake(&state).set_password("p1", POLICY_VALUE);
    for n in ["a", "b", "c", "d"] {
        fake(&state).set_password(&format!("l_{n}"), &format!("limit-value-{n}-0004"));
    }
    Setup { app, state, up }
}

fn spawn_forward(
    s: &Setup,
    token: &str,
    payload: serde_json::Value,
) -> tokio::task::JoinHandle<(StatusCode, serde_json::Value)> {
    let (app, token) = (s.app.clone(), token.to_string());
    tokio::spawn(async move { fwd(&app, &token, payload).await })
}

fn forward_events(s: &Setup) -> Vec<serde_json::Value> {
    events_of(&s.state, "forward")
}

// ── The three outcomes ────────────────────────────────────────────────────────

#[tokio::test]
async fn a_request_is_held_and_goes_through_when_it_is_approved_while_waiting() {
    let s = setup(|c| c.approval.wait_secs = 20).await;
    let (_, token) = s.key("agent-a", "[]").await;
    let held = spawn_forward(&s, &token, s.payload("sensitive"));

    // Held: an approval is open, and nothing was fetched or sent.
    let open = s.wait_for_pending(1).await;
    assert_eq!(open[0].key_name, "agent-a");
    assert_eq!(open[0].items[0].item, "sensitive");
    assert!(open[0].items[0].reasons.vault_field && !open[0].items[0].reasons.key_policy);
    assert_eq!(open[0].method, "GET");
    assert_eq!(fake(&s.state).value_reads(), 0);
    assert_eq!(s.up.hits(), 0);
    assert!(!held.is_finished());

    let (st, body) = s.approve(&open[0].id, 15).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "approved");
    assert_eq!(body["grant"]["approver"], "admin_api");
    assert_eq!(body["grant"]["credentials"], json!(["sensitive"]));

    let (st, resp) = held.await.unwrap();
    assert_eq!(st, StatusCode::OK, "{resp}");
    assert_eq!(s.up.hits(), 1);
    assert_eq!(s.sent_values(), 1, "the value reached the target");
    assert_eq!(fake(&s.state).value_reads(), 1);
    // The agent's answer never has the value (the scrubber).
    assert!(!resp.to_string().contains(SENSITIVE_VALUE));

    // The forward event records the gate; the other events name the ids.
    let ev = &forward_events(&s)[0];
    assert_eq!(
        ev["ferrowarden"]["details"]["approval"],
        "approved_while_waiting"
    );
    assert_eq!(events_of(&s.state, "approval_requested").len(), 1);
    let granted = &events_of(&s.state, "approval_granted")[0];
    assert_eq!(granted["ferrowarden"]["details"]["approver"], "admin_api");
    assert_eq!(granted["ferrowarden"]["details"]["minutes"], 15);
    assert_eq!(granted["ferrowarden"]["details"]["via"], "api");

    // The grant covers the next requests with no hold at all.
    let started = std::time::Instant::now();
    let (st, _) = fwd(&s.app, &token, s.payload_at("sensitive", "/y")).await;
    assert_eq!(st, StatusCode::OK);
    assert!(started.elapsed() < HELD_FOR_20, "not held");
    assert_eq!(
        forward_events(&s)[0]["ferrowarden"]["details"]["approval"],
        "granted_by_grant"
    );
    assert_eq!(events_of(&s.state, "approval_requested").len(), 1);

    // No event carries a value.
    assert!(!all_events_text(&s.state).contains(SENSITIVE_VALUE));
}

#[tokio::test]
async fn a_denial_answers_the_held_request_and_every_retry_without_a_new_prompt() {
    let s = setup(|c| c.approval.wait_secs = 20).await;
    let (_, token) = s.key("agent-a", "[]").await;
    let held = spawn_forward(&s, &token, s.payload("sensitive"));
    let open = s.wait_for_pending(1).await;

    let (st, body) = s.decide(&open[0].id, "deny", None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let (st, resp) = held.await.unwrap();
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(resp["code"], "approval_denied");
    assert!(resp.get("approval_id").is_none());
    assert_eq!(s.up.hits(), 0, "nothing was sent");
    assert_eq!(fake(&s.state).value_reads(), 0, "no value was fetched");

    // A retry is refused at once, and nobody is asked again.
    let started = std::time::Instant::now();
    let (st, resp) = fwd(&s.app, &token, s.payload("sensitive")).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(resp["code"], "approval_denied");
    assert!(started.elapsed() < HELD_FOR_20, "answered without a hold");
    assert_eq!(events_of(&s.state, "approval_requested").len(), 1);
    assert_eq!(s.up.hits(), 0);
    assert_eq!(fake(&s.state).value_reads(), 0);
    let ev = &forward_events(&s)[0];
    assert_eq!(ev["ferrowarden"]["details"]["approval"], "denied");
    assert_eq!(ev["event"]["reason"], "approval_denied");
    let denied = &events_of(&s.state, "approval_denied")[0];
    assert_eq!(denied["ferrowarden"]["details"]["approver"], "admin_api");
}

#[tokio::test]
async fn an_undecided_request_is_answered_pending_and_a_late_approval_lets_the_retry_pass() {
    let s = setup(|_| {}).await;
    let (_, token) = s.key("agent-a", "[]").await;

    let started = std::time::Instant::now();
    let (st, resp) = fwd(&s.app, &token, s.payload("sensitive")).await;
    // Held for `wait_secs` (1), then told to retry.
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert_eq!(st, StatusCode::FORBIDDEN, "{resp}");
    assert_eq!(resp["code"], "approval_pending");
    let id = resp["approval_id"].as_str().unwrap().to_string();
    assert!(id.len() >= 22);
    let msg = resp["error"].as_str().unwrap();
    assert!(
        msg.contains("admin UI") && msg.contains("retry the same request"),
        "{msg}"
    );
    assert_eq!(s.up.hits(), 0);
    assert_eq!(fake(&s.state).value_reads(), 0);
    assert_eq!(
        forward_events(&s)[0]["ferrowarden"]["details"]["approval"],
        "pending"
    );
    assert_eq!(forward_events(&s)[0]["event"]["reason"], "approval_pending");

    // The approval stays open, and a retry finds it: no second prompt.
    assert_eq!(s.pending().len(), 1);
    let (st, again) = fwd(&s.app, &token, s.payload("sensitive")).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(again["approval_id"], id.as_str());
    assert_eq!(events_of(&s.state, "approval_requested").len(), 1);

    // Approved afterwards: the retry of the same request passes.
    let (st, body) = s.approve(&id, 5).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let (st, resp) = fwd(&s.app, &token, s.payload("sensitive")).await;
    assert_eq!(st, StatusCode::OK, "{resp}");
    assert_eq!(s.sent_values(), 1);
    assert_eq!(
        forward_events(&s)[0]["ferrowarden"]["details"]["approval"],
        "granted_by_grant"
    );
}

#[tokio::test]
async fn the_client_going_away_leaves_the_approval_open_for_the_retry() {
    let s = setup(|c| c.approval.wait_secs = 30).await;
    let (_, token) = s.key("agent-a", "[]").await;
    let held = spawn_forward(&s, &token, s.payload("sensitive"));
    let open = s.wait_for_pending(1).await;
    held.abort();
    let _ = held.await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(s.pending().len(), 1, "the approval stays");
    assert_eq!(s.pending()[0].id, open[0].id);
    // The held request was counted and is not any more: the key can hold again.
    let (st, _) = s.approve(&open[0].id, 5).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = fwd(&s.app, &token, s.payload("sensitive")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(s.up.hits(), 1);
}

#[tokio::test]
async fn stopping_the_process_answers_held_requests_instead_of_waiting() {
    let s = setup(|c| c.approval.wait_secs = 30).await;
    let (_, token) = s.key("agent-a", "[]").await;
    let held = spawn_forward(&s, &token, s.payload("sensitive"));
    s.wait_for_pending(1).await;
    s.state.approvals.shutdown();
    let (st, resp) = tokio::time::timeout(Duration::from_secs(5), held)
        .await
        .expect("the held request was answered")
        .unwrap();
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(resp["code"], "approval_pending");
    assert_eq!(s.up.hits(), 0);
}

// ── The two sources ───────────────────────────────────────────────────────────

#[tokio::test]
async fn the_key_policy_can_require_approval_and_the_vault_field_cannot_be_exempted() {
    let s = setup(|_| {}).await;
    // `policy_item` has no field: only this key's patterns make it sensitive.
    let (_, with_policy) = s.key("with-policy", r#"["policy_*"]"#).await;
    let (_, without) = s.key("without", "[]").await;

    let (st, r) = fwd(&s.app, &with_policy, s.payload("policy_item")).await;
    assert_eq!(
        (st, r["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("approval_pending"))
    );
    let open = &s.pending()[0];
    assert!(open.items[0].reasons.key_policy && !open.items[0].reasons.vault_field);
    assert_eq!(s.up.hits(), 0);
    assert_eq!(fake(&s.state).value_reads(), 0);

    // Another key, without the pattern, uses the same item freely.
    let (st, _) = fwd(&s.app, &without, s.payload("policy_item")).await;
    assert_eq!(st, StatusCode::OK);
    // A plain item needs nothing for either key.
    let (st, _) = fwd(&s.app, &with_policy, s.payload("ordinary")).await;
    assert_eq!(st, StatusCode::OK);

    // The vault field asks whatever the key's list says (here: nothing).
    let (st, r) = fwd(&s.app, &without, s.payload("sensitive")).await;
    assert_eq!(
        (st, r["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("approval_pending"))
    );
    // An item with both reasons says so.
    let (_, both) = s.key("both", r#"["sensitive"]"#).await;
    let (st, _) = fwd(&s.app, &both, s.payload("sensitive")).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let both_open: Vec<_> = s
        .pending()
        .into_iter()
        .filter(|p| p.key_name == "both")
        .collect();
    assert!(both_open[0].items[0].reasons.vault_field && both_open[0].items[0].reasons.key_policy);
    // Only what needed no approval was sent: the plain item for `without`, and
    // `policy_item` for the key that has no pattern for it.
    let sent = s.up.requests();
    assert!(sent.iter().all(|r| !r.contains(SENSITIVE_VALUE)));
    assert_eq!(sent.iter().filter(|r| r.contains(POLICY_VALUE)).count(), 1);
    assert_eq!(
        sent.iter().filter(|r| r.contains(ORDINARY_VALUE)).count(),
        1
    );
}

#[tokio::test]
async fn approving_one_item_covers_every_selector_of_it() {
    let s = setup(|_| {}).await;
    let (_, token) = s.key("agent-a", "[]").await;
    let username = json!({"request": {"method": "GET", "url": format!("{}/x", s.up.base()),
        "headers": {"X-User": "{{vault:sensitive:username}}"}}});
    let (st, r1) = fwd(&s.app, &token, username).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    // The password placeholder of the same item is the same approval.
    let (st, r2) = fwd(&s.app, &token, s.payload("sensitive")).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(r1["approval_id"], r2["approval_id"]);
    assert_eq!(s.pending().len(), 1);
    let (st, _) = s.approve(r1["approval_id"].as_str().unwrap(), 5).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = fwd(&s.app, &token, s.payload("sensitive")).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn the_grant_is_bound_to_the_key_and_the_origin() {
    let s = setup(|_| {}).await;
    let (_, a) = s.key("agent-a", "[]").await;
    let (_, b) = s.key("agent-b", "[]").await;
    let (_, r) = fwd(&s.app, &a, s.payload("sensitive")).await;
    s.approve(r["approval_id"].as_str().unwrap(), 5).await;
    assert_eq!(
        fwd(&s.app, &a, s.payload("sensitive")).await.0,
        StatusCode::OK
    );
    // Another key needs its own approval.
    let (st, r) = fwd(&s.app, &b, s.payload("sensitive")).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(r["code"], "approval_pending");
}

// ── Order of the checks ───────────────────────────────────────────────────────

#[tokio::test]
async fn nobody_is_asked_about_a_request_that_is_refused_anyway() {
    let s = setup(|_| {}).await;
    // Key policy: `sensitive` is out of scope for this key.
    let (_, narrow) = {
        let (st, _, body) = call(
            &s.app,
            "POST",
            "/v1/admin/keys",
            &[("x-admin-key", ADMIN_KEY)],
            Some(r#"{"name":"narrow","credentials":["ordinary"],"methods":["GET"]}"#),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        (
            body["id"].as_str().unwrap().to_string(),
            body["token"].as_str().unwrap().to_string(),
        )
    };
    let (st, r) = fwd(&s.app, &narrow, s.payload("sensitive")).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(r.get("code").is_none(), "{r}");
    // Method not allowed.
    let post = json!({"request": {"method": "POST", "url": format!("{}/x", s.up.base()),
        "headers": {"Authorization": "Bearer {{vault:ordinary}}"}}});
    assert_eq!(fwd(&s.app, &narrow, post).await.0, StatusCode::FORBIDDEN);

    let (_, token) = s.key("agent-a", "[]").await;
    // Not bound to the target host.
    let elsewhere = json!({"request": {"method": "GET", "url": "http://127.0.0.1:9/x",
        "headers": {"Authorization": "Bearer {{vault:sensitive}}"}}});
    let (st, r) = fwd(&s.app, &token, elsewhere).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(
        r["error"].as_str().unwrap().contains("not be sent to"),
        "{r}"
    );
    // Unknown credential, and an unknown field of a sensitive one.
    let (st, _) = fwd(&s.app, &token, s.payload("nope")).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    let field = json!({"request": {"method": "GET", "url": format!("{}/x", s.up.base()),
        "headers": {"A": "{{vault:sensitive:field:ferrowarden_approval}}"}}});
    assert_eq!(
        fwd(&s.app, &token, field).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    assert!(s.pending().is_empty(), "no approval was opened");
    assert!(events_of(&s.state, "approval_requested").is_empty());
    assert_eq!(s.up.hits(), 0);
    assert_eq!(fake(&s.state).value_reads(), 0);
}

#[tokio::test]
async fn a_locked_vault_refuses_before_any_approval() {
    let s = setup(|_| {}).await;
    let (_, token) = s.key("agent-a", "[]").await;
    s.state.set_locked("vault_locked").await;
    // set_locked clears the credential cache: re-add the sensitive one.
    let mut e = CredentialEntry::login("s1", &[&s.up.base()]);
    e.approval_required = true;
    s.state
        .credentials
        .write()
        .await
        .insert("sensitive".into(), vec![e]);
    let (st, r) = fwd(&s.app, &token, s.payload("sensitive")).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "{r}");
    assert!(s.pending().is_empty());
}

#[tokio::test]
async fn captured_sessions_never_need_approval_themselves() {
    let up = login_service().await;
    let (app, state) = local_app(|c| c.approval.wait_secs = 1).await;
    // Everything asks for approval for this key, but sessions are not
    // credentials: the request that uses one has no vault placeholder.
    let (_, _, body) = call(
        &app,
        "POST",
        "/v1/admin/keys",
        &[("x-admin-key", ADMIN_KEY)],
        Some(r#"{"name":"sess","credentials":["*"],"methods":["*"],"approval":["*"]}"#),
    )
    .await;
    let token = body["token"].as_str().unwrap().to_string();
    login_all(&app, &token, &up.base()).await;
    let (st, used) = fwd(&app, &token, use_payload(&up.base(), bearer("jwt"))).await;
    assert_eq!(st, StatusCode::OK, "{used}");
    assert!(state.approvals.list(chrono::Utc::now()).0.is_empty());
}

// ── Limits ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_agent_cannot_open_more_approvals_than_the_limit() {
    let s = setup(|c| {
        c.approval.wait_secs = 20;
        c.approval.max_pending_per_key = 3;
    })
    .await;
    let (_, token) = s.key("flood", r#"["lim_*"]"#).await;
    let held: Vec<_> = ["a", "b", "c"]
        .iter()
        .map(|n| spawn_forward(&s, &token, s.payload(&format!("lim_{n}"))))
        .collect();
    s.wait_for_pending(3).await;

    // A fourth distinct approval is refused at once, with its own code.
    let started = std::time::Instant::now();
    let (st, r) = fwd(&s.app, &token, s.payload("lim_d")).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "{r}");
    assert_eq!(r["code"], "approval_limit_reached");
    assert!(started.elapsed() < HELD_FOR_20, "answered without a hold");
    assert_eq!(s.pending().len(), 3);
    assert_eq!(events_of(&s.state, "approval_requested").len(), 3);
    assert_eq!(
        forward_events(&s)[0]["event"]["reason"],
        "approval_limit_reached"
    );
    assert_eq!(s.up.hits(), 0);
    for h in held {
        h.abort();
    }
}

#[tokio::test]
async fn held_requests_per_key_are_limited_and_the_rest_answer_pending_at_once() {
    let s = setup(|c| {
        c.approval.wait_secs = 20;
        c.approval.max_waiters_per_key = 1;
    })
    .await;
    let (_, token) = s.key("agent-a", "[]").await;
    let held = spawn_forward(&s, &token, s.payload("sensitive"));
    let open = s.wait_for_pending(1).await;
    let started = std::time::Instant::now();
    let (st, r) = fwd(&s.app, &token, s.payload("sensitive")).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(r["code"], "approval_pending");
    assert_eq!(r["approval_id"], open[0].id.as_str());
    assert!(started.elapsed() < HELD_FOR_20, "not held");
    held.abort();
}

// ── Clearing ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn revoking_a_key_or_changing_its_policy_clears_its_approvals_and_grants() {
    let s = setup(|_| {}).await;
    let (id, token) = s.key("agent-a", r#"["policy_*"]"#).await;
    // A grant for `policy_item` and an open approval for `sensitive`.
    let (_, r) = fwd(&s.app, &token, s.payload("policy_item")).await;
    assert_eq!(
        s.approve(r["approval_id"].as_str().unwrap(), 30).await.0,
        StatusCode::OK
    );
    assert_eq!(
        fwd(&s.app, &token, s.payload("policy_item")).await.0,
        StatusCode::OK
    );
    let (_, r) = fwd(&s.app, &token, s.payload("sensitive")).await;
    let first_open = r["approval_id"].as_str().unwrap().to_string();
    assert_eq!(s.state.approvals.counts(chrono::Utc::now()), (1, 1));

    // Any policy change ends both: the key asks again.
    let (st, _) = admin(
        &s.app,
        "PATCH",
        &format!("/v1/admin/keys/{id}"),
        Some(r#"{"methods":["GET"]}"#),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(s.state.approvals.counts(chrono::Utc::now()), (0, 0));
    assert_eq!(s.approve(&first_open, 5).await.0, StatusCode::CONFLICT);
    let (st, r) = fwd(&s.app, &token, s.payload("policy_item")).await;
    assert_eq!(
        (st, r["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("approval_pending"))
    );
    assert_ne!(r["approval_id"], first_open.as_str());
    let causes = |action: &str| -> Vec<String> {
        events_of(&s.state, action)
            .iter()
            .map(|e| {
                e["ferrowarden"]["details"]["cause"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    };
    assert_eq!(causes("grant_revoked"), ["key_policy_change"]);
    assert_eq!(causes("approval_expired"), ["key_policy_change"]);

    // Revoking the key clears what is open, and a late decision is a 409.
    let open_id = r["approval_id"].as_str().unwrap().to_string();
    let (st, _) = admin(&s.app, "DELETE", &format!("/v1/admin/keys/{id}"), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(s.pending().is_empty());
    let (st, body) = s.approve(&open_id, 5).await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        causes("approval_expired"),
        ["key_revoke", "key_policy_change"]
    );
}

#[tokio::test]
async fn locking_the_vault_clears_every_approval_and_grant() {
    let s = setup(|_| {}).await;
    let (_, token) = s.key("agent-a", "[]").await;
    let (_, r) = fwd(&s.app, &token, s.payload("sensitive")).await;
    let id = r["approval_id"].as_str().unwrap().to_string();
    s.approve(&id, 30).await;
    // One grant, and one approval still open for another key.
    let (_, other) = s.key("agent-b", "[]").await;
    let (_, r) = fwd(&s.app, &other, s.payload("sensitive")).await;
    assert_eq!(r["code"], "approval_pending");
    assert_eq!(s.state.approvals.counts(chrono::Utc::now()), (1, 1));
    s.state.set_locked("vault_locked").await;
    assert_eq!(s.state.approvals.counts(chrono::Utc::now()), (0, 0));
    assert!(events_of(&s.state, "grant_revoked")
        .iter()
        .any(|e| e["ferrowarden"]["details"]["cause"] == "vault_lock"));
}

#[tokio::test]
async fn the_sweep_expires_open_approvals_and_grants_and_records_them() {
    let s = setup(|_| {}).await;
    let (_, token) = s.key("agent-a", "[]").await;
    let (_, r) = fwd(&s.app, &token, s.payload("sensitive")).await;
    let id = r["approval_id"].as_str().unwrap().to_string();
    s.approve(&id, 1).await;
    // A second key leaves an approval open.
    let (_, other) = s.key("agent-b", "[]").await;
    let (_, r) = fwd(&s.app, &other, s.payload("sensitive")).await;
    assert_eq!(r["code"], "approval_pending");
    assert_eq!(s.state.approvals.counts(chrono::Utc::now()), (1, 1));

    // Past both ends: the sweep removes them and records each once.
    let later = chrono::Utc::now() + chrono::Duration::hours(1);
    crate::approvals::sweep_once(&s.state, later);
    assert_eq!(s.state.approvals.counts(later), (0, 0));
    let grants = events_of(&s.state, "grant_expired");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["ferrowarden"]["key"]["name"], "agent-a");
    let expired = events_of(&s.state, "approval_expired");
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0]["ferrowarden"]["details"]["cause"], "timeout");
    // Swept once: a second sweep records nothing more.
    crate::approvals::sweep_once(&s.state, later);
    assert_eq!(events_of(&s.state, "grant_expired").len(), 1);
}

// ── The admin routes ──────────────────────────────────────────────────────────

#[tokio::test]
async fn the_agent_key_cannot_decide_or_list_anything() {
    let s = setup(|_| {}).await;
    let (_, token) = s.key("agent-a", "[]").await;
    let (_, r) = fwd(&s.app, &token, s.payload("sensitive")).await;
    let id = r["approval_id"].as_str().unwrap().to_string();
    let (st, _) = s.approve(&id, 5).await;
    assert_eq!(st, StatusCode::OK);
    let grant_id = s.state.approvals.list(chrono::Utc::now()).1[0].id.clone();
    // An open approval to try to decide.
    let (_, _, body) = call(
        &s.app,
        "POST",
        "/v1/admin/keys",
        &[("x-admin-key", ADMIN_KEY)],
        Some(r#"{"name":"b","credentials":["*"],"methods":["*"],"approval":["policy_*"]}"#),
    )
    .await;
    let b_token = body["token"].as_str().unwrap().to_string();
    let (_, r) = fwd(&s.app, &b_token, s.payload("policy_item")).await;
    let open = r["approval_id"].as_str().unwrap().to_string();

    // The agent key, in either header an admin could use, is refused on every
    // route that decides or lists, and nothing changes.
    let routes: [(&str, String, Option<&str>); 4] = [
        ("GET", "/v1/admin/approvals".into(), None),
        (
            "POST",
            format!("/v1/admin/approvals/{open}/approve"),
            Some(r#"{"minutes":5}"#),
        ),
        ("POST", format!("/v1/admin/approvals/{open}/deny"), None),
        ("DELETE", format!("/v1/admin/grants/{grant_id}"), None),
    ];
    for (method, path, body) in &routes {
        for header in ["x-agent-key", "x-admin-key", "authorization"] {
            let value = if header == "authorization" {
                format!("Bearer {token}")
            } else {
                token.clone()
            };
            let (st, _, _) = call(&s.app, method, path, &[(header, &value)], *body).await;
            assert_eq!(
                st,
                StatusCode::UNAUTHORIZED,
                "{method} {path} with {header}"
            );
        }
        let (st, _, _) = call(&s.app, method, path, &[], *body).await;
        assert_eq!(
            st,
            StatusCode::UNAUTHORIZED,
            "{method} {path} without a key"
        );
    }
    assert_eq!(s.pending().len(), 1, "the approval is still open");
    assert_eq!(s.state.approvals.counts(chrono::Utc::now()).1, 1);
    assert!(events_of(&s.state, "approval_granted").len() == 1);
    assert!(events_of(&s.state, "approval_denied").is_empty());
    assert!(events_of(&s.state, "grant_revoked").is_empty());
    // The failures are `admin_auth` events, with no key value in them.
    assert!(!all_events_text(&s.state).contains(&token));

    // The agent API has no route that decides at all.
    for path in ["/v1/approvals", "/v1/approvals/x/approve", "/v1/grants/x"] {
        let (st, _, _) = call(&s.app, "POST", path, &[("x-agent-key", &token)], Some("{}")).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn approving_needs_a_valid_length_and_a_strict_body() {
    let s = setup(|c| c.approval.max_grant_minutes = 60).await;
    let (_, token) = s.key("agent-a", "[]").await;
    let (_, r) = fwd(&s.app, &token, s.payload("sensitive")).await;
    let id = r["approval_id"].as_str().unwrap().to_string();
    let path = format!("/v1/admin/approvals/{id}/approve");
    for body in [
        None,
        Some("{}"),
        Some(r#"{"minutes":0}"#),
        Some(r#"{"minutes":61}"#),
        Some(r#"{"minutes":-5}"#),
        Some(r#"{"minutes":1.5}"#),
        Some(r#"{"minutes":"15"}"#),
        Some(r#"{"minutes":null}"#),
        Some(r#"{"minutes":99999999999}"#),
        Some(r#"{"minutes":5,"extra":1}"#),
        Some(r#"{"minutes":5,"minutes":6}"#),
        Some("[15]"),
    ] {
        let (st, resp) = admin(&s.app, "POST", &path, body).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body:?}: {resp}");
    }
    assert_eq!(s.pending().len(), 1, "a bad request decides nothing");
    // The bounds themselves are fine.
    let (st, _) = admin(&s.app, "POST", &path, Some(r#"{"minutes":60}"#)).await;
    assert_eq!(st, StatusCode::OK);
    let grant = &s.state.approvals.list(chrono::Utc::now()).1[0];
    assert!(grant.expires - grant.created == chrono::Duration::minutes(60));
}

#[tokio::test]
async fn deciding_an_approval_that_is_not_pending_is_a_409_and_changes_nothing() {
    let s = setup(|_| {}).await;
    let (_, token) = s.key("agent-a", "[]").await;
    let (_, r) = fwd(&s.app, &token, s.payload("sensitive")).await;
    let id = r["approval_id"].as_str().unwrap().to_string();
    assert_eq!(s.approve(&id, 5).await.0, StatusCode::OK);
    // Decided: neither another approval nor a denial.
    let (st, body) = s.approve(&id, 5).await;
    assert_eq!(st, StatusCode::CONFLICT, "{body}");
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("no longer pending"));
    assert_eq!(s.decide(&id, "deny", None).await.0, StatusCode::CONFLICT);
    assert_eq!(s.state.approvals.counts(chrono::Utc::now()), (0, 1));
    // Unknown and malformed ids are the same answer.
    for bad in ["nope", "x".repeat(60).as_str(), "..%2F..", "a.b"] {
        assert_eq!(s.approve(bad, 5).await.0, StatusCode::CONFLICT, "{bad}");
        assert_eq!(
            s.decide(bad, "deny", None).await.0,
            StatusCode::CONFLICT,
            "{bad}"
        );
    }
    // The failed attempts are recorded, as failures.
    assert!(events_of(&s.state, "approval_granted")
        .iter()
        .any(|e| e["event"]["outcome"] == "failure"));
}

#[tokio::test]
async fn the_list_and_the_grant_revocation_work_through_the_admin_api() {
    let s = setup(|_| {}).await;
    let (_, token) = s.key("agent-a", "[]").await;
    let (_, r) = fwd(&s.app, &token, s.payload_at("sensitive", "/a?secret=1")).await;
    let id = r["approval_id"].as_str().unwrap().to_string();

    let (st, list) = admin(&s.app, "GET", "/v1/admin/approvals", None).await;
    assert_eq!(st, StatusCode::OK);
    let p = &list["pending"][0];
    assert_eq!(p["id"], id.as_str());
    assert_eq!(p["key"]["name"], "agent-a");
    assert_eq!(p["credentials"][0]["credential"], "sensitive");
    assert_eq!(p["credentials"][0]["reasons"], json!(["vault_field"]));
    assert_eq!(p["method"], "GET");
    assert_eq!(p["origin"]["scheme"], "http");
    assert!(p["url"].as_str().unwrap().contains("/a?secret=1"));
    assert!(list["grants"].as_array().unwrap().is_empty());
    assert!(!list.to_string().contains(SENSITIVE_VALUE));

    s.approve(&id, 5).await;
    let (_, list) = admin(&s.app, "GET", "/v1/admin/approvals", None).await;
    assert!(list["pending"].as_array().unwrap().is_empty());
    let grant = &list["grants"][0];
    assert_eq!(grant["credentials"], json!(["sensitive"]));
    let grant_id = grant["id"].as_str().unwrap().to_string();

    // Revoke early: the next request asks again.
    let (st, body) = admin(
        &s.app,
        "DELETE",
        &format!("/v1/admin/grants/{grant_id}"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "revoked");
    let (st, r) = fwd(&s.app, &token, s.payload("sensitive")).await;
    assert_eq!(
        (st, r["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("approval_pending"))
    );
    let revoked = &events_of(&s.state, "grant_revoked")[0];
    assert_eq!(revoked["ferrowarden"]["details"]["approver"], "admin_api");
    // Again, or an unknown id: 404.
    for id in [grant_id.as_str(), "nope"] {
        let (st, _) = admin(&s.app, "DELETE", &format!("/v1/admin/grants/{id}"), None).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
    }
}

// ── Preview and key policy ────────────────────────────────────────────────────

#[tokio::test]
async fn the_preview_says_what_would_need_approval_and_asks_for_nothing() {
    let s = setup(|_| {}).await;
    let (id, _) = s.key("agent-a", "[]").await;
    let body = json!({
        "approval": ["policy_*"],
        "request": {"method": "GET", "url": format!("{}/x", s.up.base()),
            "headers": {"A": "{{vault:sensitive}}", "B": "{{vault:policy_item}}", "C": "{{vault:ordinary}}"}}
    })
    .to_string();
    let (st, j) = admin(
        &s.app,
        "POST",
        &format!("/v1/admin/keys/{id}/preview"),
        Some(&body),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let need: Vec<(&str, Vec<&str>)> = j["approval_required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            (
                n["credential"].as_str().unwrap(),
                n["reasons"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| r.as_str().unwrap())
                    .collect(),
            )
        })
        .collect();
    assert_eq!(
        need,
        [
            ("policy_item", vec!["key_policy"]),
            ("sensitive", vec!["vault_field"])
        ]
    );
    assert_eq!(j["draft_policy"]["approval"], json!(["policy_*"]));
    assert_eq!(j["saved_policy"]["approval"], json!([]));
    let check = &j["request_check"];
    assert_eq!(check["allowed"], true);
    assert_eq!(check["approval"].as_array().unwrap().len(), 2);
    // Nothing was asked, held, fetched or sent.
    assert!(s.pending().is_empty());
    assert!(events_of(&s.state, "approval_requested").is_empty());
    assert_eq!(fake(&s.state).value_reads(), 0);
    assert_eq!(s.up.hits(), 0);
}

#[tokio::test]
async fn the_approval_list_of_a_key_is_validated_patched_and_never_null() {
    let s = setup(|_| {}).await;
    let (id, _) = s.key("agent-a", r#"["a_*","b"]"#).await;
    let path = format!("/v1/admin/keys/{id}");
    // Absent is unchanged; present replaces; null and wrong types are errors.
    let (st, j) = admin(&s.app, "PATCH", &path, Some(r#"{"methods":["GET"]}"#)).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(j["approval"], json!(["a_*", "b"]));
    let (_, j) = admin(&s.app, "PATCH", &path, Some(r#"{"approval":["c"]}"#)).await;
    assert_eq!(j["approval"], json!(["c"]));
    for (body, needle) in [
        (
            r#"{"approval":null}"#,
            "must be an array of strings, not null",
        ),
        (r#"{"approval":"*"}"#, "`approval`"),
        (r#"{"approval":[""]}"#, "approval[0]"),
        (r#"{"approval":["a\u0001"]}"#, "control characters"),
    ] {
        let (st, j) = admin(&s.app, "PATCH", &path, Some(body)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert!(j["error"].as_str().unwrap().contains(needle), "{body}: {j}");
    }
    let (_, j) = admin(&s.app, "PATCH", &path, Some(r#"{"approval":["x","*"]}"#)).await;
    assert_eq!(j["approval"], json!(["*"]));
    let (_, j) = admin(&s.app, "PATCH", &path, Some(r#"{"approval":[]}"#)).await;
    assert_eq!(j["approval"], json!([]));
    // Creating: optional, but never null.
    let (st, _, j) = call(
        &s.app,
        "POST",
        "/v1/admin/keys",
        &[("x-admin-key", ADMIN_KEY)],
        Some(r#"{"name":"n","credentials":["*"],"methods":["*"],"approval":null}"#),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{j}");
    let (st, _, j) = call(
        &s.app,
        "POST",
        "/v1/admin/keys",
        &[("x-admin-key", ADMIN_KEY)],
        Some(r#"{"name":"n","credentials":["*"],"methods":["*"]}"#),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(j["approval"], json!([]));
    // The list shows it.
    let (_, list) = admin(&s.app, "GET", "/v1/admin/keys", None).await;
    assert!(list
        .as_array()
        .unwrap()
        .iter()
        .all(|k| k["approval"].is_array()));
}

#[tokio::test]
async fn the_approval_decisions_never_leave_a_value_in_an_event() {
    let s = setup(|c| c.approval.wait_secs = 20).await;
    let (_, token) = s.key("agent-a", "[]").await;
    let held = spawn_forward(&s, &token, s.payload("sensitive"));
    let open = s.wait_for_pending(1).await;
    s.approve(&open[0].id, 5).await;
    held.await.unwrap();
    let text = all_events_text(&s.state);
    for value in [SENSITIVE_VALUE, ORDINARY_VALUE, POLICY_VALUE, &token] {
        assert!(!text.contains(value));
    }
    // The prompt event has the names, the host and the path, not the query.
    let req = &events_of(&s.state, "approval_requested")[0];
    let d = &req["ferrowarden"]["details"];
    assert_eq!(d["path"], "/x");
    assert_eq!(d["approval_id"], open[0].id.as_str());
    assert_eq!(d["reasons"]["sensitive"], json!(["vault_field"]));
    assert_eq!(req["ferrowarden"]["credentials"], json!(["sensitive"]));
    assert!(d["host"].as_str().unwrap().starts_with("127.0.0.1:"));
}
