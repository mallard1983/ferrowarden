//! `POST /v1/credentials/{name}/rotate` and its commit and abort, through the
//! real router: the order of the checks, the approval (hold, outcomes, one
//! use), the writes on the fake vault, the admin abort, and the promise that
//! the generated value is in no response, event or metric.
//!
//! The vault is the in-memory fake: it records what was done to which item
//! (`rotate_calls`), and keeps the values apart (readable only through
//! `password_of` and `next_of`), so a test can say "nothing was generated or
//! written" with an empty list of calls.

use super::*;
use crate::approvals::{ApprovalKind, PendingView};
use crate::vault::fake::FakeVault;
use crate::vault::model::{ManagedCollection, ManagedProblem, ManagedState};
use std::time::Duration;

const COLLECTION_ID: &str = "6c0d7f0e-52d0-4b5b-8a39-0e8a7f6d5c4b";
const NAME: &str = "agent_keycloak_svc";
const OLD: &str = "the-current-password-0123456789";

fn fake(state: &AppState) -> &FakeVault {
    match &*state.vault {
        crate::vault::ActiveVault::Fake(f) => f,
        _ => unreachable!("the test state uses the fake vault"),
    }
}

fn usable() -> ManagedState {
    ManagedState::Usable(ManagedCollection {
        id: COLLECTION_ID.to_string(),
        organization_id: "org-1".to_string(),
        name: "Ferrowarden managed".to_string(),
        items: 0,
    })
}

struct Setup {
    app: Router,
    state: Arc<AppState>,
    /// The id of the managed item `NAME`.
    item: String,
}

async fn setup(tweak: impl FnOnce(&mut Config)) -> Setup {
    let (app, state) = local_app(|c| {
        c.approval.wait_secs = 1;
        c.approval.pending_ttl_secs = 30;
        tweak(c);
    })
    .await;
    fake(&state).set_managed(usable());
    let item = fake(&state).add_managed_item(NAME, &["http://127.0.0.1:9"], OLD);
    Setup { app, state, item }
}

/// The encoded path of a rotation call for `name`.
fn path(name: &str, tail: &str) -> String {
    let mut encoded = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            encoded.push(b as char);
        } else {
            encoded.push_str(&format!("%{b:02X}"));
        }
    }
    format!("/v1/credentials/{encoded}/rotate{tail}")
}

impl Setup {
    async fn key_with(&self, name: &str, credentials: &str, rotate: &str) -> String {
        let (s, body) = admin(
            &self.app,
            "POST",
            "/v1/admin/keys",
            Some(&format!(
                r#"{{"name":"{name}","credentials":{credentials},"methods":["*"],"rotate":{rotate}}}"#
            )),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{body}");
        body["token"].as_str().unwrap().to_string()
    }

    /// A key that may rotate `agent_*`.
    async fn key(&self, name: &str) -> String {
        self.key_with(name, r#"["*"]"#, r#"["agent_*"]"#).await
    }

    async fn post(
        &self,
        token: &str,
        p: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let body = body.map(|b| b.to_string());
        let (s, _, j) = call(
            &self.app,
            "POST",
            p,
            &[("x-agent-key", token)],
            body.as_deref(),
        )
        .await;
        (s, j)
    }

    async fn start(&self, token: &str, name: &str) -> (StatusCode, serde_json::Value) {
        self.post(token, &path(name, ""), None).await
    }

    fn spawn_start(
        &self,
        token: &str,
        name: &str,
        body: Option<serde_json::Value>,
    ) -> tokio::task::JoinHandle<(StatusCode, serde_json::Value)> {
        let (app, token, p) = (self.app.clone(), token.to_string(), path(name, ""));
        tokio::spawn(async move {
            let body = body.map(|b| b.to_string());
            let (s, _, j) = call(
                &app,
                "POST",
                &p,
                &[("x-agent-key", token.as_str())],
                body.as_deref(),
            )
            .await;
            (s, j)
        })
    }

    fn pending(&self) -> Vec<PendingView> {
        self.state.approvals.list(chrono::Utc::now()).0
    }

    async fn wait_for_pending(&self, n: usize) -> Vec<PendingView> {
        for _ in 0..1500 {
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

    /// A rotation started and approved: the pending value exists.
    async fn started(&self, token: &str) {
        let held = self.spawn_start(token, NAME, None);
        let open = self.wait_for_pending(1).await;
        assert_eq!(self.decide(&open[0].id, "approve", None).await.0, 200);
        let (st, resp) = held.await.unwrap();
        assert_eq!(st, StatusCode::ACCEPTED, "{resp}");
    }

    /// Nothing was asked of a human, generated or written.
    fn assert_untouched(&self) {
        assert!(self.pending().is_empty(), "an approval was opened");
        assert_eq!(fake(&self.state).rotate_calls(), Vec::<String>::new());
        assert!(events_of(&self.state, "approval_requested").is_empty());
    }
}

// ── The whole story ───────────────────────────────────────────────────────────

#[tokio::test]
async fn a_rotation_is_held_approved_started_listed_committed_and_the_value_is_nowhere() {
    let s = setup(|c| c.approval.wait_secs = 20).await;
    let token = s.key("agent-a").await;
    let held = s.spawn_start(
        &token,
        NAME,
        Some(json!({"generate": {"length": 40, "charset": "hex"}})),
    );

    // Held: an approval of the rotate kind is open, and nothing is written.
    let open = s.wait_for_pending(1).await;
    assert_eq!(open[0].kind, ApprovalKind::Rotate);
    assert_eq!(open[0].key_name, "agent-a");
    assert!(open[0].create.is_none());
    let detail = open[0].rotate.as_ref().unwrap();
    assert_eq!(detail.name, NAME);
    assert_eq!(detail.collection, "Ferrowarden managed");
    assert_eq!((detail.charset.as_str(), detail.length), ("hex", 40));
    assert!(
        fake(&s.state).rotate_calls().is_empty(),
        "nothing before approval"
    );
    assert!(!held.is_finished());

    // The admin API lists it with its kind and what it asks for.
    let (st, listed) = admin(&s.app, "GET", "/v1/admin/approvals", None).await;
    assert_eq!(st, StatusCode::OK);
    let p = &listed["pending"][0];
    assert_eq!(p["kind"], "rotate");
    assert_eq!(p["rotate"]["name"], NAME);
    assert_eq!(
        p["rotate"]["generate"],
        json!({"charset": "hex", "length": 40})
    );
    assert_eq!(p["rotate"]["collection"], "Ferrowarden managed");
    assert!(p.get("create").is_none() && p.get("method").is_none() && p.get("url").is_none());

    // Approve with no body: no duration.
    let (st, body) = s.decide(&open[0].id, "approve", None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"status": "approved", "kind": "rotate"}));

    let (st, started) = held.await.unwrap();
    assert_eq!(st, StatusCode::ACCEPTED, "{started}");
    assert_eq!(
        started,
        json!({
            "name": NAME,
            "current": format!("{{{{vault:{NAME}}}}}"),
            "next": format!("{{{{vault:{NAME}:next}}}}"),
        })
    );
    assert_eq!(fake(&s.state).rotate_calls(), [format!("start:{}", s.item)]);

    // The pending value has the length and characters asked for; the current
    // password is untouched.
    let next = fake(&s.state).next_of(&s.item).unwrap();
    assert_eq!(next.len(), 40);
    assert!(next.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(fake(&s.state).password_of(&s.item).as_deref(), Some(OLD));

    // The listing shows the pending rotation and the `next` placeholder.
    let (st, _, listing) = call(
        &s.app,
        "GET",
        "/v1/credentials?detail=true",
        &[("x-agent-key", &token)],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let entry = listing
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == NAME)
        .unwrap();
    assert_eq!(entry["rotation_pending"], true);
    assert_eq!(entry["next"], format!("{{{{vault:{NAME}:next}}}}"));
    assert_eq!(entry["placeholder"], format!("{{{{vault:{NAME}}}}}"));

    // A second start is refused before any prompt.
    let before = events_of(&s.state, "approval_requested").len();
    let (st, resp) = s.start(&token, NAME).await;
    assert_eq!(
        (st, resp["code"].as_str()),
        (StatusCode::CONFLICT, Some("rotation_in_progress"))
    );
    assert_eq!(events_of(&s.state, "approval_requested").len(), before);

    // Commit: no approval, and the pending value is now the password.
    let (st, done) = s.post(&token, &path(NAME, "/commit"), None).await;
    assert_eq!(st, StatusCode::OK, "{done}");
    assert_eq!(
        done,
        json!({"name": NAME, "placeholder": format!("{{{{vault:{NAME}}}}}")})
    );
    assert_eq!(s.pending().len(), 0, "no second approval");
    assert_eq!(fake(&s.state).password_of(&s.item), Some(next.clone()));
    assert_eq!(fake(&s.state).next_of(&s.item), None);
    assert_eq!(fake(&s.state).history_len(&s.item), 1);

    // ...and again is "no rotation pending".
    let (st, resp) = s.post(&token, &path(NAME, "/commit"), None).await;
    assert_eq!(
        (st, resp["code"].as_str()),
        (StatusCode::CONFLICT, Some("no_rotation_pending"))
    );

    // Neither value is in a response, an event or the log-like text.
    let everything = format!("{started} {done} {listing} {}", all_events_text(&s.state));
    assert!(!everything.contains(&next), "the new value");
    assert!(!everything.contains(OLD), "the old value");

    // The events: the prompt (kind rotate), the decision (no grant), the start
    // and the commit, by the agent.
    let requested = &events_of(&s.state, "approval_requested")[0];
    assert_eq!(requested["ferrowarden"]["details"]["kind"], "rotate");
    assert_eq!(requested["ferrowarden"]["details"]["rotate"]["name"], NAME);
    let granted = &events_of(&s.state, "approval_granted")[0];
    assert_eq!(granted["ferrowarden"]["details"]["kind"], "rotate");
    assert!(granted["ferrowarden"]["details"].get("grant_id").is_none());
    assert!(
        s.state.approvals.list(chrono::Utc::now()).1.is_empty(),
        "not a grant"
    );
    let start = events_of(&s.state, "credential_rotate_start")
        .into_iter()
        .find(|e| e["event"]["outcome"] == "success")
        .expect("a start was recorded");
    assert_eq!(start["event"]["outcome"], "success");
    assert_eq!(start["ferrowarden"]["key"]["name"], "agent-a");
    assert_eq!(start["ferrowarden"]["credentials"][0], NAME);
    assert_eq!(start["ferrowarden"]["details"]["item_id"], s.item.as_str());
    assert_eq!(
        start["ferrowarden"]["details"]["collection_id"],
        COLLECTION_ID
    );
    assert_eq!(start["ferrowarden"]["details"]["by"], "agent");
    let commits = events_of(&s.state, "credential_rotate_commit");
    let commit = commits
        .iter()
        .find(|e| e["event"]["outcome"] == "success")
        .expect("a commit was recorded");
    assert_eq!(commit["ferrowarden"]["details"]["by"], "agent");
    assert!(commits
        .iter()
        .any(|e| e["event"]["reason"] == "no_rotation_pending"));
}

#[tokio::test]
async fn the_body_may_be_left_out_and_the_defaults_are_32_alphanumeric() {
    let s = setup(|c| c.approval.wait_secs = 20).await;
    let token = s.key("agent-a").await;
    let held = s.spawn_start(&token, NAME, None);
    let open = s.wait_for_pending(1).await;
    let d = open[0].rotate.as_ref().unwrap();
    assert_eq!((d.charset.as_str(), d.length), ("alphanumeric", 32));
    s.decide(&open[0].id, "approve", None).await;
    assert_eq!(held.await.unwrap().0, StatusCode::ACCEPTED);
    let next = fake(&s.state).next_of(&s.item).unwrap();
    assert_eq!(next.len(), 32);
    assert!(next.bytes().all(|b| b.is_ascii_alphanumeric()));
}

#[tokio::test]
async fn abort_removes_the_pending_value_and_needs_no_approval() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    s.started(&token).await;
    let (st, done) = s.post(&token, &path(NAME, "/abort"), None).await;
    assert_eq!(st, StatusCode::OK, "{done}");
    assert_eq!(done["name"], NAME);
    assert_eq!(fake(&s.state).next_of(&s.item), None);
    assert_eq!(fake(&s.state).password_of(&s.item).as_deref(), Some(OLD));
    assert_eq!(fake(&s.state).history_len(&s.item), 0);
    let (st, resp) = s.post(&token, &path(NAME, "/abort"), Some(json!({}))).await;
    assert_eq!(
        (st, resp["code"].as_str()),
        (StatusCode::CONFLICT, Some("no_rotation_pending"))
    );
    assert_eq!(
        events_of(&s.state, "credential_rotate_abort")[0]["ferrowarden"]["details"]["by"],
        "agent"
    );
    // A new rotation can start again.
    let held = s.spawn_start(&token, NAME, None);
    let open = s.wait_for_pending(1).await;
    s.decide(&open[0].id, "approve", None).await;
    assert_eq!(held.await.unwrap().0, StatusCode::ACCEPTED);
}

// ── Names in the path ─────────────────────────────────────────────────────────

#[tokio::test]
async fn a_name_with_spaces_quotes_and_slashes_is_passed_percent_encoded() {
    let s = setup(|_| {}).await;
    let odd = "agent_Service (prod) 'x'/y";
    let id = fake(&s.state).add_managed_item(odd, &["http://127.0.0.1:9"], OLD);
    let token = s.key("agent-a").await;
    let held = s.spawn_start(&token, odd, None);
    let open = s.wait_for_pending(1).await;
    assert_eq!(open[0].rotate.as_ref().unwrap().name, odd);
    s.decide(&open[0].id, "approve", None).await;
    let (st, resp) = held.await.unwrap();
    assert_eq!(st, StatusCode::ACCEPTED, "{resp}");
    // The answer's placeholders are quoted, ready to paste.
    assert_eq!(
        resp["current"],
        "{{vault:'agent_Service (prod) \\'x\\'/y'}}"
    );
    assert_eq!(
        resp["next"],
        "{{vault:'agent_Service (prod) \\'x\\'/y':next}}"
    );
    assert!(fake(&s.state).next_of(&id).is_some());
    let (st, _) = s.post(&token, &path(odd, "/commit"), None).await;
    assert_eq!(st, StatusCode::OK);
    // Non-ASCII names too.
    let accented = "agent_dépôt";
    fake(&s.state).add_managed_item(accented, &["http://127.0.0.1:9"], OLD);
    let (st, resp) = s.post(&token, &path(accented, "/abort"), None).await;
    assert_eq!(
        (st, resp["code"].as_str()),
        (StatusCode::CONFLICT, Some("no_rotation_pending"))
    );
}

// ── Refusals come before any prompt ───────────────────────────────────────────

#[tokio::test]
async fn a_name_outside_the_keys_rotate_list_is_refused_before_any_prompt() {
    let s = setup(|_| {}).await;
    fake(&s.state).add_managed_item("grafana_svc", &["http://127.0.0.1:9"], OLD);
    let token = s.key("agent-a").await;
    let (st, resp) = s.start(&token, "grafana_svc").await;
    assert_eq!(
        (st, resp["code"].as_str()),
        (
            StatusCode::FORBIDDEN,
            Some("credential_rotate_out_of_scope")
        )
    );
    // A key with no rotate patterns at all, and `create` is not `rotate`.
    let none = s.key_with("agent-b", r#"["*"]"#, "[]").await;
    for tail in ["", "/commit", "/abort"] {
        let (st, resp) = s.post(&none, &path(NAME, tail), None).await;
        assert_eq!(
            (st, resp["code"].as_str()),
            (
                StatusCode::FORBIDDEN,
                Some("credential_rotate_out_of_scope")
            ),
            "{tail}"
        );
    }
    s.assert_untouched();
}

#[tokio::test]
async fn an_item_outside_the_managed_collection_is_not_managed_whether_or_not_it_exists() {
    let s = setup(|_| {}).await;
    // An item of the vault that is not in the managed collection.
    fake(&s.state).add_item("agent_personal", &["http://127.0.0.1:9"]);
    let token = s.key("agent-a").await;
    let (st1, r1) = s.start(&token, "agent_personal").await;
    let (st2, r2) = s.start(&token, "agent_nothing_of_the_kind").await;
    assert_eq!(
        (st1, r1["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("credential_not_managed"))
    );
    assert_eq!(st1, st2);
    assert_eq!(r1["code"], r2["code"]);
    // The message names what the caller asked for, nothing else: one shape.
    assert_eq!(
        r1["error"].as_str().unwrap().replace("agent_personal", "X"),
        r2["error"]
            .as_str()
            .unwrap()
            .replace("agent_nothing_of_the_kind", "X")
    );
    for tail in ["/commit", "/abort"] {
        let (st, resp) = s.post(&token, &path("agent_personal", tail), None).await;
        assert_eq!(
            (st, resp["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("credential_not_managed"))
        );
    }
    s.assert_untouched();
}

#[tokio::test]
async fn a_name_outside_the_credentials_scope_is_answered_like_one_that_does_not_exist() {
    let s = setup(|_| {}).await;
    // May rotate anything, but may only see `lab_*`: the managed item `NAME`
    // is outside what it can see.
    let token = s.key_with("agent-a", r#"["lab_*"]"#, r#"["*"]"#).await;
    let (st1, r1) = s.start(&token, NAME).await;
    let (st2, r2) = s.start(&token, "agent_that_does_not_exist").await;
    assert_eq!(
        (st1, r1["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("credential_not_managed"))
    );
    assert_eq!((st1, &r1["code"]), (st2, &r2["code"]));
    s.assert_untouched();
}

#[tokio::test]
async fn only_a_login_with_a_password_and_no_reprompt_that_is_unique_can_be_rotated() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    let reprompt = fake(&s.state).add_managed_item("agent_reprompt", &["http://127.0.0.1:9"], OLD);
    fake(&s.state).edit_item(&reprompt, |e| e.reprompt = true);
    let nopass = fake(&s.state).add_managed_item("agent_nopass", &["http://127.0.0.1:9"], OLD);
    fake(&s.state).edit_item(&nopass, |e| e.has_password = false);
    let note = fake(&s.state).add_managed_item("agent_note", &["http://127.0.0.1:9"], OLD);
    fake(&s.state).edit_item(&note, |e| {
        e.kind = crate::vault::model::ItemKind::SecureNote
    });
    for name in ["agent_reprompt", "agent_nopass", "agent_note"] {
        for tail in ["", "/commit", "/abort"] {
            let (st, resp) = s.post(&token, &path(name, tail), None).await;
            assert_eq!(
                (st, resp["code"].as_str()),
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Some("credential_not_rotatable")
                ),
                "{name}{tail}"
            );
        }
    }
    // Two items with one name: ambiguous (the ordinary conflict, no code).
    fake(&s.state).add_managed_item(NAME, &["http://127.0.0.1:9"], OLD);
    let (st, resp) = s.start(&token, NAME).await;
    assert_eq!(st, StatusCode::CONFLICT, "{resp}");
    assert!(resp.get("code").is_none());
    s.assert_untouched();
}

#[tokio::test]
async fn rotating_is_off_without_a_managed_collection_and_503_when_it_is_unusable() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    fake(&s.state).set_managed(ManagedState::Off);
    let (st, resp) = s.start(&token, NAME).await;
    assert_eq!(
        (st, resp["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("credential_create_disabled"))
    );
    fake(&s.state).set_managed(ManagedState::Unavailable {
        setting: "Ferrowarden managed".into(),
        problem: ManagedProblem::ReadOnly,
    });
    for tail in ["", "/commit", "/abort"] {
        let (st, resp) = s.post(&token, &path(NAME, tail), None).await;
        assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "{tail}");
        assert_eq!(resp["code"], "managed_collection_unavailable");
        assert_eq!(resp["reason"], "read_only");
    }
    s.assert_untouched();
}

#[tokio::test]
async fn a_locked_vault_refuses_before_any_prompt() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    fake(&s.state).set_locked(true);
    let (st, _) = s.start(&token, NAME).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    s.assert_untouched();
}

#[tokio::test]
async fn every_field_is_validated_before_any_prompt() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    let bad = [
        json!({"generate": {"length": 15}}),
        json!({"generate": {"length": 129}}),
        json!({"generate": {"length": -1}}),
        json!({"generate": {"length": "32"}}),
        json!({"generate": {"charset": "emoji"}}),
        json!({"generate": {"charset": null}}),
        json!({"generate": null}),
        json!({"generate": {"length": 32, "extra": 1}}),
        json!({"name": "other"}),
        json!([]),
        json!("text"),
    ];
    for body in bad {
        let (st, resp) = s.post(&token, &path(NAME, ""), Some(body.clone())).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}: {resp}");
    }
    // A name that is empty or too long, in every phase.
    let long = "n".repeat(129);
    for tail in ["", "/commit", "/abort"] {
        let (st, _) = s.post(&token, &path(&long, tail), None).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{tail}");
    }
    // A commit or an abort takes no body.
    for tail in ["/commit", "/abort"] {
        let (st, resp) = s
            .post(&token, &path(NAME, tail), Some(json!({"generate": {}})))
            .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{tail}: {resp}");
    }
    s.assert_untouched();
}

#[tokio::test]
async fn the_agent_is_authenticated_before_the_body_is_read() {
    let s = setup(|_| {}).await;
    for tail in ["", "/commit", "/abort"] {
        let (st, _, _) = call(
            &s.app,
            "POST",
            &path(NAME, tail),
            &[("x-agent-key", "wrong-key")],
            Some("{ not json"),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{tail}");
        let (st, _, _) = call(&s.app, "POST", &path(NAME, tail), &[], None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{tail}");
    }
    s.assert_untouched();
}

// ── The approval ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_denied_start_writes_nothing_and_stays_denied_without_a_new_prompt() {
    let s = setup(|c| c.approval.wait_secs = 20).await;
    let token = s.key("agent-a").await;
    let held = s.spawn_start(&token, NAME, None);
    let open = s.wait_for_pending(1).await;
    assert_eq!(s.decide(&open[0].id, "deny", None).await.0, StatusCode::OK);
    let (st, resp) = held.await.unwrap();
    assert_eq!(
        (st, resp["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("approval_denied"))
    );
    assert!(
        fake(&s.state).rotate_calls().is_empty(),
        "nothing generated or written"
    );
    assert_eq!(fake(&s.state).next_of(&s.item), None);

    let (st, resp) = s.start(&token, NAME).await;
    assert_eq!(
        (st, resp["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("approval_denied"))
    );
    assert_eq!(
        events_of(&s.state, "approval_requested").len(),
        1,
        "nobody is asked again"
    );
    assert!(fake(&s.state).rotate_calls().is_empty());
    let ev = &events_of(&s.state, "credential_rotate_start");
    assert_eq!(ev[0]["event"]["reason"], "approval_denied");
}

#[tokio::test]
async fn an_undecided_start_is_pending_and_the_identical_retry_uses_the_approval_once() {
    let s = setup(|_| {}).await; // wait_secs = 1
    let token = s.key("agent-a").await;
    let (st, resp) = s.start(&token, NAME).await;
    assert_eq!(
        (st, resp["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("approval_pending"))
    );
    let id = resp["approval_id"].as_str().unwrap().to_string();
    assert!(fake(&s.state).rotate_calls().is_empty());
    // The same request again reuses the open approval.
    let (_, resp) = s.start(&token, NAME).await;
    assert_eq!(resp["approval_id"], id.as_str());
    assert_eq!(events_of(&s.state, "approval_requested").len(), 1);

    // Approved while nobody waits: the retry gets through, once.
    assert_eq!(s.decide(&id, "approve", None).await.0, StatusCode::OK);
    assert!(
        fake(&s.state).rotate_calls().is_empty(),
        "approving writes nothing"
    );
    let (st, resp) = s.start(&token, NAME).await;
    assert_eq!(st, StatusCode::ACCEPTED, "{resp}");
    assert_eq!(fake(&s.state).rotate_calls().len(), 1);
    // Used up: a new start (after the rotation was aborted) asks again.
    s.post(&token, &path(NAME, "/abort"), None).await;
    let (st, resp) = s.start(&token, NAME).await;
    assert_eq!(
        (st, resp["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("approval_pending"))
    );
    assert_ne!(resp["approval_id"], id.as_str());
}

#[tokio::test]
async fn an_approval_covers_one_operation_only() {
    let s = setup(|c| c.approval.max_pending_per_key = 50).await;
    let token = s.key("agent-a").await;
    let other_item = fake(&s.state).add_managed_item("agent_other", &["http://127.0.0.1:9"], OLD);
    let (_, resp) = s.start(&token, NAME).await;
    let id = resp["approval_id"].as_str().unwrap().to_string();
    s.decide(&id, "approve", None).await;

    // Other options or another item are not what was approved.
    let variants = [
        (NAME, json!({"generate": {"length": 33}})),
        (NAME, json!({"generate": {"charset": "hex"}})),
        ("agent_other", json!({})),
    ];
    for (name, body) in variants {
        let (st, resp) = s.post(&token, &path(name, ""), Some(body.clone())).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{name} {body}");
        assert_eq!(resp["code"], "approval_pending", "{name} {body}");
        assert_ne!(resp["approval_id"], id.as_str(), "{name} {body}");
    }
    assert!(fake(&s.state).rotate_calls().is_empty());
    assert_eq!(fake(&s.state).next_of(&other_item), None);

    // A create's approval is not a rotation's, and another key's is not ours.
    let other = s.key("agent-b").await;
    let (st, resp) = s.start(&other, NAME).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(resp["code"], "approval_pending");
    assert_ne!(resp["approval_id"], id.as_str());
    // The original is still good for its own request.
    assert_eq!(s.start(&token, NAME).await.0, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn two_identical_requests_held_on_one_approval_start_one_rotation() {
    let s = setup(|c| c.approval.wait_secs = 20).await;
    let token = s.key("agent-a").await;
    let a = s.spawn_start(&token, NAME, None);
    let b = s.spawn_start(&token, NAME, None);
    let open = s.wait_for_pending(1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(s.pending().len(), 1);
    s.decide(&open[0].id, "approve", None).await;
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());
    let mut statuses = [ra.0, rb.0];
    statuses.sort();
    // One got through; the other either found the rotation already pending
    // or had to ask again. Never two writes.
    assert_eq!(statuses[0], StatusCode::ACCEPTED, "{ra:?} {rb:?}");
    assert_eq!(fake(&s.state).rotate_calls().len(), 1);
}

#[tokio::test]
async fn deciding_takes_no_duration_and_an_agent_cannot_decide() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    let (_, resp) = s.start(&token, NAME).await;
    let id = resp["approval_id"].as_str().unwrap().to_string();
    for body in [r#"{"minutes": 15}"#, r#"{"x": 1}"#] {
        let (st, _) = s.decide(&id, "approve", Some(body)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    }
    // An agent key on the decision route is refused.
    let (st, _, _) = call(
        &s.app,
        "POST",
        &format!("/v1/admin/approvals/{id}/approve"),
        &[("x-agent-key", &token)],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(s.pending().len(), 1, "still open");
}

// ── Conflicts and failures ────────────────────────────────────────────────────

#[tokio::test]
async fn a_change_by_someone_else_is_a_conflict_and_is_recorded() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    s.started(&token).await;
    fake(&s.state).conflict_next_write();
    let (st, resp) = s.post(&token, &path(NAME, "/commit"), None).await;
    assert_eq!(
        (st, resp["code"].as_str()),
        (StatusCode::CONFLICT, Some("vault_conflict"))
    );
    assert!(resp["error"]
        .as_str()
        .unwrap()
        .contains("Nothing was overwritten"));
    // The password is the one it was; the pending value is still there.
    assert_eq!(fake(&s.state).password_of(&s.item).as_deref(), Some(OLD));
    assert!(fake(&s.state).next_of(&s.item).is_some());
    let ev = &events_of(&s.state, "credential_rotate_commit")[0];
    assert_eq!(ev["event"]["outcome"], "failure");
    assert_eq!(ev["event"]["reason"], "vault_conflict");
    // Retrying works.
    assert_eq!(
        s.post(&token, &path(NAME, "/commit"), None).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_failed_write_is_a_502_and_leaves_no_value_anywhere() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    fake(&s.state).fail_writes(true);
    let held = s.spawn_start(&token, NAME, None);
    let open = s.wait_for_pending(1).await;
    s.decide(&open[0].id, "approve", None).await;
    let (st, resp) = held.await.unwrap();
    assert_eq!(
        (st, resp["code"].as_str()),
        (StatusCode::BAD_GATEWAY, Some("vault_write_failed"))
    );
    assert_eq!(fake(&s.state).next_of(&s.item), None);
    assert!(!all_events_text(&s.state).contains(OLD));
}

// ── The operator ──────────────────────────────────────────────────────────────

fn admin_path(name: &str) -> String {
    path(name, "/abort").replacen("/v1/credentials", "/v1/admin/credentials", 1)
}

#[tokio::test]
async fn an_operator_can_clear_a_stuck_rotation_and_an_agent_key_cannot() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    s.started(&token).await;

    // The agent key is not an admin key.
    let (st, _, _) = call(
        &s.app,
        "POST",
        &admin_path(NAME),
        &[("x-agent-key", &token)],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert!(fake(&s.state).next_of(&s.item).is_some(), "untouched");

    let (st, body) = admin(&s.app, "POST", &admin_path(NAME), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"status": "aborted", "name": NAME}));
    assert_eq!(fake(&s.state).next_of(&s.item), None);
    assert_eq!(fake(&s.state).password_of(&s.item).as_deref(), Some(OLD));
    let ev = events_of(&s.state, "credential_rotate_abort");
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["ferrowarden"]["details"]["by"], "admin");
    assert_eq!(ev[0]["ferrowarden"]["details"]["approver"], "admin_api");
    assert_eq!(ev[0]["ferrowarden"]["details"]["via"], "api");
    assert!(ev[0]["ferrowarden"].get("key").is_none());

    // Nothing pending: the usual conflict. Not managed: refused.
    let (st, body) = admin(&s.app, "POST", &admin_path(NAME), None).await;
    assert_eq!(
        (st, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("no_rotation_pending"))
    );
    fake(&s.state).add_item("agent_personal", &["http://127.0.0.1:9"]);
    let (st, body) = admin(&s.app, "POST", &admin_path("agent_personal"), None).await;
    assert_eq!(
        (st, body["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("credential_not_managed"))
    );
    // A body is refused.
    let (st, _) = admin(&s.app, "POST", &admin_path(NAME), Some(r#"{"a":1}"#)).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn revoking_the_key_clears_its_rotate_approvals() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    let (_, resp) = s.start(&token, NAME).await;
    let id = resp["approval_id"].as_str().unwrap().to_string();
    let (_, keys) = admin(&s.app, "GET", "/v1/admin/keys", None).await;
    let key_id = keys
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["name"] == "agent-a")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        admin(&s.app, "DELETE", &format!("/v1/admin/keys/{key_id}"), None)
            .await
            .0,
        StatusCode::OK
    );
    assert!(s.pending().is_empty());
    let (st, _) = s.decide(&id, "approve", None).await;
    assert_eq!(st, StatusCode::CONFLICT);
}

#[tokio::test]
async fn refusals_are_recorded_with_the_fixed_reasons_the_counter_maps() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    s.start(&token, "grafana").await;
    s.start(&token, "agent_nope").await;
    s.post(&token, &path(NAME, "/commit"), None).await;
    let mut reasons: Vec<String> = events_of(&s.state, "credential_rotate_start")
        .iter()
        .chain(events_of(&s.state, "credential_rotate_commit").iter())
        .map(|e| e["event"]["reason"].as_str().unwrap().to_string())
        .collect();
    reasons.sort();
    assert_eq!(
        reasons,
        [
            "credential_not_managed",
            "credential_rotate_out_of_scope",
            "no_rotation_pending"
        ]
    );
    for e in events_of(&s.state, "credential_rotate_start") {
        assert_eq!(e["event"]["outcome"], "failure");
        assert_eq!(e["ferrowarden"]["details"]["by"], "agent");
    }
}
