//! `POST /v1/credentials` through the real router: the order of the checks,
//! the approval (hold, outcomes, one use), the write on the fake vault, and
//! the promise that the generated value is in no response, event or metric.
//!
//! The vault is the in-memory fake: it records what was written (and keeps the
//! value apart, readable only through `password_of`), so a test can say
//! "nothing was generated or written" with `create_calls() == 0`.

use super::*;
use crate::approvals::PendingView;
use crate::vault::fake::FakeVault;
use crate::vault::model::{ManagedCollection, ManagedProblem, ManagedState};
use std::time::Duration;

const COLLECTION_ID: &str = "6c0d7f0e-52d0-4b5b-8a39-0e8a7f6d5c4b";
const NAME: &str = "agent_keycloak_admin";

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
}

async fn setup(tweak: impl FnOnce(&mut Config)) -> Setup {
    let (app, state) = local_app(|c| {
        c.approval.wait_secs = 1;
        c.approval.pending_ttl_secs = 30;
        tweak(c);
    })
    .await;
    fake(&state).set_managed(usable());
    Setup { app, state }
}

impl Setup {
    /// A key that may create `agent_*`.
    async fn key(&self, name: &str) -> String {
        self.key_with(name, r#"["agent_*"]"#).await
    }

    async fn key_with(&self, name: &str, create: &str) -> String {
        let (s, body) = admin(
            &self.app,
            "POST",
            "/v1/admin/keys",
            Some(&format!(
                r#"{{"name":"{name}","credentials":["*"],"methods":["*"],"create":{create}}}"#
            )),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{body}");
        body["token"].as_str().unwrap().to_string()
    }

    async fn create(
        &self,
        token: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let (s, _, j) = call(
            &self.app,
            "POST",
            "/v1/credentials",
            &[("x-agent-key", token)],
            Some(&body.to_string()),
        )
        .await;
        (s, j)
    }

    fn spawn_create(
        &self,
        token: &str,
        body: serde_json::Value,
    ) -> tokio::task::JoinHandle<(StatusCode, serde_json::Value)> {
        let (app, token) = (self.app.clone(), token.to_string());
        tokio::spawn(async move {
            let (s, _, j) = call(
                &app,
                "POST",
                "/v1/credentials",
                &[("x-agent-key", token.as_str())],
                Some(&body.to_string()),
            )
            .await;
            (s, j)
        })
    }

    fn pending(&self) -> Vec<PendingView> {
        self.state.approvals.list(chrono::Utc::now()).0
    }

    async fn wait_for_pending(&self, n: usize) -> Vec<PendingView> {
        // Resolving the vault host for the outbound policy can take seconds on
        // some machines, once per URI.
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

    /// Nothing was asked of a human, generated or written.
    fn assert_untouched(&self) {
        assert!(self.pending().is_empty(), "an approval was opened");
        assert_eq!(fake(&self.state).create_calls(), 0, "a write was tried");
        assert!(fake(&self.state).created().is_empty());
        assert!(events_of(&self.state, "approval_requested").is_empty());
    }
}

fn body_for(name: &str) -> serde_json::Value {
    json!({
        "name": name,
        "username": "admin",
        "uris": ["http://127.0.0.1:9"],
        "generate": { "length": 32, "charset": "alphanumeric" },
    })
}

// ── The happy path ────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_create_is_held_approved_and_written_and_the_value_is_nowhere() {
    let s = setup(|c| c.approval.wait_secs = 20).await;
    let token = s.key("agent-a").await;
    let held = s.spawn_create(&token, body_for(NAME));

    // Held: an approval of the create kind is open, and nothing is written.
    let open = s.wait_for_pending(1).await;
    assert_eq!(open[0].kind, crate::approvals::ApprovalKind::Create);
    assert_eq!(open[0].key_name, "agent-a");
    let detail = open[0].create.as_ref().unwrap();
    assert_eq!(detail.name, NAME);
    assert_eq!(detail.username.as_deref(), Some("admin"));
    assert_eq!(detail.uris, ["http://127.0.0.1:9"]);
    assert_eq!(
        (detail.charset.as_str(), detail.length),
        ("alphanumeric", 32)
    );
    assert!(!detail.approval_required);
    assert_eq!(detail.collection, "Ferrowarden managed");
    assert_eq!(fake(&s.state).create_calls(), 0, "nothing before approval");
    assert!(!held.is_finished());

    // The admin API lists it with its kind and what it asks for.
    let (st, listed) = admin(&s.app, "GET", "/v1/admin/approvals", None).await;
    assert_eq!(st, StatusCode::OK);
    let p = &listed["pending"][0];
    assert_eq!(p["kind"], "create");
    assert_eq!(p["create"]["name"], NAME);
    assert_eq!(p["create"]["generate"]["length"], 32);
    assert_eq!(p["create"]["collection"], "Ferrowarden managed");
    assert!(p.get("method").is_none() && p.get("origin").is_none() && p.get("url").is_none());

    // Approve with no body: no duration.
    let (st, body) = s.decide(&open[0].id, "approve", None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"status": "approved", "kind": "create"}));

    let (st, resp) = held.await.unwrap();
    assert_eq!(st, StatusCode::CREATED, "{resp}");
    assert_eq!(resp["name"], NAME);
    assert_eq!(resp["placeholder"], format!("{{{{vault:{NAME}}}}}"));
    assert_eq!(resp["cache_refreshed"], true);

    // What was written: the managed collection, the key's name, no more.
    let created = fake(&s.state).created();
    assert_eq!(created.len(), 1);
    let item = &created[0];
    assert_eq!(item.name, NAME);
    assert_eq!(item.username.as_deref(), Some("admin"));
    assert_eq!(item.uris, ["http://127.0.0.1:9"]);
    assert_eq!(item.created_by, "agent-a");
    assert_eq!(item.collection_id, COLLECTION_ID);
    assert!(!item.approval_required);

    // The value has the length and the character set that were asked for...
    let value = fake(&s.state).password_of(&item.id).unwrap();
    assert_eq!(value.len(), 32);
    assert!(value.bytes().all(|b| b.is_ascii_alphanumeric()));
    // ...and is in no response, event or log-like text.
    assert!(!resp.to_string().contains(&value));
    assert!(!all_events_text(&s.state).contains(&value));

    // It is usable at once: the cache lists the name.
    assert!(s.state.credentials.read().await.contains_key(NAME));

    // The events: the prompt (kind create), the decision, the creation.
    let requested = &events_of(&s.state, "approval_requested")[0];
    assert_eq!(requested["ferrowarden"]["details"]["kind"], "create");
    assert_eq!(requested["ferrowarden"]["details"]["create"]["name"], NAME);
    let granted = &events_of(&s.state, "approval_granted")[0];
    assert_eq!(granted["ferrowarden"]["details"]["kind"], "create");
    assert!(granted["ferrowarden"]["details"].get("grant_id").is_none());
    let ev = &events_of(&s.state, "credential_create")[0];
    assert_eq!(ev["event"]["outcome"], "success");
    assert_eq!(ev["ferrowarden"]["details"]["collection_id"], COLLECTION_ID);
    assert_eq!(ev["ferrowarden"]["key"]["name"], "agent-a");
    assert_eq!(ev["ferrowarden"]["credentials"][0], NAME);

    // An approved create is not a grant.
    assert!(s.state.approvals.list(chrono::Utc::now()).1.is_empty());
}

#[tokio::test]
async fn charset_length_username_and_the_approval_flag_are_honoured() {
    let s = setup(|c| c.approval.wait_secs = 20).await;
    let token = s.key("agent-a").await;
    let body = json!({
        "name": "agent_hex",
        "uris": ["http://127.0.0.1:9", "http://127.0.0.1:10"],
        "generate": { "length": 64, "charset": "hex" },
        "approval_required": true,
    });
    let held = s.spawn_create(&token, body);
    let open = s.wait_for_pending(1).await;
    assert!(open[0].create.as_ref().unwrap().approval_required);
    assert_eq!(open[0].create.as_ref().unwrap().username, None);
    s.decide(&open[0].id, "approve", None).await;
    let (st, resp) = held.await.unwrap();
    assert_eq!(st, StatusCode::CREATED, "{resp}");

    let item = fake(&s.state).created().remove(0);
    assert!(item.approval_required);
    assert_eq!(item.username, None);
    assert_eq!(item.uris.len(), 2);
    let value = fake(&s.state).password_of(&item.id).unwrap();
    assert_eq!(value.len(), 64);
    assert!(value
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    // The defaults: 32 alphanumeric characters.
    let held = s.spawn_create(
        &token,
        json!({"name": "agent_default", "uris": ["http://127.0.0.1:9"], "generate": {}}),
    );
    let open = s.wait_for_pending(1).await;
    let d = open[0].create.as_ref().unwrap();
    assert_eq!((d.charset.as_str(), d.length), ("alphanumeric", 32));
    s.decide(&open[0].id, "approve", None).await;
    assert_eq!(held.await.unwrap().0, StatusCode::CREATED);
}

#[tokio::test]
async fn a_name_that_needs_quoting_gets_a_quoted_placeholder() {
    let s = setup(|c| c.approval.wait_secs = 20).await;
    let token = s.key_with("agent-a", r#"["*"]"#).await;
    let held = s.spawn_create(&token, body_for("Service (prod) 'one'"));
    let open = s.wait_for_pending(1).await;
    s.decide(&open[0].id, "approve", None).await;
    let (st, resp) = held.await.unwrap();
    assert_eq!(st, StatusCode::CREATED, "{resp}");
    assert_eq!(resp["placeholder"], "{{vault:'Service (prod) \\'one\\''}}");
}

// ── The approval ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_denied_create_writes_nothing_and_stays_denied_without_a_new_prompt() {
    let s = setup(|c| c.approval.wait_secs = 20).await;
    let token = s.key("agent-a").await;
    let held = s.spawn_create(&token, body_for(NAME));
    let open = s.wait_for_pending(1).await;
    let (st, body) = s.decide(&open[0].id, "deny", None).await;
    assert_eq!(st, StatusCode::OK, "{body}");

    let (st, resp) = held.await.unwrap();
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(resp["code"], "approval_denied");
    assert_eq!(
        fake(&s.state).create_calls(),
        0,
        "nothing was generated or written"
    );

    // The identical retry is refused at once, and nobody is asked again.
    let (st, resp) = s.create(&token, body_for(NAME)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(resp["code"], "approval_denied");
    assert_eq!(events_of(&s.state, "approval_requested").len(), 1);
    assert_eq!(fake(&s.state).create_calls(), 0);

    // A different operation is a different approval (a new prompt).
    let other = s.spawn_create(
        &token,
        json!({
            "name": "agent_other", "uris": ["http://127.0.0.1:9"], "generate": {"length": 20}
        }),
    );
    s.wait_for_pending(1).await;
    assert_eq!(events_of(&s.state, "approval_requested").len(), 2);
    other.abort();
}

#[tokio::test]
async fn an_undecided_create_is_pending_and_the_identical_retry_uses_the_approval_once() {
    let s = setup(|_| {}).await; // wait_secs = 1
    let token = s.key("agent-a").await;

    let (st, resp) = s.create(&token, body_for(NAME)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(resp["code"], "approval_pending");
    let id = resp["approval_id"].as_str().unwrap().to_string();
    assert_eq!(fake(&s.state).create_calls(), 0);

    // The same request again reuses the open approval: no second prompt.
    let (st, resp) = s.create(&token, body_for(NAME)).await;
    assert_eq!(
        (st, resp["approval_id"].as_str()),
        (StatusCode::FORBIDDEN, Some(id.as_str()))
    );
    assert_eq!(events_of(&s.state, "approval_requested").len(), 1);

    // Approved while nobody is waiting: the retry gets through, and creates.
    let (st, body) = s.decide(&id, "approve", None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(fake(&s.state).create_calls(), 0, "approving writes nothing");
    let (st, resp) = s.create(&token, body_for(NAME)).await;
    assert_eq!(st, StatusCode::CREATED, "{resp}");
    assert_eq!(fake(&s.state).created().len(), 1);

    // The approval was used up: the same request again is a conflict (the
    // name exists now), checked before any prompt.
    let (st, resp) = s.create(&token, body_for(NAME)).await;
    assert_eq!(st, StatusCode::CONFLICT, "{resp}");
    assert_eq!(resp["code"], "credential_exists");
    assert_eq!(events_of(&s.state, "approval_requested").len(), 1);
}

#[tokio::test]
async fn an_approval_covers_one_operation_only() {
    let s = setup(|c| c.approval.max_pending_per_key = 50).await;
    let token = s.key("agent-a").await;
    let (_, resp) = s.create(&token, body_for(NAME)).await;
    let id = resp["approval_id"].as_str().unwrap().to_string();
    s.decide(&id, "approve", None).await;

    // Another username, URI, length, charset, flag or name is not what was
    // approved: each opens its own approval instead of using this one.
    let variants = [
        json!({"name": NAME, "username": "root", "uris": ["http://127.0.0.1:9"], "generate": {"length": 32, "charset": "alphanumeric"}}),
        json!({"name": NAME, "username": "admin", "uris": ["http://127.0.0.1:8"], "generate": {"length": 32, "charset": "alphanumeric"}}),
        json!({"name": NAME, "username": "admin", "uris": ["http://127.0.0.1:9"], "generate": {"length": 33, "charset": "alphanumeric"}}),
        json!({"name": NAME, "username": "admin", "uris": ["http://127.0.0.1:9"], "generate": {"length": 32, "charset": "hex"}}),
        json!({"name": NAME, "username": "admin", "uris": ["http://127.0.0.1:9"], "generate": {"length": 32, "charset": "alphanumeric"}, "approval_required": true}),
        json!({"name": "agent_other", "username": "admin", "uris": ["http://127.0.0.1:9"], "generate": {"length": 32, "charset": "alphanumeric"}}),
    ];
    for v in variants {
        let (st, resp) = s.create(&token, v.clone()).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{v}");
        assert_eq!(resp["code"], "approval_pending", "{v}");
        assert_ne!(resp["approval_id"], id.as_str(), "{v}");
    }
    assert_eq!(fake(&s.state).create_calls(), 0);

    // The same operation with the URIs in another order is the same
    // operation (they are sorted for the fingerprint).
    let two = json!({"name": "agent_two", "uris": ["http://127.0.0.1:9", "http://127.0.0.1:8"], "generate": {}});
    let (_, resp) = s.create(&token, two.clone()).await;
    s.decide(resp["approval_id"].as_str().unwrap(), "approve", None)
        .await;
    let swapped = json!({"name": "agent_two", "uris": ["http://127.0.0.1:8", "http://127.0.0.1:9"], "generate": {}});
    assert_eq!(s.create(&token, swapped).await.0, StatusCode::CREATED);

    // Another key asking for the same thing is not covered either.
    let other = s.key("agent-b").await;
    let (st, resp) = s.create(&other, body_for(NAME)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(resp["code"], "approval_pending");
    assert_ne!(resp["approval_id"], id.as_str());
}

#[tokio::test]
async fn two_identical_requests_held_on_one_approval_create_one_credential() {
    let s = setup(|c| c.approval.wait_secs = 20).await;
    let token = s.key("agent-a").await;
    let a = s.spawn_create(&token, body_for(NAME));
    let b = s.spawn_create(&token, body_for(NAME));
    // One approval (the second request reused the first's)...
    let open = s.wait_for_pending(1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(s.pending().len(), 1);
    assert_eq!(events_of(&s.state, "approval_requested").len(), 1);
    s.decide(&open[0].id, "approve", None).await;

    // ...so one request used it and the other did not: one credential.
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());
    let mut codes = [ra.0.as_u16(), rb.0.as_u16()];
    codes.sort_unstable();
    assert_eq!(codes[0], 201, "{ra:?} {rb:?}");
    assert_eq!(fake(&s.state).created().len(), 1);
    assert_eq!(fake(&s.state).create_calls(), 1);
}

#[tokio::test]
async fn deciding_a_create_takes_no_duration_and_an_agent_cannot_decide() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    let (_, resp) = s.create(&token, body_for(NAME)).await;
    let id = resp["approval_id"].as_str().unwrap().to_string();

    // A duration makes no sense for one operation.
    for body in [
        r#"{"minutes":15}"#,
        r#"{"minutes":null}"#,
        r#"{"x":1}"#,
        "[]",
        "5",
    ] {
        let (st, j) = s.decide(&id, "approve", Some(body)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}: {j}");
    }
    assert_eq!(s.pending().len(), 1, "still open");

    // The agent's key is refused on both decisions.
    for action in ["approve", "deny"] {
        let (st, _, _) = call(
            &s.app,
            "POST",
            &format!("/v1/admin/approvals/{id}/{action}"),
            &[("x-agent-key", token.as_str())],
            None,
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{action}");
    }
    assert_eq!(s.pending().len(), 1, "still open");

    // An empty object is fine, and a second decision is a conflict.
    let (st, j) = s.decide(&id, "approve", Some("{}")).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, _) = s.decide(&id, "approve", None).await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, _) = s.decide(&id, "deny", None).await;
    assert_eq!(st, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_create_approval_counts_towards_the_same_limits_as_forwards() {
    let s = setup(|c| c.approval.max_pending_per_key = 1).await;
    let token = s.key("agent-a").await;
    let (st, _) = s.create(&token, body_for("agent_one")).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, resp) = s.create(&token, body_for("agent_two")).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "{resp}");
    assert_eq!(resp["code"], "approval_limit_reached");
    assert_eq!(fake(&s.state).create_calls(), 0);
}

#[tokio::test]
async fn revoking_the_key_clears_its_create_approvals() {
    let s = setup(|c| c.approval.wait_secs = 20).await;
    let (st, body) = admin(
        &s.app,
        "POST",
        "/v1/admin/keys",
        Some(r#"{"name":"agent-a","credentials":["*"],"methods":["*"],"create":["agent_*"]}"#),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let (id, token) = (
        body["id"].as_str().unwrap().to_string(),
        body["token"].as_str().unwrap().to_string(),
    );
    let held = s.spawn_create(&token, body_for(NAME));
    s.wait_for_pending(1).await;
    let (st, _) = admin(&s.app, "DELETE", &format!("/v1/admin/keys/{id}"), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(s.pending().is_empty());
    let (st, resp) = held.await.unwrap();
    assert_eq!(st, StatusCode::FORBIDDEN, "{resp}");
    assert_eq!(fake(&s.state).create_calls(), 0);
}

// ── Refused before any prompt ─────────────────────────────────────────────────

#[tokio::test]
async fn a_name_that_exists_is_a_conflict_before_any_prompt() {
    let s = setup(|_| {}).await;
    fake(&s.state).add_item(NAME, &["https://other.example"]);
    let token = s.key("agent-a").await;
    let (st, resp) = s.create(&token, body_for(NAME)).await;
    assert_eq!(st, StatusCode::CONFLICT, "{resp}");
    assert_eq!(resp["code"], "credential_exists");
    s.assert_untouched();
    let ev = &events_of(&s.state, "credential_create")[0];
    assert_eq!(ev["event"]["outcome"], "failure");
    assert_eq!(ev["event"]["reason"], "credential_exists");
}

#[tokio::test]
async fn a_name_outside_the_keys_create_list_is_refused_before_any_prompt() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    let (st, resp) = s.create(&token, body_for("other_name")).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{resp}");
    assert_eq!(resp["code"], "credential_create_out_of_scope");
    s.assert_untouched();
    assert_eq!(
        events_of(&s.state, "credential_create")[0]["event"]["reason"],
        "credential_create_out_of_scope"
    );

    // A key without a `create` list cannot create at all, whatever its
    // credential and method lists say.
    let none = s.key_with("agent-none", "[]").await;
    let (st, resp) = s.create(&none, body_for(NAME)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(resp["code"], "credential_create_out_of_scope");
    s.assert_untouched();
}

#[tokio::test]
async fn create_is_its_own_permission_apart_from_credentials_and_methods() {
    let s = setup(|_| {}).await;
    // No credentials, no methods, but a create pattern: the permission is
    // `create` alone.
    let (st, body) = admin(
        &s.app,
        "POST",
        "/v1/admin/keys",
        Some(r#"{"name":"only-create","credentials":[],"methods":[],"create":["agent_*"]}"#),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    let token = body["token"].as_str().unwrap();
    let (st, resp) = s.create(token, body_for(NAME)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(resp["code"], "approval_pending", "{resp}");
}

#[tokio::test]
async fn creating_is_off_without_a_managed_collection() {
    let s = setup(|_| {}).await;
    fake(&s.state).set_managed(ManagedState::Off);
    let token = s.key("agent-a").await;
    let (st, resp) = s.create(&token, body_for(NAME)).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{resp}");
    assert_eq!(resp["code"], "credential_create_disabled");
    s.assert_untouched();
}

#[tokio::test]
async fn an_unusable_collection_is_503_with_the_reason_and_nothing_falls_back() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    for (problem, code) in [
        (ManagedProblem::NotFound, "not_found"),
        (ManagedProblem::ReadOnly, "read_only"),
        (ManagedProblem::HidesPasswords, "hides_passwords"),
        (ManagedProblem::Ambiguous, "ambiguous_name"),
        (ManagedProblem::NoOrganizationKey, "no_organization_key"),
    ] {
        fake(&s.state).set_managed(ManagedState::Unavailable {
            setting: "Ferrowarden managed".into(),
            problem,
        });
        let (st, resp) = s.create(&token, body_for(NAME)).await;
        assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "{code}: {resp}");
        assert_eq!(resp["code"], "managed_collection_unavailable");
        assert_eq!(resp["reason"], code);
        s.assert_untouched();
    }
    assert_eq!(
        events_of(&s.state, "credential_create")[0]["event"]["reason"],
        "managed_collection_unavailable"
    );
}

#[tokio::test]
async fn a_uri_the_outbound_policy_blocks_is_refused_before_any_prompt() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    for uri in [
        "http://169.254.169.254/latest",
        "http://10.0.0.5:8080",
        "http://[::1]:80",
    ] {
        let mut body = body_for(NAME);
        body["uris"] = json!([uri]);
        let (st, resp) = s.create(&token, body).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{uri}: {resp}");
        s.assert_untouched();
    }
}

#[tokio::test]
async fn every_field_is_validated_before_any_prompt() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    let ok = body_for(NAME);
    let with = |key: &str, value: serde_json::Value| {
        let mut b = ok.clone();
        b[key] = value;
        b
    };
    let long_name = "a".repeat(129);
    let long_user = "u".repeat(257);
    let many: Vec<String> = (0..17)
        .map(|i| format!("http://127.0.0.1:{}", 1000 + i))
        .collect();
    let bad = [
        ("empty name", with("name", json!(""))),
        ("long name", with("name", json!(long_name))),
        ("control in name", with("name", json!("agent_\nx"))),
        ("blank name", with("name", json!("   "))),
        ("empty username", with("username", json!(""))),
        ("long username", with("username", json!(long_user))),
        ("control in username", with("username", json!("a\u{7}b"))),
        ("null username", with("username", json!(null))),
        ("no uris", with("uris", json!([]))),
        ("too many uris", with("uris", json!(many))),
        ("relative uri", with("uris", json!(["/x"]))),
        ("ftp uri", with("uris", json!(["ftp://127.0.0.1/"]))),
        ("not a url", with("uris", json!(["nope"]))),
        ("userinfo", with("uris", json!(["http://u:p@127.0.0.1/"]))),
        (
            "duplicate uri",
            with("uris", json!(["http://127.0.0.1:9", "http://127.0.0.1:9"])),
        ),
        ("uris not a list", with("uris", json!("http://127.0.0.1:9"))),
        ("no generate", {
            let mut b = ok.clone();
            b.as_object_mut().unwrap().remove("generate");
            b
        }),
        ("null generate", with("generate", json!(null))),
        ("short length", with("generate", json!({"length": 15}))),
        ("long length", with("generate", json!({"length": 129}))),
        ("negative length", with("generate", json!({"length": -1}))),
        ("float length", with("generate", json!({"length": 32.5}))),
        ("null length", with("generate", json!({"length": null}))),
        ("bad charset", with("generate", json!({"charset": "emoji"}))),
        ("upper charset", with("generate", json!({"charset": "HEX"}))),
        (
            "unknown generate field",
            with("generate", json!({"words": 4})),
        ),
        ("null approval flag", with("approval_required", json!(null))),
        (
            "string approval flag",
            with("approval_required", json!("yes")),
        ),
        ("unknown field", with("extra", json!(1))),
    ];
    for (what, body) in bad {
        let (st, resp) = s.create(&token, body).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{what}: {resp}");
    }
    s.assert_untouched();

    // Strict JSON: a duplicate key and a wrong content type.
    let (st, _, _) = call(
        &s.app,
        "POST",
        "/v1/credentials",
        &[("x-agent-key", token.as_str())],
        Some(r#"{"name":"agent_a","name":"agent_b","uris":["http://127.0.0.1:9"],"generate":{}}"#),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let resp = s
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/credentials")
                .header("x-agent-key", token.as_str())
                .header("content-type", "text/plain")
                .body(Body::from(ok.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    s.assert_untouched();
}

#[tokio::test]
async fn the_agent_is_authenticated_before_the_body_is_read() {
    let s = setup(|_| {}).await;
    let (st, _, resp) = call(
        &s.app,
        "POST",
        "/v1/credentials",
        &[("x-agent-key", "not-a-key")],
        Some("{ this is not json"),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{resp}");
    let (st, _, _) = call(&s.app, "POST", "/v1/credentials", &[], Some("{}")).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    // The admin key is not an agent key.
    let (st, _, _) = call(
        &s.app,
        "POST",
        "/v1/credentials",
        &[("x-admin-key", ADMIN_KEY)],
        Some(&body_for(NAME).to_string()),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    s.assert_untouched();
}

#[tokio::test]
async fn a_locked_vault_refuses_before_any_prompt() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    fake(&s.state).set_locked(true);
    s.state.set_locked("test").await;
    let (st, resp) = s.create(&token, body_for(NAME)).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "{resp}");
    s.assert_untouched();
}

// ── The write fails ───────────────────────────────────────────────────────────

#[tokio::test]
async fn a_failed_write_is_a_502_and_leaves_no_value_anywhere() {
    let s = setup(|c| c.approval.wait_secs = 20).await;
    fake(&s.state).fail_writes(true);
    let token = s.key("agent-a").await;
    let held = s.spawn_create(&token, body_for(NAME));
    let open = s.wait_for_pending(1).await;
    s.decide(&open[0].id, "approve", None).await;
    let (st, resp) = held.await.unwrap();
    assert_eq!(st, StatusCode::BAD_GATEWAY, "{resp}");
    assert_eq!(resp["code"], "vault_write_failed");
    assert_eq!(fake(&s.state).create_calls(), 1);
    assert!(fake(&s.state).created().is_empty());
    assert!(!s.state.credentials.read().await.contains_key(NAME));
    let ev = &events_of(&s.state, "credential_create")[0];
    assert_eq!(ev["event"]["outcome"], "failure");
    assert_eq!(ev["event"]["reason"], "vault_write_failed");
    // The approval was used by that attempt: another needs a new one.
    let (st, resp) = s.create(&token, body_for(NAME)).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{resp}");
    assert_eq!(resp["code"], "approval_pending");
}

#[tokio::test]
async fn refusals_are_recorded_with_the_fixed_reasons_the_counter_maps() {
    let s = setup(|_| {}).await;
    let token = s.key("agent-a").await;
    let _ = s.create(&token, body_for("other_name")).await; // out of scope
    fake(&s.state).add_item(NAME, &["https://x.example"]);
    let _ = s.create(&token, body_for(NAME)).await; // exists
    let reasons: Vec<String> = events_of(&s.state, "credential_create")
        .iter()
        .map(|e| e["event"]["reason"].as_str().unwrap().to_string())
        .collect();
    assert!(reasons.contains(&"credential_create_out_of_scope".to_string()));
    assert!(reasons.contains(&"credential_exists".to_string()));
}
