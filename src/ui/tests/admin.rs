//! Tests of the phase-2 pages: keys, policy editor, revoke, audit, the sudo
//! window and the `next` redirect. Same harness as the sign-in tests.

use super::*;
use crate::api::key_service::{self, Caller, Via};
use crate::keys::{hash_token, load};
use crate::middleware::request_context::RequestContext;
use crate::vault::model::CredentialEntry;

const HOSTILE_CRED: &str = "\"><img src=x onerror=alert(1)>";
const HOSTILE_KEY: &str = "<script>alert(1)</script>";

fn full_opts() -> Opts {
    Opts {
        keys_file: true,
        ..Opts::default()
    }
}

async fn signed_in(h: &Harness) -> Browser {
    let mut b = Browser::new();
    let r = b.sign_in(h, PASSWORD).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(r.location(), "/ui/");
    b
}

async fn seed(h: &Harness) {
    let mut c = h.app.credentials.write().await;
    c.insert(
        "lab_nas".into(),
        vec![CredentialEntry::login("1", &["https://nas.lab"])],
    );
    c.insert(
        "prod_db".into(),
        vec![CredentialEntry::login("2", &["https://db.prod"])],
    );
    c.insert(
        HOSTILE_CRED.into(),
        vec![CredentialEntry::login("3", &["https://x.example"])],
    );
}

/// A key made the way the JSON API makes it.
async fn api_key(h: &Harness, name: &str, creds: &[&str], methods: &[&str]) -> (String, String) {
    let ctx = RequestContext::new("10.0.0.1".parse().unwrap());
    let c = key_service::create_key(
        &h.app,
        Caller {
            ctx: &ctx,
            via: Via::Api,
        },
        name,
        creds.iter().map(|s| s.to_string()).collect(),
        methods.iter().map(|s| s.to_string()).collect(),
        Vec::new(),
        vec![],
        vec![],
    )
    .await
    .unwrap();
    (c.id, c.token)
}

fn token_in(body: &str) -> String {
    let marker = "readonly value=\"";
    let start = body.find(marker).expect("token field") + marker.len();
    let end = body[start..].find('"').unwrap();
    body[start..start + end].to_string()
}

async fn edit(b: &mut Browser, h: &Harness, id: &str, extra: &[(&str, &str)]) -> Resp {
    let csrf = b.get(h, &format!("/ui/keys/{id}")).await.csrf();
    let mut fields = vec![("csrf", csrf.as_str())];
    fields.extend_from_slice(extra);
    b.post(h, &format!("/ui/keys/{id}"), &fields).await
}

fn key_count(h: &Harness) -> usize {
    h.app.agent_keys.try_read().unwrap().len()
}

fn via(e: &Value) -> &str {
    e["ferrowarden"]["details"]["via"].as_str().unwrap_or("")
}

// -- keys list -------------------------------------------------------------------

#[tokio::test]
async fn the_keys_list_is_sorted_and_marks_keys_without_a_policy() {
    let h = harness(full_opts()).await;
    api_key(&h, "zeta", &["a", "b", "c", "d", "e"], &["GET"]).await;
    api_key(&h, "Alpha", &["*"], &["*"]).await;
    h.app.agent_keys.write().await.insert(
        "legacyhash".into(),
        AgentKey {
            id: "legacy-0000-1111".into(),
            name: "legacy".into(),
            created_at: chrono::Utc::now(),
            policy: Default::default(),
            policy_set: false,
        },
    );
    let mut b = signed_in(&h).await;
    let r = b.get(&h, "/ui/keys").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_security_headers(&r);
    let (a, l, z) = (
        r.body.find(">Alpha<").unwrap(),
        r.body.find(">legacy<").unwrap(),
        r.body.find(">zeta<").unwrap(),
    );
    assert!(a < l && l < z, "sorted by name");
    assert!(
        r.body.contains("No policy &#38;mdash; deny-all")
            || r.body.contains("No policy &mdash; deny-all")
    );
    assert_eq!(r.body.matches("deny-all").count(), 1);
    assert!(r.body.contains("and 2 more"));
    assert!(r.body.contains("(5 in total)"));
    assert!(r.body.contains("href=\"/ui/keys/new\""));
    assert!(r.body.contains("/revoke\""));
    assert_eq!(h.events_of("key_list").len(), 1);
    assert_eq!(via(&h.events_of("key_list")[0]), "ui");
}

#[tokio::test]
async fn pages_need_a_session_and_carry_the_navigation() {
    let h = harness(full_opts()).await;
    let mut anon = Browser::new();
    for p in [
        "/ui/keys",
        "/ui/keys/new",
        "/ui/keys/x",
        "/ui/keys/x/revoke",
        "/ui/audit",
    ] {
        assert_eq!(anon.get(&h, p).await.location(), "/ui/login", "{p}");
    }
    let mut b = signed_in(&h).await;
    for (path, current) in [
        ("/ui/", "Status"),
        ("/ui/keys", "Keys"),
        ("/ui/audit", "Audit"),
    ] {
        let r = b.get(&h, path).await;
        assert_eq!(r.status, StatusCode::OK, "{path}");
        assert!(r.body.contains("aria-label=\"Main\""));
        assert_eq!(r.body.matches("aria-current=\"page\"").count(), 1, "{path}");
        let marked = format!("aria-current=\"page\">{current}</a>");
        assert!(r.body.contains(&marked), "{path}");
        assert!(r.body.contains(EMAIL));
        assert!(r.body.contains("action=\"/ui/logout\""));
    }
    // The sign-in page has none.
    assert!(!anon
        .get(&h, "/ui/login")
        .await
        .body
        .contains("aria-label=\"Main\""));
    // No scripts anywhere.
    for p in ["/ui/keys", "/ui/keys/new", "/ui/audit"] {
        let body = b.get(&h, p).await.body.to_lowercase();
        assert!(!body.contains("<script") && !body.contains("style=") && !body.contains("onclick"));
    }
}

// -- create ----------------------------------------------------------------------

#[tokio::test]
async fn creating_a_key_shows_the_token_once() {
    let h = harness(full_opts()).await;
    let mut b = signed_in(&h).await;
    let form = b.get(&h, "/ui/keys/new").await;
    let (csrf, fid) = (form.csrf(), form.form_id());
    let r = b
        .post(
            &h,
            "/ui/keys/new",
            &[
                ("csrf", &csrf),
                ("form_id", &fid),
                ("name", "  homelab  "),
                ("credentials", "lab_*\r\n\r\n  uptime_ \r\n"),
                ("m_GET", "1"),
                ("m_HEAD", "1"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.headers.get("location").is_none(), "no redirect");
    assert_eq!(r.headers["cache-control"], "no-store");
    assert!(r.body.contains("This token will not be shown again"));
    let token = token_in(&r.body);
    assert_eq!(token.len(), 48);
    assert_eq!(r.body.matches(token.as_str()).count(), 1);
    assert!(r.body.contains("readonly"));
    assert!(r.body.contains("lab_*") && r.body.contains("uptime_"));

    // It works as an agent token, with the cleaned-up policy.
    let keys = h.app.agent_keys.read().await;
    let key = keys.get(&hash_token(&token)).expect("key is active");
    assert_eq!(key.name, "homelab");
    assert_eq!(key.policy.credentials, vec!["lab_*", "uptime_"]);
    assert_eq!(key.policy.methods, vec!["GET", "HEAD"]);
    drop(keys);
    let stored = load(h.keys_path.as_ref().unwrap()).unwrap();
    assert_eq!(stored.len(), 1);
    assert!(!std::fs::read_to_string(h.keys_path.as_ref().unwrap())
        .unwrap()
        .contains(&token));

    // Event: via ui, no token anywhere but the one response.
    let e = &h.events_of("key_create")[0];
    assert_eq!(via(e), "ui");
    assert_eq!(e["ferrowarden"]["details"]["key_name"], "homelab");
    h.assert_not_logged(&[token.as_str()]);
    for p in ["/ui/keys", "/ui/audit", "/ui/", "/ui/keys/new"] {
        let page = b.get(&h, p).await;
        assert!(!page.body.contains(&token), "{p}");
    }
    let id = key_id_of(&h, "homelab").await;
    assert!(!b
        .get(&h, &format!("/ui/keys/{id}"))
        .await
        .body
        .contains(&token));
    // Nothing but the token page itself ever held it.
    let seen = h.seen.lock().unwrap();
    assert_eq!(seen.iter().filter(|s| s.contains(&token)).count(), 1);
}

async fn key_id_of(h: &Harness, name: &str) -> String {
    h.app
        .agent_keys
        .read()
        .await
        .values()
        .find(|k| k.name == name)
        .unwrap()
        .id
        .clone()
}

#[tokio::test]
async fn create_errors_keep_the_input_escaped() {
    let h = harness(full_opts()).await;
    let mut b = signed_in(&h).await;
    let form = b.get(&h, "/ui/keys/new").await;
    let (csrf, fid) = (form.csrf(), form.form_id());
    // "All methods" together with a method is ambiguous.
    let r = b
        .post(
            &h,
            "/ui/keys/new",
            &[
                ("csrf", &csrf),
                ("form_id", &fid),
                ("name", "\"><b>x</b>"),
                ("credentials", "a<b>\nb"),
                ("m_GET", "1"),
                ("m_all", "1"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body.contains("must be the only entry"));
    assert!(!r.body.contains("<b>"));
    assert!(r.body.contains("&#60;b&#62;x"));
    assert!(r.body.contains("a&#60;b&#62;"));
    assert!(r.body.contains("name=\"m_GET\" value=\"1\" checked"));
    assert!(r.body.contains("name=\"m_all\" value=\"1\" checked"));
    assert_eq!(key_count(&h), 0);
    let e = &h.events_of("key_create")[0];
    assert_eq!(e["event"]["outcome"], "failure");
    assert_eq!(via(e), "ui");

    // Empty and over-long names; a control character in a pattern.
    for (name, creds) in [
        ("", "a"),
        ("   ", "a"),
        (&"n".repeat(129), "a"),
        ("ok", "a\u{7}b"),
    ] {
        let r = b
            .post(
                &h,
                "/ui/keys/new",
                &[
                    ("csrf", &csrf),
                    ("form_id", &fid),
                    ("name", name),
                    ("credentials", creds),
                    ("m_GET", "1"),
                ],
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{name:?} {creds:?}");
    }
    assert_eq!(key_count(&h), 0);
    // No methods and no patterns is a valid, deny-everything key.
    let r = b
        .post(
            &h,
            "/ui/keys/new",
            &[("csrf", &csrf), ("form_id", &fid), ("name", "none")],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(key_count(&h), 1);
}

// -- the sudo window and `next` ----------------------------------------------------

#[tokio::test]
async fn sensitive_actions_need_a_recent_sign_in_on_get_and_post() {
    let h = harness(full_opts()).await;
    seed(&h).await;
    let (id, _) = api_key(&h, "victim", &["lab_*"], &["GET"]).await;
    let mut b = signed_in(&h).await;
    // Forms fetched while fresh.
    let form = b.get(&h, "/ui/keys/new").await;
    let (csrf, fid) = (form.csrf(), form.form_id());

    h.ui.advance(Duration::from_secs(9 * 60 + 59));
    assert_eq!(b.get(&h, "/ui/keys/new").await.status, StatusCode::OK);
    h.ui.advance(Duration::from_secs(2));

    let new_path = "/ui/keys/new";
    let revoke_path = format!("/ui/keys/{id}/revoke");
    let edit_path = format!("/ui/keys/{id}");
    for (label, path, next) in [
        ("create form", new_path, new_path),
        ("revoke form", &revoke_path, &revoke_path),
    ] {
        let r = b.get(&h, path).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{label}");
        assert_eq!(r.location(), format!("/ui/login?m=sudo&next={next}"));
    }
    let mut attempts = vec![
        (
            new_path.to_string(),
            "/ui/keys/new/draft/".to_string(),
            (vec![
                ("csrf", csrf.as_str()),
                ("form_id", fid.as_str()),
                ("name", "n"),
            ]),
        ),
        (
            revoke_path.clone(),
            revoke_path.clone(),
            (vec![("csrf", csrf.as_str())]),
        ),
        (
            edit_path.clone(),
            format!("{edit_path}/draft/"),
            (vec![
                ("csrf", csrf.as_str()),
                ("op", "save"),
                ("credentials", "*"),
                ("m_all", "1"),
            ]),
        ),
    ];
    for (path, next, fields) in attempts.drain(..) {
        let r = b.post(&h, &path, &fields).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{path}");
        if next.ends_with("/draft/") {
            // The unsaved form is parked, and the sign-in comes back to it.
            let prefix = format!("/ui/login?m=sudo&next={next}");
            assert!(r.location().starts_with(&prefix), "{}", r.location());
            assert_eq!(r.location().len(), prefix.len() + 43);
        } else {
            assert_eq!(r.location(), format!("/ui/login?m=sudo&next={next}"));
        }
    }
    // Nothing happened.
    assert_eq!(key_count(&h), 1);
    let policy = h
        .app
        .agent_keys
        .read()
        .await
        .values()
        .next()
        .unwrap()
        .policy
        .clone();
    assert_eq!(policy.credentials, vec!["lab_*"]);
    assert!(h.events_of("key_revoke").is_empty() && h.events_of("key_policy_change").is_empty());

    // Viewing, Check policy, request check and audit still work when stale.
    for p in ["/ui/keys", "/ui/audit", edit_path.as_str(), "/ui/"] {
        assert_eq!(b.get(&h, p).await.status, StatusCode::OK, "{p}");
    }
    let r = edit(
        &mut b,
        &h,
        &id,
        &[("op", "check"), ("credentials", "*"), ("m_GET", "1")],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("Signed in 10 minutes ago"));
    assert!(r.body.contains("you will be asked to sign in again"));

    // Sign in again: the login page keeps `next`; success lands on it.
    let page = b
        .get(&h, &format!("/ui/login?m=sudo&next={new_path}"))
        .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Sign in again to continue."));
    assert!(page.body.contains("name=\"next\" value=\"/ui/keys/new\""));
    let r = b
        .post(
            &h,
            "/ui/login",
            &[
                ("csrf", &page.csrf()),
                ("password", PASSWORD),
                ("next", new_path),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), new_path);
    let r = b.get(&h, new_path).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("Signed in just now"));
    h.assert_no_leaks(&[]);
}

#[tokio::test]
async fn a_fresh_session_asked_to_sign_in_again_is_sent_to_next() {
    let h = harness(full_opts()).await;
    let mut b = signed_in(&h).await;
    assert_eq!(
        b.get(&h, "/ui/login?next=/ui/audit").await.location(),
        "/ui/audit"
    );
    assert_eq!(
        b.get(&h, "/ui/login?next=//evil.com").await.location(),
        "/ui/"
    );
    assert_eq!(b.get(&h, "/ui/login").await.location(), "/ui/");
}

#[tokio::test]
async fn a_tampered_next_never_leaves_the_ui() {
    let h = harness(full_opts()).await;
    for bad in [
        "//evil.com",
        "/\\evil.com",
        "https://evil.com",
        "/ui/../x",
        "/ui/%2f%2fevil.com",
        "/ui//evil.com",
    ] {
        let mut b = Browser::new();
        let page = b.get(&h, "/ui/login").await;
        let r = b
            .post(
                &h,
                "/ui/login",
                &[
                    ("csrf", &page.csrf()),
                    ("password", PASSWORD),
                    ("next", bad),
                ],
            )
            .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{bad}");
        assert_eq!(r.location(), "/ui/", "{bad}");
        // And the login page does not reflect it.
        let shown = Browser::new()
            .get(&h, &format!("/ui/login?next={bad}"))
            .await;
        assert!(!shown.body.contains("name=\"next\""), "{bad}");
    }
}

#[tokio::test]
async fn next_is_kept_server_side_through_two_factor() {
    let h = harness(Opts {
        two_fa: Some(TwoFa::totp()),
        keys_file: true,
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    let page = b.get(&h, "/ui/login").await;
    let r = b
        .post(
            &h,
            "/ui/login",
            &[
                ("csrf", &page.csrf()),
                ("password", PASSWORD),
                ("next", "/ui/keys/new"),
            ],
        )
        .await;
    assert_eq!(r.location(), "/ui/login/2fa", "next is not in a URL");
    let page2 = b.get(&h, "/ui/login/2fa").await;
    assert!(!page2.body.contains("/ui/keys/new"), "not even in the form");
    // The second step cannot change it.
    let csrf = page2.csrf();
    let r = b
        .post(
            &h,
            "/ui/login/2fa",
            &[
                ("csrf", &csrf),
                ("provider", "0"),
                ("action", "verify"),
                ("code", TOTP),
                ("next", "//evil.com"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = b.second_factor(&h, "0", "verify", TOTP).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/ui/keys/new");
}

#[tokio::test]
async fn the_sudo_window_is_ten_minutes_from_the_sign_in() {
    use crate::ui::session::{SessionStore, SUDO_WINDOW};
    let mut store = SessionStore::new(Duration::from_secs(3600), Duration::from_secs(36000));
    let t0 = std::time::Instant::now();
    let (id, _) = store.create(t0).unwrap();
    assert_eq!(SUDO_WINDOW, Duration::from_secs(600));
    // Activity keeps the session alive but does not extend the window.
    for m in [3, 6, 9] {
        let crate::ui::session::Lookup::Valid(v) =
            store.lookup(&id, t0 + Duration::from_secs(m * 60))
        else {
            panic!()
        };
        assert!(v.sudo_active(t0 + Duration::from_secs(m * 60)));
    }
    let now = t0 + SUDO_WINDOW;
    let crate::ui::session::Lookup::Valid(v) = store.lookup(&id, now) else {
        panic!()
    };
    assert!(!v.sudo_active(now));
    assert!(v.sudo_active(now - Duration::from_secs(1)));
    assert_eq!(v.signed_in_minutes(now), 10);
}

// -- policy editor ---------------------------------------------------------------------

#[tokio::test]
async fn check_policy_shows_gained_lost_and_placeholders() {
    let h = harness(full_opts()).await;
    seed(&h).await;
    let (id, _) = api_key(&h, "agent", &["lab_*"], &["GET"]).await;
    let mut b = signed_in(&h).await;

    let r = edit(
        &mut b,
        &h,
        &id,
        &[("op", "check"), ("credentials", "prod_*"), ("m_GET", "1")],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.contains("<code class=\"gain\">prod_db</code>"));
    assert!(r.body.contains("<code class=\"loss\">lab_nas</code>"));
    assert!(r.body.contains("{{vault:prod_db}}"));
    assert!(r.body.contains("https://db.prod"));
    assert!(
        !r.body.contains("lab_nas}}"),
        "lab_nas is not reached by the draft"
    );
    assert!(r
        .body
        .contains("Saving this draft would give the key more access"));
    // The form stays filled in.
    assert!(r.body.contains("prod_*</textarea>"));
    assert!(r.body.contains("name=\"m_GET\" value=\"1\" checked"));
    // Nothing saved; a preview event, via ui; no value ever read.
    let policy = h
        .app
        .agent_keys
        .read()
        .await
        .values()
        .next()
        .unwrap()
        .policy
        .clone();
    assert_eq!(policy.credentials, vec!["lab_*"]);
    let e = &h.events_of("policy_preview")[0];
    assert_eq!(via(e), "ui");
    assert_eq!(e["ferrowarden"]["details"]["request_checked"], false);

    // A validation error keeps the form and saves nothing.
    let r = edit(
        &mut b,
        &h,
        &id,
        &[("op", "check"), ("m_GET", "1"), ("m_all", "1")],
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body.contains("must be the only entry"));
}

#[tokio::test]
async fn widening_saves_need_confirmation_and_narrowing_ones_do_not() {
    let h = harness(full_opts()).await;
    seed(&h).await;
    let (id, token) = api_key(&h, "agent", &["lab_*"], &["GET"]).await;
    let mut b = signed_in(&h).await;
    let policy_now = |h: &Harness| {
        h.app
            .agent_keys
            .try_read()
            .unwrap()
            .get(&hash_token(&token))
            .unwrap()
            .policy
            .clone()
    };

    // Widening credentials, methods, and patterns that match nothing yet.
    for extra in [
        vec![("credentials", "*"), ("m_GET", "1")],
        vec![("credentials", "lab_*"), ("m_GET", "1"), ("m_POST", "1")],
        vec![("credentials", "lab_*\nfuture_*"), ("m_GET", "1")],
    ] {
        let mut fields = vec![("op", "save")];
        fields.extend(extra);
        let r = edit(&mut b, &h, &id, &fields).await;
        assert_eq!(r.status, StatusCode::OK, "{fields:?}");
        assert!(r.body.contains("Confirm save"), "{fields:?}");
        assert!(r.body.contains("name=\"confirm\" value=\"1\""));
        assert_eq!(policy_now(&h).credentials, vec!["lab_*"], "unchanged");
        assert!(h.events_of("key_policy_change").is_empty());
    }
    // The confirmation page shows the diff.
    let r = edit(
        &mut b,
        &h,
        &id,
        &[("op", "save"), ("credentials", "*"), ("m_GET", "1")],
    )
    .await;
    assert!(r.body.contains("<code class=\"gain\">prod_db</code>"));

    // Confirm.
    let r = edit(
        &mut b,
        &h,
        &id,
        &[
            ("op", "save"),
            ("confirm", "1"),
            ("credentials", "lab_*\nprod_*"),
            ("m_GET", "1"),
            ("m_POST", "1"),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), format!("/ui/keys/{id}?m=saved"));
    let p = policy_now(&h);
    assert_eq!(p.credentials, vec!["lab_*", "prod_*"]);
    assert_eq!(p.methods, vec!["GET", "POST"]);
    let stored = load(h.keys_path.as_ref().unwrap()).unwrap();
    assert_eq!(
        stored[0].credentials,
        Some(vec!["lab_*".into(), "prod_*".into()])
    );
    let e = &h.events_of("key_policy_change")[0];
    assert_eq!(via(e), "ui");
    assert_eq!(
        e["ferrowarden"]["details"]["before"]["credentials"],
        json!(["lab_*"])
    );
    assert_eq!(
        e["ferrowarden"]["details"]["after"]["methods"],
        json!(["GET", "POST"])
    );
    let page = b.get(&h, &format!("/ui/keys/{id}?m=saved")).await;
    assert!(page.body.contains("Policy saved"));

    // Narrowing saves straight away.
    let r = edit(
        &mut b,
        &h,
        &id,
        &[("op", "save"), ("credentials", "lab_nas"), ("m_GET", "1")],
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(policy_now(&h).credentials, vec!["lab_nas"]);
    assert_eq!(h.events_of("key_policy_change").len(), 2);
    // The agent's token sees the effect at once.
    assert!(h
        .app
        .agent_keys
        .read()
        .await
        .get(&hash_token(&token))
        .unwrap()
        .policy
        .allows_credential("lab_nas"));
    assert!(!h
        .app
        .agent_keys
        .read()
        .await
        .get(&hash_token(&token))
        .unwrap()
        .policy
        .allows_credential("prod_db"));
    // Saving with a bad confirm value or action is a bad request.
    assert_eq!(
        edit(&mut b, &h, &id, &[("op", "save"), ("confirm", "yes")])
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        edit(&mut b, &h, &id, &[("op", "delete")]).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        edit(&mut b, &h, &id, &[]).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn a_key_without_a_policy_is_explained_and_can_be_given_one() {
    let h = harness(full_opts()).await;
    h.app.agent_keys.write().await.insert(
        "legacyhash".into(),
        AgentKey {
            id: "legacy-id".into(),
            name: "old".into(),
            created_at: chrono::Utc::now(),
            policy: Default::default(),
            policy_set: false,
        },
    );
    let mut b = signed_in(&h).await;
    let r = b.get(&h, "/ui/keys/legacy-id").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("deny-all"));
    assert!(r.body.contains("<strong>both</strong>"));
    // It lacks the key file entry, so the save fails loudly, not silently.
    let r = edit(
        &mut b,
        &h,
        "legacy-id",
        &[
            ("op", "save"),
            ("confirm", "1"),
            ("credentials", "a"),
            ("m_GET", "1"),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!r.body.contains("key file"), "no internals shown");
}

#[tokio::test]
async fn request_check_reports_allowed_and_denied_with_reasons() {
    let h = harness(full_opts()).await;
    seed(&h).await;
    let (id, _) = api_key(&h, "agent", &["lab_*"], &["GET"]).await;
    let mut b = signed_in(&h).await;
    let check = |method: &'static str, url: &'static str, headers: &'static str| {
        vec![
            ("op", "request"),
            ("credentials", "lab_*"),
            ("m_GET", "1"),
            ("req_method", method),
            ("req_url", url),
            ("req_headers", headers),
        ]
    };
    let r = edit(
        &mut b,
        &h,
        &id,
        &check(
            "GET",
            "https://nas.lab/api",
            "Authorization: Bearer {{vault:lab_nas}}\nAccept: x",
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("Allowed</span>"), "{}", r.body);
    let e = &h.events_of("policy_preview")[0];
    assert_eq!(e["ferrowarden"]["details"]["request_checked"], true);

    let denied = |body: &str, reason: &str, status: &str| {
        assert!(body.contains("Denied</span>"), "{body}");
        assert!(body.contains(&format!("<code>{reason}</code>")));
        assert!(body.contains(&format!("Status {status}")));
    };
    let r = edit(
        &mut b,
        &h,
        &id,
        &check("GET", "https://db.prod/", "A: {{vault:prod_db}}"),
    )
    .await;
    denied(&r.body, "credential_out_of_scope", "403");
    let r = edit(&mut b, &h, &id, &check("POST", "https://nas.lab/", "")).await;
    denied(&r.body, "method_not_allowed", "403");
    let r = edit(
        &mut b,
        &h,
        &id,
        &check("GET", "https://evil.example/", "A: {{vault:lab_nas}}"),
    )
    .await;
    denied(&r.body, "credential_host_not_allowed", "403");
    let r = edit(&mut b, &h, &id, &check("GET", "ftp://nas.lab/", "")).await;
    denied(&r.body, "invalid_target_url", "400");

    // Header parsing is strict.
    for (headers, why) in [
        ("A: 1\na: 2", "twice"),
        ("no colon here", "colon"),
        (": value", "name"),
        ("Bad Name: v", "name"),
    ] {
        let r = edit(&mut b, &h, &id, &check("GET", "https://nas.lab/", headers)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{why}");
        assert!(r.body.contains("alert error"));
    }
    let many: String = (0..51).map(|i| format!("H{i}: v\n")).collect();
    let mut f = check("GET", "https://nas.lab/", "");
    f[5].1 = Box::leak(many.into_boxed_str());
    assert_eq!(
        edit(&mut b, &h, &id, &f).await.status,
        StatusCode::BAD_REQUEST
    );
    let fifty: String = (0..50).map(|i| format!("H{i}: v\n")).collect();
    f[5].1 = Box::leak(fifty.into_boxed_str());
    assert_eq!(edit(&mut b, &h, &id, &f).await.status, StatusCode::OK);
    assert_eq!(
        edit(&mut b, &h, &id, &check("GET", "  ", "")).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        edit(&mut b, &h, &id, &check("TRACE", "https://nas.lab/", ""))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    // A body is accepted as a raw string.
    let mut f = check("GET", "https://nas.lab/", "");
    f.push(("req_body", "{\"x\": \"{{vault:lab_nas}}\"}"));
    assert!(edit(&mut b, &h, &id, &f)
        .await
        .body
        .contains("Allowed</span>"));
}

// -- revoke -------------------------------------------------------------------------------

#[tokio::test]
async fn revoking_asks_first_and_takes_effect() {
    let h = harness(full_opts()).await;
    let (id, token) = api_key(&h, "doomed", &["*"], &["*"]).await;
    api_key(&h, "keeper", &["*"], &["*"]).await;
    let mut b = signed_in(&h).await;
    let page = b.get(&h, &format!("/ui/keys/{id}/revoke")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("<strong>doomed</strong>"));
    assert!(page.body.contains(&id));
    assert_eq!(key_count(&h), 2, "a GET revokes nothing");

    let r = b
        .post(
            &h,
            &format!("/ui/keys/{id}/revoke"),
            &[("csrf", &page.csrf())],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/ui/keys?m=revoked");
    assert!(b
        .get(&h, "/ui/keys?m=revoked")
        .await
        .body
        .contains("Key revoked"));
    assert!(h
        .app
        .agent_keys
        .read()
        .await
        .get(&hash_token(&token))
        .is_none());
    assert_eq!(load(h.keys_path.as_ref().unwrap()).unwrap().len(), 1);
    let e = &h.events_of("key_revoke")[0];
    assert_eq!(
        (via(e), e["ferrowarden"]["details"]["key_name"].as_str()),
        ("ui", Some("doomed"))
    );

    // Again: gone. Odd ids: not found, nothing echoed.
    let r = b
        .post(
            &h,
            &format!("/ui/keys/{id}/revoke"),
            &[("csrf", &page.csrf())],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    for bad in ["x%3Cscript%3E", "..%2f..", "a.b"] {
        assert_eq!(
            b.get(&h, &format!("/ui/keys/{bad}/revoke")).await.status,
            StatusCode::NOT_FOUND,
            "{bad}"
        );
        assert_eq!(
            b.get(&h, &format!("/ui/keys/{bad}")).await.status,
            StatusCode::NOT_FOUND,
            "{bad}"
        );
    }
}

// -- audit ----------------------------------------------------------------------------------

#[tokio::test]
async fn the_audit_page_filters_and_is_strict() {
    let h = harness(full_opts()).await;
    let (id, _) = api_key(&h, "audited", &["*"], &["*"]).await;
    api_key(&h, "other", &["*"], &["*"]).await;
    // A failure from another address.
    h.app.events.emit(
        crate::events::SecurityEvent::new(crate::events::Action::AdminAuth)
            .request(&RequestContext::new("203.0.113.9".parse().unwrap()))
            .reason(crate::events::Reason::InvalidAdminKey)
            .status(401),
    );
    h.app.events.emit(
        crate::events::SecurityEvent::new(crate::events::Action::Forward)
            .key(&AgentKey {
                id: id.clone(),
                name: "audited".into(),
                created_at: chrono::Utc::now(),
                policy: Default::default(),
                policy_set: true,
            })
            .method("GET")
            .url("https://nas.lab/x")
            .status(200),
    );
    let mut b = signed_in(&h).await;

    let all = b.get(&h, "/ui/audit").await;
    assert_eq!(all.status, StatusCode::OK);
    assert!(all
        .body
        .contains("<details><summary>Details</summary><pre>"));
    assert!(all.body.contains("GET nas.lab"));
    // Newest first: the forward event precedes the key_create events.
    assert!(
        all.body.find("<code>forward</code>").unwrap()
            < all.body.find("<code>key_create</code>").unwrap()
    );

    let only = |r: &Resp, action: &str| {
        let rows = r.body.matches("<tr class=\"detail\">").count();
        (
            rows,
            r.body.contains(&format!(
                "<td data-label=\"Action\"><code>{action}</code></td>"
            )),
        )
    };
    let r = b
        .get(
            &h,
            "/ui/audit?action=key_create&outcome=&key=&ip=&limit=100",
        )
        .await;
    assert_eq!(only(&r, "key_create"), (2, true));
    assert!(!r
        .body
        .contains("<td data-label=\"Action\"><code>forward</code></td>"));
    let r = b.get(&h, "/ui/audit?outcome=failure").await;
    assert_eq!(only(&r, "admin_auth"), (1, true));
    let r = b.get(&h, "/ui/audit?ip=203.0.113.9").await;
    assert_eq!(r.body.matches("<tr class=\"detail\">").count(), 1);
    let r = b.get(&h, "/ui/audit?key=audited").await;
    assert_eq!(only(&r, "forward"), (1, true));
    let r = b.get(&h, &format!("/ui/audit?key={id}")).await;
    assert_eq!(r.body.matches("<tr class=\"detail\">").count(), 1);
    assert!(
        b.get(&h, "/ui/audit?key=audit")
            .await
            .body
            .contains("No events match"),
        "exact match only"
    );
    let r = b.get(&h, "/ui/audit?limit=25").await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("<option value=\"25\" selected>"));

    // Strict.
    for bad in [
        "?foo=1",
        "?limit=100&limit=100",
        "?limit=10",
        "?limit=abc",
        "?action=nope",
        "?outcome=Success",
        "?ip=not-an-ip",
        "?action=forward&action=forward",
        "?limit",
        "?&",
    ] {
        assert_eq!(
            b.get(&h, &format!("/ui/audit{bad}")).await.status,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    let reads = h.events_of("audit_read");
    assert!(!reads.is_empty());
    assert!(reads.iter().all(|e| via(e) == "ui"));
    assert!(reads
        .iter()
        .any(|e| e["ferrowarden"]["details"]["filtered"] == true));
}

#[tokio::test]
async fn api_events_carry_via_api() {
    let h = harness(full_opts()).await;
    let (id, _) = api_key(&h, "k", &["*"], &["*"]).await;
    let ctx = RequestContext::new("10.0.0.1".parse().unwrap());
    let c = Caller {
        ctx: &ctx,
        via: Via::Api,
    };
    key_service::list_keys(&h.app, c).await;
    key_service::revoke_key(&h.app, c, &id).await.unwrap();
    for a in ["key_create", "key_list", "key_revoke"] {
        assert_eq!(via(&h.events_of(a)[0]), "api", "{a}");
    }
}

// -- CSRF, origin, strict forms on every new POST -----------------------------------------

fn with_token<'a>(
    token: Option<&'a str>,
    extra: &'a [(&'a str, String)],
) -> Vec<(&'a str, &'a str)> {
    let mut f: Vec<(&str, &str)> = Vec::new();
    if let Some(t) = token {
        f.push(("csrf", t));
    }
    f.extend(extra.iter().map(|(k, v)| (*k, v.as_str())));
    f
}

#[tokio::test]
async fn every_new_post_route_enforces_csrf_origin_and_strict_forms() {
    let h = harness(full_opts()).await;
    let (id, _) = api_key(&h, "t", &["lab_*"], &["GET"]).await;
    let mut b = signed_in(&h).await;
    let csrf = b.get(&h, "/ui/keys").await.csrf();
    let routes: Vec<(String, Vec<(&str, String)>)> = vec![
        ("/ui/keys/new".into(), vec![("name", "x".into())]),
        (
            format!("/ui/keys/{id}"),
            vec![
                ("op", "save".into()),
                ("credentials", "*".into()),
                ("m_all", "1".into()),
            ],
        ),
        (format!("/ui/keys/{id}/revoke"), vec![]),
        ("/ui/notify/test".into(), vec![]),
        ("/ui/logout".into(), vec![]),
    ];
    for (path, extra) in &routes {
        // Missing, wrong, empty tokens.
        for token in [None, Some("wrong"), Some("")] {
            let r = b.post(&h, path, &with_token(token, extra)).await;
            assert_eq!(r.status, StatusCode::FORBIDDEN, "{path} {token:?}");
        }
        // Cross-site, other origin, no origin headers.
        for headers in [
            vec![("sec-fetch-site", "cross-site")],
            vec![("sec-fetch-site", "same-site")],
            vec![("origin", "https://evil.example")],
            vec![],
        ] {
            let r = b
                .post_with(&h, path, &with_token(Some(&csrf), extra), &headers)
                .await;
            assert_eq!(r.status, StatusCode::FORBIDDEN, "{path} {headers:?}");
        }
        // A session is required.
        let r = Browser::new()
            .post(&h, path, &with_token(Some(&csrf), extra))
            .await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{path}");
        assert_eq!(r.location(), "/ui/login");
        // Unknown and repeated fields, wrong content type.
        let mut unknown = with_token(Some(&csrf), extra);
        unknown.push(("surprise", "1"));
        assert_eq!(
            b.post(&h, path, &unknown).await.status,
            StatusCode::BAD_REQUEST,
            "{path}"
        );
        let raw = format!("csrf={csrf}&csrf={csrf}");
        let r = b
            .send(
                &h,
                Method::POST,
                path,
                &[
                    ("content-type", "application/x-www-form-urlencoded"),
                    ("sec-fetch-site", "same-origin"),
                ],
                Some(raw),
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{path} duplicate");
        let r = b
            .send(
                &h,
                Method::POST,
                path,
                &[
                    ("content-type", "text/plain"),
                    ("sec-fetch-site", "same-origin"),
                ],
                Some(format!("csrf={csrf}")),
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{path} content type");
        let r = b
            .post_with(
                &h,
                path,
                &with_token(Some(&csrf), extra),
                &[("sec-fetch-site", "same-origin")],
            )
            .await;
        // Not logout: that one would end the session for the rest of the loop.
        if path != "/ui/logout" {
            assert_ne!(r.status, StatusCode::FORBIDDEN, "{path}");
        } else {
            b = signed_in(&h).await;
        }
        // Rebuild state for the next route (the revoke above succeeded).
    }
    assert!(h
        .events_of("request_rejected")
        .iter()
        .all(|e| e["http"]["response"]["status_code"] == 403));
}

#[tokio::test]
async fn rejected_posts_change_nothing() {
    let h = harness(full_opts()).await;
    let (id, _) = api_key(&h, "t", &["lab_*"], &["GET"]).await;
    let mut b = signed_in(&h).await;
    for (path, fields) in [
        ("/ui/keys/new".to_string(), vec![("name", "x")]),
        (format!("/ui/keys/{id}/revoke"), vec![]),
        (
            format!("/ui/keys/{id}"),
            vec![("op", "save"), ("m_all", "1")],
        ),
    ] {
        let mut f = vec![("csrf", "nope")];
        f.extend(fields);
        assert_eq!(b.post(&h, &path, &f).await.status, StatusCode::FORBIDDEN);
    }
    assert_eq!(key_count(&h), 1);
    assert_eq!(h.events_of("key_create").len(), 1, "only the setup");
    assert!(h.events_of("key_revoke").is_empty());
    assert!(h.events_of("key_policy_change").is_empty());
}

// -- rendering safety -------------------------------------------------------------------------

fn assert_escaped(page: &str, what: &str) {
    for raw in [
        "<script>",
        "<img src=x",
        "\"><img",
        "<script",
        "onerror=alert(1)>",
    ] {
        assert!(!page.contains(raw), "{what}: raw {raw:?} in page");
    }
}

#[tokio::test]
async fn hostile_credential_names_only_appear_escaped() {
    let h = harness(full_opts()).await;
    seed(&h).await;
    let (id, _) = api_key(&h, "agent", &["lab_*"], &["GET"]).await;
    let mut b = signed_in(&h).await;
    let r = edit(
        &mut b,
        &h,
        &id,
        &[("op", "check"), ("credentials", "*"), ("m_GET", "1")],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_escaped(&r.body, "preview");
    assert!(
        r.body.contains("&#60;img src=x onerror=alert(1)&#62;"),
        "escaped form is present"
    );
    // On the confirmation page (names in the diff).
    let r = edit(
        &mut b,
        &h,
        &id,
        &[("op", "save"), ("credentials", "*"), ("m_GET", "1")],
    )
    .await;
    assert!(r.body.contains("Confirm save"));
    assert_escaped(&r.body, "confirm");
    // And hostile input echoed back through the draft and request fields.
    let r = edit(
        &mut b,
        &h,
        &id,
        &[
            ("op", "request"),
            ("credentials", "\"><script>alert(1)</script>"),
            ("req_url", "\"><img src=x onerror=alert(1)>"),
            ("req_headers", "</textarea><script>x</script>: v"),
            ("req_body", "</textarea><script>1</script>"),
        ],
    )
    .await;
    assert_escaped(&r.body, "request check");
    assert!(!r.body.contains("</textarea><script>"));
}

#[tokio::test]
async fn hostile_key_names_only_appear_escaped_on_every_page() {
    let h = harness(full_opts()).await;
    let (id, _) = api_key(&h, HOSTILE_KEY, &["*"], &["*"]).await;
    let mut b = signed_in(&h).await;
    let mut pages = vec![
        b.get(&h, "/ui/keys").await,
        b.get(&h, &format!("/ui/keys/{id}")).await,
        b.get(&h, &format!("/ui/keys/{id}/revoke")).await,
        b.get(&h, "/ui/audit").await,
        b.get(&h, "/ui/audit?key=%22%3E%3Cscript%3E").await,
        b.get(&h, "/ui/").await,
    ];
    pages.push(
        edit(
            &mut b,
            &h,
            &id,
            &[("op", "check"), ("credentials", "x"), ("m_GET", "1")],
        )
        .await,
    );
    pages.push(
        edit(
            &mut b,
            &h,
            &id,
            &[
                ("op", "save"),
                ("credentials", "*"),
                ("m_all", "1"),
                ("confirm", "1"),
            ],
        )
        .await,
    );
    for (i, p) in pages.iter().enumerate() {
        assert_escaped(&p.body, &format!("page {i}"));
    }
    assert!(pages[0].body.contains("&#60;script&#62;alert(1)"));
    // A key created through the UI with a hostile name, on the token page.
    let form = b.get(&h, "/ui/keys/new").await;
    let (csrf, fid) = (form.csrf(), form.form_id());
    let r = b
        .post(
            &h,
            "/ui/keys/new",
            &[
                ("csrf", &csrf),
                ("form_id", &fid),
                ("name", "\" onfocus=\"alert(1)<img src=x>"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_escaped(&r.body, "token page");
    assert!(!r.body.contains("\" onfocus=\""));
    // The create form echoes a hostile name escaped, inside the attribute.
    let fid = b.get(&h, "/ui/keys/new").await.form_id();
    let r = b
        .post(
            &h,
            "/ui/keys/new",
            &[
                ("csrf", &csrf),
                ("form_id", &fid),
                ("name", "\" onfocus=\"x"),
                ("m_all", "1"),
                ("m_GET", "1"),
            ],
        )
        .await;
    assert!(!r.body.contains("\" onfocus=\"x"));
}
