//! Tests of the Approvals pages and of the approval patterns in the key
//! forms: the same harness as the other admin pages.

use super::*;
use crate::approvals::{AskFor, Check, Reasons};
use crate::keys::load;
use crate::sessions::Origin;
use crate::vault::model::CredentialEntry;

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
    b
}

const URL: &str =
    "https://pve.example.com:8006/api2/json/nodes/{{vault:pve_root:username}}?ticket=QUERYMARK";

/// Open an approval as the gate does, without holding a request.
fn open_approval(h: &Harness, key: &str, items: &[&str], url: &str) -> String {
    let origin = Origin::of(
        &reqwest::Url::parse(url.replace("{{vault:pve_root:username}}", "x").as_str()).unwrap(),
    )
    .unwrap();
    let required = items
        .iter()
        .map(|i| {
            (
                (*i).to_string(),
                Reasons {
                    vault_field: true,
                    key_policy: items.len() > 1,
                },
            )
        })
        .collect();
    let ask = AskFor {
        key_id: &format!("{key}-id"),
        key_name: key,
        origin: &origin,
        method: "DELETE",
        url,
        request_id: "0193abcd-0000-7000-8000-000000000001",
    };
    let cfg = crate::config::ApprovalConfig {
        max_pending_per_key: 50,
        max_requests_per_key_per_hour: 1000,
        ..Default::default()
    };
    match h
        .app
        .approvals
        .check(&ask, &required, &cfg, chrono::Utc::now())
        .unwrap()
    {
        Check::Wait { view, .. } | Check::Pending { view, .. } => view.id,
        _ => panic!("not opened"),
    }
}

fn counts(h: &Harness) -> (usize, usize) {
    h.app.approvals.counts(chrono::Utc::now())
}

fn grant_id(h: &Harness) -> String {
    h.app.approvals.list(chrono::Utc::now()).1[0].id.clone()
}

async fn detail_csrf(b: &mut Browser, h: &Harness, id: &str) -> String {
    let r = b.get(h, &format!("/ui/approvals/{id}")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    r.csrf()
}

// ── Pages ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_approvals_page_lists_what_waits_and_what_is_granted() {
    let h = harness(full_opts()).await;
    let mut anon = Browser::new();
    for p in ["/ui/approvals", "/ui/approvals/abc"] {
        assert_eq!(anon.get(&h, p).await.location(), "/ui/login", "{p}");
    }
    let mut b = signed_in(&h).await;
    let r = b.get(&h, "/ui/approvals").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_security_headers(&r);
    assert!(r.body.contains("Nothing is waiting."));
    assert!(r.body.contains("aria-current=\"page\">Approvals</a>"));
    // No count in the navigation while nothing waits.
    assert!(!r.body.contains("Waiting for a decision\">"));

    let id = open_approval(&h, "agent-a", &["pve_root"], URL);
    let r = b.get(&h, "/ui/approvals").await;
    assert!(r.body.contains("Waiting for a decision (1)"));
    assert!(r.body.contains("agent-a") && r.body.contains("pve_root"));
    assert!(r.body.contains("DELETE") && r.body.contains("https://pve.example.com:8006"));
    assert!(r.body.contains(&format!("href=\"/ui/approvals/{id}\"")));
    // The query string is not on the list, and the navigation shows the count.
    assert!(!r.body.contains("QUERYMARK"));
    assert!(r.body.contains("title=\"Waiting for a decision\">1</span>"));
    // Every signed-in page carries the count.
    let keys = b.get(&h, "/ui/keys").await;
    assert!(keys
        .body
        .contains("title=\"Waiting for a decision\">1</span>"));

    // Approve it: it becomes a grant, with a Revoke button and who approved.
    let csrf = detail_csrf(&mut b, &h, &id).await;
    let r = b
        .post(
            &h,
            &format!("/ui/approvals/{id}/approve"),
            &[("csrf", &csrf), ("preset", "15")],
        )
        .await;
    assert_eq!(r.location(), "/ui/approvals?m=approved");
    let r = b.get(&h, "/ui/approvals?m=approved").await;
    assert!(r.body.contains("Approved. The agent"));
    assert!(r.body.contains("Live grants (1)"));
    assert!(r.body.contains(EMAIL));
    assert!(r
        .body
        .contains(&format!("action=\"/ui/grants/{}/revoke\"", grant_id(&h))));
    assert!(r.body.contains("Nothing is waiting."));
    // No script, no inline style.
    let lower = r.body.to_lowercase();
    assert!(!lower.contains("<script") && !lower.contains("style=") && !lower.contains("onclick"));
    // Only fixed notices are ever shown for `?m=`.
    let r = b.get(&h, "/ui/approvals?m=%3Cscript%3E").await;
    assert!(!r.body.contains("<script>"));
}

#[tokio::test]
async fn the_detail_page_shows_what_the_agent_asked_for_and_never_a_value() {
    let h = harness(full_opts()).await;
    let hostile = "https://pve.example.com:8006/<img src=x onerror=alert(1)>?q={{vault:pve_root}}";
    let id = open_approval(&h, "agent-a", &["pve_root", "nas_admin"], hostile);
    let mut b = signed_in(&h).await;
    let r = b.get(&h, &format!("/ui/approvals/{id}")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_security_headers(&r);
    for needle in [
        "agent-a",
        "pve_root",
        "nas_admin",
        "needs approval: vault field and key policy",
        "needs approval: vault field",
        "<code>DELETE</code>",
        "<code>https://pve.example.com:8006</code>",
        "0193abcd-0000-7000-8000-000000000001",
        &id,
        "Approve this request?",
        "name=\"preset\"",
        "name=\"minutes\"",
        "max=\"480\"",
        "action=\"/ui/approvals/",
    ] {
        assert!(r.body.contains(needle), "{needle}\n{}", r.body);
    }
    // The URL as sent, with its placeholders, escaped; the path without query.
    assert!(r.body.contains("{{vault:pve_root}}"));
    assert!(!r.body.contains("<img"), "escaped");
    assert!(r.body.contains("&#60;img") || r.body.contains("&lt;img"));
    // Four presets, 15 minutes selected.
    for m in [5, 15, 60, 240] {
        assert!(
            r.body.contains(&format!("name=\"preset\" value=\"{m}\"")),
            "{m}"
        );
    }
    assert!(r.body.contains("value=\"15\" checked"));
    // Approve and Deny both need the CSRF token.
    assert_eq!(
        r.body.matches("name=\"csrf\"").count(),
        3,
        "two forms and sign-out"
    );
    h.assert_no_leaks(&[]);
}

#[tokio::test]
async fn an_approval_that_is_gone_is_a_404_to_view_and_a_409_to_decide() {
    let h = harness(full_opts()).await;
    let id = open_approval(&h, "agent-a", &["pve_root"], URL);
    let mut b = signed_in(&h).await;
    let csrf = detail_csrf(&mut b, &h, &id).await;
    let r = b
        .post(&h, &format!("/ui/approvals/{id}/deny"), &[("csrf", &csrf)])
        .await;
    assert_eq!(r.location(), "/ui/approvals?m=denied");
    // Decided: viewing says so (404), deciding again changes nothing (409).
    let r = b.get(&h, &format!("/ui/approvals/{id}")).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(r.body.contains("not pending any more"));
    for action in ["approve", "deny"] {
        let mut fields = vec![("csrf", csrf.as_str())];
        if action == "approve" {
            fields.push(("preset", "5"));
        }
        let r = b
            .post(&h, &format!("/ui/approvals/{id}/{action}"), &fields)
            .await;
        assert_eq!(r.status, StatusCode::CONFLICT, "{action}");
        assert!(r.body.contains("no longer pending"), "{action}");
    }
    assert_eq!(counts(&h), (0, 0));
    // Malformed ids are the same.
    for bad in ["x.y", "a%20b", "ab"] {
        assert_eq!(
            b.get(&h, &format!("/ui/approvals/{bad}")).await.status,
            StatusCode::NOT_FOUND,
            "{bad}"
        );
        let r = b
            .post(&h, &format!("/ui/approvals/{bad}/deny"), &[("csrf", &csrf)])
            .await;
        assert_eq!(r.status, StatusCode::CONFLICT, "{bad}");
    }
    assert_eq!(
        h.events_of("approval_denied").len(),
        3,
        "one real and two failed"
    );
}

#[tokio::test]
async fn the_short_links_of_a_prompt_lead_to_the_pages_and_the_sign_in() {
    let h = harness(full_opts()).await;
    let id = open_approval(&h, "agent-a", &["pve_root"], URL);
    let mut anon = Browser::new();
    // `<public_url>/approvals/<id>` -> the UI page -> (no session) the sign-in.
    let r = anon.get(&h, &format!("/approvals/{id}")).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), format!("/ui/approvals/{id}"));
    assert_eq!(anon.get(&h, "/approvals").await.location(), "/ui/approvals");
    assert_eq!(
        anon.get(&h, &format!("/ui/approvals/{id}"))
            .await
            .location(),
        "/ui/login"
    );
    // A bad id goes to the list; nothing is echoed.
    assert_eq!(
        anon.get(&h, "/approvals/a.b%3Cx").await.location(),
        "/ui/approvals"
    );
    // Knowing an id is not a capability: the link never decides anything.
    assert_eq!(counts(&h), (1, 0));
    // The sign-in comes back to the page afterwards.
    let page = anon
        .get(&h, &format!("/ui/login?m=sudo&next=/ui/approvals/{id}"))
        .await;
    assert!(page
        .body
        .contains(&format!("name=\"next\" value=\"/ui/approvals/{id}\"")));
}

// ── Sensitive: sudo, CSRF, origin ─────────────────────────────────────────────

#[tokio::test]
async fn deciding_needs_a_recent_sign_in_on_the_page_and_on_every_post() {
    let h = harness(full_opts()).await;
    let id = open_approval(&h, "agent-a", &["pve_root"], URL);
    let mut b = signed_in(&h).await;
    let csrf = detail_csrf(&mut b, &h, &id).await;
    h.ui.advance(Duration::from_secs(10 * 60 + 1));

    // The page that offers a decision asks for the sign-in first.
    let r = b.get(&h, &format!("/ui/approvals/{id}")).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(
        r.location(),
        format!("/ui/login?m=sudo&next=/ui/approvals/{id}")
    );
    // The list can still be viewed.
    assert_eq!(b.get(&h, "/ui/approvals").await.status, StatusCode::OK);

    // Every decision with a stale sign-in is sent to sign in again.
    for (path, fields) in [
        (
            format!("/ui/approvals/{id}/approve"),
            vec![("csrf", csrf.as_str()), ("preset", "15")],
        ),
        (
            format!("/ui/approvals/{id}/deny"),
            vec![("csrf", csrf.as_str())],
        ),
    ] {
        let r = b.post(&h, &path, &fields).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{path}");
        assert_eq!(
            r.location(),
            format!("/ui/login?m=sudo&next=/ui/approvals/{id}")
        );
    }
    assert_eq!(counts(&h), (1, 0), "nothing was decided");
    assert!(h.events_of("approval_granted").is_empty());
    assert!(h.events_of("approval_denied").is_empty());

    // After a fresh sign-in it works.
    let page = b
        .get(&h, &format!("/ui/login?m=sudo&next=/ui/approvals/{id}"))
        .await;
    let r = b
        .post(
            &h,
            "/ui/login",
            &[
                ("csrf", &page.csrf()),
                ("password", PASSWORD),
                ("next", &format!("/ui/approvals/{id}")),
            ],
        )
        .await;
    assert_eq!(r.location(), format!("/ui/approvals/{id}"));
    let csrf = detail_csrf(&mut b, &h, &id).await;
    let r = b
        .post(
            &h,
            &format!("/ui/approvals/{id}/approve"),
            &[("csrf", &csrf), ("preset", "15")],
        )
        .await;
    assert_eq!(r.location(), "/ui/approvals?m=approved");
    assert_eq!(counts(&h), (0, 1));

    // Revoking a grant is sensitive too.
    let gid = grant_id(&h);
    h.ui.advance(Duration::from_secs(10 * 60 + 1));
    let r = b
        .post(&h, &format!("/ui/grants/{gid}/revoke"), &[("csrf", &csrf)])
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "/ui/login?m=sudo&next=/ui/approvals");
    assert_eq!(counts(&h), (0, 1), "the grant stands");
}

#[tokio::test]
async fn every_decision_route_enforces_csrf_origin_and_strict_forms() {
    let h = harness(full_opts()).await;
    let id = open_approval(&h, "agent-a", &["pve_root"], URL);
    let mut b = signed_in(&h).await;
    let csrf = detail_csrf(&mut b, &h, &id).await;
    let routes: Vec<(String, Vec<(&str, String)>)> = vec![
        (
            format!("/ui/approvals/{id}/approve"),
            vec![("preset", "15".into())],
        ),
        (format!("/ui/approvals/{id}/deny"), vec![]),
        ("/ui/grants/someid/revoke".into(), vec![]),
    ];
    for (path, extra) in &routes {
        for token in [None, Some("wrong"), Some("")] {
            let r = b.post(&h, path, &with_token(token, extra)).await;
            assert_eq!(r.status, StatusCode::FORBIDDEN, "{path} {token:?}");
        }
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
        // A session is required: a link alone decides nothing.
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
    }
    // None of those decided anything.
    assert_eq!(counts(&h), (1, 0));
    assert!(h.events_of("approval_granted").is_empty());
    assert!(h.events_of("approval_denied").is_empty());
    // The rejected ones are recorded as such.
    assert!(!h.events_of("request_rejected").is_empty());
}

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
async fn the_ui_router_has_no_admin_api_and_no_agent_route() {
    let h = harness(full_opts()).await;
    let mut b = signed_in(&h).await;
    for (method, path) in [
        (Method::GET, "/v1/admin/approvals"),
        (Method::POST, "/v1/admin/approvals/x/approve"),
        (Method::DELETE, "/v1/admin/grants/x"),
        (Method::POST, "/v1/forward"),
    ] {
        let r = b
            .send(&h, method, path, &[("x-admin-key", "x")], None)
            .await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}");
    }
}

// ── Approve: durations ────────────────────────────────────────────────────────

#[tokio::test]
async fn the_length_comes_from_a_preset_or_the_number_and_is_bounded() {
    let h = harness(full_opts()).await;
    let mut b = signed_in(&h).await;
    let id = open_approval(&h, "agent-a", &["pve_root"], URL);
    let csrf = detail_csrf(&mut b, &h, &id).await;
    let path = format!("/ui/approvals/{id}/approve");

    // Nothing, not a number, out of range, signs or spaces inside: 400, and the
    // page is the form again with the reason; nothing is decided.
    for fields in [
        vec![("csrf", csrf.as_str())],
        vec![("csrf", csrf.as_str()), ("preset", "abc")],
        vec![("csrf", csrf.as_str()), ("preset", "15"), ("minutes", "0")],
        vec![
            ("csrf", csrf.as_str()),
            ("preset", "15"),
            ("minutes", "481"),
        ],
        vec![("csrf", csrf.as_str()), ("preset", "15"), ("minutes", "-5")],
        vec![
            ("csrf", csrf.as_str()),
            ("preset", "15"),
            ("minutes", "1.5"),
        ],
        vec![
            ("csrf", csrf.as_str()),
            ("preset", "15"),
            ("minutes", "1e3"),
        ],
        vec![
            ("csrf", csrf.as_str()),
            ("preset", "15"),
            ("minutes", "99999999999"),
        ],
        vec![("csrf", csrf.as_str()), ("preset", "0")],
        vec![("csrf", csrf.as_str()), ("preset", "481")],
    ] {
        let r = b.post(&h, &path, &fields).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{fields:?}\n{}", r.body);
        assert!(r.body.contains("role=\"alert\""), "{fields:?}");
        assert_eq!(counts(&h), (1, 0), "{fields:?}");
    }

    // A number overrides the preset; the edges are allowed.
    let r = b
        .post(
            &h,
            &path,
            &[("csrf", &csrf), ("preset", "15"), ("minutes", " 480 ")],
        )
        .await;
    assert_eq!(r.location(), "/ui/approvals?m=approved", "{}", r.body);
    let grant = &h.app.approvals.list(chrono::Utc::now()).1[0];
    assert_eq!(
        grant.expires - grant.created,
        chrono::Duration::minutes(480)
    );
    assert_eq!(grant.approver, EMAIL, "the signed-in vault account");
    let e = &h.events_of("approval_granted")[0];
    assert_eq!(e["ferrowarden"]["details"]["via"], "ui");
    assert_eq!(e["ferrowarden"]["details"]["approver"], EMAIL);
    assert_eq!(e["ferrowarden"]["details"]["minutes"], 480);

    let id2 = open_approval(&h, "agent-a", &["nas_admin"], URL);
    let r = b
        .post(
            &h,
            &format!("/ui/approvals/{id2}/approve"),
            &[("csrf", &csrf), ("preset", "5")],
        )
        .await;
    assert_eq!(r.location(), "/ui/approvals?m=approved");
    let grants = h.app.approvals.list(chrono::Utc::now()).1;
    assert!(grants
        .iter()
        .any(|g| g.expires - g.created == chrono::Duration::minutes(5)));
    let id3 = open_approval(&h, "agent-a", &["third"], URL);
    let r = b
        .post(
            &h,
            &format!("/ui/approvals/{id3}/approve"),
            &[("csrf", &csrf), ("minutes", "1")],
        )
        .await;
    assert_eq!(r.location(), "/ui/approvals?m=approved");
}

#[tokio::test]
async fn the_longest_grant_follows_the_configuration() {
    let h = harness(full_opts()).await;
    // The page and the check use `approval.max_grant_minutes`; the harness keeps
    // the default, so 480 is the edge (see the other test). Here: the form says so.
    let id = open_approval(&h, "agent-a", &["pve_root"], URL);
    let mut b = signed_in(&h).await;
    let r = b.get(&h, &format!("/ui/approvals/{id}")).await;
    assert!(r.body.contains("(1 to 480)"));
}

#[tokio::test]
async fn deny_and_revoke_take_effect_and_are_recorded() {
    let h = harness(full_opts()).await;
    let mut b = signed_in(&h).await;
    let denied = open_approval(&h, "agent-a", &["pve_root"], URL);
    let granted = open_approval(&h, "agent-a", &["nas_admin"], URL);
    let csrf = detail_csrf(&mut b, &h, &denied).await;

    let r = b
        .post(
            &h,
            &format!("/ui/approvals/{denied}/deny"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(r.location(), "/ui/approvals?m=denied");
    let e = &h.events_of("approval_denied")[0];
    assert_eq!(e["ferrowarden"]["details"]["via"], "ui");
    assert_eq!(e["ferrowarden"]["details"]["approver"], EMAIL);
    assert_eq!(e["ferrowarden"]["credentials"], json!(["pve_root"]));
    assert!(b
        .get(&h, "/ui/approvals?m=denied")
        .await
        .body
        .contains("Denied. The agent is refused"));

    b.post(
        &h,
        &format!("/ui/approvals/{granted}/approve"),
        &[("csrf", &csrf), ("preset", "60")],
    )
    .await;
    let gid = grant_id(&h);
    let r = b
        .post(&h, &format!("/ui/grants/{gid}/revoke"), &[("csrf", &csrf)])
        .await;
    assert_eq!(r.location(), "/ui/approvals?m=revoked");
    assert_eq!(counts(&h), (0, 0));
    let e = &h.events_of("grant_revoked")[0];
    assert_eq!(e["ferrowarden"]["details"]["approver"], EMAIL);
    assert_eq!(e["ferrowarden"]["details"]["via"], "ui");
    // Again: it is gone.
    let r = b
        .post(&h, &format!("/ui/grants/{gid}/revoke"), &[("csrf", &csrf)])
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(r.body.contains("not live any more"));
    h.assert_no_leaks(&[]);
}

// ── The key forms ─────────────────────────────────────────────────────────────

async fn key_with_approval(h: &Harness, name: &str, approval: &[&str]) -> (String, String) {
    let ctx = crate::middleware::request_context::RequestContext::new("10.0.0.1".parse().unwrap());
    let c = crate::api::key_service::create_key(
        &h.app,
        crate::api::key_service::Caller {
            ctx: &ctx,
            via: crate::api::key_service::Via::Api,
        },
        name,
        vec!["*".into()],
        vec!["GET".into()],
        approval.iter().map(|s| s.to_string()).collect(),
        vec![],
    )
    .await
    .unwrap();
    (c.id, c.token)
}

fn approval_of(h: &Harness, token: &str) -> Vec<String> {
    h.app
        .agent_keys
        .try_read()
        .unwrap()
        .get(&crate::keys::hash_token(token))
        .unwrap()
        .policy
        .approval
        .clone()
}

#[tokio::test]
async fn the_create_form_takes_the_approval_patterns_and_the_token_page_shows_them() {
    let h = harness(full_opts()).await;
    let mut b = signed_in(&h).await;
    let form = b.get(&h, "/ui/keys/new").await;
    assert!(form.body.contains("name=\"approval\""));
    assert!(form.body.contains("ferrowarden_approval"));
    let (csrf, fid) = (form.csrf(), form.form_id());
    let r = b
        .post(
            &h,
            "/ui/keys/new",
            &[
                ("csrf", &csrf),
                ("form_id", &fid),
                ("name", "guarded"),
                ("credentials", "*"),
                ("approval", "proxmox_*\r\n\r\n  nas_admin \r\n"),
                ("m_GET", "1"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.contains("Needs approval"));
    assert!(r.body.contains("proxmox_*") && r.body.contains("nas_admin"));
    let token = token_in(&r.body);
    assert_eq!(approval_of(&h, &token), ["proxmox_*", "nas_admin"]);
    assert_eq!(
        h.events_of("key_create")[0]["ferrowarden"]["details"]["approval"],
        json!(["proxmox_*", "nas_admin"])
    );
    let stored = load(h.keys_path.as_ref().unwrap()).unwrap();
    assert_eq!(
        stored[0].approval,
        Some(vec!["proxmox_*".into(), "nas_admin".into()])
    );

    // An invalid pattern keeps the form, with the reason.
    let form = b.get(&h, "/ui/keys/new").await;
    let long = "x".repeat(300);
    let r = b
        .post(
            &h,
            "/ui/keys/new",
            &[
                ("csrf", &form.csrf()),
                ("form_id", &form.form_id()),
                ("name", "bad"),
                ("credentials", "*"),
                ("approval", &long),
                ("m_GET", "1"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body.contains("approval[0]"), "{}", r.body);
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

#[tokio::test]
async fn removing_or_narrowing_an_approval_pattern_needs_confirmation_like_any_widening() {
    let h = harness(full_opts()).await;
    {
        let mut c = h.app.credentials.write().await;
        let mut e = CredentialEntry::login("1", &["https://pve.example.com"]);
        e.approval_required = false;
        c.insert("proxmox_root".into(), vec![e]);
    }
    let (id, token) = key_with_approval(&h, "agent", &["proxmox_*", "nas"]).await;
    let mut b = signed_in(&h).await;
    let page = b.get(&h, &format!("/ui/keys/{id}")).await;
    assert!(page.body.contains("Needs approval:"));
    assert!(page.body.contains("<code>proxmox_*</code>"));
    assert!(page.body.contains("name=\"approval\""));

    let base = [("op", "save"), ("credentials", "*"), ("m_GET", "1")];
    // Removing a pattern, or narrowing one, asks first and saves nothing.
    for approval in ["proxmox_*", "", "proxmox_a*\nnas"] {
        let mut fields = base.to_vec();
        fields.push(("approval", approval));
        let r = edit(&mut b, &h, &id, &fields).await;
        assert_eq!(r.status, StatusCode::OK, "{approval:?}");
        assert!(r.body.contains("Confirm save"), "{approval:?}");
        // The confirmation carries the draft, approval patterns included.
        assert!(r.body.contains("name=\"approval\""), "{approval:?}");
        assert_eq!(approval_of(&h, &token), ["proxmox_*", "nas"], "unchanged");
    }
    assert!(h.events_of("key_policy_change").is_empty());

    // Confirming saves it (and ends the key's grants, as any change does).
    let mut fields = base.to_vec();
    fields.extend([("confirm", "1"), ("approval", "proxmox_*")]);
    let r = edit(&mut b, &h, &id, &fields).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(approval_of(&h, &token), ["proxmox_*"]);
    let e = &h.events_of("key_policy_change")[0];
    assert_eq!(
        e["ferrowarden"]["details"]["before"]["approval"],
        json!(["proxmox_*", "nas"])
    );
    assert_eq!(
        e["ferrowarden"]["details"]["after"]["approval"],
        json!(["proxmox_*"])
    );

    // Adding or broadening patterns asks for more, so it saves at once.
    for approval in ["proxmox_*\nextra", "*"] {
        let mut fields = base.to_vec();
        fields.push(("approval", approval));
        let r = edit(&mut b, &h, &id, &fields).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{approval:?}: {}", r.body);
    }
    assert_eq!(approval_of(&h, &token), ["*"]);
}

#[tokio::test]
async fn the_policy_check_says_what_would_need_approval() {
    let h = harness(full_opts()).await;
    {
        let mut c = h.app.credentials.write().await;
        let mut guarded = CredentialEntry::login("1", &["https://pve.example.com"]);
        guarded.approval_required = true;
        c.insert("pve_root".into(), vec![guarded]);
        c.insert(
            "grafana".into(),
            vec![CredentialEntry::login("2", &["https://pve.example.com"])],
        );
    }
    let (id, _) = key_with_approval(&h, "agent", &[]).await;
    let mut b = signed_in(&h).await;
    let r = edit(
        &mut b,
        &h,
        &id,
        &[
            ("op", "request"),
            ("credentials", "*"),
            ("approval", "grafana"),
            ("m_GET", "1"),
            ("req_method", "GET"),
            ("req_url", "https://pve.example.com/x"),
            ("req_headers", "A: {{vault:pve_root}}\nB: {{vault:grafana}}"),
        ],
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.contains("Credentials that would need approval (2)"));
    assert!(r
        .body
        .contains("<code>grafana</code> <span class=\"muted\">(key policy)</span>"));
    assert!(r
        .body
        .contains("<code>pve_root</code> <span class=\"muted\">(vault field)</span>"));
    assert!(r.body.contains("This request would be held for approval"));
    // A check never asks for one.
    assert_eq!(counts(&h), (0, 0));
    assert!(h.events_of("approval_requested").is_empty());
}

#[tokio::test]
async fn a_draft_parked_by_a_stale_sign_in_keeps_the_approval_patterns() {
    let h = harness(full_opts()).await;
    let (id, token) = key_with_approval(&h, "agent", &["a_*"]).await;
    let mut b = signed_in(&h).await;
    let csrf = b.get(&h, &format!("/ui/keys/{id}")).await.csrf();
    h.ui.advance(Duration::from_secs(10 * 60 + 1));
    let r = b
        .post(
            &h,
            &format!("/ui/keys/{id}"),
            &[
                ("csrf", &csrf),
                ("op", "save"),
                ("credentials", "*"),
                ("approval", "a_*\nb_*"),
                ("m_GET", "1"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let next = r.location().split("next=").nth(1).unwrap().to_string();
    // Sign in again; the page that comes back has the typed patterns.
    let page = b.get(&h, &format!("/ui/login?m=sudo&next={next}")).await;
    let r = b
        .post(
            &h,
            "/ui/login",
            &[
                ("csrf", &page.csrf()),
                ("password", PASSWORD),
                ("next", &next),
            ],
        )
        .await;
    assert_eq!(r.location(), next);
    let r = b.get(&h, &next).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("Your unsaved changes were restored"));
    assert!(r.body.contains("a_*\nb_*"));
    assert_eq!(approval_of(&h, &token), ["a_*"], "restored, not saved");
}

// ── Create approvals ──────────────────────────────────────────────────────────

/// Open a create approval as the gate does, without holding a request.
fn open_create(h: &Harness, key: &str, name: &str) -> String {
    let detail = crate::approvals::CreateDetail {
        name: name.to_string(),
        username: Some("admin".to_string()),
        uris: vec![
            "https://keycloak.example.com".to_string(),
            "https://sso.example.com".to_string(),
        ],
        charset: "ascii".to_string(),
        length: 40,
        approval_required: true,
        collection: "Ferrowarden managed".to_string(),
    };
    let ask = crate::approvals::CreateAsk {
        key_id: &format!("{key}-id"),
        key_name: key,
        request_id: "0193abcd-0000-7000-8000-000000000002",
        fingerprint: &format!("fp-{name}"),
        detail: &detail,
    };
    let cfg = crate::config::ApprovalConfig {
        max_pending_per_key: 50,
        max_requests_per_key_per_hour: 1000,
        ..Default::default()
    };
    match h
        .app
        .approvals
        .check_create(&ask, &cfg, chrono::Utc::now())
        .unwrap()
    {
        Check::Wait { view, .. } | Check::Pending { view, .. } => view.id,
        _ => panic!("not opened"),
    }
}

#[tokio::test]
async fn a_create_approval_is_listed_with_its_kind_and_shown_in_full() {
    let h = harness(full_opts()).await;
    let id = open_create(&h, "agent-a", "agent_keycloak_admin");
    let mut b = signed_in(&h).await;

    let r = b.get(&h, "/ui/approvals").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.contains("Waiting for a decision (1)"));
    assert!(r.body.contains("<code>create</code>"));
    assert!(r.body.contains("agent_keycloak_admin"));
    assert!(r
        .body
        .contains("Create in <code>Ferrowarden managed</code>"));

    let r = b.get(&h, &format!("/ui/approvals/{id}")).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_security_headers(&r);
    for want in [
        "Create this credential?",
        "agent-a",
        "agent_keycloak_admin",
        "<code>admin</code>",
        "https://keycloak.example.com",
        "https://sso.example.com",
        "40 characters, <code>ascii</code>",
        "ferrowarden_approval",
        "Ferrowarden managed",
        "never sees the password",
        "one credential",
        "Approve and create",
    ] {
        assert!(r.body.contains(want), "missing {want:?}");
    }
    // Approve or deny, and nothing else: no duration to choose.
    for absent in ["name=\"preset\"", "name=\"minutes\"", "How long"] {
        assert!(!r.body.contains(absent), "unexpected {absent:?}");
    }
    assert!(r
        .body
        .contains(&format!("action=\"/ui/approvals/{id}/approve\"")));
    assert!(r
        .body
        .contains(&format!("action=\"/ui/approvals/{id}/deny\"")));
}

#[tokio::test]
async fn approving_a_create_in_the_ui_allows_one_operation_and_gives_no_grant() {
    let h = harness(full_opts()).await;
    let id = open_create(&h, "agent-a", "agent_one");
    let mut b = signed_in(&h).await;
    let csrf = detail_csrf(&mut b, &h, &id).await;
    let r = b
        .post(
            &h,
            &format!("/ui/approvals/{id}/approve"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(
        r.location(),
        "/ui/approvals?m=approved_create",
        "{}",
        r.body
    );
    assert_eq!(counts(&h), (0, 0), "no open approval and no grant");
    let r = b.get(&h, "/ui/approvals?m=approved_create").await;
    assert!(r.body.contains("covers that one credential only"));
    assert!(r.body.contains("Live grants (0)"));
    // The approval is waiting for its one request.
    assert!(h
        .app
        .approvals
        .consume_create("agent-a-id", "fp-agent_one", chrono::Utc::now()));
    assert!(!h
        .app
        .approvals
        .consume_create("agent-a-id", "fp-agent_one", chrono::Utc::now()));

    // The event names the kind and the approver, with no grant.
    let granted = h.events_of("approval_granted");
    assert_eq!(granted.len(), 1);
    let d = &granted[0]["ferrowarden"]["details"];
    assert_eq!(d["kind"], "create");
    assert_eq!(d["via"], "ui");
    assert_eq!(d["approver"], EMAIL);
    assert!(d.get("grant_id").is_none() && d.get("minutes").is_none());
}

#[tokio::test]
async fn a_create_can_be_denied_in_the_ui_and_a_duration_field_is_refused() {
    let h = harness(full_opts()).await;
    let id = open_create(&h, "agent-a", "agent_two");
    let mut b = signed_in(&h).await;
    let csrf = detail_csrf(&mut b, &h, &id).await;
    // The form of a forward approval is not the form of a create: a `minutes`
    // field is not accepted for it (the form has no such field).
    let r = b
        .post(
            &h,
            &format!("/ui/approvals/{id}/approve"),
            &[("csrf", &csrf), ("minutes", "30")],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.body);
    assert!(r.body.contains("has no duration"));
    assert_eq!(counts(&h).0, 1, "still open");

    let r = b
        .post(&h, &format!("/ui/approvals/{id}/deny"), &[("csrf", &csrf)])
        .await;
    assert_eq!(r.location(), "/ui/approvals?m=denied", "{}", r.body);
    assert_eq!(counts(&h), (0, 0));
    assert!(!h
        .app
        .approvals
        .consume_create("agent-a-id", "fp-agent_two", chrono::Utc::now()));
    // And a second decision is "no longer pending".
    let r = b
        .post(
            &h,
            &format!("/ui/approvals/{id}/approve"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_hostile_create_request_is_escaped_on_the_pages() {
    let h = harness(full_opts()).await;
    let id = open_create(&h, "agent-a", "<script>alert(1)</script>");
    let mut b = signed_in(&h).await;
    for path in ["/ui/approvals".to_string(), format!("/ui/approvals/{id}")] {
        let r = b.get(&h, &path).await;
        assert!(!r.body.contains("<script>alert"), "{path}");
        assert!(
            r.body.contains("&lt;script&gt;") || r.body.contains("&#60;script&#62;"),
            "{path}"
        );
    }
}

// ── The create patterns in the key forms ──────────────────────────────────────

#[tokio::test]
async fn the_key_forms_take_and_show_the_create_patterns() {
    let h = harness(full_opts()).await;
    let mut b = signed_in(&h).await;

    // The create form has the field and creates a key with the list.
    let r = b.get(&h, "/ui/keys/new").await;
    assert!(r.body.contains("name=\"create\""));
    assert!(r.body.contains("Credentials this key may create"));
    let csrf = r.csrf();
    let form_id = r.form_id();
    let r = b
        .post(
            &h,
            "/ui/keys/new",
            &[
                ("csrf", &csrf),
                ("form_id", &form_id),
                ("name", "creator"),
                ("credentials", "*"),
                ("m_GET", "1"),
                ("create", "agent_*\nsvc_*"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.contains("May create"));
    assert!(r.body.contains("agent_*") && r.body.contains("svc_*"));
    let stored = load(h.keys_path.as_ref().unwrap()).unwrap();
    assert_eq!(
        stored[0].create.as_deref(),
        Some(&["agent_*".to_string(), "svc_*".to_string()][..])
    );
    assert!(stored[0].policy().allows_create("agent_x"));

    // The detail page shows the saved list and the edit form carries it.
    let id = stored[0].id.clone();
    let r = b.get(&h, &format!("/ui/keys/{id}")).await;
    assert!(r.body.contains("May create:"));
    assert!(r.body.contains("name=\"create\""));
    assert!(r.body.contains("agent_*"));
}

async fn save_create(
    b: &mut Browser,
    h: &Harness,
    id: &str,
    csrf: &str,
    create: &str,
    confirm: bool,
) -> Resp {
    let mut fields = vec![
        ("csrf", csrf),
        ("op", "save"),
        ("credentials", "*"),
        ("m_GET", "1"),
        ("create", create),
    ];
    if confirm {
        fields.push(("confirm", "1"));
    }
    b.post(h, &format!("/ui/keys/{id}"), &fields).await
}

#[tokio::test]
async fn widening_the_create_list_needs_confirmation_and_narrowing_does_not() {
    let h = harness(full_opts()).await;
    let (id, _) = key_with_approval(&h, "creator", &[]).await;
    let mut b = signed_in(&h).await;
    let csrf = b.get(&h, &format!("/ui/keys/{id}")).await.csrf();

    // Adding a pattern shows the confirmation page and saves nothing yet.
    let r = save_create(&mut b, &h, &id, &csrf, "agent_*", false).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.contains("Confirm save"));
    assert!(load(h.keys_path.as_ref().unwrap()).unwrap()[0]
        .policy()
        .create
        .is_empty());
    // The draft is carried by the confirm form.
    assert!(r.body.contains("name=\"create\" value=\"agent_*\""));

    // Confirmed: saved.
    let r = save_create(&mut b, &h, &id, &csrf, "agent_*", true).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert_eq!(
        load(h.keys_path.as_ref().unwrap()).unwrap()[0]
            .policy()
            .create,
        ["agent_*"]
    );

    // Narrowing needs no confirmation.
    let r = save_create(&mut b, &h, &id, &csrf, "agent_a*", false).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let r = save_create(&mut b, &h, &id, &csrf, "", false).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    assert!(load(h.keys_path.as_ref().unwrap()).unwrap()[0]
        .policy()
        .create
        .is_empty());
}
