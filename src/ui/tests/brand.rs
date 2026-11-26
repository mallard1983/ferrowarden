//! Tests of the brand redesign and the two form fixes of the same change:
//! static assets (font, icons), the brand header and mark on every page, the
//! single-use create form, and drafts that survive a sign-in.

use super::*;
use crate::api::key_service::{self, Caller, Via};
use crate::middleware::request_context::RequestContext;

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

async fn signed_in_from(h: &Harness, ip: &str) -> Browser {
    let mut b = Browser::from(ip);
    let r = b.sign_in(h, PASSWORD).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    b
}

async fn api_key(h: &Harness, name: &str, creds: &[&str], methods: &[&str]) -> String {
    let ctx = RequestContext::new("10.0.0.1".parse().unwrap());
    key_service::create_key(
        &h.app,
        Caller {
            ctx: &ctx,
            via: Via::Api,
        },
        name,
        creds.iter().map(|s| s.to_string()).collect(),
        methods.iter().map(|s| s.to_string()).collect(),
        Vec::new(),
    )
    .await
    .unwrap()
    .id
}

fn key_count(h: &Harness) -> usize {
    h.app.agent_keys.try_read().unwrap().len()
}

fn token_in(body: &str) -> String {
    let marker = "readonly value=\"";
    let start = body.find(marker).expect("token field") + marker.len();
    let end = body[start..].find('"').unwrap();
    body[start..start + end].to_string()
}

/// Past the ten-minute sudo window, within the session's idle time.
fn make_sign_in_stale(h: &Harness) {
    h.ui.advance(Duration::from_secs(10 * 60 + 1));
}

/// The `next` of a redirect to the sign-in page.
fn next_of(r: &Resp) -> String {
    r.location()
        .split_once("&next=")
        .unwrap_or_else(|| panic!("no next in {}", r.location()))
        .1
        .to_string()
}

/// Sign in again for `next`; the browser lands on it.
async fn sign_in_again(b: &mut Browser, h: &Harness, next: &str) -> Resp {
    let page = b.get(h, &format!("/ui/login?m=sudo&next={next}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    b.post(
        h,
        "/ui/login",
        &[
            ("csrf", &page.csrf()),
            ("password", PASSWORD),
            ("next", next),
        ],
    )
    .await
}

/// A form POST whose values are owned strings.
async fn post_owned(b: &mut Browser, h: &Harness, path: &str, fields: &[(&str, String)]) -> Resp {
    let f: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    b.post(h, path, &f).await
}

const RESTORED: &str = "Your unsaved changes were restored. Review them and save again.";

fn bytes_start_with(r: &Resp, magic: &[u8]) -> bool {
    r.bytes.starts_with(magic)
}

// -- assets -------------------------------------------------------------------------

#[tokio::test]
async fn the_font_and_icons_are_static_assets_without_a_session() {
    let h = harness(Opts::default()).await;
    let mut b = Browser::new();
    let cases: [(&str, &str, &[u8], &[u8]); 5] = [
        (
            "/ui/static/inter-latin-wght.woff2",
            "font/woff2",
            b"wOF2",
            crate::ui::FONT,
        ),
        (
            "/ui/static/favicon.ico",
            "image/x-icon",
            &[0, 0, 1, 0],
            crate::ui::FAVICON_ICO,
        ),
        (
            "/ui/static/favicon-32.png",
            "image/png",
            b"\x89PNG",
            crate::ui::FAVICON_32,
        ),
        (
            "/ui/static/apple-touch-icon.png",
            "image/png",
            b"\x89PNG",
            crate::ui::APPLE_TOUCH_ICON,
        ),
        (
            "/favicon.ico",
            "image/x-icon",
            &[0, 0, 1, 0],
            crate::ui::FAVICON_ICO,
        ),
    ];
    for (path, content_type, magic, bytes) in cases {
        let r = b.get(&h, path).await;
        assert_eq!(r.status, StatusCode::OK, "{path}");
        assert_eq!(r.headers["content-type"], content_type, "{path}");
        assert_eq!(
            r.headers["cache-control"], "public, max-age=86400",
            "{path}"
        );
        assert_eq!(r.headers["x-content-type-options"], "nosniff", "{path}");
        assert!(bytes_start_with(&r, magic), "{path}");
        assert_eq!(r.bytes, bytes, "{path}");
        assert!(r.set_cookies().is_empty(), "{path}");
        assert_security_headers(&r);
    }
    // The root favicon is the same file as the one the pages link.
    assert_eq!(
        b.get(&h, "/favicon.ico").await.bytes,
        b.get(&h, "/ui/static/favicon.ico").await.bytes
    );
    // Nothing else lives there.
    for path in [
        "/ui/static/other.woff2",
        "/ui/static/app.css",
        "/ui/static/..%2Fsecret",
    ] {
        assert_eq!(
            b.get(&h, path).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    // Static files need no sign-in; the pages still do.
    assert_eq!(b.get(&h, "/ui/keys").await.location(), "/ui/login");
}

#[tokio::test]
async fn assets_are_served_over_plain_http_so_the_explanation_renders() {
    let h = harness(Opts {
        tls: false,
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    for path in [
        "/ui/static/inter-latin-wght.woff2",
        "/ui/static/favicon.ico",
        "/favicon.ico",
    ] {
        assert_eq!(b.get(&h, path).await.status, StatusCode::OK, "{path}");
    }
    let page = b.get(&h, "/ui/").await;
    assert_eq!(page.status, StatusCode::BAD_REQUEST);
    assert!(
        page.body.contains("class=\"mark\""),
        "the refusal is branded"
    );
}

#[test]
fn the_stylesheet_is_self_contained_and_follows_the_brand() {
    let css = crate::ui::CSS;
    // Font: from this origin, variable weights, swap.
    assert!(css.contains("@font-face"));
    assert!(css.contains("url(\"/ui/static/inter-latin-wght.woff2\")"));
    assert!(css.contains("font-weight: 100 900"));
    assert!(css.contains("font-display: swap"));
    // Every url() points at this origin's static files; nothing external.
    for part in css.split("url(").skip(1) {
        assert!(part.starts_with("\"/ui/static/"), "{part:.40}");
    }
    assert!(!css.contains("http://") && !css.contains("https://") && !css.contains("@import"));
    // Brand tokens and the system theme.
    for token in [
        "#17212b", "#3d5967", "#cb7545", "#f6f8f9", "#a6b7c4", "#101820", "#7797a8",
    ] {
        assert!(css.to_lowercase().contains(token), "{token}");
    }
    assert!(css.contains("--fw-radius-md: 12px") && css.contains("--fw-radius-lg: 20px"));
    assert!(css.contains("@media (prefers-color-scheme: dark)"));
    assert!(css.contains(":focus-visible"));
    // No long data stays on one line, and no fixed widths wider than a phone.
    for line in css.lines() {
        let l = line.trim();
        if l.starts_with("td") || l.contains("code") {
            assert!(!l.contains("white-space: nowrap"), "{l}");
        }
        for prop in ["width:", "min-width:"] {
            if let Some(i) = l.find(prop) {
                let value = l[i + prop.len()..].trim();
                if let Some(px) = value.strip_suffix("px;") {
                    if let Ok(px) = px.parse::<u32>() {
                        assert!(px <= 320, "{l}");
                    }
                }
            }
        }
    }
}

// -- brand --------------------------------------------------------------------------

#[tokio::test]
async fn pages_carry_the_brand_header_icons_and_mark() {
    let h = harness(full_opts()).await;
    let mut b = signed_in(&h).await;
    for path in [
        "/ui/",
        "/ui/keys",
        "/ui/keys/new",
        "/ui/audit",
        "/ui/nothing",
    ] {
        let r = b.get(&h, path).await;
        let body = &r.body;
        assert!(body.contains("<header class=\"top\">"), "{path}");
        assert!(body.contains("<a class=\"brand\" href=\"/ui/\">"), "{path}");
        assert!(body.contains("class=\"mark\""), "{path}");
        assert!(body.contains("aria-hidden=\"true\""), "{path}");
        assert!(body.contains("<span>Ferrowarden</span>"), "{path}");
        assert!(body.contains("<span class=\"sub\">Admin</span>"), "{path}");
        // The mark's three parts, recoloured through CSS only.
        for part in ["mark-portal", "mark-f", "mark-gate"] {
            assert!(body.contains(&format!("class=\"{part}\"")), "{path} {part}");
        }
        assert!(
            !body.contains("fill=\""),
            "colours come from the stylesheet"
        );
        // Icons and theme colour.
        assert!(body.contains("href=\"/ui/static/favicon.ico\""), "{path}");
        assert!(
            body.contains("href=\"/ui/static/favicon-32.png\""),
            "{path}"
        );
        assert!(
            body.contains("href=\"/ui/static/apple-touch-icon.png\""),
            "{path}"
        );
        assert!(body.contains(
            "<meta name=\"theme-color\" content=\"#F6F8F9\" media=\"(prefers-color-scheme: light)\">"
        ));
        assert!(body.contains(
            "<meta name=\"theme-color\" content=\"#101820\" media=\"(prefers-color-scheme: dark)\">"
        ));
        assert!(!body.contains("manifest"), "{path}: not a PWA");
        // Still no scripts, inline styles or external references.
        let lower = body.to_lowercase();
        assert!(
            !lower.contains("<script") && !lower.contains("style=") && !lower.contains("<style")
        );
        assert!(
            !lower.contains("http://") && !lower.contains("https://"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn the_sign_in_pages_show_the_lockup() {
    let h = harness(Opts {
        two_fa: Some(TwoFa::totp()),
        ..Opts::default()
    })
    .await;
    let mut b = Browser::new();
    let login = b.get(&h, "/ui/login").await;
    {
        let page = &login;
        assert!(page.body.contains("class=\"lockup\""));
        assert!(page.body.contains("class=\"mark\""));
        assert!(page.body.contains("<p class=\"name\">Ferrowarden</p>"));
        assert!(page
            .body
            .contains("<p class=\"tagline\">The credential boundary for AI agents</p>"));
        assert!(!page.body.contains("<header"), "one brand, in the card");
        assert!(page.body.contains("<main class=\"auth\">"));
    }
    assert!(login.body.contains("Ferrowarden does not store it"));
    let r = b
        .post(
            &h,
            "/ui/login",
            &[("csrf", &login.csrf()), ("password", PASSWORD)],
        )
        .await;
    assert_eq!(r.location(), "/ui/login/2fa");
    let page = b.get(&h, "/ui/login/2fa").await;
    assert!(page.body.contains("class=\"lockup\"") && page.body.contains("class=\"mark\""));
    // The error page without a session still has the plain brand header.
    let nope = Browser::new().get(&h, "/nope").await;
    assert!(nope.body.contains("<header class=\"top\">"));
    assert!(!nope.body.contains("aria-label=\"Main\""));
}

// -- the create form is single use ------------------------------------------------------

#[tokio::test]
async fn submitting_the_create_form_twice_creates_one_key() {
    let h = harness(full_opts()).await;
    let mut b = signed_in(&h).await;
    let form = b.get(&h, "/ui/keys/new").await;
    let (csrf, fid) = (form.csrf(), form.form_id());
    assert_eq!(fid.len(), 43, "32 random bytes, base64url");
    let fields = [
        ("csrf", csrf.as_str()),
        ("form_id", fid.as_str()),
        ("name", "once"),
        ("credentials", "lab_*"),
        ("m_GET", "1"),
    ];
    let first = b.post(&h, "/ui/keys/new", &fields).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let token = token_in(&first.body);
    assert_eq!(key_count(&h), 1);

    // The browser's "reload this page" re-sends the same form.
    let second = b.post(&h, "/ui/keys/new", &fields).await;
    assert_eq!(second.status, StatusCode::CONFLICT);
    assert!(second.body.contains("This form was already submitted"));
    assert!(second.body.contains("No key was created"));
    assert!(second.body.contains("href=\"/ui/keys\""));
    assert!(!second.body.contains(&token), "the token is shown once");
    assert!(!second.body.contains("readonly"));
    assert_eq!(second.headers["cache-control"], "no-store");
    assert_eq!(key_count(&h), 1);
    assert_eq!(h.events_of("key_create").len(), 1);
    // The failed attempt is not a key event and the token is nowhere else.
    let held = h
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|s| s.contains(&token))
        .count();
    assert_eq!(held, 1);
    h.assert_not_logged(&[token.as_str()]);

    // A fresh form works again.
    let form = b.get(&h, "/ui/keys/new").await;
    assert_ne!(form.form_id(), fid, "a new id every time");
    let r = b
        .post(
            &h,
            "/ui/keys/new",
            &[
                ("csrf", &form.csrf()),
                ("form_id", &form.form_id()),
                ("name", "twice"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(key_count(&h), 2);
}

#[tokio::test]
async fn a_create_post_with_a_missing_wrong_or_foreign_form_id_creates_nothing() {
    let h = harness(full_opts()).await;
    let mut b = signed_in(&h).await;
    let mut other = signed_in(&h).await;
    let csrf = b.get(&h, "/ui/keys/new").await.csrf();
    let foreign = other.get(&h, "/ui/keys/new").await.form_id();
    for fid in [None, Some(""), Some("nope"), Some(foreign.as_str())] {
        let mut fields = vec![("csrf", csrf.as_str()), ("name", "x"), ("m_GET", "1")];
        if let Some(fid) = fid {
            fields.push(("form_id", fid));
        }
        let r = b.post(&h, "/ui/keys/new", &fields).await;
        assert_eq!(r.status, StatusCode::CONFLICT, "{fid:?}");
        assert!(r.body.contains("This form was already submitted"));
        assert!(!r.body.contains("readonly"));
    }
    assert_eq!(key_count(&h), 0);
    // The foreign id is still good for its own session.
    let other_csrf = other.get(&h, "/ui/keys").await.csrf();
    let r = other
        .post(
            &h,
            "/ui/keys/new",
            &[
                ("csrf", &other_csrf),
                ("form_id", &foreign),
                ("name", "mine"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(key_count(&h), 1);
}

#[tokio::test]
async fn a_rejected_create_keeps_its_form_id_and_only_eight_stay_outstanding() {
    let h = harness(full_opts()).await;
    let mut b = signed_in(&h).await;
    let form = b.get(&h, "/ui/keys/new").await;
    let (csrf, fid) = (form.csrf(), form.form_id());
    // A validation error creates nothing and the same form can be fixed.
    let r = b
        .post(
            &h,
            "/ui/keys/new",
            &[("csrf", &csrf), ("form_id", &fid), ("name", "")],
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.form_id(), fid);
    let r = b
        .post(
            &h,
            "/ui/keys/new",
            &[("csrf", &csrf), ("form_id", &fid), ("name", "fixed")],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(key_count(&h), 1);

    // Nine forms opened: the oldest id is gone, the newest eight work.
    let ids: Vec<String> = {
        let mut ids = Vec::new();
        for _ in 0..9 {
            ids.push(b.get(&h, "/ui/keys/new").await.form_id());
        }
        ids
    };
    let post = |id: &String| {
        vec![
            ("csrf", csrf.clone()),
            ("form_id", id.clone()),
            ("name", "n".to_string()),
        ]
    };
    let status = |r: Resp| r.status;
    assert_eq!(
        status(post_owned(&mut b, &h, "/ui/keys/new", &post(&ids[0])).await),
        StatusCode::CONFLICT
    );
    assert_eq!(
        status(post_owned(&mut b, &h, "/ui/keys/new", &post(&ids[8])).await),
        StatusCode::OK
    );
    assert_eq!(
        status(post_owned(&mut b, &h, "/ui/keys/new", &post(&ids[1])).await),
        StatusCode::OK
    );
    assert_eq!(key_count(&h), 3);
}

#[tokio::test]
async fn a_session_has_its_own_form_ids() {
    use crate::ui::session::{Lookup, SessionStore, MAX_FORM_IDS};
    let t0 = std::time::Instant::now();
    let mut store = SessionStore::new(Duration::from_secs(900), Duration::from_secs(36000));
    let (a, _) = store.create(t0).unwrap();
    let (b, _) = store.create(t0).unwrap();
    let view = |store: &mut SessionStore, id: &str| match store.lookup(id, t0) {
        Lookup::Valid(v) => v,
        _ => panic!(),
    };
    let (va, vb) = (view(&mut store, &a), view(&mut store, &b));
    assert_eq!(MAX_FORM_IDS, 8);
    let id = store.issue_form_id(&va).unwrap();
    assert!(store.form_id_valid(&va, &id));
    assert!(
        !store.form_id_valid(&vb, &id),
        "not valid in another session"
    );
    assert!(!store.consume_form_id(&vb, &id));
    assert!(store.consume_form_id(&va, &id));
    assert!(!store.consume_form_id(&va, &id), "once");
    store.restore_form_id(&va, &id);
    assert!(store.form_id_valid(&va, &id));
    // Ending the session ends its ids.
    store.destroy(&a);
    assert!(!store.form_id_valid(&va, &id));
    assert!(store.issue_form_id(&va).is_none());
}

// -- drafts survive a sign-in --------------------------------------------------------

#[tokio::test]
async fn a_stale_save_is_parked_and_restored_unsaved() {
    let h = harness(full_opts()).await;
    let id = api_key(&h, "homelab", &["lab_*"], &["GET"]).await;
    let mut b = signed_in(&h).await;
    let key_path = format!("/ui/keys/{id}");
    let csrf = b.get(&h, &key_path).await.csrf();
    make_sign_in_stale(&h);

    let r = b
        .post(
            &h,
            &key_path,
            &[
                ("csrf", &csrf),
                ("op", "save"),
                ("credentials", "lab_*\r\nprod_*"),
                ("m_GET", "1"),
                ("m_POST", "1"),
                ("req_method", "POST"),
                ("req_url", "https://x.test/a"),
                ("req_headers", "X-A: b"),
                ("req_body", "hello body"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let next = next_of(&r);
    assert!(next.starts_with(&format!("/ui/keys/{id}/draft/")), "{next}");
    assert_eq!(next.len(), key_path.len() + "/draft/".len() + 43);
    // The URL carries an id, never the typed text.
    assert!(!r.location().contains("prod_"));
    // Nothing was saved.
    {
        let keys = h.app.agent_keys.read().await;
        assert_eq!(keys.values().next().unwrap().policy.credentials, ["lab_*"]);
    }
    assert!(h.events_of("key_policy_change").is_empty());

    // Sign in again: the browser lands on the draft.
    let r = sign_in_again(&mut b, &h, &next).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), next);
    let page = b.get(&h, &next).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains(RESTORED));
    assert!(page.body.contains("prod_*</textarea>"));
    assert!(page.body.contains("lab_*\nprod_*"));
    assert!(page.body.contains("name=\"m_GET\" value=\"1\" checked"));
    assert!(page.body.contains("name=\"m_POST\" value=\"1\" checked"));
    assert!(!page.body.contains("name=\"m_PUT\" value=\"1\" checked"));
    assert!(!page.body.contains("name=\"m_all\" value=\"1\" checked"));
    assert!(page.body.contains("<option value=\"POST\" selected>"));
    assert!(page.body.contains("value=\"https://x.test/a\""));
    assert!(page.body.contains("X-A: b"));
    assert!(page.body.contains("hello body"));
    assert!(page.body.contains("Signed in just now"));
    // Still not saved: the page only shows it.
    {
        let keys = h.app.agent_keys.read().await;
        assert_eq!(keys.values().next().unwrap().policy.credentials, ["lab_*"]);
    }
    assert!(h.events_of("key_policy_change").is_empty());

    // The draft is single use.
    let again = b.get(&h, &next).await;
    assert_eq!(again.status, StatusCode::OK);
    assert!(!again.body.contains(RESTORED));
    assert!(again.body.contains("could not be restored"));
    assert!(!again.body.contains("prod_*"), "the saved policy is shown");

    // Saving goes the normal way: widening needs the confirmation.
    let fields = |confirm: bool| {
        let mut f = vec![
            ("csrf", page.csrf()),
            ("op", "save".to_string()),
            ("credentials", "lab_*\nprod_*".to_string()),
            ("m_GET", "1".to_string()),
            ("m_POST", "1".to_string()),
        ];
        if confirm {
            f.push(("confirm", "1".to_string()));
        }
        f
    };
    let r = post_owned(&mut b, &h, &key_path, &fields(false)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("this change gives the key more access"));
    assert!(h.events_of("key_policy_change").is_empty());
    let r = post_owned(&mut b, &h, &key_path, &fields(true)).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), format!("{key_path}?m=saved"));
    let keys = h.app.agent_keys.read().await;
    let policy = &keys.values().next().unwrap().policy;
    assert_eq!(policy.credentials, ["lab_*", "prod_*"]);
    assert_eq!(policy.methods, ["GET", "POST"]);
    drop(keys);
    assert_eq!(h.events_of("key_policy_change").len(), 1);
    h.assert_no_leaks(&[]);
}

#[tokio::test]
async fn a_confirm_save_after_the_window_is_parked_too() {
    let h = harness(full_opts()).await;
    let id = api_key(&h, "homelab", &["lab_*"], &["GET"]).await;
    let mut b = signed_in(&h).await;
    let csrf = b.get(&h, &format!("/ui/keys/{id}")).await.csrf();
    make_sign_in_stale(&h);
    let r = b
        .post(
            &h,
            &format!("/ui/keys/{id}"),
            &[
                ("csrf", &csrf),
                ("op", "save"),
                ("confirm", "1"),
                ("credentials", "*"),
                ("m_all", "1"),
            ],
        )
        .await;
    let next = next_of(&r);
    sign_in_again(&mut b, &h, &next).await;
    let page = b.get(&h, &next).await;
    assert!(page.body.contains(RESTORED));
    assert!(page.body.contains("name=\"m_all\" value=\"1\" checked"));
    assert!(
        h.events_of("key_policy_change").is_empty(),
        "never auto-saved"
    );
}

#[tokio::test]
async fn missing_expired_and_foreign_drafts_give_the_saved_policy() {
    let h = harness(Opts {
        keys_file: true,
        trusted_proxies: "127.0.0.1",
        ..Opts::default()
    })
    .await;
    let a = api_key(&h, "alpha", &["lab_*"], &["GET"]).await;
    let z = api_key(&h, "zeta", &["db_*"], &["HEAD"]).await;
    let mut owner = signed_in_from(&h, "198.51.100.10").await;
    let csrf = owner.get(&h, &format!("/ui/keys/{a}")).await.csrf();
    make_sign_in_stale(&h);
    let r = owner
        .post(
            &h,
            &format!("/ui/keys/{a}"),
            &[
                ("csrf", &csrf),
                ("op", "save"),
                ("credentials", "typed_*"),
                ("m_PUT", "1"),
            ],
        )
        .await;
    let next = next_of(&r);
    let draft_id = next.rsplit('/').next().unwrap().to_string();
    sign_in_again(&mut owner, &h, &next).await;

    let expired = |body: &str| {
        assert!(body.contains("could not be restored"), "{body}");
        assert!(!body.contains(RESTORED));
        assert!(!body.contains("typed_*"));
    };

    // Unknown ids, odd ids, another key's page: the saved policy and a notice.
    for (case, path) in [
        format!("/ui/keys/{a}/draft/{}", "A".repeat(43)),
        format!("/ui/keys/{a}/draft/short"),
        format!("/ui/keys/{a}/draft/{}", "x".repeat(100)),
        format!("/ui/keys/{a}/draft/bad%21id"),
        // The right id on the wrong key does not give it up ...
        format!("/ui/keys/{z}/draft/{draft_id}"),
    ]
    .iter()
    .enumerate()
    {
        let r = owner.get(&h, path).await;
        assert_eq!(r.status, StatusCode::OK, "draft case {case}");
        expired(&r.body);
    }
    // ... and for the key and form it is not (a key that is not there).
    let r = owner.get(&h, "/ui/keys/nokey/draft/abc").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // The create form's draft is not a key draft either.
    let r = owner
        .get(&h, &format!("/ui/keys/new/draft/{draft_id}"))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("could not be restored"));
    assert!(r.body.contains("name=\"form_id\""));

    // Another address cannot take it; it stays for its owner.
    let mut other = signed_in_from(&h, "203.0.113.9").await;
    let r = other.get(&h, &next).await;
    assert_eq!(r.status, StatusCode::OK);
    expired(&r.body);
    let r = owner.get(&h, &next).await;
    assert!(r.body.contains(RESTORED), "{}", r.body);
    assert!(r.body.contains("typed_*"));
}

#[tokio::test]
async fn a_draft_expires_after_fifteen_minutes() {
    let h = harness(full_opts()).await;
    let id = api_key(&h, "homelab", &["lab_*"], &["GET"]).await;
    let mut b = signed_in(&h).await;
    let csrf = b.get(&h, &format!("/ui/keys/{id}")).await.csrf();
    make_sign_in_stale(&h);
    let r = b
        .post(
            &h,
            &format!("/ui/keys/{id}"),
            &[
                ("csrf", &csrf),
                ("op", "save"),
                ("credentials", "typed_*"),
                ("m_GET", "1"),
            ],
        )
        .await;
    let next = next_of(&r);
    // Almost 15 minutes later: still there. (A new session each time.)
    h.ui.advance(Duration::from_secs(14 * 60 + 30));
    let mut b2 = signed_in(&h).await;
    let page = b2.get(&h, &next).await;
    assert!(page.body.contains(RESTORED), "{}", page.body);

    // A second parked draft, left for 15 minutes.
    let mut b3 = signed_in(&h).await;
    let csrf = b3.get(&h, &format!("/ui/keys/{id}")).await.csrf();
    make_sign_in_stale(&h);
    let r = b3
        .post(
            &h,
            &format!("/ui/keys/{id}"),
            &[
                ("csrf", &csrf),
                ("op", "save"),
                ("credentials", "typed_*"),
                ("m_GET", "1"),
            ],
        )
        .await;
    let next = next_of(&r);
    h.ui.advance(Duration::from_secs(15 * 60 + 1));
    let mut b4 = signed_in(&h).await;
    let page = b4.get(&h, &next).await;
    assert!(page.body.contains("could not be restored"));
    assert!(!page.body.contains("typed_*"));
}

#[tokio::test]
async fn a_stale_create_is_parked_and_restored_unsaved() {
    let h = harness(full_opts()).await;
    let mut b = signed_in(&h).await;
    let form = b.get(&h, "/ui/keys/new").await;
    let (csrf, fid) = (form.csrf(), form.form_id());
    make_sign_in_stale(&h);
    let r = b
        .post(
            &h,
            "/ui/keys/new",
            &[
                ("csrf", &csrf),
                ("form_id", &fid),
                ("name", "my agent"),
                ("credentials", "lab_*\nuptime_*"),
                ("m_GET", "1"),
                ("m_HEAD", "1"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let next = next_of(&r);
    assert!(next.starts_with("/ui/keys/new/draft/"), "{next}");
    assert_eq!(key_count(&h), 0, "nothing created");
    assert!(!r.location().contains("my"), "no typed text in the URL");

    let r = sign_in_again(&mut b, &h, &next).await;
    assert_eq!(r.location(), next);
    let page = b.get(&h, &next).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains(RESTORED));
    assert!(page.body.contains("value=\"my agent\""));
    assert!(page.body.contains("lab_*\nuptime_*</textarea>"));
    assert!(page.body.contains("name=\"m_GET\" value=\"1\" checked"));
    assert!(page.body.contains("name=\"m_HEAD\" value=\"1\" checked"));
    assert_eq!(key_count(&h), 0, "restoring creates nothing");
    assert!(h.events_of("key_create").is_empty());
    assert_ne!(page.form_id(), fid, "the restored form has its own id");

    // The draft is single use: the blank form, with a notice.
    let again = b.get(&h, &next).await;
    assert!(again.body.contains("could not be restored"));
    assert!(!again.body.contains("my agent"));

    // Submitting the restored form creates the key.
    let r = b
        .post(
            &h,
            "/ui/keys/new",
            &[
                ("csrf", &page.csrf()),
                ("form_id", &page.form_id()),
                ("name", "my agent"),
                ("credentials", "lab_*\nuptime_*"),
                ("m_GET", "1"),
                ("m_HEAD", "1"),
            ],
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(key_count(&h), 1);
}

#[tokio::test]
async fn a_draft_survives_two_step_sign_in() {
    let h = harness(Opts {
        two_fa: Some(TwoFa::totp()),
        keys_file: true,
        ..Opts::default()
    })
    .await;
    let id = api_key(&h, "homelab", &["lab_*"], &["GET"]).await;
    let mut b = Browser::new();
    b.sign_in(&h, PASSWORD).await;
    assert_eq!(
        b.second_factor(&h, "0", "verify", TOTP).await.location(),
        "/ui/"
    );
    let csrf = b.get(&h, &format!("/ui/keys/{id}")).await.csrf();
    make_sign_in_stale(&h);
    let r = b
        .post(
            &h,
            &format!("/ui/keys/{id}"),
            &[
                ("csrf", &csrf),
                ("op", "save"),
                ("credentials", "typed_*"),
                ("m_GET", "1"),
            ],
        )
        .await;
    let next = next_of(&r);
    // Password step: the draft path is kept server side, not in a URL or form.
    let r = sign_in_again(&mut b, &h, &next).await;
    assert_eq!(r.location(), "/ui/login/2fa");
    let page2 = b.get(&h, "/ui/login/2fa").await;
    assert!(!page2.body.contains("/draft/"));
    let r = b.second_factor(&h, "0", "verify", TOTP).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), next);
    let page = b.get(&h, &next).await;
    assert!(page.body.contains(RESTORED));
    assert!(page.body.contains("typed_*"));
}

#[test]
fn draft_urls_pass_the_next_validator() {
    use crate::ui::web::safe_next;
    let token = "AbC-_9".repeat(7) + "x";
    assert_eq!(token.len(), 43);
    for path in [
        format!("/ui/keys/new/draft/{token}"),
        format!("/ui/keys/0b5c1c88-ad3f-4f43-9a73-1e7d0cbd2b61/draft/{token}"),
    ] {
        assert_eq!(safe_next(&path).as_deref(), Some(path.as_str()), "{path}");
    }
}
