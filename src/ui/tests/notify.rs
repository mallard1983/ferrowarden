//! The "Notifications" section of the status page and its test button.

use super::*;
use crate::config::{NotifyConfig, NotifyTokens};
use crate::notify::tests::receiver;
use zeroize::Zeroizing;

const HOOK_TOKEN: &str = "hook-token-UIUIUI-424242";

fn notify_opts(base: &str) -> Opts {
    Opts {
        notify: Some(NotifyConfig {
            webhook_url: format!("{base}/secret-hook-path/abc123"),
            allow_http: true,
            tokens: NotifyTokens {
                webhook: Some(Zeroizing::new(HOOK_TOKEN.into())),
                ..Default::default()
            },
            ..NotifyConfig::default()
        }),
        ..Opts::default()
    }
}

async fn signed_in(h: &Harness) -> Browser {
    let mut b = Browser::new();
    let r = b.sign_in(h, PASSWORD).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    b
}

#[tokio::test]
async fn without_a_notifier_the_section_says_so_and_has_no_button() {
    let h = harness(Opts::default()).await;
    let mut b = signed_in(&h).await;
    let page = b.get(&h, "/ui/").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Notifications"));
    assert!(page.body.contains("No notifier is configured"));
    assert!(!page.body.contains("Send test notification"));
    assert!(!page.body.contains("/ui/notify/test"));
}

#[tokio::test]
async fn the_status_page_lists_type_and_host_only_and_the_counters() {
    let recv = receiver(vec![], Duration::ZERO).await;
    let h = harness(notify_opts(&recv.url)).await;
    let mut b = signed_in(&h).await;
    let page = b.get(&h, "/ui/").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body.contains("webhook at <code>127.0.0.1</code>"),
        "{}",
        page.body
    );
    assert!(page.body.contains("blocked, auth_failure, vault, system"));
    for label in ["Sent", "Failed", "Suppressed", "Dropped"] {
        assert!(page.body.contains(&format!("<dt>{label}</dt>")), "{label}");
    }
    assert!(page.body.contains("Send test notification"));
    assert!(page.body.contains("action=\"/ui/notify/test\""));
    assert!(page.body.contains("name=\"csrf\""));
    // Nothing of the URL beyond the host, and no token.
    for bad in ["secret-hook-path", "abc123", HOOK_TOKEN, "http://127.0.0.1"] {
        assert!(!page.body.contains(bad), "{bad} on the status page");
    }
    assert_security_headers(&page);
    h.assert_no_leaks(&[HOOK_TOKEN]);
    h.assert_not_logged(&[HOOK_TOKEN]);
}

#[tokio::test]
async fn the_test_button_sends_a_notification_and_shows_each_result() {
    let recv = receiver(vec![], Duration::ZERO).await;
    let h = harness(notify_opts(&recv.url)).await;
    let mut b = signed_in(&h).await;
    let csrf = b.get(&h, "/ui/").await.csrf();

    // Not a sudo action: the sign-in is older than the sudo window and it
    // still works.
    h.ui.advance(Duration::from_secs(11 * 60));
    let r = b.post(&h, "/ui/notify/test", &[("csrf", &csrf)]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.contains("Test notification"));
    assert!(
        r.body
            .contains("webhook: <span class=\"badge ok\">Sent</span> HTTP 200"),
        "{}",
        r.body
    );
    assert!(
        r.body.contains("Send test notification"),
        "the page still has its button"
    );
    assert!(!r.body.contains("secret-hook-path") && !r.body.contains(HOOK_TOKEN));

    let got = recv.wait_for(1).await;
    assert_eq!(
        got[0].headers["authorization"],
        format!("Bearer {HOOK_TOKEN}")
    );
    let payload: Value = serde_json::from_str(&got[0].body).unwrap();
    assert_eq!(payload["title"], "Ferrowarden: test notification");

    let e = h.events_of("notify_test");
    assert_eq!(e.len(), 1);
    assert_eq!(e[0]["ferrowarden"]["details"]["via"], "ui");
    assert_eq!(e[0]["event"]["outcome"], "success");

    // A second press within ten seconds is refused, and sends nothing.
    let r = b.post(&h, "/ui/notify/test", &[("csrf", &csrf)]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("sent a moment ago"), "{}", r.body);
    assert_eq!(recv.requests().len(), 1);
    h.assert_no_leaks(&[HOOK_TOKEN]);
    h.assert_not_logged(&[HOOK_TOKEN, "secret-hook-path"]);
}

#[tokio::test]
async fn a_failing_notifier_shows_as_failed_without_its_url() {
    let recv = receiver(vec![403], Duration::ZERO).await;
    let h = harness(notify_opts(&recv.url)).await;
    let mut b = signed_in(&h).await;
    let csrf = b.get(&h, "/ui/").await.csrf();
    let r = b.post(&h, "/ui/notify/test", &[("csrf", &csrf)]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(
        r.body
            .contains("<span class=\"badge bad\">Failed</span> the notifier answered HTTP 403"),
        "{}",
        r.body
    );
    assert!(!r.body.contains("secret-hook-path") && !r.body.contains("127.0.0.1:"));
    assert_eq!(h.events_of("notify_test")[0]["event"]["outcome"], "failure");
}

#[tokio::test]
async fn pressing_the_button_with_no_notifier_sends_nothing() {
    let h = harness(Opts::default()).await;
    let mut b = signed_in(&h).await;
    let csrf = b.get(&h, "/ui/").await.csrf();
    let r = b.post(&h, "/ui/notify/test", &[("csrf", &csrf)]).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r
        .body
        .contains("No notifier is configured, so nothing was sent."));
}
