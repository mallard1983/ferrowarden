
use super::*;

#[test]
fn interpolated_values_are_escaped() {
    let page = MessagePage {
        css_path: "/ui/static/app-x.css",
        nav: None,
        heading: "<script>alert(1)</script>",
        message: "\"><img src=x onerror=alert(1)>",
        link: Some("/ui/login"),
        link_label: "back",
    }
    .render()
    .unwrap();
    assert!(!page.contains("<script>"));
    assert!(!page.contains("<img"));
    assert!(page.contains("&#60;script&#62;") || page.contains("&lt;script&gt;"));

    let page = StatusPage {
        css_path: "/c.css",
        nav: None,
        account_email: "<b>a@b.test</b>",
        vault_locked: false,
        vault_backend: "native",
        credential_count: 1,
        last_sync: "never",
        version: "1",
        https: true,
        api_tls: false,
        key_count: 0,
        keys_without_policy: 0,
        events_dropped: 0,
        session_expires: "soon",
        csrf: "tok",
        notify: NotifyView {
            enabled: true,
            senders: vec![NotifySenderRow {
                kind: "webhook",
                host: "<i>h</i>".to_string(),
                sent: 1,
                failed: 0,
            }],
            categories: "blocked".to_string(),
            sent: 1,
            failed: 0,
            suppressed: 0,
            dropped: 0,
            test: Some(NotifyTestView {
                wait: None,
                rows: vec![NotifyTestRow {
                    sender: "webhook",
                    ok: false,
                    detail: "<u>x</u>".to_string(),
                }],
            }),
        },
    }
    .render()
    .unwrap();
    assert!(!page.contains("<b>a@b.test"));
    assert!(page.contains("&#60;b&#62;a@b.test") || page.contains("&lt;b&gt;a@b.test"));
    assert!(!page.contains("<i>h</i>") && !page.contains("<u>x</u>"));
}

#[test]
fn pages_carry_no_script_or_inline_style_or_external_reference() {
    let login = LoginPage {
        css_path: "/ui/static/app-x.css",
        csrf: "tok",
        error: Some("e"),
        notice: Some("n"),
        next: None,
    }
    .render()
    .unwrap();
    let lower = login.to_lowercase();
    assert!(!lower.contains("<script"));
    assert!(!lower.contains("style="));
    assert!(!lower.contains("http://") && !lower.contains("https://"));
    assert!(!lower.contains("onclick") && !lower.contains("onload"));
    assert!(login.contains("autocomplete=\"current-password\""));
    // No email field: only the password.
    assert!(!lower.contains("type=\"email\""));
    assert!(!lower.contains("name=\"email\""));
}

#[test]
fn code_field_hints() {
    let page = |is_yubikey: bool| {
        TwoFactorPage {
            css_path: "/c.css",
            csrf: "tok",
            error: None,
            notice: None,
            providers: vec![
                ProviderOption {
                    id: 0,
                    label: "Authenticator app",
                    selected: !is_yubikey,
                },
                ProviderOption {
                    id: 3,
                    label: "YubiKey",
                    selected: is_yubikey,
                },
            ],
            selected_id: if is_yubikey { 3 } else { 0 },
            selected_label: "x",
            is_email: false,
            is_yubikey,
            email_hint: None,
        }
        .render()
        .unwrap()
    };
    let totp = page(false);
    assert!(totp.contains("autocomplete=\"one-time-code\""));
    assert!(totp.contains("inputmode=\"numeric\""));
    let yubikey = page(true);
    assert!(yubikey.contains("maxlength=\"44\""));
    assert!(!yubikey.contains("one-time-code"));
}
