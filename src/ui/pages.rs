//! Page templates. Askama escapes every interpolated value (the `.html`
//! extension turns auto-escaping on); the templates live in `templates/ui/`.

use askama::Template;

#[derive(Template)]
#[template(path = "ui/login.html")]
pub struct LoginPage<'a> {
    pub css_path: &'a str,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
    pub notice: Option<&'a str>,
}

pub struct ProviderOption {
    pub id: u8,
    pub label: &'static str,
    pub selected: bool,
}

#[derive(Template)]
#[template(path = "ui/twofactor.html")]
pub struct TwoFactorPage<'a> {
    pub css_path: &'a str,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
    pub notice: Option<&'a str>,
    pub providers: Vec<ProviderOption>,
    pub selected_id: u8,
    pub selected_label: &'static str,
    pub is_email: bool,
    pub is_yubikey: bool,
    pub email_hint: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "ui/status.html")]
pub struct StatusPage<'a> {
    pub css_path: &'a str,
    pub csrf: &'a str,
    pub account_email: &'a str,
    pub vault_locked: bool,
    pub credential_count: usize,
    pub last_sync: &'a str,
    pub version: &'a str,
    pub https: bool,
    pub api_tls: bool,
    pub key_count: usize,
    pub keys_without_policy: usize,
    pub events_dropped: u64,
    pub session_expires: &'a str,
}

#[derive(Template)]
#[template(path = "ui/message.html")]
pub struct MessagePage<'a> {
    pub css_path: &'a str,
    pub heading: &'a str,
    pub message: &'a str,
    pub link: Option<&'a str>,
    pub link_label: &'a str,
}

#[derive(Template)]
#[template(path = "ui/insecure.html")]
pub struct InsecurePage<'a> {
    pub css_path: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolated_values_are_escaped() {
        let page = MessagePage {
            css_path: "/ui/static/app-x.css",
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
            csrf: "tok",
            account_email: "<b>a@b.test</b>",
            vault_locked: false,
            credential_count: 1,
            last_sync: "never",
            version: "1",
            https: true,
            api_tls: false,
            key_count: 0,
            keys_without_policy: 0,
            events_dropped: 0,
            session_expires: "soon",
        }
        .render()
        .unwrap();
        assert!(!page.contains("<b>a@b.test"));
        assert!(page.contains("&#60;b&#62;a@b.test") || page.contains("&lt;b&gt;a@b.test"));
    }

    #[test]
    fn pages_carry_no_script_or_inline_style_or_external_reference() {
        let login = LoginPage {
            css_path: "/ui/static/app-x.css",
            csrf: "tok",
            error: Some("e"),
            notice: Some("n"),
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
}
