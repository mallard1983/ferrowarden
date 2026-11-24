//! Page templates. Askama escapes every interpolated value (the `.html`
//! extension turns auto-escaping on); the templates live in `templates/ui/`.

use askama::Template;

use crate::api::credentials::CredentialDetail;

/// The header navigation of a signed-in page. `current` is one of `status`,
/// `keys`, `audit` (or empty on a page that is none of them); pages without
/// a session pass `None` instead.
pub struct Nav<'a> {
    pub current: &'a str,
    pub account_email: &'a str,
    /// The session's CSRF token, for the sign-out button.
    pub csrf: &'a str,
}

/// "Signed in N minutes ago" and whether the sudo window is open.
pub struct SudoInfo {
    pub active: bool,
    pub signed_in: String,
}

#[derive(Template)]
#[template(path = "ui/login.html")]
pub struct LoginPage<'a> {
    pub css_path: &'a str,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
    pub notice: Option<&'a str>,
    /// Validated post-sign-in target (see `web::safe_next`).
    pub next: Option<&'a str>,
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
    pub nav: Option<Nav<'a>>,
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
    pub nav: Option<Nav<'a>>,
    pub heading: &'a str,
    pub message: &'a str,
    pub link: Option<&'a str>,
    pub link_label: &'a str,
}

#[derive(Template)]
#[template(path = "ui/insecure.html")]
pub struct InsecurePage<'a> {
    pub css_path: &'a str,
    pub nav: Option<Nav<'a>>,
}

// -- Keys ---------------------------------------------------------------------

/// One row of the keys table.
pub struct KeyRow {
    pub id: String,
    pub short_id: String,
    pub name: String,
    pub created: String,
    pub policy_set: bool,
    /// The methods as chips: `none`, `all (*)` or one per method.
    pub method_chips: Vec<String>,
    /// The first few credential patterns, and how many more there are.
    pub shown: Vec<String>,
    pub more: usize,
    pub count: usize,
}

#[derive(Template)]
#[template(path = "ui/keys.html")]
pub struct KeysPage<'a> {
    pub css_path: &'a str,
    pub nav: Option<Nav<'a>>,
    pub sudo: SudoInfo,
    pub notice: Option<&'a str>,
    pub rows: Vec<KeyRow>,
}

/// One method checkbox (`m_GET`, ...).
pub struct MethodBox {
    pub field: String,
    pub label: &'static str,
    pub checked: bool,
}

#[derive(Template)]
#[template(path = "ui/key_new.html")]
pub struct KeyNewPage<'a> {
    pub css_path: &'a str,
    pub nav: Option<Nav<'a>>,
    pub sudo: SudoInfo,
    pub csrf: &'a str,
    /// The single-use id of this form (see `session::issue_form_id`).
    pub form_id: &'a str,
    pub notice: Option<&'a str>,
    pub error: Option<&'a str>,
    pub name: &'a str,
    pub patterns: &'a str,
    pub methods: Vec<MethodBox>,
    pub all_methods: bool,
}

/// Shown instead of creating a key when the form was already submitted.
#[derive(Template)]
#[template(path = "ui/key_form_used.html")]
pub struct KeyFormUsedPage<'a> {
    pub css_path: &'a str,
    pub nav: Option<Nav<'a>>,
}

#[derive(Template)]
#[template(path = "ui/key_token.html")]
pub struct KeyTokenPage<'a> {
    pub css_path: &'a str,
    pub nav: Option<Nav<'a>>,
    pub id: &'a str,
    pub name: &'a str,
    pub token: &'a str,
    pub credentials: &'a [String],
    pub methods: &'a str,
}

/// A policy as text: the pattern list and the method label.
pub struct PolicyView {
    pub credentials: Vec<String>,
    pub methods: String,
}

/// One credential the draft reaches.
pub struct CredRow {
    pub d: CredentialDetail,
    pub gained: bool,
}

pub struct PreviewView {
    pub saved: PolicyView,
    pub draft: PolicyView,
    pub gained: Vec<String>,
    pub lost: Vec<String>,
    pub creds: Vec<CredRow>,
    pub widens: bool,
}

pub struct RequestCheckView {
    pub allowed: bool,
    pub status: u16,
    pub reason: String,
    pub message: String,
    pub note: &'static str,
}

pub struct Opt {
    pub value: String,
    pub selected: bool,
}

/// The values of the edit form (also what the confirmation page carries).
pub struct DraftForm {
    pub patterns: String,
    pub methods: Vec<MethodBox>,
    pub all_methods: bool,
    pub req_methods: Vec<Opt>,
    pub req_url: String,
    pub req_headers: String,
    pub req_body: String,
}

pub struct KeyFacts {
    pub id: String,
    pub name: String,
    pub created: String,
    pub policy_set: bool,
    pub credentials: Vec<String>,
    pub methods: String,
}

#[derive(Template)]
#[template(path = "ui/key.html")]
pub struct KeyPage<'a> {
    pub css_path: &'a str,
    pub nav: Option<Nav<'a>>,
    pub sudo: SudoInfo,
    pub csrf: &'a str,
    pub key: KeyFacts,
    pub notice: Option<&'a str>,
    pub error: Option<&'a str>,
    pub form: DraftForm,
    pub preview: Option<PreviewView>,
    pub check: Option<RequestCheckView>,
    /// Show the "this widens access" confirmation step.
    pub confirm: bool,
}

#[derive(Template)]
#[template(path = "ui/key_revoke.html")]
pub struct KeyRevokePage<'a> {
    pub css_path: &'a str,
    pub nav: Option<Nav<'a>>,
    pub sudo: SudoInfo,
    pub csrf: &'a str,
    pub id: &'a str,
    pub name: &'a str,
}

// -- Audit --------------------------------------------------------------------

pub struct AuditRow {
    pub time: String,
    pub action: String,
    pub outcome: String,
    pub reason: String,
    pub key_name: String,
    pub ip: String,
    pub method: String,
    pub host: String,
    pub status: String,
    pub request_id: String,
    /// The whole event, pretty-printed. Rendered as escaped text in a `<pre>`.
    pub json: String,
}

pub struct LimitOpt {
    pub value: usize,
    pub selected: bool,
}

#[derive(Template)]
#[template(path = "ui/audit.html")]
pub struct AuditPage<'a> {
    pub css_path: &'a str,
    pub nav: Option<Nav<'a>>,
    pub rows: Vec<AuditRow>,
    pub actions: Vec<Opt>,
    pub outcomes: Vec<Opt>,
    pub limits: Vec<LimitOpt>,
    pub key: &'a str,
    pub ip: &'a str,
}

#[cfg(test)]
mod tests {
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
}
