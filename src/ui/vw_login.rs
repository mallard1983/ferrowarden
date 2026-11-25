//! Vaultwarden sign-in: prelogin, token request, second step, email code.
//!
//! The protocol was verified against Vaultwarden 1.37.5 (see docs/admin-ui.md).
//! The one rule of this module: **Vaultwarden's responses never leave it**
//! except as a small closed enum. A success response carries access and
//! refresh tokens and the encrypted vault keys; it is dropped without being
//! read. An error response is parsed into a minimal struct; its `message` is
//! written to the server log at debug level only (a failed TOTP message
//! contains the server time and our IP) and goes nowhere else — not to the
//! UI, not to events.

use std::collections::HashMap;
use std::time::Duration;

use reqwest::{redirect::Policy, Client, StatusCode};
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::UiConfig;
use crate::ui::crypto::{normalize_email, Kdf};

/// Fixed namespace of the device-identifier UUIDv5, generated once.
const DEVICE_NAMESPACE: Uuid = Uuid::from_u128(0x03193fd8_0d05_4976_aa73_9e8f4fb86050);

/// Vaultwarden device type 22 = "Linux CLI"-style generic client; with a fixed
/// device name it shows up as one stable device in the account's device list.
const DEVICE_TYPE: &str = "22";
const DEVICE_NAME: &str = "ferrowarden-admin-ui";

/// Error responses are tiny; a larger body is not read further.
const MAX_ERROR_BODY: usize = 64 * 1024;
/// Debug-logged Vaultwarden messages are cut to this many characters.
const MAX_LOGGED_MESSAGE: usize = 200;

/// A second factor Ferrowarden can complete from a web form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// TOTP authenticator app (Vaultwarden provider 0).
    Authenticator,
    /// Code sent by email (1).
    Email,
    /// YubiKey OTP (3).
    YubiKey,
}

impl Provider {
    pub fn id(self) -> u8 {
        match self {
            Provider::Authenticator => 0,
            Provider::Email => 1,
            Provider::YubiKey => 3,
        }
    }

    pub fn from_id(id: &str) -> Option<Provider> {
        match id {
            "0" => Some(Provider::Authenticator),
            "1" => Some(Provider::Email),
            "3" => Some(Provider::YubiKey),
            _ => None,
        }
    }

    /// Name used in events (`details.provider`).
    pub fn name(self) -> &'static str {
        match self {
            Provider::Authenticator => "authenticator",
            Provider::Email => "email",
            Provider::YubiKey => "yubikey",
        }
    }

    /// Label shown to the operator.
    pub fn label(self) -> &'static str {
        match self {
            Provider::Authenticator => "Authenticator app",
            Provider::Email => "Email code",
            Provider::YubiKey => "YubiKey",
        }
    }

    /// Check a code locally before it is sent anywhere, and return it in the
    /// form Vaultwarden expects (spaces removed from numeric codes). `None`
    /// means the format is wrong.
    pub fn normalize_code(self, raw: &str) -> Option<Zeroizing<String>> {
        match self {
            Provider::Authenticator | Provider::Email => {
                let code: String = raw.chars().filter(|c| *c != ' ').collect();
                let ok = (6..=8).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_digit());
                ok.then(|| Zeroizing::new(code))
            }
            Provider::YubiKey => {
                // A YubiKey OTP is 44 modhex characters.
                let code = raw.trim();
                let ok = code.len() == 44
                    && code
                        .bytes()
                        .all(|b| b"cbdefghijklnrtuv".contains(&b.to_ascii_lowercase()));
                ok.then(|| Zeroizing::new(code.to_ascii_lowercase()))
            }
        }
    }
}

/// The server wants a second factor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoFactorRequired {
    /// Providers offered by the account that Ferrowarden supports, in the
    /// order the server listed them. Empty: the account has only providers
    /// that cannot work here (WebAuthn, Duo, ...).
    pub providers: Vec<Provider>,
    /// Obscured address the email code goes to (`a***@example.com`).
    pub email_hint: Option<String>,
}

/// Result of a token request that reached Vaultwarden and was understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    /// HTTP 200: signed in. Nothing from the response is kept.
    Authenticated,
    /// The password was right; a second factor is required (or, on the second
    /// step, was not accepted).
    TwoFactorRequired(TwoFactorRequired),
    /// Any other 400: wrong password, wrong code, disabled account, ...
    InvalidCredentials,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VwError {
    /// HTTP 429 from Vaultwarden.
    RateLimited,
    /// Network error, timeout, unexpected status or body, unusable KDF
    /// parameters: anything else.
    Upstream,
}

// ── Response parsing ──────────────────────────────────────────────────────────

/// A provider id as Vaultwarden sends it (a string; tolerate a number).
#[derive(Deserialize)]
#[serde(untagged)]
enum ProviderId {
    Text(String),
    Number(u32),
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(rename = "TwoFactorProviders", default)]
    providers: Option<Vec<ProviderId>>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Deserialize)]
struct HintBody {
    #[serde(rename = "TwoFactorProviders2", default)]
    providers2: Option<HashMap<String, Option<ProviderDetails>>>,
}

#[derive(Deserialize, Clone)]
struct ProviderDetails {
    #[serde(rename = "Email", default)]
    email: Option<String>,
}

/// An obscured address is shown on a page; keep it short and to the
/// characters of an email address and the `*` that hides some of them.
fn clean_hint(hint: &str) -> Option<String> {
    let ok = !hint.is_empty()
        && hint.len() <= 100
        && hint
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "*@._+-".contains(c));
    ok.then(|| hint.to_string())
}

/// Turn a token-endpoint response into an outcome. Pure, so it can be tested
/// exhaustively. The body of a 200 is ignored on purpose (the caller does not
/// even read it); only 400 bodies are parsed.
pub fn classify_token_response(status: u16, body: &[u8]) -> Result<LoginOutcome, VwError> {
    match status {
        200 => Ok(LoginOutcome::Authenticated),
        429 => Err(VwError::RateLimited),
        400 => {
            let parsed: Option<ErrorBody> = serde_json::from_slice(body).ok();
            if let Some(ErrorBody {
                providers: Some(ids),
                ..
            }) = &parsed
            {
                let mut providers = Vec::new();
                for id in ids {
                    let text = match id {
                        ProviderId::Text(s) => s.clone(),
                        ProviderId::Number(n) => n.to_string(),
                    };
                    if let Some(p) = Provider::from_id(&text) {
                        if !providers.contains(&p) {
                            providers.push(p);
                        }
                    }
                }
                let email_hint = serde_json::from_slice::<HintBody>(body)
                    .ok()
                    .and_then(|h| h.providers2)
                    .and_then(|m| m.get("1").cloned().flatten())
                    .and_then(|d| d.email)
                    .and_then(|e| clean_hint(&e));
                return Ok(LoginOutcome::TwoFactorRequired(TwoFactorRequired {
                    providers,
                    email_hint,
                }));
            }
            // The only place the message exists outside the parse: debug log.
            if let Some(message) = parsed.and_then(|p| p.message) {
                let shown: String = message.chars().take(MAX_LOGGED_MESSAGE).collect();
                tracing::debug!(
                    vaultwarden_message = %shown,
                    "Vaultwarden rejected the sign-in request (400)"
                );
            }
            Ok(LoginOutcome::InvalidCredentials)
        }
        _ => Err(VwError::Upstream),
    }
}

#[derive(Deserialize)]
struct PreloginBody {
    #[serde(alias = "Kdf")]
    kdf: u8,
    #[serde(rename = "kdfIterations", alias = "KdfIterations")]
    iterations: u32,
    #[serde(rename = "kdfMemory", alias = "KdfMemory", default)]
    memory: Option<u32>,
    #[serde(rename = "kdfParallelism", alias = "KdfParallelism", default)]
    parallelism: Option<u32>,
}

/// Parse and validate a prelogin response. Parameters outside the accepted
/// range are an upstream error: they are never used.
pub fn parse_prelogin(status: u16, body: &[u8]) -> Result<Kdf, VwError> {
    match status {
        200 => {}
        429 => return Err(VwError::RateLimited),
        _ => return Err(VwError::Upstream),
    }
    let p: PreloginBody = serde_json::from_slice(body).map_err(|_| VwError::Upstream)?;
    let kdf = match p.kdf {
        0 => Kdf::Pbkdf2 {
            iterations: p.iterations,
        },
        1 => Kdf::Argon2id {
            memory_mib: p.memory.ok_or(VwError::Upstream)?,
            iterations: p.iterations,
            parallelism: p.parallelism.ok_or(VwError::Upstream)?,
        },
        _ => return Err(VwError::Upstream),
    };
    kdf.validate().map_err(|_| VwError::Upstream)?;
    Ok(kdf)
}

/// Stable device identifier for the account: a UUIDv5 of a fixed label and the
/// normalized email. The same value on every start, so Vaultwarden keeps one
/// device row and sends at most one "new device" email.
pub fn device_identifier(email: &str) -> Uuid {
    Uuid::new_v5(
        &DEVICE_NAMESPACE,
        format!("ferrowarden-admin-ui:{}", normalize_email(email)).as_bytes(),
    )
}

// ── Client ────────────────────────────────────────────────────────────────────

pub struct VwClient {
    client: Client,
    base: String,
}

impl VwClient {
    /// Build the HTTP client once: no proxy, redirects off, 10 s timeout, the
    /// public roots plus (optionally) the operator's CA. Certificate
    /// verification is never switched off.
    pub fn new(cfg: &UiConfig) -> Result<Self, String> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(Policy::none())
            .no_proxy();
        if !cfg.vaultwarden_ca_file.trim().is_empty() {
            let pem = std::fs::read(cfg.vaultwarden_ca_file.trim())
                .map_err(|e| format!("cannot read vault.ca_file: {e}"))?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|e| format!("vault.ca_file is not a PEM certificate: {e}"))?;
            if certs.is_empty() {
                return Err("vault.ca_file contains no certificate".to_string());
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        let client = builder
            .build()
            .map_err(|e| format!("cannot build the Vaultwarden HTTP client: {e}"))?;
        Ok(Self {
            client,
            base: cfg.vaultwarden_url.trim_end_matches('/').to_string(),
        })
    }

    /// Read at most `MAX_ERROR_BODY` bytes of a response.
    async fn read_limited(mut resp: reqwest::Response) -> Vec<u8> {
        let mut out = Vec::new();
        while let Ok(Some(chunk)) = resp.chunk().await {
            if out.len() + chunk.len() > MAX_ERROR_BODY {
                break;
            }
            out.extend_from_slice(&chunk);
        }
        out
    }

    /// `POST /identity/accounts/prelogin`: the account's KDF settings.
    pub async fn prelogin(&self, email: &str) -> Result<Kdf, VwError> {
        let resp = self
            .client
            .post(format!("{}/identity/accounts/prelogin", self.base))
            .json(&serde_json::json!({ "email": normalize_email(email) }))
            .send()
            .await
            .map_err(|_| VwError::Upstream)?;
        let status = resp.status().as_u16();
        let body = if status == 200 {
            Self::read_limited(resp).await
        } else {
            Vec::new()
        };
        parse_prelogin(status, &body)
    }

    /// `POST /identity/connect/token` with the password grant. `second` is the
    /// provider and code of the second step. `twoFactorRemember` is never sent.
    pub async fn token(
        &self,
        email: &str,
        auth_hash: &str,
        second: Option<(Provider, &str)>,
    ) -> Result<LoginOutcome, VwError> {
        let email = normalize_email(email);
        let device_id = device_identifier(&email).to_string();
        // Built in its own scope: the serializer is not `Send`, so it must not
        // be alive across the request's await.
        let body = {
            let mut form = form_urlencoded::Serializer::new(String::new());
            form.append_pair("grant_type", "password")
                .append_pair("username", &email)
                .append_pair("password", auth_hash)
                .append_pair("scope", "api offline_access")
                .append_pair("client_id", "web")
                .append_pair("deviceType", DEVICE_TYPE)
                .append_pair("deviceIdentifier", &device_id)
                .append_pair("deviceName", DEVICE_NAME);
            if let Some((provider, code)) = second {
                form.append_pair("twoFactorProvider", &provider.id().to_string())
                    .append_pair("twoFactorToken", code);
            }
            form.finish()
        };

        let resp = self
            .client
            .post(format!("{}/identity/connect/token", self.base))
            .header("Device-Type", DEVICE_TYPE)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await
            .map_err(|_| VwError::Upstream)?;
        let status = resp.status();
        if status == StatusCode::OK {
            // Tokens and vault keys: dropped unread.
            drop(resp);
            return classify_token_response(200, &[]);
        }
        let status = status.as_u16();
        let body = Self::read_limited(resp).await;
        classify_token_response(status, &body)
    }

    /// `POST /api/two-factor/send-email-login`: ask Vaultwarden to email a
    /// login code to the address registered for the account.
    pub async fn send_email_login(&self, email: &str, auth_hash: &str) -> Result<(), VwError> {
        let email = normalize_email(email);
        let resp = self
            .client
            .post(format!("{}/api/two-factor/send-email-login", self.base))
            .json(&serde_json::json!({
                "email": email,
                "masterPasswordHash": auth_hash,
                "deviceIdentifier": device_identifier(&email).to_string(),
            }))
            .send()
            .await
            .map_err(|_| VwError::Upstream)?;
        match resp.status().as_u16() {
            200 | 204 => Ok(()),
            429 => Err(VwError::RateLimited),
            400 => {
                let body = Self::read_limited(resp).await;
                if let Some(message) = serde_json::from_slice::<ErrorBody>(&body)
                    .ok()
                    .and_then(|b| b.message)
                {
                    let shown: String = message.chars().take(MAX_LOGGED_MESSAGE).collect();
                    tracing::debug!(
                        vaultwarden_message = %shown,
                        "Vaultwarden refused to send the email code (400)"
                    );
                }
                Err(VwError::Upstream)
            }
            _ => Err(VwError::Upstream),
        }
    }
}

#[cfg(test)]
mod tests;
