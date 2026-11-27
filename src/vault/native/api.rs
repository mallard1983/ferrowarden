//! The slice of Vaultwarden's HTTP API the native backend uses: API-key login,
//! `GET /api/sync`, `GET /api/accounts/revision-date`, the account profile and
//! `POST /api/ciphers/create` (the write path, docs/native-vault.md).
//!
//! The HTTP client is locked down: no proxy (vault traffic must never go
//! through `HTTP(S)_PROXY`), no redirects, timeouts, a cap on every response
//! body, the public roots plus the operator's CA, and certificate
//! verification that is never switched off. Response bodies are never
//! logged; an error carries a fixed category and nothing from the server.

use std::time::{Duration, Instant};

use reqwest::{header, redirect::Policy, Client, StatusCode};
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::ui::crypto::Kdf;

/// The Bitwarden client version sent with every request: **the protocol
/// version Ferrowarden implements**, not a claim to be that client. Vaultwarden
/// gates parts of the sync response on it; 2024.12.0 is the first version that
/// includes SSH-key items, so the listing is the same as the CLI's.
pub const PROTOCOL_VERSION: &str = "2024.12.0";
const CLIENT_NAME: &str = "ferrowarden";

/// Fixed namespace of the device-identifier UUIDv5, generated once.
const DEVICE_NAMESPACE: Uuid = Uuid::from_u128(0x7d0f5f3e_43a8_4f1b_9b8d_2c6a1e94b7c5);
/// Vaultwarden device type 22 ("Server"), the same the admin UI login uses.
const DEVICE_TYPE: &str = "22";
const DEVICE_NAME: &str = "ferrowarden";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Token and profile responses are a few KiB.
const MAX_SMALL_BODY: usize = 256 * 1024;
/// A very large vault (tens of thousands of items) is a few tens of MiB.
const MAX_SYNC_BODY: usize = 64 * 1024 * 1024;
/// More items than this in one sync is refused rather than held in memory.
pub const MAX_ITEMS: usize = 50_000;
/// A token is renewed this long before it expires.
const TOKEN_SKEW: Duration = Duration::from_secs(60);

/// Why a request to Vaultwarden did not produce a usable answer. Never carries
/// anything from the server's response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    /// 401/403 on a request, or 400 on login: the key or token was rejected.
    Unauthorized,
    /// 429.
    RateLimited,
    /// Network error, timeout or a 5xx status.
    Unavailable,
    /// A body that is too large, not JSON, or not the expected shape.
    BadResponse,
}

/// The stable device identifier for an API key: a UUIDv5 of a fixed label and
/// the client id, so Vaultwarden keeps one device row per key across restarts.
pub fn device_identifier(client_id: &str) -> Uuid {
    Uuid::new_v5(
        &DEVICE_NAMESPACE,
        format!("ferrowarden-vault:{client_id}").as_bytes(),
    )
}

#[derive(Deserialize)]
struct TokenBody {
    access_token: Zeroizing<String>,
    expires_in: u64,
    #[serde(rename = "Kdf", alias = "kdf", default)]
    kdf: Option<u8>,
    #[serde(rename = "KdfIterations", alias = "kdfIterations", default)]
    iterations: Option<u32>,
    #[serde(rename = "KdfMemory", alias = "kdfMemory", default)]
    memory: Option<u32>,
    #[serde(rename = "KdfParallelism", alias = "kdfParallelism", default)]
    parallelism: Option<u32>,
}

/// A bearer token and when to replace it.
pub struct Session {
    pub token: Zeroizing<String>,
    pub renew_at: Instant,
}

impl Session {
    pub fn is_fresh(&self) -> bool {
        Instant::now() < self.renew_at
    }
}

/// What a successful login yields.
pub struct Login {
    pub session: Session,
    /// The account's KDF settings (validated by the caller).
    pub kdf: Option<Kdf>,
}

/// `GET /api/sync`, only the parts the backend reads. Unknown fields are
/// ignored.
#[derive(Deserialize)]
pub struct SyncResponse {
    pub profile: Profile,
    #[serde(default)]
    pub ciphers: Vec<RawCipher>,
    /// The collections the account can see (those of its organisations).
    #[serde(default)]
    pub collections: Vec<RawCollection>,
}

/// A collection as `/api/sync` lists it for this account. The name is
/// ciphertext under the organisation key. The permission flags are the
/// account's own on this collection; one that is absent is not trusted
/// (fail closed: see `ManagedState`). Servers also send
/// `manage` and `externalId`: creating an item needs "Can edit", not "Can
/// manage", so they are ignored.
#[derive(Deserialize, Clone)]
pub struct RawCollection {
    pub id: String,
    #[serde(rename = "organizationId", default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    /// "View only": the account cannot change the collection's items.
    #[serde(rename = "readOnly", default)]
    pub read_only: Option<bool>,
    /// "Hide passwords": the account may not see the items' passwords.
    #[serde(rename = "hidePasswords", default)]
    pub hide_passwords: Option<bool>,
}

impl std::fmt::Debug for RawCollection {
    // The name is ciphertext, but there is no reason to print even that.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawCollection")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub id: Option<String>,
    pub email: String,
    /// The user key, encrypted with the stretched master key.
    #[serde(default)]
    pub key: Option<String>,
    /// The RSA private key (PKCS#8), encrypted with the user key.
    #[serde(rename = "privateKey", default)]
    pub private_key: Option<String>,
    #[serde(rename = "securityStamp", default)]
    pub security_stamp: Option<String>,
    #[serde(default)]
    pub organizations: Vec<RawOrganization>,
}

#[derive(Deserialize)]
pub struct RawOrganization {
    pub id: String,
    /// The organisation key, RSA-OAEP encrypted to the user's public key.
    #[serde(default)]
    pub key: Option<String>,
}

/// A cipher as the server stores it: ciphertext (EncStrings) and structure,
/// no plaintext. Unknown fields are ignored.
#[derive(Deserialize, Clone)]
pub struct RawCipher {
    pub id: String,
    #[serde(rename = "organizationId", default)]
    pub organization_id: Option<String>,
    #[serde(rename = "type")]
    pub item_type: u32,
    #[serde(default)]
    pub reprompt: u32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    /// Per-item key, wrapped by the user key or the organisation key.
    #[serde(default)]
    pub key: Option<String>,
    #[serde(rename = "deletedDate", default)]
    pub deleted_date: Option<String>,
    #[serde(rename = "archivedDate", default)]
    pub archived_date: Option<String>,
    /// `false` when the item's collection hides passwords from this member
    /// ("Hide passwords"). Absent (an older server) counts as visible.
    #[serde(rename = "viewPassword", default)]
    pub view_password: Option<bool>,
    /// The collections the item is in (organisation items).
    #[serde(rename = "collectionIds", default)]
    pub collection_ids: Vec<String>,
    #[serde(default)]
    pub login: Option<RawLogin>,
    #[serde(default)]
    pub fields: Option<Vec<RawField>>,
}

#[derive(Deserialize, Clone)]
pub struct RawLogin {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub uris: Option<Vec<RawUri>>,
}

#[derive(Deserialize, Clone)]
pub struct RawUri {
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(rename = "match", default)]
    pub match_type: Option<u32>,
}

#[derive(Deserialize, Clone)]
pub struct RawField {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(rename = "type", default)]
    pub field_type: u32,
    #[serde(rename = "linkedId", default)]
    pub linked_id: Option<u32>,
}

impl std::fmt::Debug for RawCipher {
    // Ciphertext only, but there is no reason to print even that.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawCipher")
            .field("id", &self.id)
            .field("type", &self.item_type)
            .finish_non_exhaustive()
    }
}

pub struct Api {
    client: Client,
    base: String,
}

impl Api {
    /// Build the HTTP client once. `ca_file` is an optional PEM bundle trusted
    /// in addition to the public roots.
    pub fn new(base_url: &str, ca_file: &str) -> Result<Self, String> {
        let mut builder = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(Policy::none())
            .no_proxy();
        if !ca_file.trim().is_empty() {
            let pem = std::fs::read(ca_file.trim())
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
            base: base_url.trim_end_matches('/').to_string(),
        })
    }

    #[cfg(test)]
    pub(super) fn base(&self) -> &str {
        &self.base
    }

    fn with_client_headers(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        rb.header("Bitwarden-Client-Name", CLIENT_NAME)
            .header("Bitwarden-Client-Version", PROTOCOL_VERSION)
    }

    /// Read a response body up to `limit` bytes into a buffer that is wiped
    /// when dropped.
    async fn read_body(
        mut resp: reqwest::Response,
        limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>, ApiError> {
        if resp.content_length().is_some_and(|n| n as usize > limit) {
            return Err(ApiError::BadResponse);
        }
        let mut out = Zeroizing::new(Vec::new());
        while let Some(chunk) = resp.chunk().await.map_err(|_| ApiError::Unavailable)? {
            if out.len() + chunk.len() > limit {
                return Err(ApiError::BadResponse);
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    fn classify(status: StatusCode, login: bool) -> Result<(), ApiError> {
        match status.as_u16() {
            200..=299 => Ok(()),
            400 if login => Err(ApiError::Unauthorized),
            401 | 403 => Err(ApiError::Unauthorized),
            429 => Err(ApiError::RateLimited),
            _ => Err(ApiError::Unavailable),
        }
    }

    /// API-key login (`grant_type=client_credentials`, `scope=api`).
    pub async fn login(&self, client_id: &str, client_secret: &str) -> Result<Login, ApiError> {
        // The form is built in a buffer that is wiped on drop. The HTTP stack
        // needs its own copy of the bytes to send, and that copy cannot be
        // wiped from here (docs/security.md lists it among the limits).
        let body = Zeroizing::new(
            form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "client_credentials")
                .append_pair("client_id", client_id)
                .append_pair("client_secret", client_secret)
                .append_pair("scope", "api")
                .append_pair(
                    "device_identifier",
                    &device_identifier(client_id).to_string(),
                )
                .append_pair("device_name", DEVICE_NAME)
                .append_pair("device_type", DEVICE_TYPE)
                .finish(),
        );
        let resp = Self::with_client_headers(
            self.client
                .post(format!("{}/identity/connect/token", self.base)),
        )
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body.as_bytes().to_vec())
        .send()
        .await
        .map_err(|_| ApiError::Unavailable)?;
        drop(body);
        Self::classify(resp.status(), true)?;
        let raw = Self::read_body(resp, MAX_SMALL_BODY).await?;
        let t: TokenBody = serde_json::from_slice(&raw).map_err(|_| ApiError::BadResponse)?;
        let kdf = match t.kdf {
            Some(0) => t.iterations.map(|iterations| Kdf::Pbkdf2 { iterations }),
            Some(1) => match (t.iterations, t.memory, t.parallelism) {
                (Some(iterations), Some(memory_mib), Some(parallelism)) => Some(Kdf::Argon2id {
                    memory_mib,
                    iterations,
                    parallelism,
                }),
                _ => None,
            },
            _ => None,
        };
        // Renew a little early, but never in the past for a short-lived token.
        let lifetime = Duration::from_secs(t.expires_in.min(24 * 3600));
        let renew_at = Instant::now() + lifetime.saturating_sub(TOKEN_SKEW).max(lifetime / 2);
        Ok(Login {
            session: Session {
                token: t.access_token,
                renew_at,
            },
            kdf,
        })
    }

    async fn get(
        &self,
        path: &str,
        token: &str,
        limit: usize,
    ) -> Result<Zeroizing<Vec<u8>>, ApiError> {
        let resp = Self::with_client_headers(self.client.get(format!("{}{path}", self.base)))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| ApiError::Unavailable)?;
        Self::classify(resp.status(), false)?;
        Self::read_body(resp, limit).await
    }

    /// `GET /api/accounts/revision-date`: a number that changes whenever the
    /// account's vault does. Returned as text, compared for equality only.
    pub async fn revision_date(&self, token: &str) -> Result<String, ApiError> {
        let raw = self.get("/api/accounts/revision-date", token, 1024).await?;
        let text = std::str::from_utf8(&raw).map_err(|_| ApiError::BadResponse)?;
        let text = text.trim();
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            return Err(ApiError::BadResponse);
        }
        Ok(text.to_string())
    }

    /// `GET /api/sync?excludeDomains=true`.
    pub async fn sync(&self, token: &str) -> Result<SyncResponse, ApiError> {
        let raw = self
            .get("/api/sync?excludeDomains=true", token, MAX_SYNC_BODY)
            .await?;
        let parsed: SyncResponse =
            serde_json::from_slice(&raw).map_err(|_| ApiError::BadResponse)?;
        if parsed.ciphers.len() > MAX_ITEMS {
            return Err(ApiError::BadResponse);
        }
        Ok(parsed)
    }

    /// `POST /api/ciphers/create`: write a new item (the JSON body is
    /// ciphertext and structure only) and return the id the server gave it.
    /// Not retried here: a request that timed out may have been applied.
    pub async fn create_cipher(
        &self,
        token: &str,
        body: &serde_json::Value,
    ) -> Result<String, ApiError> {
        #[derive(Deserialize)]
        struct Created {
            id: String,
        }
        let resp = Self::with_client_headers(
            self.client
                .post(format!("{}/api/ciphers/create", self.base)),
        )
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .map_err(|_| ApiError::Unavailable)?;
        Self::classify(resp.status(), false)?;
        let raw = Self::read_body(resp, MAX_SMALL_BODY).await?;
        let created: Created = serde_json::from_slice(&raw).map_err(|_| ApiError::BadResponse)?;
        Ok(created.id)
    }

    /// `GET /api/accounts/profile`: only the account email is read.
    pub async fn profile_email(&self, token: &str) -> Result<String, ApiError> {
        #[derive(Deserialize)]
        struct P {
            email: String,
        }
        let raw = self
            .get("/api/accounts/profile", token, MAX_SMALL_BODY)
            .await?;
        let p: P = serde_json::from_slice(&raw).map_err(|_| ApiError::BadResponse)?;
        Ok(p.email)
    }
}

#[cfg(test)]
mod tests;
