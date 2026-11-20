use reqwest::Client;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::error::{FerroError, FerroResult};

/// Minimal response shapes from bw serve. We only deserialize what we need.
#[derive(Debug, Deserialize)]
struct BwResponse<T> {
    success: bool,
    message: Option<String>,
    data: Option<T>,
}

#[derive(Debug, Deserialize)]
struct BwItem {
    name: String,
}

#[derive(Debug, Deserialize)]
struct BwListData {
    data: Vec<BwItem>,
}

#[derive(Debug, Deserialize)]
struct BwStringData {
    data: String,
}

/// Client for the bw serve local REST API.
/// All methods assume bw serve is running and unlocked — callers must check
/// lock state before calling. The bw_serve_url must be localhost-only.
pub struct VaultClient {
    client: Client,
    base_url: String,
}

impl VaultClient {
    pub fn new(base_url: String) -> Self {
        Self {
            // Short timeouts — bw serve is local, slow responses indicate a problem
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("Failed to build vault HTTP client"),
            base_url,
        }
    }

    /// Return all vault item names. Values are never fetched here.
    /// Called on unlock and periodically to refresh the credential name cache.
    pub async fn list_item_names(&self) -> FerroResult<Vec<String>> {
        let url = format!("{}/list/object/items", self.base_url);

        let resp = self.client.get(&url).send().await?;

        if resp.status() == reqwest::StatusCode::BAD_REQUEST {
            return Err(FerroError::VaultLocked);
        }

        let body: BwResponse<BwListData> = resp
            .json()
            .await
            .map_err(|e| FerroError::Internal(e.to_string()))?;

        if !body.success {
            let msg = body
                .message
                .unwrap_or_else(|| "unknown vault error".to_string());
            // A "vault is locked" message from bw serve maps to VaultLocked
            if msg.to_lowercase().contains("locked") {
                return Err(FerroError::VaultLocked);
            }
            return Err(FerroError::Internal(msg));
        }

        let names = body
            .data
            .map(|d| d.data.into_iter().map(|item| item.name).collect())
            .unwrap_or_default();

        Ok(names)
    }

    /// Fetch the password value for a named vault item.
    /// Returns a Zeroizing<String> so the caller's binding wipes the value
    /// from memory when it goes out of scope.
    pub async fn get_password(&self, name: &str) -> FerroResult<Zeroizing<String>> {
        let url = format!(
            "{}/object/password/{}",
            self.base_url,
            urlencoding::encode(name)
        );

        let resp = self.client.get(&url).send().await?;

        if resp.status() == reqwest::StatusCode::BAD_REQUEST {
            return Err(FerroError::VaultLocked);
        }

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(FerroError::CredentialNotFound(name.to_string()));
        }

        let body: BwResponse<BwStringData> = resp
            .json()
            .await
            .map_err(|e| FerroError::Internal(e.to_string()))?;

        if !body.success {
            let msg = body
                .message
                .unwrap_or_else(|| "unknown vault error".to_string());
            if msg.to_lowercase().contains("locked") {
                return Err(FerroError::VaultLocked);
            }
            if msg.to_lowercase().contains("no item") || msg.to_lowercase().contains("not found") {
                return Err(FerroError::CredentialNotFound(name.to_string()));
            }
            return Err(FerroError::Internal(msg));
        }

        let value = body
            .data
            .map(|d| Zeroizing::new(d.data))
            .ok_or_else(|| FerroError::CredentialNotFound(name.to_string()))?;

        Ok(value)
    }

    /// Check whether bw serve is reachable and the vault is unlocked.
    pub async fn status(&self) -> FerroResult<bool> {
        let url = format!("{}/status", self.base_url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|_| FerroError::VaultLocked)?;

        // bw serve returns status regardless of lock state — parse the response
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| FerroError::Internal(e.to_string()))?;

        let status = body
            .pointer("/data/template/status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        Ok(status == "unlocked")
    }
}
