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
    id: String,
    name: String,
    /// 1 = login. Only login items carry a password.
    #[serde(rename = "type")]
    item_type: u8,
    #[serde(default)]
    login: Option<BwLogin>,
}

/// Only the URI list is deserialized. The full item (including the password)
/// is in the bw serve response, but serde never copies those fields out.
#[derive(Debug, Deserialize)]
struct BwLogin {
    #[serde(default)]
    uris: Option<Vec<BwUri>>,
}

#[derive(Debug, Deserialize)]
struct BwUri {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BwListData {
    data: Vec<BwItem>,
}

#[derive(Debug, Deserialize)]
struct BwStringData {
    data: String,
}

/// One vault login item as seen by ferrowarden: never the password, only
/// the id used to fetch it and the URIs that bind it to target hosts.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialEntry {
    pub id: String,
    pub uris: Vec<String>,
}

/// Credential cache: item name -> all login items with that name. More than
/// one entry means the name is ambiguous and cannot be used.
pub type CredentialMap = std::collections::BTreeMap<String, Vec<CredentialEntry>>;

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
            // Short timeouts — bw serve is local, slow responses indicate a problem.
            // no_proxy: vault traffic must never be routed via an HTTP(S)_PROXY.
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .no_proxy()
                .build()
                .expect("Failed to build vault HTTP client"),
            base_url,
        }
    }

    /// Pull the latest vault contents from Vaultwarden into bw serve's local
    /// cache. Without this, items added after `bw login` never appear.
    pub async fn sync(&self) -> FerroResult<()> {
        let url = format!("{}/sync", self.base_url);
        let resp = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|_| FerroError::VaultUnavailable)?;
        if !resp.status().is_success() {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let msg = body
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("sync failed");
            if msg.to_lowercase().contains("locked") {
                return Err(FerroError::VaultLocked);
            }
            return Err(FerroError::Internal(msg.to_string()));
        }
        Ok(())
    }

    /// Return every login item's name, id and URIs. Values are never kept.
    /// Called on unlock and periodically to refresh the credential cache.
    pub async fn list_credentials(&self) -> FerroResult<CredentialMap> {
        let url = format!("{}/list/object/items", self.base_url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|_| FerroError::VaultUnavailable)?;

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

        let mut map = CredentialMap::new();
        for item in body.data.map(|d| d.data).unwrap_or_default() {
            if item.item_type != 1 {
                continue;
            }
            let uris = item
                .login
                .and_then(|l| l.uris)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|u| u.uri)
                .filter(|u| !u.trim().is_empty())
                .collect();
            map.entry(item.name)
                .or_default()
                .push(CredentialEntry { id: item.id, uris });
        }

        Ok(map)
    }

    /// Fetch the password value of a vault item by its id. Looking up by id
    /// (not name) avoids bw's search matching a different item. `name` is
    /// only used in error messages.
    /// Returns a Zeroizing<String> so the caller's binding wipes the value
    /// from memory when it goes out of scope.
    pub async fn get_password(&self, id: &str, name: &str) -> FerroResult<Zeroizing<String>> {
        let url = format!(
            "{}/object/password/{}",
            self.base_url,
            urlencoding::encode(id)
        );

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|_| FerroError::VaultUnavailable)?;

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
                .unwrap_or_else(|| "unknown vault error".to_string())
                .to_lowercase();
            if msg.contains("locked") {
                return Err(FerroError::VaultLocked);
            }
            if msg.contains("no item") || msg.contains("not found") {
                return Err(FerroError::CredentialNotFound(name.to_string()));
            }
            return Err(FerroError::Internal("vault returned an error".to_string()));
        }

        let value = body
            .data
            .map(|d| Zeroizing::new(d.data))
            .ok_or_else(|| FerroError::CredentialNotFound(name.to_string()))?;

        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_parsing_keeps_logins_and_uris_only() {
        let raw = r#"{"success":true,"data":{"object":"list","data":[
            {"id":"1","name":"a","type":1,"login":{"password":"SECRET","uris":[{"uri":"https://a.example"},{"uri":null}]}},
            {"id":"2","name":"note","type":2},
            {"id":"3","name":"a","type":1,"login":{"password":"OTHER","uris":null}}
        ]}}"#;
        let body: BwResponse<BwListData> = serde_json::from_str(raw).unwrap();
        let items = body.data.unwrap().data;
        assert_eq!(items.len(), 3);
        assert_eq!(
            items[0]
                .login
                .as_ref()
                .unwrap()
                .uris
                .as_ref()
                .unwrap()
                .len(),
            2
        );
    }
}
