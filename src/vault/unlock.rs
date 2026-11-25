use reqwest::Client;
use serde_json::json;
use zeroize::Zeroizing;

use crate::error::{FerroError, FerroResult};

/// Send the master password to bw serve POST /unlock.
/// The password is consumed and zeroed by this function — the caller must not
/// retain a copy. Returns Ok(()) on success.
pub async fn unlock_vault(base_url: &str, password: Zeroizing<String>) -> FerroResult<()> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .no_proxy()
        .build()
        .map_err(|e| FerroError::Internal(e.to_string()))?;

    let url = format!("{}/unlock", base_url);

    // Build the body while the password is still in scope, then drop it.
    // serde_json::json! copies the string value into the JSON buffer — that
    // copy lives until the response is processed, then both are dropped.
    let body = json!({ "password": *password });

    // Password Zeroizing<String> is dropped here — the original is wiped.
    drop(password);

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|_| FerroError::VaultUnavailable)?;

    let status = resp.status();

    let result: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| FerroError::UnlockFailed(e.to_string()))?;

    if !status.is_success() || result.get("success").and_then(|v| v.as_bool()) == Some(false) {
        let msg = result
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unlock failed")
            .to_string();
        return Err(FerroError::UnlockFailed(msg));
    }

    Ok(())
}

/// Read the master password from a file, returning it as a Zeroizing string.
/// The file must contain only the password on the first line (no trailing newline required).
/// Caller is responsible for passing the result directly to unlock_vault.
pub fn read_password_file(path: &std::path::Path) -> FerroResult<Zeroizing<String>> {
    let raw = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| FerroError::Config(format!("Cannot read unlock file: {}", e)))?,
    );

    // Trim trailing newlines only — preserve any intentional whitespace in the
    // password. The same rule as every other secret file (config::secrets).
    let password = crate::config::secrets::strip_line_end(&raw).to_string();

    if password.is_empty() {
        return Err(FerroError::Config("Unlock file is empty".to_string()));
    }

    Ok(Zeroizing::new(password))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn reads_plain_password() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "my_secure_password").unwrap();
        let pw = read_password_file(f.path()).unwrap();
        assert_eq!(pw.as_str(), "my_secure_password");
    }

    #[test]
    fn strips_trailing_newline() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "my_secure_password").unwrap();
        let pw = read_password_file(f.path()).unwrap();
        assert_eq!(pw.as_str(), "my_secure_password");
    }

    #[test]
    fn strips_crlf() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "my_secure_password\r\n").unwrap();
        let pw = read_password_file(f.path()).unwrap();
        assert_eq!(pw.as_str(), "my_secure_password");
    }

    #[test]
    fn preserves_internal_whitespace() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "pass word with spaces").unwrap();
        let pw = read_password_file(f.path()).unwrap();
        assert_eq!(pw.as_str(), "pass word with spaces");
    }

    #[test]
    fn empty_file_returns_error() {
        let f = NamedTempFile::new().unwrap();
        let err = read_password_file(f.path()).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn missing_file_returns_error() {
        let path = std::path::Path::new("/nonexistent/path/unlock.key");
        let err = read_password_file(path).unwrap_err();
        assert!(err.to_string().contains("Cannot read unlock file"));
    }
}
