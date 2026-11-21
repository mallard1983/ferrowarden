//! Persistent agent key store.
//!
//! Agent tokens are **never** stored in plaintext — only their SHA-256 hashes
//! are written to disk or held in the runtime HashMap. The plaintext token is
//! returned once at creation time and never stored after that.
//!
//! # File format
//!
//! A JSON array written atomically (write to `.tmp`, rename):
//! ```json
//! [
//!   {
//!     "id": "uuid",
//!     "name": "homelab-claude",
//!     "token_hash": "hex-encoded-sha256",
//!     "created_at": "2026-11-21T01:00:00Z"
//!   }
//! ]
//! ```
//!
//! # Key rotation
//!
//! Done entirely via the admin API — no container access required:
//!   1. `POST /v1/admin/keys`  → new token (shown once), configure the agent
//!   2. `DELETE /v1/admin/keys/{old_id}` → old key revoked immediately

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use std::path::Path;

/// One entry in the on-disk key file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    pub id: String,
    pub name: String,
    /// Hex-encoded SHA-256 of the plaintext token.
    pub token_hash: String,
    pub created_at: DateTime<Utc>,
}

/// Hash a token for storage or lookup.
/// SHA-256 is sufficient here — tokens are 48 random alphanumeric characters
/// (~286 bits of entropy), so preimage attacks are infeasible.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Load all stored keys from the key file.
/// Returns an empty vec if the file does not exist (first run).
pub fn load(path: &Path) -> io::Result<Vec<StoredKey>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Write all keys to disk atomically.
/// Writes to `<path>.tmp` first, then renames — a crash mid-write cannot
/// produce a corrupted key file.
pub fn save(path: &Path, keys: &[StoredKey]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let json = serde_json::to_string_pretty(keys)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    write_private(&tmp, json.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Write a file readable only by the owner (0600 on Unix) and flush it to disk
/// before the rename, so the rename never exposes a partially written file.
fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        // The mode only applies on creation; tighten a pre-existing tmp file too.
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(data)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(hash_token("abc"), hash_token("abc"));
    }

    #[test]
    fn hash_differs_for_different_inputs() {
        assert_ne!(hash_token("abc"), hash_token("xyz"));
    }

    #[test]
    fn hash_is_hex_sha256_length() {
        // SHA-256 → 32 bytes → 64 hex chars
        assert_eq!(hash_token("any_token").len(), 64);
    }

    #[test]
    fn load_returns_empty_for_missing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let keys = load(&path).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.json");

        let keys = vec![
            StoredKey {
                id: "id-1".to_string(),
                name: "agent-one".to_string(),
                token_hash: hash_token("secret-token-one"),
                created_at: Utc::now(),
            },
            StoredKey {
                id: "id-2".to_string(),
                name: "agent-two".to_string(),
                token_hash: hash_token("secret-token-two"),
                created_at: Utc::now(),
            },
        ];

        save(&path, &keys).unwrap();
        let loaded = load(&path).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, "id-1");
        assert_eq!(loaded[1].name, "agent-two");
        assert_eq!(loaded[0].token_hash, hash_token("secret-token-one"));
    }

    #[test]
    fn save_is_atomic_tmp_file_cleaned_up() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let tmp = path.with_extension("tmp");

        save(&path, &[]).unwrap();

        assert!(path.exists(), "key file should exist after save");
        assert!(!tmp.exists(), "tmp file should be gone after atomic rename");
    }

    #[test]
    fn save_overwrites_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.json");

        let v1 = vec![StoredKey {
            id: "original".to_string(),
            name: "old".to_string(),
            token_hash: "hash1".to_string(),
            created_at: Utc::now(),
        }];
        save(&path, &v1).unwrap();

        save(&path, &[]).unwrap();
        let loaded = load(&path).unwrap();
        assert!(loaded.is_empty(), "overwrite should replace previous contents");
    }
}
