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
//!     "created_at": "2026-11-21T01:00:00Z",
//!     "credentials": ["uptime_*"],
//!     "methods": ["GET"]
//!   }
//! ]
//! ```
//!
//! `credentials` and `methods` are the key's policy (see [`crate::policy`]);
//! entries written by this version always contain both. An entry without them
//! was written by 0.1.0 and loads as **deny-all**: the operator has to set a
//! policy with `PATCH /v1/admin/keys/{id}`. `null` is rejected, so startup
//! fails rather than guessing what was meant.
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

use crate::policy::{self, KeyPolicy};

/// One entry in the on-disk key file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredKey {
    pub id: String,
    pub name: String,
    /// Hex-encoded SHA-256 of the plaintext token.
    pub token_hash: String,
    pub created_at: DateTime<Utc>,
    /// Credential name patterns. Absent only in entries written by 0.1.0.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "policy::stored_credentials"
    )]
    pub credentials: Option<Vec<String>>,
    /// Allowed HTTP methods. Absent only in entries written by 0.1.0.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "policy::stored_methods"
    )]
    pub methods: Option<Vec<String>>,
}

impl StoredKey {
    /// An entry with an explicit policy.
    pub fn new(
        id: String,
        name: String,
        token_hash: String,
        created_at: DateTime<Utc>,
        policy: &KeyPolicy,
    ) -> Self {
        Self {
            id,
            name,
            token_hash,
            created_at,
            credentials: Some(policy.credentials.clone()),
            methods: Some(policy.methods.clone()),
        }
    }

    /// Whether the entry carries a policy (both fields present). A legacy
    /// entry does not.
    pub fn policy_set(&self) -> bool {
        self.credentials.is_some() && self.methods.is_some()
    }

    /// The policy in effect: the stored one, with any missing field (a legacy
    /// entry) denying everything.
    pub fn policy(&self) -> KeyPolicy {
        KeyPolicy {
            credentials: self.credentials.clone().unwrap_or_default(),
            methods: self.methods.clone().unwrap_or_default(),
        }
    }

    /// Store `policy` explicitly (both fields).
    pub fn set_policy(&mut self, policy: &KeyPolicy) {
        self.credentials = Some(policy.credentials.clone());
        self.methods = Some(policy.methods.clone());
    }
}

/// Hash a token for storage or lookup.
/// SHA-256 is sufficient here — tokens are 48 random alphanumeric characters
/// (~286 bits of entropy), so preimage attacks are infeasible.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    // Lowercase hex, two digits per byte. This exact format is what key files
    // store, so it must never change (see hash_matches_known_sha256_vectors).
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Load all stored keys from the key file.
/// Returns an empty vec if the file does not exist (first run).
pub fn load(path: &Path) -> io::Result<Vec<StoredKey>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read(path)?;
    // Same strictness as request bodies: duplicate keys and unknown fields make
    // the file ambiguous, so startup fails closed instead of guessing.
    let mut keys: Vec<StoredKey> = crate::api::strict_json::parse_strict(&raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("key file: {e}")))?;
    // Policies are validated (and normalised) like API input; an invalid one
    // fails startup instead of being loaded in some guessed form.
    for key in &mut keys {
        let id = key.id.clone();
        let bad = |e: crate::error::FerroError| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("key file: key {id:?}: {e}"),
            )
        };
        if let Some(list) = key.credentials.take() {
            key.credentials = Some(policy::validate_credentials(list).map_err(bad)?);
        }
        if let Some(list) = key.methods.take() {
            key.methods = Some(policy::validate_methods(list).map_err(bad)?);
        }
    }
    Ok(keys)
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
    fn hash_matches_known_sha256_vectors() {
        // FIPS 180-2 test vectors. Agent key files store this exact lowercase
        // hex form, so a dependency upgrade that changed it would invalidate
        // every persisted agent key.
        assert_eq!(
            hash_token(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
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
                credentials: None,
                methods: None,
            },
            StoredKey {
                id: "id-2".to_string(),
                name: "agent-two".to_string(),
                token_hash: hash_token("secret-token-two"),
                created_at: Utc::now(),
                credentials: None,
                methods: None,
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
            credentials: None,
            methods: None,
        }];
        save(&path, &v1).unwrap();

        save(&path, &[]).unwrap();
        let loaded = load(&path).unwrap();
        assert!(
            loaded.is_empty(),
            "overwrite should replace previous contents"
        );
    }

    fn write_raw(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.json");
        std::fs::write(&path, contents).unwrap();
        (dir, path)
    }

    const ONE: &str =
        r#"{"id":"i","name":"n","token_hash":"h","created_at":"2024-01-01T00:00:00Z"}"#;

    #[test]
    fn load_accepts_valid_key_file() {
        let (_d, p) = write_raw(&format!("[{ONE}]"));
        let keys = load(&p).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].id, "i");
    }

    #[test]
    fn load_rejects_duplicate_keys_in_an_entry() {
        let (_d, p) = write_raw(
            r#"[{"id":"i","id":"j","name":"n","token_hash":"h","created_at":"2024-01-01T00:00:00Z"}]"#,
        );
        let e = load(&p).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(e.to_string().contains("duplicate key"), "{e}");
    }

    #[test]
    fn load_rejects_unknown_fields() {
        let (_d, p) = write_raw(&format!("[{}]", ONE.replace('}', r#","role":"admin"}"#)));
        let e = load(&p).unwrap_err();
        assert!(e.to_string().contains("unknown field `role`"), "{e}");
    }

    #[test]
    fn load_rejects_malformed_and_trailing_data() {
        let (_d, p) = write_raw("[");
        assert!(load(&p).is_err());
        let (_d, p) = write_raw(&format!("[{ONE}] []"));
        assert!(load(&p).is_err());
    }

    // ── policy fields ─────────────────────────────────────────────────────────

    #[test]
    fn legacy_entry_without_policy_loads_deny_all_and_is_marked() {
        let (_d, p) = write_raw(&format!("[{ONE}]"));
        let keys = load(&p).unwrap();
        assert!(!keys[0].policy_set());
        assert_eq!(keys[0].policy(), KeyPolicy::default());
    }

    #[test]
    fn entry_with_both_fields_has_a_policy() {
        let (_d, p) = write_raw(&format!(
            "[{}]",
            ONE.replace('}', r#","credentials":["a_*","a_*"],"methods":["get"]}"#)
        ));
        let keys = load(&p).unwrap();
        assert!(keys[0].policy_set());
        let policy = keys[0].policy();
        assert_eq!(policy.credentials, vec!["a_*".to_string()]);
        assert_eq!(policy.methods, vec!["GET".to_string()]);
    }

    #[test]
    fn explicit_empty_lists_are_a_set_deny_all_policy() {
        let (_d, p) = write_raw(&format!(
            "[{}]",
            ONE.replace('}', r#","credentials":[],"methods":[]}"#)
        ));
        let keys = load(&p).unwrap();
        assert!(keys[0].policy_set());
        assert!(keys[0].policy().credentials.is_empty());
    }

    #[test]
    fn a_single_field_leaves_the_other_denied_and_the_policy_unset() {
        let (_d, p) = write_raw(&format!(
            "[{}]",
            ONE.replace('}', r#","credentials":["*"]}"#)
        ));
        let keys = load(&p).unwrap();
        assert!(!keys[0].policy_set());
        assert_eq!(keys[0].policy().credentials, vec!["*".to_string()]);
        assert!(keys[0].policy().methods.is_empty());
    }

    #[test]
    fn null_policy_fields_fail_the_load() {
        for field in ["credentials", "methods"] {
            let (_d, p) = write_raw(&format!(
                "[{}]",
                ONE.replace('}', &format!(r#","{field}":null}}"#))
            ));
            let e = load(&p).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData);
            assert!(e.to_string().contains(&format!("`{field}`")), "{e}");
        }
    }

    #[test]
    fn invalid_policy_values_fail_the_load() {
        for extra in [
            r#","credentials":[""]"#,
            r#","credentials":["a
b"]"#,
            r#","credentials":"*""#,
            r#","methods":["TRACE"]"#,
            r#","methods":["*","GET"]"#,
        ] {
            let (_d, p) = write_raw(&format!("[{}]", ONE.replace('}', &format!("{extra}}}"))));
            assert!(load(&p).is_err(), "{extra}");
        }
    }

    #[test]
    fn policy_roundtrips_and_is_always_written_explicitly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let policy = KeyPolicy::from_raw(vec!["lab_*".into()], vec!["*".into()]).unwrap();
        let keys = vec![StoredKey::new(
            "i".into(),
            "n".into(),
            "h".into(),
            Utc::now(),
            &policy,
        )];
        save(&path, &keys).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("\"credentials\"") && raw.contains("\"methods\""),
            "{raw}"
        );
        let loaded = load(&path).unwrap();
        assert!(loaded[0].policy_set());
        assert_eq!(loaded[0].policy(), policy);
    }
}
