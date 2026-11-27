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
//!     "methods": ["GET"],
//!     "approval": []
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
//! `approval` (credential patterns that need a human's approval for this key,
//! docs/approvals.md) is the one optional list: entries written before
//! approvals existed lack it and load as `[]`, which only means "no extra
//! requirement". `null` is rejected like every other policy value.
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
    /// Credential patterns that need approval for this key. Absent in
    /// entries written before approvals existed: `[]`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "policy::stored_approval"
    )]
    pub approval: Option<Vec<String>>,
    /// Credential name patterns this key may create in the managed
    /// collection. Absent in entries written before creating existed: `[]`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "policy::stored_create"
    )]
    pub create: Option<Vec<String>>,
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
            approval: Some(policy.approval.clone()),
            create: Some(policy.create.clone()),
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
            approval: self.approval.clone().unwrap_or_default(),
            create: self.create.clone().unwrap_or_default(),
        }
    }

    /// Store `policy` explicitly (both fields).
    pub fn set_policy(&mut self, policy: &KeyPolicy) {
        self.credentials = Some(policy.credentials.clone());
        self.methods = Some(policy.methods.clone());
        self.approval = Some(policy.approval.clone());
        self.create = Some(policy.create.clone());
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
        if let Some(list) = key.approval.take() {
            key.approval = Some(policy::validate_approval(list).map_err(bad)?);
        }
        if let Some(list) = key.create.take() {
            key.create = Some(policy::validate_create(list).map_err(bad)?);
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
mod tests;
