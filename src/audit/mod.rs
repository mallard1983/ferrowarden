use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

/// The outcome of a proxied request.
#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    /// Vault was locked when the request arrived.
    VaultLocked,
    /// A placeholder referenced a credential that doesn't exist.
    UnknownCredential,
    /// The forwarded request failed at the network level.
    ForwardFailed,
    /// The agent presented an invalid or missing API key.
    Unauthorized,
    /// An internal error occurred.
    InternalError,
}

/// A single audit log entry. Credential names are recorded (they are not
/// secret) but credential values are never included anywhere in this struct.
#[derive(Debug, Serialize, Clone)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    /// The agent key ID that made the request (not the token value).
    pub agent_id: String,
    pub agent_name: String,
    pub method: String,
    /// Target URL with any credentials stripped by the scrubber.
    pub target_url: String,
    /// Names of credentials resolved for this request.
    pub credential_names: Vec<String>,
    pub outcome: Outcome,
    pub response_status: Option<u16>,
}

/// In-memory audit log with a fixed capacity ring buffer.
/// A production deployment should persist this to disk or a log sink —
/// the in-memory log is lost on restart. This provides a session-level
/// view for the admin UI without requiring a database dependency.
pub struct AuditLog {
    entries: Arc<RwLock<Vec<AuditEntry>>>,
    /// Maximum entries retained in memory. Oldest entries are dropped when
    /// capacity is exceeded.
    capacity: usize,
}

impl AuditLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::with_capacity(capacity))),
            capacity,
        }
    }

    pub async fn record(&self, entry: AuditEntry) {
        // Emit a structured log line regardless of in-memory storage so that
        // log aggregators (Loki, etc.) receive every event even after a restart.
        tracing::info!(
            agent_id = %entry.agent_id,
            agent_name = %entry.agent_name,
            method = %entry.method,
            target_url = %entry.target_url,
            credential_names = ?entry.credential_names,
            outcome = ?entry.outcome,
            response_status = ?entry.response_status,
            "audit"
        );

        let mut entries = self.entries.write().await;

        if entries.len() >= self.capacity {
            entries.remove(0);
        }

        entries.push(entry);
    }

    /// Return up to `limit` most recent entries, newest first.
    pub async fn recent(&self, limit: usize) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
}

/// Build an audit entry for the common proxy request path.
pub fn build_entry(
    agent_id: &str,
    agent_name: &str,
    method: &str,
    target_url: &str,
    credential_names: Vec<String>,
    outcome: Outcome,
    response_status: Option<u16>,
) -> AuditEntry {
    AuditEntry {
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        agent_name: agent_name.to_string(),
        method: method.to_string(),
        target_url: target_url.to_string(),
        credential_names,
        outcome,
        response_status,
    }
}
