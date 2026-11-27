use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

use crate::vault::model::ManagedProblem;

#[derive(Debug, Error)]
pub enum FerroError {
    // Vault errors
    #[error("Vault is locked")]
    VaultLocked,

    #[error("Vault unlock failed: {0}")]
    UnlockFailed(String),

    #[error("Credential not found: {0}")]
    CredentialNotFound(String),

    #[error("Vault client error: {0}")]
    VaultClient(#[from] reqwest::Error),

    #[error("Vault backend is unreachable")]
    VaultUnavailable,

    #[error(
        "Credential name is ambiguous — {0} matches more than one vault item; rename one of them"
    )]
    AmbiguousCredential(String),

    #[error("Credential {name} may not be sent to {host}: {reason}")]
    CredentialHostNotAllowed {
        name: String,
        host: String,
        reason: String,
    },

    // Auth errors
    #[error("Missing or invalid agent API key")]
    Unauthorized,

    #[error("Agent key not found")]
    AgentKeyNotFound,

    // Per-key policy. The credential message is the same whether or not the
    // credential exists, so it cannot be used to probe the vault.
    #[error("Credential {0} is not available to this agent key")]
    CredentialOutOfScope(String),

    #[error("Method {0} is not allowed for this agent key")]
    MethodNotAllowed(String),

    // Proxy errors
    #[error("Forward request failed: {0}")]
    ForwardFailed(String),

    #[error("Invalid target URL: {0}")]
    InvalidTargetUrl(String),

    #[error("Target not allowed: {0}")]
    TargetBlocked(String),

    #[error("Target response exceeds the {0}-byte limit")]
    ResponseTooLarge(usize),

    // Placeholder errors
    #[error("Placeholder references an unknown credential or field: {0}")]
    UnknownPlaceholder(String),

    #[error("Malformed placeholder: {0}")]
    MalformedPlaceholder(String),

    #[error("Field {field} of credential {item} is ambiguous: the vault item has more than one field with that name")]
    AmbiguousField { item: String, field: String },

    #[error("Credential {0} has master password re-prompt enabled; it cannot be used by agents until approvals are supported")]
    RepromptRequired(String),

    // Captured-session errors (docs/sessions.md). `UnknownSession` is the one
    // answer for a name that is absent, expired or another key's, so it cannot
    // be used to find out what other keys hold.
    #[error("Session {0} is unknown or expired; log in again")]
    UnknownSession(String),

    #[error("Session {name} may not be sent to {host}: it was captured from another origin")]
    SessionHostNotAllowed { name: String, host: String },

    #[error("Captured sessions are disabled (sessions.enabled = false)")]
    SessionsDisabled,

    // Human approval (docs/approvals.md). Each has a stable `code` in the
    // response body, and `ApprovalPending` carries the approval id.
    #[error("Approval required: a human has to approve this request. Ask your human to approve approval {id} in the Ferrowarden admin UI, then retry the same request.")]
    ApprovalPending { id: String },

    #[error("Approval denied: a human denied this request. Do not retry it; tell your human what was refused.")]
    ApprovalDenied,

    // Deciding: only the admin API and the admin UI reach these.
    #[error("That approval is no longer pending: it was decided, has expired or was cleared. Nothing was changed.")]
    ApprovalNotPending,

    #[error("There is no such live grant: it was revoked, has expired or was cleared. Nothing was changed.")]
    GrantNotFound,

    #[error("Too many approval requests from this agent key. Wait for the pending ones to be decided or to expire, then retry.")]
    ApprovalLimitReached,

    // Creating credentials (docs/managed-credentials.md). Each has a stable
    // `code` in the response body.
    #[error("Creating and rotating credentials is switched off: no managed collection is configured (vault.managed.collection)")]
    CredentialCreateDisabled,

    #[error("This agent key may not create a credential called {0}")]
    CredentialCreateOutOfScope(String),

    #[error("A credential called {0} already exists; choose another name")]
    CredentialExists(String),

    #[error("The managed collection cannot be written to right now: {}", .0.describe())]
    ManagedCollectionUnavailable(ManagedProblem),

    // The vault refused the credentials before doing anything, or the write
    // was never sent: true that nothing was created or changed.
    #[error("The vault refused the write before anything was written; nothing was created or changed. Try again later.")]
    VaultWriteFailed,

    // A timeout, a lost connection or a server error: the write may have been
    // applied, and saying otherwise would be a guess.
    #[error(
        "The write may have been applied: read the credential again (GET /v1/credentials?detail=true) before retrying."
    )]
    VaultWriteUnknown,

    // Rotating credentials (docs/managed-credentials.md). Each has a stable
    // `code` in the response body.
    #[error("This agent key may not rotate a credential called {0}")]
    CredentialRotateOutOfScope(String),

    // One answer for "exists elsewhere" and "does not exist", so that it is
    // not an existence oracle for names outside the key's scope.
    #[error(
        "There is no credential called {0} in the managed collection, so it cannot be rotated"
    )]
    CredentialNotManaged(String),

    #[error("The credential {0} cannot be rotated: only a login with a password and without master password re-prompt can")]
    CredentialNotRotatable(String),

    #[error("A rotation of {0} is already in progress: commit it or abort it first")]
    RotationInProgress(String),

    #[error("No rotation of {0} is pending: start one first")]
    NoRotationPending(String),

    #[error("Someone changed the item in the vault while it was being rotated, or it needs a person to fix it. Nothing was overwritten: re-read the credential and try again.")]
    VaultConflict,

    // The item was deleted from the vault (or is no longer ours to see). Stable
    // code `vault_conflict`: it is a change made by someone else.
    #[error("The password was changed after the rotation started. Nothing was changed: abort the rotation, or ask a person to look at the item.")]
    VaultPasswordChanged,

    #[error("The item no longer exists in the vault. Nothing was changed: re-read the credential (GET /v1/credentials?detail=true).")]
    VaultItemGone,

    #[error("The item was replaced in the vault while the approval was pending. Nothing was written: start the rotation again.")]
    VaultItemReplaced,

    #[error("The pending value of {0} is not the one this request names (the rotation was finished, or replaced, since). Nothing was written: read the credential again (GET /v1/credentials?detail=true) for its current rotation_id.")]
    RotationMismatch(String),

    // Config errors
    #[error("Configuration error: {0}")]
    Config(String),

    // Unlock mode errors — POST /v1/unlock called but mode is file-based
    #[error("Manual unlock endpoint is disabled in file unlock mode")]
    UnlockEndpointDisabled,

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Invalid JSON: {0}")]
    InvalidJson(String),

    // Internal errors
    #[error("Internal error: {0}")]
    Internal(String),
}

impl FerroError {
    /// The HTTP status code this error is returned with.
    pub fn status_code(&self) -> StatusCode {
        self.status_and_message().0
    }

    /// The stable code of the approval errors, which carry it in the response
    /// body next to the message (`None` for every other error).
    pub fn approval_code(&self) -> Option<&'static str> {
        match self {
            FerroError::ApprovalPending { .. } => Some("approval_pending"),
            FerroError::ApprovalDenied => Some("approval_denied"),
            FerroError::ApprovalLimitReached => Some("approval_limit_reached"),
            _ => None,
        }
    }

    /// The stable code of the errors of creating and rotating a credential
    /// (`None` for every other error).
    pub fn create_code(&self) -> Option<&'static str> {
        match self {
            FerroError::CredentialCreateDisabled => Some("credential_create_disabled"),
            FerroError::CredentialCreateOutOfScope(_) => Some("credential_create_out_of_scope"),
            FerroError::CredentialExists(_) => Some("credential_exists"),
            FerroError::ManagedCollectionUnavailable(_) => Some("managed_collection_unavailable"),
            FerroError::VaultWriteFailed => Some("vault_write_failed"),
            FerroError::VaultWriteUnknown => Some("vault_write_unknown"),
            FerroError::CredentialRotateOutOfScope(_) => Some("credential_rotate_out_of_scope"),
            FerroError::CredentialNotManaged(_) => Some("credential_not_managed"),
            FerroError::CredentialNotRotatable(_) => Some("credential_not_rotatable"),
            FerroError::RotationInProgress(_) => Some("rotation_in_progress"),
            FerroError::NoRotationPending(_) => Some("no_rotation_pending"),
            FerroError::VaultConflict
            | FerroError::VaultItemGone
            | FerroError::VaultItemReplaced
            | FerroError::VaultPasswordChanged => Some("vault_conflict"),
            FerroError::RotationMismatch(_) => Some("rotation_mismatch"),
            _ => None,
        }
    }

    fn status_and_message(&self) -> (StatusCode, String) {
        match self {
            FerroError::VaultLocked => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            FerroError::UnlockFailed(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            FerroError::CredentialNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            FerroError::VaultClient(_) => (
                StatusCode::BAD_GATEWAY,
                "Failed to communicate with vault".to_string(),
            ),
            FerroError::VaultUnavailable => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            FerroError::AmbiguousCredential(_) => (StatusCode::CONFLICT, self.to_string()),
            FerroError::CredentialHostNotAllowed { .. } => {
                (StatusCode::FORBIDDEN, self.to_string())
            }
            FerroError::TargetBlocked(_) => (StatusCode::FORBIDDEN, self.to_string()),
            FerroError::ResponseTooLarge(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            FerroError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            FerroError::AgentKeyNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            FerroError::CredentialOutOfScope(_) | FerroError::MethodNotAllowed(_) => {
                (StatusCode::FORBIDDEN, self.to_string())
            }
            FerroError::ForwardFailed(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            FerroError::InvalidTargetUrl(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            FerroError::UnknownPlaceholder(_)
            | FerroError::MalformedPlaceholder(_)
            | FerroError::UnknownSession(_) => (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()),
            FerroError::SessionHostNotAllowed { .. } => (StatusCode::FORBIDDEN, self.to_string()),
            FerroError::SessionsDisabled => (StatusCode::BAD_REQUEST, self.to_string()),
            FerroError::ApprovalPending { .. } | FerroError::ApprovalDenied => {
                (StatusCode::FORBIDDEN, self.to_string())
            }
            FerroError::ApprovalLimitReached => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            FerroError::ApprovalNotPending => (StatusCode::CONFLICT, self.to_string()),
            FerroError::GrantNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            FerroError::AmbiguousField { .. } => (StatusCode::CONFLICT, self.to_string()),
            FerroError::RepromptRequired(_) => (StatusCode::FORBIDDEN, self.to_string()),
            FerroError::CredentialCreateDisabled | FerroError::CredentialCreateOutOfScope(_) => {
                (StatusCode::FORBIDDEN, self.to_string())
            }
            FerroError::CredentialExists(_) => (StatusCode::CONFLICT, self.to_string()),
            FerroError::ManagedCollectionUnavailable(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, self.to_string())
            }
            FerroError::VaultWriteFailed | FerroError::VaultWriteUnknown => {
                (StatusCode::BAD_GATEWAY, self.to_string())
            }
            FerroError::CredentialRotateOutOfScope(_) | FerroError::CredentialNotManaged(_) => {
                (StatusCode::FORBIDDEN, self.to_string())
            }
            FerroError::CredentialNotRotatable(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, self.to_string())
            }
            FerroError::RotationInProgress(_)
            | FerroError::NoRotationPending(_)
            | FerroError::VaultConflict
            | FerroError::VaultItemGone
            | FerroError::VaultItemReplaced
            | FerroError::VaultPasswordChanged
            | FerroError::RotationMismatch(_) => (StatusCode::CONFLICT, self.to_string()),
            FerroError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            FerroError::UnlockEndpointDisabled => (StatusCode::NOT_FOUND, self.to_string()),
            FerroError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            FerroError::InvalidJson(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            FerroError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        }
    }
}

// Map FerroError to HTTP responses. Credential values are never included in
// error responses — only the error category and a safe message.
impl IntoResponse for FerroError {
    fn into_response(self) -> Response {
        let (status, message) = self.status_and_message();
        let mut body = json!({ "error": message });
        if let Some(code) = self.approval_code().or_else(|| self.create_code()) {
            body["code"] = json!(code);
        }
        if let FerroError::ManagedCollectionUnavailable(problem) = &self {
            body["reason"] = json!(problem.code());
        }
        if let FerroError::ApprovalPending { id } = &self {
            body["approval_id"] = json!(id);
        }
        (status, Json(body)).into_response()
    }
}

pub type FerroResult<T> = Result<T, FerroError>;
