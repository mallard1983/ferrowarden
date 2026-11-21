use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FerroError {
    // Vault / bw serve errors
    #[error("Vault is locked")]
    VaultLocked,

    #[error("Vault unlock failed: {0}")]
    UnlockFailed(String),

    #[error("Credential not found: {0}")]
    CredentialNotFound(String),

    #[error("Vault client error: {0}")]
    VaultClient(#[from] reqwest::Error),

    // Auth errors
    #[error("Missing or invalid agent API key")]
    Unauthorized,

    #[error("Agent key not found")]
    AgentKeyNotFound,

    // Proxy errors
    #[error("Forward request failed: {0}")]
    ForwardFailed(String),

    #[error("Invalid target URL: {0}")]
    InvalidTargetUrl(String),

    // Placeholder errors
    #[error("Placeholder references unknown credential: {0}")]
    UnknownPlaceholder(String),

    // Config errors
    #[error("Configuration error: {0}")]
    Config(String),

    // Unlock mode errors — POST /v1/unlock called but mode is file-based
    #[error("Manual unlock endpoint is disabled in file unlock mode")]
    UnlockEndpointDisabled,

    // Internal errors
    #[error("Internal error: {0}")]
    Internal(String),
}

// Map FerroError to HTTP responses. Credential values are never included in
// error responses — only the error category and a safe message.
impl IntoResponse for FerroError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            FerroError::VaultLocked => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            FerroError::UnlockFailed(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            FerroError::CredentialNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            FerroError::VaultClient(_) => (
                StatusCode::BAD_GATEWAY,
                "Failed to communicate with vault".to_string(),
            ),
            FerroError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            FerroError::AgentKeyNotFound => (StatusCode::UNAUTHORIZED, self.to_string()),
            FerroError::ForwardFailed(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            FerroError::InvalidTargetUrl(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            FerroError::UnknownPlaceholder(_) => (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()),
            FerroError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            FerroError::UnlockEndpointDisabled => (StatusCode::NOT_FOUND, self.to_string()),
            FerroError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

pub type FerroResult<T> = Result<T, FerroError>;
