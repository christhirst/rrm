use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;
use tonic::Status;

/// Message returned to clients for server-side failures; details are logged instead.
const INTERNAL_ERROR_MESSAGE: &str = "Internal server error";

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Resource already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Unauthenticated: {0}")]
    Unauthenticated(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Cedar policy error: {0}")]
    CedarPolicy(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl AppError {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::InvalidArgument(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn unauthenticated(msg: impl Into<String>) -> Self {
        Self::Unauthenticated(msg.into())
    }

    pub fn permission_denied(msg: impl Into<String>) -> Self {
        Self::PermissionDenied(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Returns the client-facing message. Server-side failures (database / internal)
    /// are logged and replaced with a generic message so internals do not leak.
    fn into_public_message(self) -> String {
        match self {
            Self::NotFound(m)
            | Self::AlreadyExists(m)
            | Self::InvalidArgument(m)
            | Self::Unauthenticated(m)
            | Self::PermissionDenied(m)
            | Self::CedarPolicy(m) => m,
            Self::Database(m) | Self::Internal(m) => {
                tracing::error!(error = %m, "request failed with server error");
                INTERNAL_ERROR_MESSAGE.to_string()
            }
        }
    }
}

impl From<surrealdb::Error> for AppError {
    fn from(err: surrealdb::Error) -> Self {
        Self::Database(err.to_string())
    }
}

impl From<AppError> for Status {
    fn from(err: AppError) -> Self {
        let code = match &err {
            AppError::NotFound(_) => tonic::Code::NotFound,
            AppError::AlreadyExists(_) => tonic::Code::AlreadyExists,
            AppError::InvalidArgument(_) | AppError::CedarPolicy(_) => tonic::Code::InvalidArgument,
            AppError::Unauthenticated(_) => tonic::Code::Unauthenticated,
            AppError::PermissionDenied(_) => tonic::Code::PermissionDenied,
            AppError::Database(_) | AppError::Internal(_) => tonic::Code::Internal,
        };
        Self::new(code, err.into_public_message())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::InvalidArgument(_) => StatusCode::BAD_REQUEST,
            Self::Unauthenticated(_) => StatusCode::UNAUTHORIZED,
            Self::PermissionDenied(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::AlreadyExists(_) => StatusCode::CONFLICT,
            Self::CedarPolicy(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Database(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(json!({ "error": self.into_public_message() }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_do_not_leak_details_to_clients() {
        let status = Status::from(AppError::Database("connection string secret".into()));
        assert_eq!(status.code(), tonic::Code::Internal);
        assert_eq!(status.message(), INTERNAL_ERROR_MESSAGE);
    }

    #[test]
    fn client_errors_keep_their_message_and_code() {
        let status = Status::from(AppError::invalid("bad input"));
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert_eq!(status.message(), "bad input");

        let resp = AppError::not_found("nope").into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
