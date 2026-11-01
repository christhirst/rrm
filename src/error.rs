use thiserror::Error;
use tonic::Status;

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

impl From<surrealdb::Error> for AppError {
    fn from(err: surrealdb::Error) -> Self {
        Self::Database(err.to_string())
    }
}

impl From<AppError> for Status {
    fn from(err: AppError) -> Self {
        match err {
            AppError::NotFound(msg) => Self::not_found(msg),
            AppError::AlreadyExists(msg) => Self::already_exists(msg),
            AppError::InvalidArgument(msg) | AppError::CedarPolicy(msg) => {
                Self::invalid_argument(msg)
            }
            AppError::Unauthenticated(msg) => Self::unauthenticated(msg),
            AppError::PermissionDenied(msg) => Self::permission_denied(msg),
            AppError::Database(msg) | AppError::Internal(msg) => Self::internal(msg),
        }
    }
}
