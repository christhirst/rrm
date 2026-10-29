use tonic::metadata::MetadataMap;

use crate::error::AppError;
use crate::models::SpaceRecord;
use crate::store::Store;

pub const ADMIN_TOKEN_HEADER: &str = "x-admin-token";
pub const SPACE_TOKEN_HEADER: &str = "x-space-token";
pub const AUTHORIZATION_HEADER: &str = "authorization";

fn extract_bearer_or_raw(value: &str) -> &str {
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value)
        .trim()
}

/// Verifies that the caller supplied a valid RRM Platform Admin token via
/// `x-admin-token` (or `authorization: Bearer <admin_token>`).
pub fn verify_admin(metadata: &MetadataMap, expected_admin_token: &str) -> Result<(), AppError> {
    let candidate = metadata
        .get(ADMIN_TOKEN_HEADER)
        .or_else(|| metadata.get(AUTHORIZATION_HEADER))
        .and_then(|v| v.to_str().ok())
        .map(extract_bearer_or_raw);

    match candidate {
        Some(token) if !token.is_empty() && token == expected_admin_token => Ok(()),
        Some(_) => Err(AppError::PermissionDenied(
            "Invalid admin token".to_string(),
        )),
        None => Err(AppError::Unauthenticated(
            "Missing 'x-admin-token' metadata header".to_string(),
        )),
    }
}

/// Verifies that the requested space exists and that the caller supplied a valid
/// space API token (`x-space-token` or `authorization: Bearer <space_token>`) for
/// that space, or the platform `x-admin-token`.
pub async fn verify_space_access(
    metadata: &MetadataMap,
    store: &Store,
    expected_admin_token: &str,
    space_id: &str,
) -> Result<SpaceRecord, AppError> {
    if space_id.trim().is_empty() {
        return Err(AppError::InvalidArgument(
            "space_id cannot be empty".to_string(),
        ));
    }

    let space = store.get_space(space_id).await?;

    // Check if authenticated as platform admin via x-admin-token
    if let Some(admin_val) = metadata
        .get(ADMIN_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        && extract_bearer_or_raw(admin_val) == expected_admin_token
    {
        return Ok(space);
    }

    // Check x-space-token or authorization header
    let candidate = metadata
        .get(SPACE_TOKEN_HEADER)
        .or_else(|| metadata.get(AUTHORIZATION_HEADER))
        .and_then(|v| v.to_str().ok())
        .map(extract_bearer_or_raw);

    match candidate {
        Some(token) if !token.is_empty() && token == space.api_token => Ok(space),
        Some(_) => Err(AppError::PermissionDenied(format!(
            "Invalid token for space '{space_id}'"
        ))),
        None => Err(AppError::Unauthenticated(
            "Missing 'x-space-token' or 'authorization' metadata header".to_string(),
        )),
    }
}
