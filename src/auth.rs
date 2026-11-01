use std::sync::Arc;
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;
use tonic::metadata::MetadataMap;

use crate::config::OAuthConfig;
use crate::error::AppError;
use crate::models::SpaceRecord;
use crate::store::Store;

pub const ADMIN_TOKEN_HEADER: &str = "x-admin-token";
pub const SPACE_TOKEN_HEADER: &str = "x-space-token";
pub const SPACE_ID_HEADER: &str = "x-space-id";
pub const AUTHORIZATION_HEADER: &str = "authorization";

pub fn extract_bearer_or_raw(value: &str) -> &str {
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value)
        .trim()
}

/// Extracts `space_id` from a native RRM API token (`rrm_sp_<space_id>_<uuid>`).
pub fn extract_space_id_from_native_token(token: &str) -> Option<&str> {
    let rest = token.strip_prefix("rrm_sp_")?;
    let last_underscore = rest.rfind('_')?;
    let space_id = &rest[..last_underscore];
    if !space_id.is_empty() {
        Some(space_id)
    } else {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClaims {
    pub sub: Option<String>,
    pub iss: Option<String>,
    pub aud: Option<Value>,
    pub exp: Option<u64>,
    pub space_id: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Clone)]
pub struct OAuthValidator {
    config: Arc<OAuthConfig>,
    jwks_cache: Arc<RwLock<Option<JwkSet>>>,
    http_client: reqwest::Client,
}

impl OAuthValidator {
    pub fn new(config: OAuthConfig) -> Self {
        Self {
            config: Arc::new(config),
            jwks_cache: Arc::new(RwLock::new(None)),
            http_client: reqwest::Client::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Validates an incoming JWT token against the configured OAuth / IdP settings.
    pub async fn validate_jwt(&self, token: &str) -> Result<OAuthClaims, AppError> {
        if !self.config.enabled {
            return Err(AppError::Unauthenticated(
                "OAuth/IdP authentication is disabled".to_string(),
            ));
        }

        let header = decode_header(token).map_err(|e| {
            AppError::Unauthenticated(format!("Invalid JWT header: {e}"))
        })?;

        let mut validation = Validation::new(header.alg);
        if let Some(ref iss) = self.config.issuer {
            validation.set_issuer(&[iss.as_str()]);
        }
        if let Some(ref aud) = self.config.audience {
            validation.set_audience(&[aud.as_str()]);
        } else {
            validation.validate_aud = false;
        }

        let decoding_key = self.resolve_decoding_key(&header).await?;
        let token_data = decode::<Value>(token, &decoding_key, &validation).map_err(|e| {
            AppError::Unauthenticated(format!("JWT validation failed: {e}"))
        })?;

        let claims_value = token_data.claims;
        let mut parsed: OAuthClaims = serde_json::from_value(claims_value.clone()).map_err(|e| {
            AppError::Unauthenticated(format!("Failed to parse JWT claims: {e}"))
        })?;

        // Extract custom space_id claim if not already populated
        if parsed.space_id.is_none()
            && let Some(space_val) = claims_value.get(&self.config.space_claim)
            && let Some(s) = space_val.as_str()
        {
            parsed.space_id = Some(s.to_string());
        }

        Ok(parsed)
    }

    async fn resolve_decoding_key(
        &self,
        header: &jsonwebtoken::Header,
    ) -> Result<DecodingKey, AppError> {
        // 1. Static secret or public key
        if let Some(ref key_str) = self.config.secret_or_public_key {
            let trimmed = key_str.trim();
            if trimmed.starts_with("-----BEGIN") {
                return DecodingKey::from_rsa_pem(trimmed.as_bytes())
                    .or_else(|_| DecodingKey::from_ed_pem(trimmed.as_bytes()))
                    .or_else(|_| DecodingKey::from_ec_pem(trimmed.as_bytes()))
                    .map_err(|e| AppError::Internal(format!("Invalid static PEM key: {e}")));
            } else {
                return Ok(DecodingKey::from_secret(trimmed.as_bytes()));
            }
        }

        // 2. Remote JWKS
        if let Some(ref jwks_url) = self.config.jwks_url {
            let kid = header.kid.as_deref().ok_or_else(|| {
                AppError::Unauthenticated("JWT missing 'kid' in header for JWKS lookup".to_string())
            })?;

            // Check cache
            {
                let cache = self.jwks_cache.read().await;
                if let Some(ref jwks) = *cache
                    && let Some(jwk) = jwks.find(kid)
                {
                    return DecodingKey::from_jwk(jwk).map_err(|e| {
                        AppError::Internal(format!("Failed to parse JWK: {e}"))
                    });
                }
            }

            // Fetch fresh JWKS
            let resp = self
                .http_client
                .get(jwks_url)
                .send()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to fetch JWKS from {jwks_url}: {e}")))?;
            let jwks: JwkSet = resp
                .json()
                .await
                .map_err(|e| AppError::Internal(format!("Failed to parse JWKS: {e}")))?;

            let jwk = jwks.find(kid).ok_or_else(|| {
                AppError::Unauthenticated(format!("Key '{kid}' not found in JWKS"))
            })?;
            let key = DecodingKey::from_jwk(jwk)
                .map_err(|e| AppError::Internal(format!("Failed to parse JWK: {e}")))?;

            *self.jwks_cache.write().await = Some(jwks);
            return Ok(key);
        }

        Err(AppError::Internal(
            "Neither jwks_url nor secret_or_public_key is configured for OAuth validation"
                .to_string(),
        ))
    }
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

