use std::sync::Arc;

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use subtle::ConstantTimeEq;
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

/// Prefix of native RRM space API tokens (`rrm_sp_<space_id>_<uuid>`).
pub const NATIVE_TOKEN_PREFIX: &str = "rrm_sp_";

const HMAC_ALGORITHMS: &[Algorithm] = &[Algorithm::HS256, Algorithm::HS384, Algorithm::HS512];
const RSA_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];
const EC_ALGORITHMS: &[Algorithm] = &[Algorithm::ES256, Algorithm::ES384];
const ED_ALGORITHMS: &[Algorithm] = &[Algorithm::EdDSA];

/// Strips an optional (case-insensitive) `Bearer ` scheme prefix and surrounding whitespace.
pub fn extract_bearer_or_raw(value: &str) -> &str {
    let value = value.trim();
    match value.split_at_checked(7) {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("bearer ") => rest.trim(),
        _ => value,
    }
}

/// Returns the first non-empty bearer/raw token found under `headers`, in order.
///
/// `lookup` abstracts over tonic `MetadataMap` and axum `HeaderMap`.
pub fn first_token<'a>(
    lookup: impl Fn(&str) -> Option<&'a str>,
    headers: &[&str],
) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|name| lookup(name))
        .map(extract_bearer_or_raw)
}

/// Returns an ASCII metadata value as `&str`, if present and valid.
pub fn metadata_str<'a>(metadata: &'a MetadataMap, key: &str) -> Option<&'a str> {
    metadata.get(key).and_then(|v| v.to_str().ok())
}

/// Compares two secrets in constant time (with respect to their contents).
/// Empty candidates never match.
pub fn tokens_match(candidate: &str, expected: &str) -> bool {
    !candidate.is_empty() && bool::from(candidate.as_bytes().ct_eq(expected.as_bytes()))
}

/// Extracts `space_id` from a native RRM API token (`rrm_sp_<space_id>_<uuid>`).
pub fn extract_space_id_from_native_token(token: &str) -> Option<&str> {
    let rest = token.strip_prefix(NATIVE_TOKEN_PREFIX)?;
    let (space_id, _) = rest.rsplit_once('_')?;
    (!space_id.is_empty()).then_some(space_id)
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
    ///
    /// The accepted signature algorithms are derived from the configured key type,
    /// never from the (untrusted) token header alone.
    pub async fn validate_jwt(&self, token: &str) -> Result<OAuthClaims, AppError> {
        if !self.config.enabled {
            return Err(AppError::unauthenticated(
                "OAuth/IdP authentication is disabled",
            ));
        }

        let header = decode_header(token)
            .map_err(|e| AppError::unauthenticated(format!("Invalid JWT header: {e}")))?;

        let (decoding_key, allowed_algorithms) = self.resolve_decoding_key(&header).await?;
        if !allowed_algorithms.contains(&header.alg) {
            return Err(AppError::unauthenticated(format!(
                "JWT algorithm {:?} is not allowed for the configured key",
                header.alg
            )));
        }

        let mut validation = Validation::new(header.alg);
        validation.algorithms = allowed_algorithms.to_vec();
        if let Some(iss) = &self.config.issuer {
            validation.set_issuer(&[iss.as_str()]);
        }
        if let Some(aud) = &self.config.audience {
            validation.set_audience(&[aud.as_str()]);
        } else {
            validation.validate_aud = false;
        }

        let claims = decode::<Value>(token, &decoding_key, &validation)
            .map_err(|e| AppError::unauthenticated(format!("JWT validation failed: {e}")))?
            .claims;

        // Extract custom space_id claim before `claims` is consumed below.
        let custom_space_id = claims
            .get(&self.config.space_claim)
            .and_then(Value::as_str)
            .map(str::to_owned);

        let mut parsed: OAuthClaims = serde_json::from_value(claims)
            .map_err(|e| AppError::unauthenticated(format!("Failed to parse JWT claims: {e}")))?;
        if parsed.space_id.is_none() {
            parsed.space_id = custom_space_id;
        }

        Ok(parsed)
    }

    async fn resolve_decoding_key(
        &self,
        header: &Header,
    ) -> Result<(DecodingKey, &'static [Algorithm]), AppError> {
        // 1. Static secret or public key
        if let Some(key_str) = &self.config.secret_or_public_key {
            return static_decoding_key(key_str.trim());
        }

        // 2. Remote JWKS
        let Some(jwks_url) = &self.config.jwks_url else {
            return Err(AppError::internal(
                "Neither jwks_url nor secret_or_public_key is configured for OAuth validation",
            ));
        };

        let kid = header.kid.as_deref().ok_or_else(|| {
            AppError::unauthenticated("JWT missing 'kid' in header for JWKS lookup")
        })?;

        if let Some(jwks) = self.jwks_cache.read().await.as_ref()
            && let Some(jwk) = jwks.find(kid)
        {
            return jwk_decoding_key(jwk);
        }

        // Cache miss: fetch a fresh JWKS (handles key rotation).
        let jwks: JwkSet = self
            .http_client
            .get(jwks_url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| AppError::internal(format!("Failed to fetch JWKS from {jwks_url}: {e}")))?
            .json()
            .await
            .map_err(|e| AppError::internal(format!("Failed to parse JWKS: {e}")))?;

        let key = jwks
            .find(kid)
            .ok_or_else(|| AppError::unauthenticated(format!("Key '{kid}' not found in JWKS")))
            .and_then(jwk_decoding_key)?;

        *self.jwks_cache.write().await = Some(jwks);
        Ok(key)
    }
}

fn static_decoding_key(key: &str) -> Result<(DecodingKey, &'static [Algorithm]), AppError> {
    if !key.starts_with("-----BEGIN") {
        return Ok((DecodingKey::from_secret(key.as_bytes()), HMAC_ALGORITHMS));
    }
    let pem = key.as_bytes();
    DecodingKey::from_rsa_pem(pem)
        .map(|k| (k, RSA_ALGORITHMS))
        .or_else(|_| DecodingKey::from_ed_pem(pem).map(|k| (k, ED_ALGORITHMS)))
        .or_else(|_| DecodingKey::from_ec_pem(pem).map(|k| (k, EC_ALGORITHMS)))
        .map_err(|e| AppError::internal(format!("Invalid static PEM key: {e}")))
}

fn jwk_decoding_key(jwk: &Jwk) -> Result<(DecodingKey, &'static [Algorithm]), AppError> {
    let algorithms = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => RSA_ALGORITHMS,
        AlgorithmParameters::EllipticCurve(_) => EC_ALGORITHMS,
        AlgorithmParameters::OctetKeyPair(_) => ED_ALGORITHMS,
        AlgorithmParameters::OctetKey(_) => HMAC_ALGORITHMS,
    };
    let key = DecodingKey::from_jwk(jwk)
        .map_err(|e| AppError::internal(format!("Failed to parse JWK: {e}")))?;
    Ok((key, algorithms))
}

/// Verifies that the caller supplied a valid RRM Platform Admin token via
/// `x-admin-token` (or `authorization: Bearer <admin_token>`).
pub fn verify_admin(metadata: &MetadataMap, expected_admin_token: &str) -> Result<(), AppError> {
    let candidate = first_token(
        |k| metadata_str(metadata, k),
        &[ADMIN_TOKEN_HEADER, AUTHORIZATION_HEADER],
    );

    match candidate {
        Some(token) if tokens_match(token, expected_admin_token) => Ok(()),
        Some(_) => Err(AppError::permission_denied("Invalid admin token")),
        None => Err(AppError::unauthenticated(
            "Missing 'x-admin-token' metadata header",
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
        return Err(AppError::invalid("space_id cannot be empty"));
    }

    let space = store.get_space(space_id).await?;

    // Check if authenticated as platform admin via x-admin-token
    if first_token(|k| metadata_str(metadata, k), &[ADMIN_TOKEN_HEADER])
        .is_some_and(|token| tokens_match(token, expected_admin_token))
    {
        return Ok(space);
    }

    // Check x-space-token or authorization header
    let candidate = first_token(
        |k| metadata_str(metadata, k),
        &[SPACE_TOKEN_HEADER, AUTHORIZATION_HEADER],
    );

    match candidate {
        Some(token) if tokens_match(token, &space.api_token) => Ok(space),
        Some(_) => Err(AppError::permission_denied(format!(
            "Invalid token for space '{space_id}'"
        ))),
        None => Err(AppError::unauthenticated(
            "Missing 'x-space-token' or 'authorization' metadata header",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_bearer_or_raw_handles_scheme_case_and_whitespace() {
        assert_eq!(extract_bearer_or_raw("Bearer abc"), "abc");
        assert_eq!(extract_bearer_or_raw("bearer abc"), "abc");
        assert_eq!(extract_bearer_or_raw("BEARER  abc "), "abc");
        assert_eq!(extract_bearer_or_raw(" raw-token "), "raw-token");
        assert_eq!(extract_bearer_or_raw("short"), "short");
    }

    #[test]
    fn extract_space_id_from_native_token_parses_underscored_ids() {
        assert_eq!(
            extract_space_id_from_native_token("rrm_sp_billing_0123abcd"),
            Some("billing")
        );
        assert_eq!(
            extract_space_id_from_native_token("rrm_sp_my_space_0123abcd"),
            Some("my_space")
        );
        assert_eq!(extract_space_id_from_native_token("rrm_sp__0123abcd"), None);
        assert_eq!(
            extract_space_id_from_native_token("rrm_sp_nounderscore"),
            None
        );
        assert_eq!(extract_space_id_from_native_token("other_token"), None);
    }

    #[test]
    fn tokens_match_rejects_empty_and_mismatched_tokens() {
        assert!(tokens_match("secret", "secret"));
        assert!(!tokens_match("secret", "secreT"));
        assert!(!tokens_match("secret", "secret-longer"));
        assert!(!tokens_match("", ""));
    }
}
