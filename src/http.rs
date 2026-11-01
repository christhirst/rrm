use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};

use crate::auth::{
    ADMIN_TOKEN_HEADER, AUTHORIZATION_HEADER, OAuthValidator, SPACE_ID_HEADER, SPACE_TOKEN_HEADER,
    extract_bearer_or_raw, extract_space_id_from_native_token,
};
use crate::authzen::{
    AuthzenBatchRequest, AuthzenBatchResponse, AuthzenDiscovery, AuthzenEvaluationRequest,
    AuthzenEvaluationResponse, evaluate_authzen, evaluate_authzen_batch,
};
use crate::error::AppError;
use crate::store::Store;

#[derive(Clone)]
pub struct HttpAppState {
    pub store: Store,
    pub admin_token: String,
    pub oauth_validator: OAuthValidator,
    pub default_base_url: String,
}

pub fn create_http_router(state: HttpAppState) -> Router {
    Router::new()
        // Discovery endpoints (OpenID RFC 8615 & AuthZEN metadata)
        .route("/.well-known/authzen-configuration", get(get_global_discovery))
        .route("/spaces/{space_id}/.well-known/authzen-configuration", get(get_space_discovery))
        // Single Access Evaluation
        .route("/access/v1/evaluation", post(post_single_evaluation))
        .route("/spaces/{space_id}/access/v1/evaluation", post(post_space_single_evaluation))
        // Batch Access Evaluations
        .route("/access/v1/evaluations", post(post_batch_evaluations))
        .route("/spaces/{space_id}/access/v1/evaluations", post(post_space_batch_evaluations))
        .with_state(Arc::new(state))
}

// ============================================================================
// Discovery Handlers
// ============================================================================

async fn get_global_discovery(
    State(state): State<Arc<HttpAppState>>,
    headers: HeaderMap,
) -> Json<AuthzenDiscovery> {
    let base = resolve_base_url(&headers, &state.default_base_url);
    Json(AuthzenDiscovery {
        policy_decision_point: base.clone(),
        access_evaluation_endpoint: format!("{base}/access/v1/evaluation"),
        access_evaluations_endpoint: format!("{base}/access/v1/evaluations"),
    })
}

async fn get_space_discovery(
    State(state): State<Arc<HttpAppState>>,
    Path(space_id): Path<String>,
    headers: HeaderMap,
) -> Json<AuthzenDiscovery> {
    let base = resolve_base_url(&headers, &state.default_base_url);
    Json(AuthzenDiscovery {
        policy_decision_point: format!("{base}/spaces/{space_id}"),
        access_evaluation_endpoint: format!("{base}/spaces/{space_id}/access/v1/evaluation"),
        access_evaluations_endpoint: format!("{base}/spaces/{space_id}/access/v1/evaluations"),
    })
}

// ============================================================================
// Evaluation Handlers
// ============================================================================

async fn post_single_evaluation(
    State(state): State<Arc<HttpAppState>>,
    headers: HeaderMap,
    Json(req): Json<AuthzenEvaluationRequest>,
) -> Result<Json<AuthzenEvaluationResponse>, (StatusCode, Json<Value>)> {
    let space_id = authenticate_and_resolve_space(
        &state,
        &headers,
        None,
        req.space_id.as_deref(),
    )
    .await?;

    let outcome = evaluate_authzen(
        &state.store,
        &space_id,
        &req.subject,
        &req.action,
        &req.resource,
        req.context.as_ref(),
    )
    .await
    .map_err(app_error_to_http_response)?;

    Ok(Json(outcome))
}

async fn post_space_single_evaluation(
    State(state): State<Arc<HttpAppState>>,
    Path(space_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<AuthzenEvaluationRequest>,
) -> Result<Json<AuthzenEvaluationResponse>, (StatusCode, Json<Value>)> {
    let space_id = authenticate_and_resolve_space(
        &state,
        &headers,
        Some(&space_id),
        req.space_id.as_deref(),
    )
    .await?;

    let outcome = evaluate_authzen(
        &state.store,
        &space_id,
        &req.subject,
        &req.action,
        &req.resource,
        req.context.as_ref(),
    )
    .await
    .map_err(app_error_to_http_response)?;

    Ok(Json(outcome))
}

async fn post_batch_evaluations(
    State(state): State<Arc<HttpAppState>>,
    headers: HeaderMap,
    Json(req): Json<AuthzenBatchRequest>,
) -> Result<Json<AuthzenBatchResponse>, (StatusCode, Json<Value>)> {
    let space_id = authenticate_and_resolve_space(
        &state,
        &headers,
        None,
        req.space_id.as_deref(),
    )
    .await?;

    let outcome = evaluate_authzen_batch(&state.store, &space_id, &req)
        .await
        .map_err(app_error_to_http_response)?;

    Ok(Json(outcome))
}

async fn post_space_batch_evaluations(
    State(state): State<Arc<HttpAppState>>,
    Path(space_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<AuthzenBatchRequest>,
) -> Result<Json<AuthzenBatchResponse>, (StatusCode, Json<Value>)> {
    let space_id = authenticate_and_resolve_space(
        &state,
        &headers,
        Some(&space_id),
        req.space_id.as_deref(),
    )
    .await?;

    let outcome = evaluate_authzen_batch(&state.store, &space_id, &req)
        .await
        .map_err(app_error_to_http_response)?;

    Ok(Json(outcome))
}

// ============================================================================
// Authentication & Space Resolution Helpers
// ============================================================================

async fn authenticate_and_resolve_space(
    state: &HttpAppState,
    headers: &HeaderMap,
    path_space_id: Option<&str>,
    payload_space_id: Option<&str>,
) -> Result<String, (StatusCode, Json<Value>)> {
    // 1. Extract token from Authorization / x-space-token / x-admin-token
    let token = headers
        .get(AUTHORIZATION_HEADER)
        .or_else(|| headers.get(SPACE_TOKEN_HEADER))
        .or_else(|| headers.get(ADMIN_TOKEN_HEADER))
        .and_then(|v| v.to_str().ok())
        .map(extract_bearer_or_raw);

    let Some(raw_token) = token else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Missing Authorization header or space token" })),
        ));
    };

    if raw_token.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Token cannot be empty" })),
        ));
    }

    // 2. Check Platform Admin Token
    if raw_token == state.admin_token {
        let space_id = path_space_id
            .or(payload_space_id)
            .or_else(|| {
                headers
                    .get(SPACE_ID_HEADER)
                    .and_then(|v| v.to_str().ok())
            });

        let Some(sid) = space_id else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Admin authenticated, but no space_id provided in path, header, or payload" })),
            ));
        };

        state
            .store
            .get_space(sid)
            .await
            .map_err(app_error_to_http_response)?;

        return Ok(sid.to_string());
    }

    // 3. Check Native RRM Space API Token (`rrm_sp_<space_id>_...`)
    if let Some(inferred_space_id) = extract_space_id_from_native_token(raw_token) {
        let target_space = path_space_id
            .or(payload_space_id)
            .unwrap_or(inferred_space_id);

        let space = state
            .store
            .get_space(target_space)
            .await
            .map_err(app_error_to_http_response)?;

        if space.api_token == raw_token {
            return Ok(target_space.to_string());
        } else {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": format!("Invalid API token for space '{target_space}'") })),
            ));
        }
    }

    // 4. Check Optional OAuth 2.0 / OIDC JWT Token (if enabled)
    if state.oauth_validator.is_enabled() {
        match state.oauth_validator.validate_jwt(raw_token).await {
            Ok(claims) => {
                let target_space = path_space_id
                    .or(payload_space_id)
                    .or(claims.space_id.as_deref())
                    .or_else(|| {
                        headers
                            .get(SPACE_ID_HEADER)
                            .and_then(|v| v.to_str().ok())
                    });

                let Some(sid) = target_space else {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "Valid OAuth JWT, but no space_id identified in claims, path, or header" })),
                    ));
                };

                state
                    .store
                    .get_space(sid)
                    .await
                    .map_err(app_error_to_http_response)?;

                return Ok(sid.to_string());
            }
            Err(e) => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": format!("OAuth JWT validation failed: {e}") })),
                ));
            }
        }
    }

    // 5. If we have a path or payload space_id, check if raw_token directly matches its api_token
    if let Some(target_space) = path_space_id.or(payload_space_id)
        && let Ok(space) = state.store.get_space(target_space).await
        && space.api_token == raw_token
    {
        return Ok(target_space.to_string());
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "Invalid or unrecognized authorization token" })),
    ))
}

fn resolve_base_url(headers: &HeaderMap, default_base: &str) -> String {
    if let Some(host) = headers.get("host").and_then(|v| v.to_str().ok()) {
        let scheme = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("http");
        format!("{scheme}://{host}")
    } else {
        default_base.to_string()
    }
}

fn app_error_to_http_response(err: AppError) -> (StatusCode, Json<Value>) {
    let (status, msg) = match err {
        AppError::InvalidArgument(m) => (StatusCode::BAD_REQUEST, m),
        AppError::Unauthenticated(m) => (StatusCode::UNAUTHORIZED, m),
        AppError::PermissionDenied(m) => (StatusCode::FORBIDDEN, m),
        AppError::NotFound(m) => (StatusCode::NOT_FOUND, m),
        AppError::AlreadyExists(m) => (StatusCode::CONFLICT, m),
        AppError::CedarPolicy(m) => (StatusCode::UNPROCESSABLE_ENTITY, m),
        AppError::Database(m) | AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
    };
    (status, Json(json!({ "error": msg })))
}
