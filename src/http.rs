use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};

use crate::auth::{
    ADMIN_TOKEN_HEADER, AUTHORIZATION_HEADER, OAuthValidator, SPACE_ID_HEADER, SPACE_TOKEN_HEADER,
    extract_space_id_from_native_token, first_token, tokens_match,
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
    pub admin_token: Arc<str>,
    pub oauth_validator: OAuthValidator,
    pub default_base_url: String,
}

pub fn create_http_router(state: HttpAppState) -> Router {
    Router::new()
        // Discovery endpoints (OpenID RFC 8615 & AuthZEN metadata)
        .route(
            "/.well-known/authzen-configuration",
            get(get_global_discovery),
        )
        .route(
            "/spaces/{space_id}/.well-known/authzen-configuration",
            get(get_space_discovery),
        )
        // Single Access Evaluation
        .route("/access/v1/evaluation", post(post_single_evaluation))
        .route(
            "/spaces/{space_id}/access/v1/evaluation",
            post(post_space_single_evaluation),
        )
        // Batch Access Evaluations
        .route("/access/v1/evaluations", post(post_batch_evaluations))
        .route(
            "/spaces/{space_id}/access/v1/evaluations",
            post(post_space_batch_evaluations),
        )
        .with_state(Arc::new(state))
}

// ============================================================================
// Discovery Handlers
// ============================================================================

fn make_discovery(base: &str, space_id: Option<&str>) -> AuthzenDiscovery {
    match space_id {
        Some(sid) => AuthzenDiscovery {
            policy_decision_point: format!("{base}/spaces/{sid}"),
            access_evaluation_endpoint: format!("{base}/spaces/{sid}/access/v1/evaluation"),
            access_evaluations_endpoint: format!("{base}/spaces/{sid}/access/v1/evaluations"),
        },
        None => AuthzenDiscovery {
            policy_decision_point: base.to_string(),
            access_evaluation_endpoint: format!("{base}/access/v1/evaluation"),
            access_evaluations_endpoint: format!("{base}/access/v1/evaluations"),
        },
    }
}

async fn get_global_discovery(
    State(state): State<Arc<HttpAppState>>,
    headers: HeaderMap,
) -> Json<AuthzenDiscovery> {
    let base = resolve_base_url(&headers, &state.default_base_url);
    Json(make_discovery(&base, None))
}

async fn get_space_discovery(
    State(state): State<Arc<HttpAppState>>,
    Path(space_id): Path<String>,
    headers: HeaderMap,
) -> Json<AuthzenDiscovery> {
    let base = resolve_base_url(&headers, &state.default_base_url);
    Json(make_discovery(&base, Some(&space_id)))
}

// ============================================================================
// Evaluation Handlers
// ============================================================================

async fn handle_single_evaluation(
    state: &HttpAppState,
    headers: &HeaderMap,
    path_space_id: Option<&str>,
    req: AuthzenEvaluationRequest,
) -> Result<Json<AuthzenEvaluationResponse>, AppError> {
    let space_id =
        authenticate_and_resolve_space(state, headers, path_space_id, req.space_id.as_deref())
            .await?;

    let outcome = evaluate_authzen(
        &state.store,
        &space_id,
        &req.subject,
        &req.action,
        &req.resource,
        req.context.as_ref(),
    )
    .await?;

    Ok(Json(outcome))
}

async fn post_single_evaluation(
    State(state): State<Arc<HttpAppState>>,
    headers: HeaderMap,
    Json(req): Json<AuthzenEvaluationRequest>,
) -> Result<Json<AuthzenEvaluationResponse>, AppError> {
    handle_single_evaluation(&state, &headers, None, req).await
}

async fn post_space_single_evaluation(
    State(state): State<Arc<HttpAppState>>,
    Path(space_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<AuthzenEvaluationRequest>,
) -> Result<Json<AuthzenEvaluationResponse>, AppError> {
    handle_single_evaluation(&state, &headers, Some(&space_id), req).await
}

async fn handle_batch_evaluations(
    state: &HttpAppState,
    headers: &HeaderMap,
    path_space_id: Option<&str>,
    req: AuthzenBatchRequest,
) -> Result<Json<AuthzenBatchResponse>, AppError> {
    let space_id =
        authenticate_and_resolve_space(state, headers, path_space_id, req.space_id.as_deref())
            .await?;

    let outcome = evaluate_authzen_batch(&state.store, &space_id, &req).await?;

    Ok(Json(outcome))
}

async fn post_batch_evaluations(
    State(state): State<Arc<HttpAppState>>,
    headers: HeaderMap,
    Json(req): Json<AuthzenBatchRequest>,
) -> Result<Json<AuthzenBatchResponse>, AppError> {
    handle_batch_evaluations(&state, &headers, None, req).await
}

async fn post_space_batch_evaluations(
    State(state): State<Arc<HttpAppState>>,
    Path(space_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<AuthzenBatchRequest>,
) -> Result<Json<AuthzenBatchResponse>, AppError> {
    handle_batch_evaluations(&state, &headers, Some(&space_id), req).await
}

// ============================================================================
// Authentication & Space Resolution Helpers
// ============================================================================

async fn authenticate_and_resolve_space(
    state: &HttpAppState,
    headers: &HeaderMap,
    path_space_id: Option<&str>,
    payload_space_id: Option<&str>,
) -> Result<String, AppError> {
    let token = first_token(
        |k| headers.get(k).and_then(|v| v.to_str().ok()),
        &[AUTHORIZATION_HEADER, SPACE_TOKEN_HEADER, ADMIN_TOKEN_HEADER],
    );

    let Some(raw_token) = token else {
        return Err(AppError::unauthenticated(
            "Missing Authorization header or space token",
        ));
    };

    if raw_token.is_empty() {
        return Err(AppError::unauthenticated("Token cannot be empty"));
    }

    // 1. Check Platform Admin Token
    if tokens_match(raw_token, &state.admin_token) {
        let space_id = path_space_id
            .or(payload_space_id)
            .or_else(|| headers.get(SPACE_ID_HEADER).and_then(|v| v.to_str().ok()));

        let Some(sid) = space_id else {
            return Err(AppError::invalid(
                "Admin authenticated, but no space_id provided in path, header, or payload",
            ));
        };

        state.store.get_space(sid).await?;
        return Ok(sid.to_string());
    }

    // 2. Check Native RRM Space API Token (`rrm_sp_<space_id>_...`)
    if let Some(inferred_space_id) = extract_space_id_from_native_token(raw_token) {
        let target_space = path_space_id
            .or(payload_space_id)
            .unwrap_or(inferred_space_id);

        let space = state.store.get_space(target_space).await?;
        if tokens_match(raw_token, &space.api_token) {
            return Ok(target_space.to_string());
        }
        return Err(AppError::permission_denied(format!(
            "Invalid API token for space '{target_space}'"
        )));
    }

    // 3. Check Optional OAuth 2.0 / OIDC JWT Token (if enabled)
    if state.oauth_validator.is_enabled() {
        let claims = state.oauth_validator.validate_jwt(raw_token).await?;
        let target_space = path_space_id
            .or(payload_space_id)
            .or(claims.space_id.as_deref())
            .or_else(|| headers.get(SPACE_ID_HEADER).and_then(|v| v.to_str().ok()));

        let Some(sid) = target_space else {
            return Err(AppError::invalid(
                "Valid OAuth JWT, but no space_id identified in claims, path, or header",
            ));
        };

        state.store.get_space(sid).await?;
        return Ok(sid.to_string());
    }

    Err(AppError::unauthenticated(
        "Invalid or unrecognized authorization token",
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
