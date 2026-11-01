use axum::http::StatusCode;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use tokio::net::TcpListener;
use tonic::transport::{Channel, Server};

use rrm::auth::OAuthValidator;
use rrm::authzen_grpc::AuthzenGrpcService;
use rrm::authzen_pb::{
    AccessEvaluationBatchRequest, EvaluationItem, EvaluationRequest,
    authorization_service_client::AuthorizationServiceClient,
    authorization_service_server::AuthorizationServiceServer,
};
use rrm::config::{OAuthConfig, SurrealDbConfig};
use rrm::http::{HttpAppState, create_http_router};
use rrm::store::Store;

const TEST_ADMIN_TOKEN: &str = "test-admin-secret-token";

#[allow(dead_code)]
struct TestContext {
    http_base_url: String,
    grpc_channel: Channel,
    store: Store,
    space_id: String,
    api_token: String,
}

async fn setup_test_server(oauth_config: OAuthConfig) -> TestContext {
    let store = Store::connect(&SurrealDbConfig {
        endpoint: "memory".to_string(),
        namespace: "test_authzen_ns".to_string(),
        database: "test_authzen_db".to_string(),
        username: None,
        password: None,
    })
    .await
    .expect("in-memory surrealdb should connect");

    // 1. Create a space
    let space_id = "test-space".to_string();
    let space = store
        .create_space(&space_id, "Test Space", "Space for AuthZEN testing")
        .await
        .expect("space creation should succeed");

    // 2. Add sample Cedar policies for ABAC and RBAC:
    // Policy 1: permit User to read Document if resource.classification != "top-secret"
    store
        .upsert_policy(
            &space_id,
            "policy-read-docs",
            "Permit read on Document unless top-secret",
            r#"permit(
                principal is User,
                action == Action::"read",
                resource is Document
            ) when {
                resource.classification != "top-secret"
            };"#,
        )
        .await
        .expect("policy creation should succeed");

    // Policy 2: permit User to delete Document if subject.role == "admin"
    store
        .upsert_policy(
            &space_id,
            "policy-delete-admin",
            "Permit delete only for admin role",
            r#"permit(
                principal is User,
                action == Action::"delete",
                resource is Document
            ) when {
                principal.role == "admin"
            };"#,
        )
        .await
        .expect("policy creation should succeed");

    // 3. Start HTTP Server on ephemeral port
    let http_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind http ephemeral port");
    let http_addr = http_listener.local_addr().expect("http local addr");
    let http_base_url = format!("http://{http_addr}");

    let oauth_validator = OAuthValidator::new(oauth_config);
    let http_state = HttpAppState {
        store: store.clone(),
        admin_token: TEST_ADMIN_TOKEN.to_string(),
        oauth_validator,
        default_base_url: http_base_url.clone(),
    };
    let http_router = create_http_router(http_state);

    tokio::spawn(async move {
        axum::serve(http_listener, http_router)
            .await
            .expect("axum serve failed");
    });

    // 4. Start gRPC Server on ephemeral port
    let grpc_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind grpc ephemeral port");
    let grpc_addr = grpc_listener.local_addr().expect("grpc local addr");

    let authzen_grpc = AuthzenGrpcService::new(store.clone(), TEST_ADMIN_TOKEN);
    tokio::spawn(async move {
        Server::builder()
            .add_service(AuthorizationServiceServer::new(authzen_grpc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(grpc_listener))
            .await
            .expect("grpc serve failed");
    });

    let grpc_channel = Channel::from_shared(format!("http://{grpc_addr}"))
        .expect("valid uri")
        .connect_lazy();

    TestContext {
        http_base_url,
        grpc_channel,
        store,
        space_id,
        api_token: space.api_token,
    }
}

#[tokio::test]
async fn test_authzen_discovery_endpoint() {
    let ctx = setup_test_server(OAuthConfig::default()).await;
    let client = reqwest::Client::new();

    // 1. Global discovery
    let resp = client
        .get(format!("{}/.well-known/authzen-configuration", ctx.http_base_url))
        .send()
        .await
        .expect("discovery request should succeed");

    let status = resp.status();
    let text = resp.text().await.expect("text");
    println!("Status: {status}, Body: {text}");
    assert_eq!(status, StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&text).expect("json body");
    assert!(body["policy_decision_point"].is_string());
    assert_eq!(
        body["access_evaluation_endpoint"],
        format!("{}/access/v1/evaluation", ctx.http_base_url)
    );
    assert_eq!(
        body["access_evaluations_endpoint"],
        format!("{}/access/v1/evaluations", ctx.http_base_url)
    );

    // 2. Space-scoped discovery
    let space_resp = client
        .get(format!("{}/spaces/{}/.well-known/authzen-configuration", ctx.http_base_url, ctx.space_id))
        .send()
        .await
        .expect("space discovery request should succeed");

    assert_eq!(space_resp.status(), StatusCode::OK);
    let space_body: serde_json::Value = space_resp.json().await.expect("json body");
    assert_eq!(
        space_body["policy_decision_point"],
        format!("{}/spaces/{}", ctx.http_base_url, ctx.space_id)
    );
    assert_eq!(
        space_body["access_evaluation_endpoint"],
        format!("{}/spaces/{}/access/v1/evaluation", ctx.http_base_url, ctx.space_id)
    );
}

#[tokio::test]
async fn test_authzen_single_evaluation_permit_and_deny() {
    let ctx = setup_test_server(OAuthConfig::default()).await;
    let client = reqwest::Client::new();

    // 1. Allowed request (read standard document)
    let permit_payload = json!({
        "subject": {
            "type": "User",
            "id": "alice"
        },
        "action": {
            "name": "read"
        },
        "resource": {
            "type": "Document",
            "id": "doc-public",
            "properties": {
                "classification": "public"
            }
        }
    });

    let resp = client
        .post(format!("{}/access/v1/evaluation", ctx.http_base_url))
        .header("Authorization", format!("Bearer {}", ctx.api_token))
        .json(&permit_payload)
        .send()
        .await
        .expect("evaluation request should succeed");

    let status = resp.status();
    let text = resp.text().await.expect("text");
    println!("Status: {status}, Body: {text}");
    assert_eq!(status, StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&text).expect("json body");
    assert_eq!(body["decision"], true, "Should allow public read");
    assert!(body["context"].is_object());

    // 2. Denied request: read top-secret document (policy condition fails)
    let deny_payload = json!({
        "subject": {
            "type": "User",
            "id": "alice"
        },
        "action": {
            "name": "read"
        },
        "resource": {
            "type": "Document",
            "id": "doc-secret",
            "properties": {
                "classification": "top-secret"
            }
        }
    });

    let deny_resp = client
        .post(format!("{}/access/v1/evaluation", ctx.http_base_url))
        .header("Authorization", format!("Bearer {}", ctx.api_token))
        .json(&deny_payload)
        .send()
        .await
        .expect("deny evaluation request should succeed");

    // Per AuthZEN spec: Authorization denial MUST return HTTP 200 with decision = false
    assert_eq!(deny_resp.status(), StatusCode::OK);
    let deny_body: serde_json::Value = deny_resp.json().await.expect("json body");
    assert_eq!(deny_body["decision"], false, "Should deny top-secret read");

    // 3. Dynamic Subject Properties (ABAC): delete with role == "admin" vs "viewer"
    let admin_delete_payload = json!({
        "subject": {
            "type": "User",
            "id": "bob",
            "properties": {
                "role": "admin"
            }
        },
        "action": {
            "name": "delete"
        },
        "resource": {
            "type": "Document",
            "id": "doc-101"
        }
    });

    let admin_resp = client
        .post(format!("{}/access/v1/evaluation", ctx.http_base_url))
        .header("Authorization", format!("Bearer {}", ctx.api_token))
        .json(&admin_delete_payload)
        .send()
        .await
        .expect("admin delete request should succeed");

    assert_eq!(admin_resp.status(), StatusCode::OK);
    let admin_body: serde_json::Value = admin_resp.json().await.expect("json body");
    assert_eq!(admin_body["decision"], true, "Admin role should be permitted to delete");

    let viewer_delete_payload = json!({
        "subject": {
            "type": "User",
            "id": "charlie",
            "properties": {
                "role": "viewer"
            }
        },
        "action": {
            "name": "delete"
        },
        "resource": {
            "type": "Document",
            "id": "doc-101"
        }
    });

    let viewer_resp = client
        .post(format!("{}/access/v1/evaluation", ctx.http_base_url))
        .header("Authorization", format!("Bearer {}", ctx.api_token))
        .json(&viewer_delete_payload)
        .send()
        .await
        .expect("viewer delete request should succeed");

    assert_eq!(viewer_resp.status(), StatusCode::OK);
    let viewer_body: serde_json::Value = viewer_resp.json().await.expect("json body");
    assert_eq!(viewer_body["decision"], false, "Viewer role must be denied delete");
}

#[tokio::test]
async fn test_authzen_batch_evaluations() {
    let ctx = setup_test_server(OAuthConfig::default()).await;
    let client = reqwest::Client::new();

    let batch_payload = json!({
        "subject": {
            "type": "User",
            "id": "alice"
        },
        "resource": {
            "type": "Document"
        },
        "evaluations": [
            {
                "id": "eval-read-public",
                "action": { "name": "read" },
                "resource": {
                    "type": "Document",
                    "id": "doc-1",
                    "properties": { "classification": "public" }
                }
            },
            {
                "id": "eval-read-secret",
                "action": { "name": "read" },
                "resource": {
                    "type": "Document",
                    "id": "doc-2",
                    "properties": { "classification": "top-secret" }
                }
            },
            {
                "id": "eval-delete-nonadmin",
                "action": { "name": "delete" },
                "resource": { "type": "Document", "id": "doc-3" }
            }
        ]
    });

    let resp = client
        .post(format!("{}/access/v1/evaluations", ctx.http_base_url))
        .header("Authorization", format!("Bearer {}", ctx.api_token))
        .json(&batch_payload)
        .send()
        .await
        .expect("batch request should succeed");

    let status = resp.status();
    let text = resp.text().await.expect("text");
    println!("Status: {status}, Body: {text}");
    assert_eq!(status, StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&text).expect("json body");

    let evals = body["evaluations"].as_array().expect("evaluations array");
    assert_eq!(evals.len(), 3);

    // 1st: read public -> true
    assert_eq!(evals[0]["id"], "eval-read-public");
    assert_eq!(evals[0]["decision"], true);

    // 2nd: read top-secret -> false
    assert_eq!(evals[1]["id"], "eval-read-secret");
    assert_eq!(evals[1]["decision"], false);

    // 3rd: delete without admin role -> false
    assert_eq!(evals[2]["id"], "eval-delete-nonadmin");
    assert_eq!(evals[2]["decision"], false);
}

#[tokio::test]
async fn test_authzen_authentication_unauthorized() {
    let ctx = setup_test_server(OAuthConfig::default()).await;
    let client = reqwest::Client::new();

    let payload = json!({
        "subject": { "type": "User", "id": "alice" },
        "action": { "name": "read" },
        "resource": { "type": "Document", "id": "doc-1" }
    });

    // 1. Missing Authorization header
    let resp = client
        .post(format!("{}/access/v1/evaluation", ctx.http_base_url))
        .json(&payload)
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Invalid Token
    let resp_invalid = client
        .post(format!("{}/access/v1/evaluation", ctx.http_base_url))
        .header("Authorization", "Bearer invalid-token-xyz")
        .json(&payload)
        .send()
        .await
        .expect("send");

    assert_eq!(resp_invalid.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_authzen_oauth_jwt_authentication() {
    let jwt_secret = "my-super-secret-jwt-key-for-testing-12345";
    let oauth_config = OAuthConfig {
        enabled: true,
        issuer: Some("https://idp.example.com".to_string()),
        jwks_url: None,
        audience: Some("rrm-service".to_string()),
        space_claim: "space_id".to_string(),
        secret_or_public_key: Some(jwt_secret.to_string()),
    };

    let ctx = setup_test_server(oauth_config).await;
    let client = reqwest::Client::new();

    // 1. Generate a valid OAuth JWT token pointing to ctx.space_id
    #[derive(serde::Serialize)]
    struct TestClaims {
        sub: String,
        iss: String,
        aud: String,
        exp: u64,
        space_id: String,
    }

    let claims = TestClaims {
        sub: "oauth-user-123".to_string(),
        iss: "https://idp.example.com".to_string(),
        aud: "rrm-service".to_string(),
        exp: 2000000000,
        space_id: ctx.space_id.clone(),
    };

    let jwt_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .expect("jwt encode should succeed");

    let payload = json!({
        "subject": { "type": "User", "id": "alice" },
        "action": { "name": "read" },
        "resource": {
            "type": "Document",
            "id": "doc-public",
            "properties": { "classification": "public" }
        }
    });

    // 2. Query with OAuth JWT token
    let resp = client
        .post(format!("{}/access/v1/evaluation", ctx.http_base_url))
        .header("Authorization", format!("Bearer {jwt_token}"))
        .json(&payload)
        .send()
        .await
        .expect("send");

    let status = resp.status();
    let text = resp.text().await.expect("text");
    println!("Status: {status}, Body: {text}");
    assert_eq!(status, StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&text).expect("json body");
    assert_eq!(body["decision"], true, "Valid OAuth JWT should authenticate successfully");

    // 3. Fallback: native space token STILL works even when OAuth is enabled!
    let fallback_resp = client
        .post(format!("{}/access/v1/evaluation", ctx.http_base_url))
        .header("Authorization", format!("Bearer {}", ctx.api_token))
        .json(&payload)
        .send()
        .await
        .expect("send");

    assert_eq!(fallback_resp.status(), StatusCode::OK);
    let fallback_body: serde_json::Value = fallback_resp.json().await.expect("json body");
    assert_eq!(fallback_body["decision"], true, "Native token should still work seamlessly");
}

#[tokio::test]
async fn test_authzen_grpc_service() {
    let ctx = setup_test_server(OAuthConfig::default()).await;
    let mut grpc_client = AuthorizationServiceClient::new(ctx.grpc_channel);

    // 1. Single evaluation over gRPC
    let mut req = tonic::Request::new(EvaluationRequest {
        space_id: ctx.space_id.clone(),
        subject: Some(rrm::authzen_pb::Subject {
            r#type: "User".to_string(),
            id: "alice".to_string(),
            properties: None,
        }),
        action: Some(rrm::authzen_pb::Action {
            name: "read".to_string(),
            properties: None,
        }),
        resource: Some(rrm::authzen_pb::Resource {
            r#type: "Document".to_string(),
            id: "doc-1".to_string(),
            properties: Some(rrm::authzen_grpc::json_to_prost_struct(&json!({
                "classification": "public"
            }))),
        }),
        context: None,
    });

    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", ctx.api_token).parse().unwrap(),
    );

    let resp = grpc_client
        .access_evaluation(req)
        .await
        .expect("grpc evaluation should succeed");

    let val = resp.into_inner();
    assert!(val.decision);

    // 2. Batch evaluation over gRPC
    let mut batch_req = tonic::Request::new(AccessEvaluationBatchRequest {
        space_id: ctx.space_id.clone(),
        subject: Some(rrm::authzen_pb::Subject {
            r#type: "User".to_string(),
            id: "alice".to_string(),
            properties: None,
        }),
        action: None,
        resource: Some(rrm::authzen_pb::Resource {
            r#type: "Document".to_string(),
            id: "default-doc".to_string(),
            properties: None,
        }),
        context: None,
        evaluations: vec![
            EvaluationItem {
                id: "item-1".to_string(),
                subject: None,
                action: Some(rrm::authzen_pb::Action {
                    name: "read".to_string(),
                    properties: None,
                }),
                resource: Some(rrm::authzen_pb::Resource {
                    r#type: "Document".to_string(),
                    id: "doc-1".to_string(),
                    properties: Some(rrm::authzen_grpc::json_to_prost_struct(&json!({
                        "classification": "public"
                    }))),
                }),
                context: None,
            },
            EvaluationItem {
                id: "item-2".to_string(),
                subject: None,
                action: Some(rrm::authzen_pb::Action {
                    name: "read".to_string(),
                    properties: None,
                }),
                resource: Some(rrm::authzen_pb::Resource {
                    r#type: "Document".to_string(),
                    id: "doc-2".to_string(),
                    properties: Some(rrm::authzen_grpc::json_to_prost_struct(&json!({
                        "classification": "top-secret"
                    }))),
                }),
                context: None,
            },
        ],
    });

    batch_req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", ctx.api_token).parse().unwrap(),
    );

    let batch_resp = grpc_client
        .access_evaluation_batch(batch_req)
        .await
        .expect("grpc batch evaluation should succeed");

    let batch_val = batch_resp.into_inner();
    assert_eq!(batch_val.evaluations.len(), 2);
    assert_eq!(batch_val.evaluations[0].id, "item-1");
    assert!(batch_val.evaluations[0].decision);
    assert_eq!(batch_val.evaluations[1].id, "item-2");
    assert!(!batch_val.evaluations[1].decision);
}
