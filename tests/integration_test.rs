use std::net::SocketAddr;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Server};

use rrm::config::SurrealDbConfig;
use rrm::grpc::RrmService;
use rrm::pb::{
    AuthDecision, AuthorizeRequest, CedarEntityRecord, CreateSpaceRequest, DeletePolicyRequest,
    DeleteSpaceRequest, DeleteUserRequest, EntityUidMsg, GetPolicyRequest, GetUserRequest,
    ListEntitiesRequest, ListPoliciesRequest, ListSpacesRequest, ListUsersRequest, PolicyInput,
    UploadPolicySetRequest, UpsertEntityRequest, UpsertPolicyRequest, UpsertUserRequest,
    admin_service_client::AdminServiceClient, admin_service_server::AdminServiceServer,
    authorization_service_client::AuthorizationServiceClient,
    authorization_service_server::AuthorizationServiceServer,
    entity_service_client::EntityServiceClient, entity_service_server::EntityServiceServer,
    policy_service_client::PolicyServiceClient, policy_service_server::PolicyServiceServer,
};
use rrm::store::Store;

const TEST_ADMIN_TOKEN: &str = "super-secret-admin-key";

async fn start_test_server() -> (SocketAddr, Channel) {
    let store = Store::connect(&SurrealDbConfig {
        endpoint: "memory".to_string(),
        namespace: "test_rrm".to_string(),
        database: "test_authz".to_string(),
        username: None,
        password: None,
    })
    .await
    .expect("in-memory SurrealDB should connect");

    let service = RrmService::new(store, TEST_ADMIN_TOKEN);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should bind ephemeral port");
    let addr = listener.local_addr().expect("should have local addr");

    tokio::spawn(async move {
        Server::builder()
            .add_service(AdminServiceServer::new(service.clone()))
            .add_service(PolicyServiceServer::new(service.clone()))
            .add_service(EntityServiceServer::new(service.clone()))
            .add_service(AuthorizationServiceServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("gRPC test server failed");
    });

    let endpoint = format!("http://{addr}");
    let channel = Channel::from_shared(endpoint)
        .expect("valid endpoint")
        .connect()
        .await
        .expect("client should connect to test gRPC server");

    (addr, channel)
}

fn with_admin<T>(msg: T) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert(
        "x-admin-token",
        MetadataValue::try_from(TEST_ADMIN_TOKEN).expect("valid header"),
    );
    req
}

fn with_space_token<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert(
        "x-space-token",
        MetadataValue::try_from(token).expect("valid header"),
    );
    req
}

#[tokio::test]
async fn full_multi_tenant_cedar_and_surrealdb_grpc_workflow() {
    let (_addr, channel) = start_test_server().await;

    let mut admin_client = AdminServiceClient::new(channel.clone());
    let mut policy_client = PolicyServiceClient::new(channel.clone());
    let mut entity_client = EntityServiceClient::new(channel.clone());
    let mut authz_client = AuthorizationServiceClient::new(channel);

    // 1. Unauthenticated Admin call should be rejected
    let unauth_err = admin_client
        .create_space(Request::new(CreateSpaceRequest {
            space_id: "orders-app".to_string(),
            name: "Orders Service".to_string(),
            description: "Order management app".to_string(),
        }))
        .await
        .expect_err("unauthenticated create_space should fail");
    assert_eq!(unauth_err.code(), tonic::Code::Unauthenticated);

    // 2. Admin creates two isolated Spaces: `orders-app` and `hr-app`
    let orders_space_resp = admin_client
        .create_space(with_admin(CreateSpaceRequest {
            space_id: "orders-app".to_string(),
            name: "Orders Service".to_string(),
            description: "Order management app".to_string(),
        }))
        .await
        .expect("admin should create orders-app space")
        .into_inner();
    let orders_token = orders_space_resp.api_token;
    assert!(!orders_token.is_empty());

    let hr_space_resp = admin_client
        .create_space(with_admin(CreateSpaceRequest {
            space_id: "hr-app".to_string(),
            name: "HR Service".to_string(),
            description: "Human resources app".to_string(),
        }))
        .await
        .expect("admin should create hr-app space")
        .into_inner();
    let hr_token = hr_space_resp.api_token;
    assert_ne!(orders_token, hr_token);

    let listed_spaces = admin_client
        .list_spaces(with_admin(ListSpacesRequest {}))
        .await
        .expect("list_spaces should succeed")
        .into_inner()
        .spaces;
    assert_eq!(listed_spaces.len(), 2);

    // 3. Cross-space isolation check: `hr-app` token cannot upload policies to `orders-app`
    let cross_tenant_err = policy_client
        .upsert_policy(with_space_token(
            UpsertPolicyRequest {
                space_id: "orders-app".to_string(),
                policy_id: "unauthorized-policy".to_string(),
                description: "Should fail".to_string(),
                cedar_text: "permit(principal, action, resource);".to_string(),
            },
            &hr_token,
        ))
        .await
        .expect_err("cross-tenant token must be rejected");
    assert_eq!(cross_tenant_err.code(), tonic::Code::PermissionDenied);

    // 4. App Owner uploads invalid Cedar syntax -> rejected with INVALID_ARGUMENT
    let syntax_err = policy_client
        .upsert_policy(with_space_token(
            UpsertPolicyRequest {
                space_id: "orders-app".to_string(),
                policy_id: "broken-policy".to_string(),
                description: "Broken Cedar syntax".to_string(),
                cedar_text: "permit(principal == , action, resource);".to_string(),
            },
            &orders_token,
        ))
        .await
        .expect_err("invalid Cedar syntax must be rejected");
    assert_eq!(syntax_err.code(), tonic::Code::InvalidArgument);

    // 5. App Owner uploads Cedar policies for `orders-app`
    let uploaded = policy_client
        .upload_policy_set(with_space_token(
            UploadPolicySetRequest {
                space_id: "orders-app".to_string(),
                replace_existing: true,
                policies: vec![
                    PolicyInput {
                        policy_id: "managers-approve-dept-orders".to_string(),
                        description: "Managers can approve orders in their department up to limit"
                            .to_string(),
                        cedar_text: r#"
                            permit(
                                principal in Role::"manager",
                                action == Action::"approve",
                                resource is Order
                            ) when {
                                principal.department == resource.department &&
                                resource.amount <= principal.approval_limit
                            };
                        "#
                        .to_string(),
                    },
                    PolicyInput {
                        policy_id: "owners-view-own-orders".to_string(),
                        description: "Users can view orders they created".to_string(),
                        cedar_text: r#"
                            permit(
                                principal,
                                action == Action::"view",
                                resource is Order
                            ) when {
                                resource.owner == principal
                            };
                        "#
                        .to_string(),
                    },
                    PolicyInput {
                        policy_id: "forbid-frozen-orders".to_string(),
                        description: "No one can approve frozen orders".to_string(),
                        cedar_text: r#"
                            forbid(
                                principal,
                                action == Action::"approve",
                                resource is Order
                            ) when {
                                resource.frozen == true
                            };
                        "#
                        .to_string(),
                    },
                ],
            },
            &orders_token,
        ))
        .await
        .expect("upload_policy_set should succeed")
        .into_inner();
    assert_eq!(uploaded.policies.len(), 3);

    let policies_list = policy_client
        .list_policies(with_space_token(
            ListPoliciesRequest {
                space_id: "orders-app".to_string(),
            },
            &orders_token,
        ))
        .await
        .expect("list_policies should succeed")
        .into_inner()
        .policies;
    assert_eq!(policies_list.len(), 3);

    let single_policy = policy_client
        .get_policy(with_space_token(
            GetPolicyRequest {
                space_id: "orders-app".to_string(),
                policy_id: "owners-view-own-orders".to_string(),
            },
            &orders_token,
        ))
        .await
        .expect("get_policy should succeed")
        .into_inner()
        .policy
        .expect("policy present");
    assert_eq!(single_policy.policy_id, "owners-view-own-orders");

    // 6. Put Users in SurrealDB via gRPC `EntityService::UpsertUser`
    entity_client
        .upsert_user(with_space_token(
            UpsertUserRequest {
                space_id: "orders-app".to_string(),
                user_id: "alice".to_string(),
                email: "alice@acme.example".to_string(),
                roles: vec!["manager".to_string()],
                groups: vec!["procurement".to_string()],
                attributes_json: r#"{"department": "logistics", "approval_limit": 5000}"#
                    .to_string(),
            },
            &orders_token,
        ))
        .await
        .expect("upsert_user alice should succeed");

    entity_client
        .upsert_user(with_space_token(
            UpsertUserRequest {
                space_id: "orders-app".to_string(),
                user_id: "bob".to_string(),
                email: "bob@acme.example".to_string(),
                roles: vec!["buyer".to_string()],
                groups: vec!["procurement".to_string()],
                attributes_json: r#"{"department": "logistics", "approval_limit": 0}"#.to_string(),
            },
            &orders_token,
        ))
        .await
        .expect("upsert_user bob should succeed");

    let fetched_alice = entity_client
        .get_user(with_space_token(
            GetUserRequest {
                space_id: "orders-app".to_string(),
                user_id: "alice".to_string(),
            },
            &orders_token,
        ))
        .await
        .expect("get_user alice should succeed")
        .into_inner()
        .user
        .expect("alice record");
    assert_eq!(fetched_alice.email, "alice@acme.example");
    assert_eq!(fetched_alice.roles, vec!["manager".to_string()]);

    let users_in_space = entity_client
        .list_users(with_space_token(
            ListUsersRequest {
                space_id: "orders-app".to_string(),
            },
            &orders_token,
        ))
        .await
        .expect("list_users should succeed")
        .into_inner()
        .users;
    assert_eq!(users_in_space.len(), 2);

    // 7. Put Order entities in SurrealDB via gRPC `EntityService::UpsertEntity`
    entity_client
        .upsert_entity(with_space_token(
            UpsertEntityRequest {
                space_id: "orders-app".to_string(),
                uid: Some(EntityUidMsg {
                    entity_type: "Order".to_string(),
                    entity_id: "ord-100".to_string(),
                }),
                parents: vec![],
                attributes_json: r#"{
                    "department": "logistics",
                    "amount": 1200,
                    "frozen": false,
                    "owner": {"__entity": {"type": "User", "id": "bob"}}
                }"#
                .to_string(),
            },
            &orders_token,
        ))
        .await
        .expect("upsert_entity ord-100 should succeed");

    entity_client
        .upsert_entity(with_space_token(
            UpsertEntityRequest {
                space_id: "orders-app".to_string(),
                uid: Some(EntityUidMsg {
                    entity_type: "Order".to_string(),
                    entity_id: "ord-frozen".to_string(),
                }),
                parents: vec![],
                attributes_json: r#"{
                    "department": "logistics",
                    "amount": 500,
                    "frozen": true,
                    "owner": {"__entity": {"type": "User", "id": "bob"}}
                }"#
                .to_string(),
            },
            &orders_token,
        ))
        .await
        .expect("upsert_entity ord-frozen should succeed");

    let stored_orders = entity_client
        .list_entities(with_space_token(
            ListEntitiesRequest {
                space_id: "orders-app".to_string(),
                entity_type: "Order".to_string(),
            },
            &orders_token,
        ))
        .await
        .expect("list_entities should succeed")
        .into_inner()
        .entities;
    assert_eq!(stored_orders.len(), 2);

    // 8. Evaluate Authorization Requests against Cedar Policies + SurrealDB Entity Store

    // Case A: Manager Alice approves ord-100 (same dept, amount 1200 <= 5000, not frozen) -> ALLOW
    let eval_alice_approve = authz_client
        .authorize(with_space_token(
            AuthorizeRequest {
                space_id: "orders-app".to_string(),
                principal: Some(EntityUidMsg {
                    entity_type: "User".to_string(),
                    entity_id: "alice".to_string(),
                }),
                action: Some(EntityUidMsg {
                    entity_type: "Action".to_string(),
                    entity_id: "approve".to_string(),
                }),
                resource: Some(EntityUidMsg {
                    entity_type: "Order".to_string(),
                    entity_id: "ord-100".to_string(),
                }),
                context_json: "{}".to_string(),
                additional_entities: vec![],
            },
            &orders_token,
        ))
        .await
        .expect("authorize alice approve ord-100 should succeed")
        .into_inner();
    assert!(eval_alice_approve.allowed);
    assert_eq!(eval_alice_approve.decision, AuthDecision::Allow as i32);
    assert_eq!(
        eval_alice_approve.determining_policies,
        vec!["managers-approve-dept-orders".to_string()]
    );

    // Case B: Buyer Bob tries to approve ord-100 (not in Role::"manager") -> DENY
    let eval_bob_approve = authz_client
        .authorize(with_space_token(
            AuthorizeRequest {
                space_id: "orders-app".to_string(),
                principal: Some(EntityUidMsg {
                    entity_type: "User".to_string(),
                    entity_id: "bob".to_string(),
                }),
                action: Some(EntityUidMsg {
                    entity_type: "Action".to_string(),
                    entity_id: "approve".to_string(),
                }),
                resource: Some(EntityUidMsg {
                    entity_type: "Order".to_string(),
                    entity_id: "ord-100".to_string(),
                }),
                context_json: "{}".to_string(),
                additional_entities: vec![],
            },
            &orders_token,
        ))
        .await
        .expect("authorize bob approve ord-100 should succeed")
        .into_inner();
    assert!(!eval_bob_approve.allowed);
    assert_eq!(eval_bob_approve.decision, AuthDecision::Deny as i32);

    // Case C: Buyer Bob views ord-100 (owner == User::"bob") -> ALLOW
    let eval_bob_view = authz_client
        .authorize(with_space_token(
            AuthorizeRequest {
                space_id: "orders-app".to_string(),
                principal: Some(EntityUidMsg {
                    entity_type: "User".to_string(),
                    entity_id: "bob".to_string(),
                }),
                action: Some(EntityUidMsg {
                    entity_type: "Action".to_string(),
                    entity_id: "view".to_string(),
                }),
                resource: Some(EntityUidMsg {
                    entity_type: "Order".to_string(),
                    entity_id: "ord-100".to_string(),
                }),
                context_json: "{}".to_string(),
                additional_entities: vec![],
            },
            &orders_token,
        ))
        .await
        .expect("authorize bob view ord-100 should succeed")
        .into_inner();
    assert!(eval_bob_view.allowed);
    assert_eq!(
        eval_bob_view.determining_policies,
        vec!["owners-view-own-orders".to_string()]
    );

    // Case D: Manager Alice tries to approve ord-frozen -> DENY due to forbid policy
    let eval_alice_frozen = authz_client
        .authorize(with_space_token(
            AuthorizeRequest {
                space_id: "orders-app".to_string(),
                principal: Some(EntityUidMsg {
                    entity_type: "User".to_string(),
                    entity_id: "alice".to_string(),
                }),
                action: Some(EntityUidMsg {
                    entity_type: "Action".to_string(),
                    entity_id: "approve".to_string(),
                }),
                resource: Some(EntityUidMsg {
                    entity_type: "Order".to_string(),
                    entity_id: "ord-frozen".to_string(),
                }),
                context_json: "{}".to_string(),
                additional_entities: vec![],
            },
            &orders_token,
        ))
        .await
        .expect("authorize alice approve ord-frozen should succeed")
        .into_inner();
    assert!(!eval_alice_frozen.allowed);
    assert_eq!(
        eval_alice_frozen.determining_policies,
        vec!["forbid-frozen-orders".to_string()]
    );

    // Case E: Transient additional_entities passed at evaluation time (e.g. unsaved order > limit)
    let eval_over_limit = authz_client
        .authorize(with_space_token(
            AuthorizeRequest {
                space_id: "orders-app".to_string(),
                principal: Some(EntityUidMsg {
                    entity_type: "User".to_string(),
                    entity_id: "alice".to_string(),
                }),
                action: Some(EntityUidMsg {
                    entity_type: "Action".to_string(),
                    entity_id: "approve".to_string(),
                }),
                resource: Some(EntityUidMsg {
                    entity_type: "Order".to_string(),
                    entity_id: "ord-999".to_string(),
                }),
                context_json: "{}".to_string(),
                additional_entities: vec![CedarEntityRecord {
                    space_id: "orders-app".to_string(),
                    uid: Some(EntityUidMsg {
                        entity_type: "Order".to_string(),
                        entity_id: "ord-999".to_string(),
                    }),
                    parents: vec![],
                    attributes_json: r#"{
                        "department": "logistics",
                        "amount": 9500,
                        "frozen": false
                    }"#
                    .to_string(),
                    updated_at: String::new(),
                }],
            },
            &orders_token,
        ))
        .await
        .expect("authorize alice approve ord-999 should succeed")
        .into_inner();
    assert!(!eval_over_limit.allowed);

    // 9. Test Delete operations for Policy, User, and Space
    let del_policy = policy_client
        .delete_policy(with_space_token(
            DeletePolicyRequest {
                space_id: "orders-app".to_string(),
                policy_id: "owners-view-own-orders".to_string(),
            },
            &orders_token,
        ))
        .await
        .expect("delete_policy should succeed")
        .into_inner();
    assert!(del_policy.deleted);

    let del_user = entity_client
        .delete_user(with_space_token(
            DeleteUserRequest {
                space_id: "orders-app".to_string(),
                user_id: "bob".to_string(),
            },
            &orders_token,
        ))
        .await
        .expect("delete_user should succeed")
        .into_inner();
    assert!(del_user.deleted);

    let del_space = admin_client
        .delete_space(with_admin(DeleteSpaceRequest {
            space_id: "hr-app".to_string(),
        }))
        .await
        .expect("delete_space should succeed")
        .into_inner();
    assert!(del_space.deleted);
}
