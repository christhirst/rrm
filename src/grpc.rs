use std::sync::Arc;

use cedar_policy::Decision;
use tonic::{Request, Response, Status};

use crate::auth::{verify_admin, verify_space_access};
use crate::cedar_engine::{
    EvaluationInput, evaluate_authorization, parse_attributes_json, parse_entity_uid,
    validate_and_parse_policy,
};
use crate::error::AppError;
use crate::models::{EntityRef, SpaceRecord, StoredEntity, StoredPolicy, StoredUser};
use crate::pb::{
    AuthDecision, AuthorizeRequest, AuthorizeResponse, CedarEntityRecord, CreateSpaceRequest,
    CreateSpaceResponse, DeleteEntityRequest, DeleteEntityResponse, DeletePolicyRequest,
    DeletePolicyResponse, DeleteSpaceRequest, DeleteSpaceResponse, DeleteUserRequest,
    DeleteUserResponse, EntityUidMsg, GetEntityRequest, GetEntityResponse, GetPolicyRequest,
    GetPolicyResponse, GetSpaceRequest, GetSpaceResponse, GetUserRequest, GetUserResponse,
    ListEntitiesRequest, ListEntitiesResponse, ListPoliciesRequest, ListPoliciesResponse,
    ListSpacesRequest, ListSpacesResponse, ListUsersRequest, ListUsersResponse, PolicyRecord,
    Space, UploadPolicySetRequest, UploadPolicySetResponse, UpsertEntityRequest,
    UpsertEntityResponse, UpsertPolicyRequest, UpsertPolicyResponse, UpsertUserRequest,
    UpsertUserResponse, UserRecord, admin_service_server::AdminService,
    authorization_service_server::AuthorizationService, entity_service_server::EntityService,
    policy_service_server::PolicyService,
};
use crate::store::Store;

#[derive(Debug, Clone)]
pub struct RrmService {
    store: Store,
    admin_token: Arc<str>,
}

impl RrmService {
    pub fn new(store: Store, admin_token: impl Into<Arc<str>>) -> Self {
        Self {
            store,
            admin_token: admin_token.into(),
        }
    }

    fn to_proto_space(record: SpaceRecord) -> Space {
        Space {
            space_id: record.space_id,
            name: record.name,
            description: record.description,
            created_at: record.created_at,
        }
    }

    fn to_proto_policy(record: StoredPolicy) -> PolicyRecord {
        PolicyRecord {
            space_id: record.space_id,
            policy_id: record.policy_id,
            description: record.description,
            cedar_text: record.cedar_text,
            updated_at: record.updated_at,
        }
    }

    fn to_proto_user(record: StoredUser) -> UserRecord {
        UserRecord {
            space_id: record.space_id,
            user_id: record.user_id,
            email: record.email,
            roles: record.roles,
            groups: record.groups,
            attributes_json: record.attributes_json,
            updated_at: record.updated_at,
        }
    }

    fn to_proto_entity(record: StoredEntity) -> CedarEntityRecord {
        CedarEntityRecord {
            space_id: record.space_id,
            uid: Some(EntityUidMsg {
                entity_type: record.entity_type,
                entity_id: record.entity_id,
            }),
            parents: record
                .parents
                .into_iter()
                .map(|p| EntityUidMsg {
                    entity_type: p.entity_type,
                    entity_id: p.entity_id,
                })
                .collect(),
            attributes_json: record.attributes_json,
            updated_at: record.updated_at,
        }
    }

    fn extract_uid_msg(uid: Option<EntityUidMsg>, field_name: &str) -> Result<EntityRef, AppError> {
        let uid = uid
            .ok_or_else(|| AppError::InvalidArgument(format!("Missing '{field_name}' field")))?;
        // Validate against Cedar's EntityUid rules
        let _ = parse_entity_uid(&uid.entity_type, &uid.entity_id)?;
        Ok(EntityRef {
            entity_type: uid.entity_type,
            entity_id: uid.entity_id,
        })
    }
}

#[tonic::async_trait]
impl AdminService for RrmService {
    async fn create_space(
        &self,
        request: Request<CreateSpaceRequest>,
    ) -> Result<Response<CreateSpaceResponse>, Status> {
        verify_admin(request.metadata(), &self.admin_token)?;
        let req = request.into_inner();
        let created = self
            .store
            .create_space(&req.space_id, &req.name, &req.description)
            .await?;
        let api_token = created.api_token.clone();

        Ok(Response::new(CreateSpaceResponse {
            space: Some(Self::to_proto_space(created)),
            api_token,
        }))
    }

    async fn get_space(
        &self,
        request: Request<GetSpaceRequest>,
    ) -> Result<Response<GetSpaceResponse>, Status> {
        verify_admin(request.metadata(), &self.admin_token)?;
        let req = request.into_inner();
        let space = self.store.get_space(&req.space_id).await?;
        Ok(Response::new(GetSpaceResponse {
            space: Some(Self::to_proto_space(space)),
        }))
    }

    async fn list_spaces(
        &self,
        request: Request<ListSpacesRequest>,
    ) -> Result<Response<ListSpacesResponse>, Status> {
        verify_admin(request.metadata(), &self.admin_token)?;
        let spaces = self.store.list_spaces().await?;
        Ok(Response::new(ListSpacesResponse {
            spaces: spaces.into_iter().map(Self::to_proto_space).collect(),
        }))
    }

    async fn delete_space(
        &self,
        request: Request<DeleteSpaceRequest>,
    ) -> Result<Response<DeleteSpaceResponse>, Status> {
        verify_admin(request.metadata(), &self.admin_token)?;
        let req = request.into_inner();
        let deleted = self.store.delete_space(&req.space_id).await?;
        Ok(Response::new(DeleteSpaceResponse { deleted }))
    }
}

#[tonic::async_trait]
impl PolicyService for RrmService {
    async fn upsert_policy(
        &self,
        request: Request<UpsertPolicyRequest>,
    ) -> Result<Response<UpsertPolicyResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();
        verify_space_access(&metadata, &self.store, &self.admin_token, &req.space_id).await?;

        // Validate Cedar policy syntax before saving
        let _ = validate_and_parse_policy(&req.policy_id, &req.cedar_text)?;

        let saved = self
            .store
            .upsert_policy(
                &req.space_id,
                &req.policy_id,
                &req.description,
                &req.cedar_text,
            )
            .await?;

        Ok(Response::new(UpsertPolicyResponse {
            policy: Some(Self::to_proto_policy(saved)),
        }))
    }

    async fn upload_policy_set(
        &self,
        request: Request<UploadPolicySetRequest>,
    ) -> Result<Response<UploadPolicySetResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();
        verify_space_access(&metadata, &self.store, &self.admin_token, &req.space_id).await?;

        // Validate all policies first before modifying the store
        for item in &req.policies {
            let _ = validate_and_parse_policy(&item.policy_id, &item.cedar_text)?;
        }

        if req.replace_existing {
            self.store.clear_space_policies(&req.space_id).await?;
        }

        let mut out = Vec::with_capacity(req.policies.len());
        for item in req.policies {
            let saved = self
                .store
                .upsert_policy(
                    &req.space_id,
                    &item.policy_id,
                    &item.description,
                    &item.cedar_text,
                )
                .await?;
            out.push(Self::to_proto_policy(saved));
        }

        Ok(Response::new(UploadPolicySetResponse { policies: out }))
    }

    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();
        verify_space_access(&metadata, &self.store, &self.admin_token, &req.space_id).await?;

        let policy = self.store.get_policy(&req.space_id, &req.policy_id).await?;
        Ok(Response::new(GetPolicyResponse {
            policy: Some(Self::to_proto_policy(policy)),
        }))
    }

    async fn list_policies(
        &self,
        request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();
        verify_space_access(&metadata, &self.store, &self.admin_token, &req.space_id).await?;

        let policies = self.store.list_policies(&req.space_id).await?;
        Ok(Response::new(ListPoliciesResponse {
            policies: policies.into_iter().map(Self::to_proto_policy).collect(),
        }))
    }

    async fn delete_policy(
        &self,
        request: Request<DeletePolicyRequest>,
    ) -> Result<Response<DeletePolicyResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();
        verify_space_access(&metadata, &self.store, &self.admin_token, &req.space_id).await?;

        let deleted = self
            .store
            .delete_policy(&req.space_id, &req.policy_id)
            .await?;
        Ok(Response::new(DeletePolicyResponse { deleted }))
    }
}

#[tonic::async_trait]
impl EntityService for RrmService {
    async fn upsert_user(
        &self,
        request: Request<UpsertUserRequest>,
    ) -> Result<Response<UpsertUserResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();
        verify_space_access(&metadata, &self.store, &self.admin_token, &req.space_id).await?;

        // Validate user_id and attributes JSON for Cedar compatibility
        let _ = parse_entity_uid("User", &req.user_id)?;
        let _ = parse_attributes_json(&req.attributes_json)?;
        for role in &req.roles {
            let _ = parse_entity_uid("Role", role)?;
        }
        for group in &req.groups {
            let _ = parse_entity_uid("Group", group)?;
        }

        let user = self
            .store
            .upsert_user(
                &req.space_id,
                &req.user_id,
                &req.email,
                req.roles,
                req.groups,
                &req.attributes_json,
            )
            .await?;

        Ok(Response::new(UpsertUserResponse {
            user: Some(Self::to_proto_user(user)),
        }))
    }

    async fn get_user(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<GetUserResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();
        verify_space_access(&metadata, &self.store, &self.admin_token, &req.space_id).await?;

        let user = self.store.get_user(&req.space_id, &req.user_id).await?;
        Ok(Response::new(GetUserResponse {
            user: Some(Self::to_proto_user(user)),
        }))
    }

    async fn list_users(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();
        verify_space_access(&metadata, &self.store, &self.admin_token, &req.space_id).await?;

        let users = self.store.list_users(&req.space_id).await?;
        Ok(Response::new(ListUsersResponse {
            users: users.into_iter().map(Self::to_proto_user).collect(),
        }))
    }

    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();
        verify_space_access(&metadata, &self.store, &self.admin_token, &req.space_id).await?;

        let deleted = self.store.delete_user(&req.space_id, &req.user_id).await?;
        Ok(Response::new(DeleteUserResponse { deleted }))
    }

    async fn upsert_entity(
        &self,
        request: Request<UpsertEntityRequest>,
    ) -> Result<Response<UpsertEntityResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();
        verify_space_access(&metadata, &self.store, &self.admin_token, &req.space_id).await?;

        let uid = Self::extract_uid_msg(req.uid, "uid")?;
        let _ = parse_attributes_json(&req.attributes_json)?;

        let mut parents = Vec::with_capacity(req.parents.len());
        for parent_msg in req.parents {
            let parent_ref = Self::extract_uid_msg(Some(parent_msg), "parents")?;
            parents.push(parent_ref);
        }

        let entity = self
            .store
            .upsert_entity(
                &req.space_id,
                &uid.entity_type,
                &uid.entity_id,
                parents,
                &req.attributes_json,
            )
            .await?;

        Ok(Response::new(UpsertEntityResponse {
            entity: Some(Self::to_proto_entity(entity)),
        }))
    }

    async fn get_entity(
        &self,
        request: Request<GetEntityRequest>,
    ) -> Result<Response<GetEntityResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();
        verify_space_access(&metadata, &self.store, &self.admin_token, &req.space_id).await?;

        let uid = Self::extract_uid_msg(req.uid, "uid")?;
        let entity = self
            .store
            .get_entity(&req.space_id, &uid.entity_type, &uid.entity_id)
            .await?;

        Ok(Response::new(GetEntityResponse {
            entity: Some(Self::to_proto_entity(entity)),
        }))
    }

    async fn list_entities(
        &self,
        request: Request<ListEntitiesRequest>,
    ) -> Result<Response<ListEntitiesResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();
        verify_space_access(&metadata, &self.store, &self.admin_token, &req.space_id).await?;

        let filter = if req.entity_type.trim().is_empty() {
            None
        } else {
            Some(req.entity_type.as_str())
        };
        let entities = self.store.list_entities(&req.space_id, filter).await?;

        Ok(Response::new(ListEntitiesResponse {
            entities: entities.into_iter().map(Self::to_proto_entity).collect(),
        }))
    }

    async fn delete_entity(
        &self,
        request: Request<DeleteEntityRequest>,
    ) -> Result<Response<DeleteEntityResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();
        verify_space_access(&metadata, &self.store, &self.admin_token, &req.space_id).await?;

        let uid = Self::extract_uid_msg(req.uid, "uid")?;
        let deleted = self
            .store
            .delete_entity(&req.space_id, &uid.entity_type, &uid.entity_id)
            .await?;

        Ok(Response::new(DeleteEntityResponse { deleted }))
    }
}

#[tonic::async_trait]
impl AuthorizationService for RrmService {
    async fn authorize(
        &self,
        request: Request<AuthorizeRequest>,
    ) -> Result<Response<AuthorizeResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();
        verify_space_access(&metadata, &self.store, &self.admin_token, &req.space_id).await?;

        let principal = Self::extract_uid_msg(req.principal, "principal")?;
        let action = Self::extract_uid_msg(req.action, "action")?;
        let resource = Self::extract_uid_msg(req.resource, "resource")?;

        let mut additional_entities = Vec::with_capacity(req.additional_entities.len());
        for item in req.additional_entities {
            let uid = Self::extract_uid_msg(item.uid, "additional_entities.uid")?;
            let mut parents = Vec::with_capacity(item.parents.len());
            for p in item.parents {
                parents.push(Self::extract_uid_msg(
                    Some(p),
                    "additional_entities.parents",
                )?);
            }
            additional_entities.push(StoredEntity {
                space_id: req.space_id.clone(),
                entity_type: uid.entity_type,
                entity_id: uid.entity_id,
                parents,
                attributes_json: item.attributes_json,
                updated_at: String::new(),
            });
        }

        let policies = self.store.list_policies(&req.space_id).await?;
        let users = self.store.list_users(&req.space_id).await?;
        let stored_entities = self.store.list_entities(&req.space_id, None).await?;

        let outcome = evaluate_authorization(&EvaluationInput {
            principal: &principal,
            action: &action,
            resource: &resource,
            context_json: &req.context_json,
            policies: &policies,
            users: &users,
            stored_entities: &stored_entities,
            additional_entities: &additional_entities,
        })?;

        let decision = match outcome.decision {
            Decision::Allow => AuthDecision::Allow as i32,
            Decision::Deny => AuthDecision::Deny as i32,
        };

        Ok(Response::new(AuthorizeResponse {
            allowed: outcome.allowed,
            decision,
            determining_policies: outcome.determining_policies,
            errors: outcome.errors,
        }))
    }
}
