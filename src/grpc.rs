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

trait HasSpaceId {
    fn space_id(&self) -> &str;
}

macro_rules! impl_has_space_id {
    ($($t:ty),* $(,)?) => {
        $(
            impl HasSpaceId for $t {
                fn space_id(&self) -> &str {
                    &self.space_id
                }
            }
        )*
    };
}

impl_has_space_id!(
    UpsertPolicyRequest,
    UploadPolicySetRequest,
    GetPolicyRequest,
    ListPoliciesRequest,
    DeletePolicyRequest,
    UpsertUserRequest,
    GetUserRequest,
    ListUsersRequest,
    DeleteUserRequest,
    UpsertEntityRequest,
    GetEntityRequest,
    ListEntitiesRequest,
    DeleteEntityRequest,
    AuthorizeRequest,
);

impl From<SpaceRecord> for Space {
    fn from(record: SpaceRecord) -> Self {
        Self {
            space_id: record.space_id,
            name: record.name,
            description: record.description,
            created_at: record.created_at,
        }
    }
}

impl From<StoredPolicy> for PolicyRecord {
    fn from(record: StoredPolicy) -> Self {
        Self {
            space_id: record.space_id,
            policy_id: record.policy_id,
            description: record.description,
            cedar_text: record.cedar_text,
            updated_at: record.updated_at,
        }
    }
}

impl From<StoredUser> for UserRecord {
    fn from(record: StoredUser) -> Self {
        Self {
            space_id: record.space_id,
            user_id: record.user_id,
            email: record.email,
            roles: record.roles,
            groups: record.groups,
            attributes_json: record.attributes_json,
            updated_at: record.updated_at,
        }
    }
}

impl From<EntityRef> for EntityUidMsg {
    fn from(r: EntityRef) -> Self {
        Self {
            entity_type: r.entity_type,
            entity_id: r.entity_id,
        }
    }
}

impl From<StoredEntity> for CedarEntityRecord {
    fn from(record: StoredEntity) -> Self {
        Self {
            space_id: record.space_id,
            uid: Some(EntityUidMsg {
                entity_type: record.entity_type,
                entity_id: record.entity_id,
            }),
            parents: record.parents.into_iter().map(Into::into).collect(),
            attributes_json: record.attributes_json,
            updated_at: record.updated_at,
        }
    }
}

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

    fn admin_request<T>(&self, req: Request<T>) -> Result<T, Status> {
        let (meta, _, msg) = req.into_parts();
        verify_admin(&meta, &self.admin_token)?;
        Ok(msg)
    }

    async fn space_request<T: HasSpaceId>(&self, req: Request<T>) -> Result<T, Status> {
        let (meta, _, msg) = req.into_parts();
        verify_space_access(&meta, &self.store, &self.admin_token, msg.space_id()).await?;
        Ok(msg)
    }

    fn extract_uid_msg(uid: Option<EntityUidMsg>, field_name: &str) -> Result<EntityRef, AppError> {
        let uid = uid.ok_or_else(|| AppError::invalid(format!("Missing '{field_name}' field")))?;
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
        let req = self.admin_request(request)?;
        let created = self
            .store
            .create_space(&req.space_id, &req.name, &req.description)
            .await?;
        let api_token = created.api_token.clone();

        Ok(Response::new(CreateSpaceResponse {
            space: Some(created.into()),
            api_token,
        }))
    }

    async fn get_space(
        &self,
        request: Request<GetSpaceRequest>,
    ) -> Result<Response<GetSpaceResponse>, Status> {
        let req = self.admin_request(request)?;
        let space = self.store.get_space(&req.space_id).await?;
        Ok(Response::new(GetSpaceResponse {
            space: Some(space.into()),
        }))
    }

    async fn list_spaces(
        &self,
        request: Request<ListSpacesRequest>,
    ) -> Result<Response<ListSpacesResponse>, Status> {
        self.admin_request(request)?;
        let spaces = self.store.list_spaces().await?;
        Ok(Response::new(ListSpacesResponse {
            spaces: spaces.into_iter().map(Into::into).collect(),
        }))
    }

    async fn delete_space(
        &self,
        request: Request<DeleteSpaceRequest>,
    ) -> Result<Response<DeleteSpaceResponse>, Status> {
        let req = self.admin_request(request)?;
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
        let req = self.space_request(request).await?;

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
            policy: Some(saved.into()),
        }))
    }

    async fn upload_policy_set(
        &self,
        request: Request<UploadPolicySetRequest>,
    ) -> Result<Response<UploadPolicySetResponse>, Status> {
        let req = self.space_request(request).await?;

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
            out.push(saved.into());
        }

        Ok(Response::new(UploadPolicySetResponse { policies: out }))
    }

    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        let req = self.space_request(request).await?;
        let policy = self.store.get_policy(&req.space_id, &req.policy_id).await?;
        Ok(Response::new(GetPolicyResponse {
            policy: Some(policy.into()),
        }))
    }

    async fn list_policies(
        &self,
        request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        let req = self.space_request(request).await?;
        let policies = self.store.list_policies(&req.space_id).await?;
        Ok(Response::new(ListPoliciesResponse {
            policies: policies.into_iter().map(Into::into).collect(),
        }))
    }

    async fn delete_policy(
        &self,
        request: Request<DeletePolicyRequest>,
    ) -> Result<Response<DeletePolicyResponse>, Status> {
        let req = self.space_request(request).await?;
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
        let req = self.space_request(request).await?;

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
            user: Some(user.into()),
        }))
    }

    async fn get_user(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<GetUserResponse>, Status> {
        let req = self.space_request(request).await?;
        let user = self.store.get_user(&req.space_id, &req.user_id).await?;
        Ok(Response::new(GetUserResponse {
            user: Some(user.into()),
        }))
    }

    async fn list_users(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        let req = self.space_request(request).await?;
        let users = self.store.list_users(&req.space_id).await?;
        Ok(Response::new(ListUsersResponse {
            users: users.into_iter().map(Into::into).collect(),
        }))
    }

    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        let req = self.space_request(request).await?;
        let deleted = self.store.delete_user(&req.space_id, &req.user_id).await?;
        Ok(Response::new(DeleteUserResponse { deleted }))
    }

    async fn upsert_entity(
        &self,
        request: Request<UpsertEntityRequest>,
    ) -> Result<Response<UpsertEntityResponse>, Status> {
        let req = self.space_request(request).await?;

        let uid = Self::extract_uid_msg(req.uid, "uid")?;
        let _ = parse_attributes_json(&req.attributes_json)?;

        let parents = req
            .parents
            .into_iter()
            .map(|p| Self::extract_uid_msg(Some(p), "parents"))
            .collect::<Result<Vec<_>, AppError>>()?;

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
            entity: Some(entity.into()),
        }))
    }

    async fn get_entity(
        &self,
        request: Request<GetEntityRequest>,
    ) -> Result<Response<GetEntityResponse>, Status> {
        let req = self.space_request(request).await?;
        let uid = Self::extract_uid_msg(req.uid, "uid")?;
        let entity = self
            .store
            .get_entity(&req.space_id, &uid.entity_type, &uid.entity_id)
            .await?;

        Ok(Response::new(GetEntityResponse {
            entity: Some(entity.into()),
        }))
    }

    async fn list_entities(
        &self,
        request: Request<ListEntitiesRequest>,
    ) -> Result<Response<ListEntitiesResponse>, Status> {
        let req = self.space_request(request).await?;
        let filter = if req.entity_type.trim().is_empty() {
            None
        } else {
            Some(req.entity_type.as_str())
        };
        let entities = self.store.list_entities(&req.space_id, filter).await?;

        Ok(Response::new(ListEntitiesResponse {
            entities: entities.into_iter().map(Into::into).collect(),
        }))
    }

    async fn delete_entity(
        &self,
        request: Request<DeleteEntityRequest>,
    ) -> Result<Response<DeleteEntityResponse>, Status> {
        let req = self.space_request(request).await?;
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
        let req = self.space_request(request).await?;

        let principal = Self::extract_uid_msg(req.principal, "principal")?;
        let action = Self::extract_uid_msg(req.action, "action")?;
        let resource = Self::extract_uid_msg(req.resource, "resource")?;

        let mut additional_entities = Vec::with_capacity(req.additional_entities.len());
        for item in req.additional_entities {
            let uid = Self::extract_uid_msg(item.uid, "additional_entities.uid")?;
            let parents = item
                .parents
                .into_iter()
                .map(|p| Self::extract_uid_msg(Some(p), "additional_entities.parents"))
                .collect::<Result<Vec<_>, AppError>>()?;
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
