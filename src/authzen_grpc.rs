use std::sync::Arc;

use prost_types::value::Kind;
use serde_json::Value;
use tonic::metadata::MetadataMap;
use tonic::{Request, Response, Status};

use crate::auth::{
    AUTHORIZATION_HEADER, SPACE_TOKEN_HEADER, extract_space_id_from_native_token, first_token,
    metadata_str, verify_space_access,
};
use crate::authzen::{
    AuthzenAction, AuthzenBatchItemRequest, AuthzenBatchRequest, AuthzenResource, AuthzenSubject,
    evaluate_authzen, evaluate_authzen_batch,
};
use crate::authzen_pb::{
    AccessEvaluationBatchRequest, AccessEvaluationBatchResponse, Action, EvaluationItemResponse,
    EvaluationRequest, EvaluationResponse, Resource, Subject,
    authorization_service_server::AuthorizationService,
};
use crate::store::Store;

#[derive(Clone)]
pub struct AuthzenGrpcService {
    store: Store,
    admin_token: Arc<str>,
}

impl AuthzenGrpcService {
    pub fn new(store: Store, admin_token: impl Into<Arc<str>>) -> Self {
        Self {
            store,
            admin_token: admin_token.into(),
        }
    }

    /// Resolves the target space (from the request, or inferred from a native space
    /// token) and verifies the caller may access it.
    async fn authenticate_space(
        &self,
        metadata: &MetadataMap,
        req_space_id: &str,
    ) -> Result<String, Status> {
        let space_id = match req_space_id.trim() {
            "" => {
                let token = first_token(
                    |k| metadata_str(metadata, k),
                    &[SPACE_TOKEN_HEADER, AUTHORIZATION_HEADER],
                )
                .ok_or_else(|| Status::unauthenticated("Missing authentication token"))?;
                extract_space_id_from_native_token(token)
                    .ok_or_else(|| {
                        Status::invalid_argument("space_id is required in request or token")
                    })?
                    .to_string()
            }
            explicit => explicit.to_string(),
        };

        verify_space_access(metadata, &self.store, &self.admin_token, &space_id).await?;
        Ok(space_id)
    }
}

/// Proto3 strings default to `""`; treat that as "not provided".
fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

impl From<Subject> for AuthzenSubject {
    fn from(s: Subject) -> Self {
        Self {
            subject_type: s.r#type,
            id: non_empty(s.id),
            properties: s.properties.as_ref().map(prost_struct_to_json),
        }
    }
}

impl From<Action> for AuthzenAction {
    fn from(a: Action) -> Self {
        Self {
            name: non_empty(a.name),
            properties: a.properties.as_ref().map(prost_struct_to_json),
        }
    }
}

impl From<Resource> for AuthzenResource {
    fn from(r: Resource) -> Self {
        Self {
            resource_type: r.r#type,
            id: non_empty(r.id),
            properties: r.properties.as_ref().map(prost_struct_to_json),
        }
    }
}

#[tonic::async_trait]
impl AuthorizationService for AuthzenGrpcService {
    async fn access_evaluation(
        &self,
        request: Request<EvaluationRequest>,
    ) -> Result<Response<EvaluationResponse>, Status> {
        let (metadata, _, req) = request.into_parts();
        let space_id = self.authenticate_space(&metadata, &req.space_id).await?;

        let subject: AuthzenSubject = req
            .subject
            .ok_or_else(|| Status::invalid_argument("subject is required"))?
            .into();
        let action: AuthzenAction = req
            .action
            .ok_or_else(|| Status::invalid_argument("action is required"))?
            .into();
        let resource: AuthzenResource = req
            .resource
            .ok_or_else(|| Status::invalid_argument("resource is required"))?
            .into();
        let context = req.context.as_ref().map(prost_struct_to_json);

        let outcome = evaluate_authzen(
            &self.store,
            &space_id,
            &subject,
            &action,
            &resource,
            context.as_ref(),
        )
        .await?;

        Ok(Response::new(EvaluationResponse {
            decision: outcome.decision,
            context: outcome.context.as_ref().map(json_to_prost_struct),
        }))
    }

    async fn access_evaluation_batch(
        &self,
        request: Request<AccessEvaluationBatchRequest>,
    ) -> Result<Response<AccessEvaluationBatchResponse>, Status> {
        let (metadata, _, req) = request.into_parts();
        let space_id = self.authenticate_space(&metadata, &req.space_id).await?;

        let evaluations = req
            .evaluations
            .into_iter()
            .map(|item| AuthzenBatchItemRequest {
                id: non_empty(item.id),
                subject: item.subject.map(Into::into),
                action: item.action.map(Into::into),
                resource: item.resource.map(Into::into),
                context: item.context.as_ref().map(prost_struct_to_json),
            })
            .collect();

        let batch_req = AuthzenBatchRequest {
            space_id: Some(space_id.clone()),
            subject: req.subject.map(Into::into),
            action: req.action.map(Into::into),
            resource: req.resource.map(Into::into),
            context: req.context.as_ref().map(prost_struct_to_json),
            evaluations,
        };

        let outcome = evaluate_authzen_batch(&self.store, &space_id, &batch_req).await?;

        Ok(Response::new(AccessEvaluationBatchResponse {
            evaluations: outcome
                .evaluations
                .into_iter()
                .map(|res| EvaluationItemResponse {
                    id: res.id.unwrap_or_default(),
                    decision: res.decision,
                    context: res.context.as_ref().map(json_to_prost_struct),
                })
                .collect(),
        }))
    }
}

// ============================================================================
// Prost Struct <-> JSON Converters
// ============================================================================

pub fn prost_struct_to_json(s: &prost_types::Struct) -> Value {
    Value::Object(
        s.fields
            .iter()
            .map(|(k, v)| (k.clone(), prost_value_to_json(v)))
            .collect(),
    )
}

pub fn prost_value_to_json(v: &prost_types::Value) -> Value {
    match &v.kind {
        Some(Kind::NullValue(_)) | None => Value::Null,
        // Non-finite numbers (NaN / ±inf) are not representable in JSON.
        Some(Kind::NumberValue(n)) => {
            serde_json::Number::from_f64(*n).map_or(Value::Null, Value::Number)
        }
        Some(Kind::StringValue(s)) => Value::String(s.clone()),
        Some(Kind::BoolValue(b)) => Value::Bool(*b),
        Some(Kind::StructValue(s)) => prost_struct_to_json(s),
        Some(Kind::ListValue(l)) => {
            Value::Array(l.values.iter().map(prost_value_to_json).collect())
        }
    }
}

/// Converts a JSON value into a protobuf `Struct`. Non-object values yield an empty struct.
pub fn json_to_prost_struct(val: &Value) -> prost_types::Struct {
    let fields = match val {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| (k.clone(), json_to_prost_value(v)))
            .collect(),
        _ => std::collections::BTreeMap::new(),
    };
    prost_types::Struct { fields }
}

pub fn json_to_prost_value(val: &Value) -> prost_types::Value {
    let kind = match val {
        Value::Null => Kind::NullValue(0),
        Value::Bool(b) => Kind::BoolValue(*b),
        Value::Number(n) => Kind::NumberValue(n.as_f64().unwrap_or(0.0)),
        Value::String(s) => Kind::StringValue(s.clone()),
        Value::Array(arr) => Kind::ListValue(prost_types::ListValue {
            values: arr.iter().map(json_to_prost_value).collect(),
        }),
        Value::Object(_) => Kind::StructValue(json_to_prost_struct(val)),
    };
    prost_types::Value { kind: Some(kind) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_and_prost_struct_round_trip() {
        let original = json!({
            "s": "x", "b": true, "n": 1.5, "null": null,
            "list": [1.0, "two"], "nested": {"k": "v"}
        });
        assert_eq!(
            prost_struct_to_json(&json_to_prost_struct(&original)),
            original
        );
    }

    #[test]
    fn empty_proto_strings_become_none() {
        let subject: AuthzenSubject = Subject {
            r#type: "User".into(),
            id: String::new(),
            properties: None,
        }
        .into();
        assert_eq!(subject.id, None);
    }
}
