use std::collections::BTreeMap;
use tonic::{Request, Response, Status};

use crate::auth::{verify_space_access, extract_space_id_from_native_token, extract_bearer_or_raw, SPACE_TOKEN_HEADER, AUTHORIZATION_HEADER};
use crate::authzen::{
    AuthzenAction, AuthzenBatchItemRequest, AuthzenBatchRequest, AuthzenResource, AuthzenSubject,
    evaluate_authzen, evaluate_authzen_batch,
};
use crate::authzen_pb::{
    AccessEvaluationBatchRequest, AccessEvaluationBatchResponse, EvaluationItemResponse,
    EvaluationRequest, EvaluationResponse,
    authorization_service_server::AuthorizationService,
};
use crate::store::Store;

#[derive(Clone)]
pub struct AuthzenGrpcService {
    store: Store,
    admin_token: String,
}

impl AuthzenGrpcService {
    pub fn new(store: Store, admin_token: impl Into<String>) -> Self {
        Self {
            store,
            admin_token: admin_token.into(),
        }
    }

    async fn authenticate_space(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        req_space_id: &str,
    ) -> Result<String, Status> {
        let space_id = if !req_space_id.trim().is_empty() {
            req_space_id.trim().to_string()
        } else {
            // Try to infer from token
            let token = metadata
                .get(SPACE_TOKEN_HEADER)
                .or_else(|| metadata.get(AUTHORIZATION_HEADER))
                .and_then(|v| v.to_str().ok())
                .map(extract_bearer_or_raw);

            if let Some(tok) = token {
                if let Some(sid) = extract_space_id_from_native_token(tok) {
                    sid.to_string()
                } else {
                    return Err(Status::invalid_argument("space_id is required in request or token"));
                }
            } else {
                return Err(Status::unauthenticated("Missing authentication token"));
            }
        };

        verify_space_access(metadata, &self.store, &self.admin_token, &space_id)
            .await
            .map_err(|e| Status::permission_denied(e.to_string()))?;

        Ok(space_id)
    }
}

#[tonic::async_trait]
impl AuthorizationService for AuthzenGrpcService {
    async fn access_evaluation(
        &self,
        request: Request<EvaluationRequest>,
    ) -> Result<Response<EvaluationResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();

        let space_id = self.authenticate_space(&metadata, &req.space_id).await?;

        let subject_proto = req
            .subject
            .ok_or_else(|| Status::invalid_argument("subject is required"))?;
        let action_proto = req
            .action
            .ok_or_else(|| Status::invalid_argument("action is required"))?;
        let resource_proto = req
            .resource
            .ok_or_else(|| Status::invalid_argument("resource is required"))?;

        let subject = AuthzenSubject {
            subject_type: subject_proto.r#type,
            id: Some(subject_proto.id),
            properties: subject_proto.properties.map(|p| prost_struct_to_json(&p)),
        };

        let action = AuthzenAction {
            name: Some(action_proto.name),
            properties: action_proto.properties.map(|p| prost_struct_to_json(&p)),
        };

        let resource = AuthzenResource {
            resource_type: resource_proto.r#type,
            id: Some(resource_proto.id),
            properties: resource_proto.properties.map(|p| prost_struct_to_json(&p)),
        };

        let context = req.context.as_ref().map(prost_struct_to_json);

        let outcome = evaluate_authzen(
            &self.store,
            &space_id,
            &subject,
            &action,
            &resource,
            context.as_ref(),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let context_proto = outcome.context.map(|c| json_to_prost_struct(&c));

        Ok(Response::new(EvaluationResponse {
            decision: outcome.decision,
            context: context_proto,
        }))
    }

    async fn access_evaluation_batch(
        &self,
        request: Request<AccessEvaluationBatchRequest>,
    ) -> Result<Response<AccessEvaluationBatchResponse>, Status> {
        let metadata = request.metadata().clone();
        let req = request.into_inner();

        let space_id = self.authenticate_space(&metadata, &req.space_id).await?;

        let default_subject = req.subject.map(|s| AuthzenSubject {
            subject_type: s.r#type,
            id: if s.id.is_empty() { None } else { Some(s.id) },
            properties: s.properties.map(|p| prost_struct_to_json(&p)),
        });

        let default_action = req.action.map(|a| AuthzenAction {
            name: if a.name.is_empty() { None } else { Some(a.name) },
            properties: a.properties.map(|p| prost_struct_to_json(&p)),
        });

        let default_resource = req.resource.map(|r| AuthzenResource {
            resource_type: r.r#type,
            id: if r.id.is_empty() { None } else { Some(r.id) },
            properties: r.properties.map(|p| prost_struct_to_json(&p)),
        });

        let default_context = req.context.as_ref().map(prost_struct_to_json);

        let mut evaluations = Vec::with_capacity(req.evaluations.len());
        for item in req.evaluations {
            evaluations.push(AuthzenBatchItemRequest {
                id: if item.id.is_empty() { None } else { Some(item.id) },
                subject: item.subject.map(|s| AuthzenSubject {
                    subject_type: s.r#type,
                    id: if s.id.is_empty() { None } else { Some(s.id) },
                    properties: s.properties.map(|p| prost_struct_to_json(&p)),
                }),
                action: item.action.map(|a| AuthzenAction {
                    name: if a.name.is_empty() { None } else { Some(a.name) },
                    properties: a.properties.map(|p| prost_struct_to_json(&p)),
                }),
                resource: item.resource.map(|r| AuthzenResource {
                    resource_type: r.r#type,
                    id: if r.id.is_empty() { None } else { Some(r.id) },
                    properties: r.properties.map(|p| prost_struct_to_json(&p)),
                }),
                context: item.context.as_ref().map(prost_struct_to_json),
            });
        }

        let batch_req = AuthzenBatchRequest {
            space_id: Some(space_id.clone()),
            subject: default_subject,
            action: default_action,
            resource: default_resource,
            context: default_context,
            evaluations,
        };

        let batch_outcome = evaluate_authzen_batch(&self.store, &space_id, &batch_req)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut out_items = Vec::with_capacity(batch_outcome.evaluations.len());
        for res in batch_outcome.evaluations {
            out_items.push(EvaluationItemResponse {
                id: res.id.unwrap_or_default(),
                decision: res.decision,
                context: res.context.map(|c| json_to_prost_struct(&c)),
            });
        }

        Ok(Response::new(AccessEvaluationBatchResponse {
            evaluations: out_items,
        }))
    }
}

// ============================================================================
// Prost Struct <-> JSON Converters
// ============================================================================

pub fn prost_struct_to_json(s: &prost_types::Struct) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (k, v) in &s.fields {
        map.insert(k.clone(), prost_value_to_json(v));
    }
    serde_json::Value::Object(map)
}

pub fn prost_value_to_json(v: &prost_types::Value) -> serde_json::Value {
    match &v.kind {
        Some(prost_types::value::Kind::NullValue(_)) => serde_json::Value::Null,
        Some(prost_types::value::Kind::NumberValue(n)) => {
            if let Some(num) = serde_json::Number::from_f64(*n) {
                serde_json::Value::Number(num)
            } else {
                serde_json::Value::Null
            }
        }
        Some(prost_types::value::Kind::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(prost_types::value::Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(prost_types::value::Kind::StructValue(s)) => prost_struct_to_json(s),
        Some(prost_types::value::Kind::ListValue(l)) => {
            serde_json::Value::Array(l.values.iter().map(prost_value_to_json).collect())
        }
        None => serde_json::Value::Null,
    }
}

pub fn json_to_prost_struct(val: &serde_json::Value) -> prost_types::Struct {
    let mut fields = BTreeMap::new();
    if let serde_json::Value::Object(map) = val {
        for (k, v) in map {
            fields.insert(k.clone(), json_to_prost_value(v));
        }
    }
    prost_types::Struct { fields }
}

pub fn json_to_prost_value(val: &serde_json::Value) -> prost_types::Value {
    let kind = match val {
        serde_json::Value::Null => prost_types::value::Kind::NullValue(0),
        serde_json::Value::Bool(b) => prost_types::value::Kind::BoolValue(*b),
        serde_json::Value::Number(n) => {
            prost_types::value::Kind::NumberValue(n.as_f64().unwrap_or(0.0))
        }
        serde_json::Value::String(s) => prost_types::value::Kind::StringValue(s.clone()),
        serde_json::Value::Array(arr) => {
            prost_types::value::Kind::ListValue(prost_types::ListValue {
                values: arr.iter().map(json_to_prost_value).collect(),
            })
        }
        serde_json::Value::Object(map) => {
            let mut fields = BTreeMap::new();
            for (k, v) in map {
                fields.insert(k.clone(), json_to_prost_value(v));
            }
            prost_types::value::Kind::StructValue(prost_types::Struct { fields })
        }
    };
    prost_types::Value { kind: Some(kind) }
}
