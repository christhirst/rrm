use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::cedar_engine::{EvaluationInput, evaluate_authorization};
use crate::error::AppError;
use crate::models::{EntityRef, StoredEntity};
use crate::store::Store;

// ============================================================================
// AuthZEN Data Structures (OpenID AuthZEN Authorization API 1.0)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthzenSubject {
    #[serde(rename = "type")]
    pub subject_type: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthzenAction {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthzenResource {
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzenEvaluationRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    pub subject: AuthzenSubject,
    pub action: AuthzenAction,
    pub resource: AuthzenResource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzenEvaluationResponse {
    pub decision: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzenBatchItemRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<AuthzenSubject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<AuthzenAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<AuthzenResource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzenBatchRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<AuthzenSubject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<AuthzenAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<AuthzenResource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
    pub evaluations: Vec<AuthzenBatchItemRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzenBatchItemResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub decision: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzenBatchResponse {
    pub evaluations: Vec<AuthzenBatchItemResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzenDiscovery {
    pub policy_decision_point: String,
    pub access_evaluation_endpoint: String,
    pub access_evaluations_endpoint: String,
}

// ============================================================================
// AuthZEN <-> Cedar Engine Adapter
// ============================================================================

/// Evaluates a single AuthZEN authorization request against Cedar policies in the given space.
pub async fn evaluate_authzen(
    store: &Store,
    space_id: &str,
    subject: &AuthzenSubject,
    action: &AuthzenAction,
    resource: &AuthzenResource,
    context: Option<&Value>,
) -> Result<AuthzenEvaluationResponse, AppError> {
    if space_id.trim().is_empty() {
        return Err(AppError::InvalidArgument("space_id cannot be empty".to_string()));
    }

    let subject_id = subject
        .id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| AppError::InvalidArgument("Subject id cannot be empty".to_string()))?;

    let action_name = action
        .name
        .as_deref()
        .filter(|a| !a.trim().is_empty())
        .ok_or_else(|| AppError::InvalidArgument("Action name cannot be empty".to_string()))?;

    let resource_id = resource
        .id
        .as_deref()
        .filter(|r| !r.trim().is_empty())
        .ok_or_else(|| AppError::InvalidArgument("Resource id cannot be empty".to_string()))?;

    let principal_ref = EntityRef {
        entity_type: subject.subject_type.clone(),
        entity_id: subject_id.to_string(),
    };

    let action_ref = if action_name.contains("::") {
        let parts: Vec<&str> = action_name.splitn(2, "::").collect();
        EntityRef {
            entity_type: parts[0].to_string(),
            entity_id: parts[1].replace('"', ""),
        }
    } else {
        EntityRef {
            entity_type: "Action".to_string(),
            entity_id: action_name.to_string(),
        }
    };

    let resource_ref = EntityRef {
        entity_type: resource.resource_type.clone(),
        entity_id: resource_id.to_string(),
    };

    let mut additional_entities = Vec::new();

    // Map subject properties into Cedar transient entity attributes (ABAC)
    if let Some(ref props) = subject.properties {
        additional_entities.push(StoredEntity {
            space_id: space_id.to_string(),
            entity_type: subject.subject_type.clone(),
            entity_id: subject_id.to_string(),
            parents: Vec::new(),
            attributes_json: props.to_string(),
            updated_at: String::new(),
        });
    }

    // Map resource properties into Cedar transient entity attributes (ABAC)
    if let Some(ref props) = resource.properties {
        additional_entities.push(StoredEntity {
            space_id: space_id.to_string(),
            entity_type: resource.resource_type.clone(),
            entity_id: resource_id.to_string(),
            parents: Vec::new(),
            attributes_json: props.to_string(),
            updated_at: String::new(),
        });
    }

    let context_json = match context {
        Some(v) => v.to_string(),
        None => "{}".to_string(),
    };

    let policies = store.list_policies(space_id).await?;
    let users = store.list_users(space_id).await?;
    let stored_entities = store.list_entities(space_id, None).await?;

    let outcome = evaluate_authorization(&EvaluationInput {
        principal: &principal_ref,
        action: &action_ref,
        resource: &resource_ref,
        context_json: &context_json,
        policies: &policies,
        users: &users,
        stored_entities: &stored_entities,
        additional_entities: &additional_entities,
    })?;

    let reason = if outcome.allowed {
        if outcome.determining_policies.is_empty() {
            "Explicit permit".to_string()
        } else {
            format!("Permitted by policies: {:?}", outcome.determining_policies)
        }
    } else if !outcome.errors.is_empty() {
        format!("Evaluation errors: {:?}", outcome.errors)
    } else {
        "Access denied by policy or default deny".to_string()
    };

    let resp_context = json!({
        "reason": reason,
        "determining_policies": outcome.determining_policies,
        "errors": outcome.errors,
    });

    Ok(AuthzenEvaluationResponse {
        decision: outcome.allowed,
        context: Some(resp_context),
    })
}

/// Evaluates a batch of AuthZEN requests against Cedar policies in the given space,
/// correctly inheriting and merging defaults from the top-level batch request.
pub async fn evaluate_authzen_batch(
    store: &Store,
    space_id: &str,
    batch: &AuthzenBatchRequest,
) -> Result<AuthzenBatchResponse, AppError> {
    let mut results = Vec::with_capacity(batch.evaluations.len());

    for item in &batch.evaluations {
        // Resolve effective subject
        let subject_type = item
            .subject
            .as_ref()
            .map(|s| &s.subject_type)
            .filter(|t| !t.trim().is_empty())
            .or_else(|| batch.subject.as_ref().map(|s| &s.subject_type))
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| {
                AppError::InvalidArgument("Subject type missing in batch item and default".to_string())
            })?;

        let subject_id = item
            .subject
            .as_ref()
            .and_then(|s| s.id.as_deref())
            .filter(|id| !id.trim().is_empty())
            .or_else(|| batch.subject.as_ref().and_then(|s| s.id.as_deref()))
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| {
                AppError::InvalidArgument("Subject id missing in batch item and default".to_string())
            })?;

        let subject_props = merge_properties(
            batch.subject.as_ref().and_then(|s| s.properties.as_ref()),
            item.subject.as_ref().and_then(|s| s.properties.as_ref()),
        );

        let effective_subject = AuthzenSubject {
            subject_type: subject_type.to_string(),
            id: Some(subject_id.to_string()),
            properties: subject_props,
        };

        // Resolve effective action
        let action_name = item
            .action
            .as_ref()
            .and_then(|a| a.name.as_deref())
            .filter(|n| !n.trim().is_empty())
            .or_else(|| batch.action.as_ref().and_then(|a| a.name.as_deref()))
            .filter(|n| !n.trim().is_empty())
            .ok_or_else(|| {
                AppError::InvalidArgument("Action name missing in batch item and default".to_string())
            })?;

        let action_props = merge_properties(
            batch.action.as_ref().and_then(|a| a.properties.as_ref()),
            item.action.as_ref().and_then(|a| a.properties.as_ref()),
        );

        let effective_action = AuthzenAction {
            name: Some(action_name.to_string()),
            properties: action_props,
        };

        // Resolve effective resource
        let resource_type = item
            .resource
            .as_ref()
            .map(|r| &r.resource_type)
            .filter(|t| !t.trim().is_empty())
            .or_else(|| batch.resource.as_ref().map(|r| &r.resource_type))
            .filter(|t| !t.trim().is_empty())
            .ok_or_else(|| {
                AppError::InvalidArgument("Resource type missing in batch item and default".to_string())
            })?;

        let resource_id = item
            .resource
            .as_ref()
            .and_then(|r| r.id.as_deref())
            .filter(|id| !id.trim().is_empty())
            .or_else(|| batch.resource.as_ref().and_then(|r| r.id.as_deref()))
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| {
                AppError::InvalidArgument("Resource id missing in batch item and default".to_string())
            })?;

        let resource_props = merge_properties(
            batch.resource.as_ref().and_then(|r| r.properties.as_ref()),
            item.resource.as_ref().and_then(|r| r.properties.as_ref()),
        );

        let effective_resource = AuthzenResource {
            resource_type: resource_type.to_string(),
            id: Some(resource_id.to_string()),
            properties: resource_props,
        };

        let effective_context = merge_properties(batch.context.as_ref(), item.context.as_ref());

        let res = evaluate_authzen(
            store,
            space_id,
            &effective_subject,
            &effective_action,
            &effective_resource,
            effective_context.as_ref(),
        )
        .await?;

        results.push(AuthzenBatchItemResponse {
            id: item.id.clone(),
            decision: res.decision,
            context: res.context,
        });
    }

    Ok(AuthzenBatchResponse {
        evaluations: results,
    })
}

fn merge_properties(base: Option<&Value>, override_val: Option<&Value>) -> Option<Value> {
    match (base, override_val) {
        (None, None) => None,
        (Some(b), None) => Some(b.clone()),
        (None, Some(o)) => Some(o.clone()),
        (Some(Value::Object(b_map)), Some(Value::Object(o_map))) => {
            let mut merged = b_map.clone();
            for (k, v) in o_map {
                merged.insert(k.clone(), v.clone());
            }
            Some(Value::Object(merged))
        }
        (_, Some(o)) => Some(o.clone()),
    }
}
