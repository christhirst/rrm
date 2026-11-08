use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::cedar_engine::{AuthorizationQuery, PreparedSpace};
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

/// Evaluates a single `AuthZEN` authorization request against Cedar policies in the given space.
pub async fn evaluate_authzen(
    store: &Store,
    space_id: &str,
    subject: &AuthzenSubject,
    action: &AuthzenAction,
    resource: &AuthzenResource,
    context: Option<&Value>,
) -> Result<AuthzenEvaluationResponse, AppError> {
    let space = load_space(store, space_id).await?;
    evaluate_prepared(&space, space_id, subject, action, resource, context)
}

/// Evaluates a batch of `AuthZEN` requests against Cedar policies in the given space,
/// inheriting and merging defaults from the top-level batch request.
///
/// The space's policies and entities are loaded and parsed once for the whole batch.
pub async fn evaluate_authzen_batch(
    store: &Store,
    space_id: &str,
    batch: &AuthzenBatchRequest,
) -> Result<AuthzenBatchResponse, AppError> {
    if batch.evaluations.is_empty() {
        return Ok(AuthzenBatchResponse {
            evaluations: Vec::new(),
        });
    }

    let space = load_space(store, space_id).await?;

    let evaluations = batch
        .evaluations
        .iter()
        .map(|item| {
            let (subject, action, resource, context) = resolve_batch_item(batch, item)?;
            let res = evaluate_prepared(
                &space,
                space_id,
                &subject,
                &action,
                &resource,
                context.as_ref(),
            )?;
            Ok(AuthzenBatchItemResponse {
                id: item.id.clone(),
                decision: res.decision,
                context: res.context,
            })
        })
        .collect::<Result<_, AppError>>()?;

    Ok(AuthzenBatchResponse { evaluations })
}

async fn load_space(store: &Store, space_id: &str) -> Result<PreparedSpace, AppError> {
    if space_id.trim().is_empty() {
        return Err(AppError::invalid("space_id cannot be empty"));
    }
    let policies = store.list_policies(space_id).await?;
    let users = store.list_users(space_id).await?;
    let stored_entities = store.list_entities(space_id, None).await?;
    PreparedSpace::new(&policies, &users, &stored_entities)
}

fn non_blank(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.trim().is_empty())
}

fn require(value: Option<&str>, what: &str) -> Result<String, AppError> {
    non_blank(value)
        .map(str::to_owned)
        .ok_or_else(|| AppError::invalid(format!("{what} cannot be empty")))
}

/// Builds a transient Cedar entity carrying request-supplied properties (ABAC).
fn transient_entity(space_id: &str, entity: &EntityRef, props: &Value) -> StoredEntity {
    StoredEntity {
        space_id: space_id.to_string(),
        entity_type: entity.entity_type.clone(),
        entity_id: entity.entity_id.clone(),
        parents: Vec::new(),
        attributes_json: props.to_string(),
        updated_at: String::new(),
    }
}

/// Maps an `AuthZEN` action name to a Cedar action uid. Names may be fully
/// qualified (`Ns::Action::"read"`), otherwise they default to `Action::"<name>"`.
fn action_ref(action_name: &str) -> EntityRef {
    match action_name.split_once("::") {
        Some((entity_type, entity_id)) => EntityRef {
            entity_type: entity_type.to_string(),
            entity_id: entity_id.replace('"', ""),
        },
        None => EntityRef {
            entity_type: "Action".to_string(),
            entity_id: action_name.to_string(),
        },
    }
}

fn evaluate_prepared(
    space: &PreparedSpace,
    space_id: &str,
    subject: &AuthzenSubject,
    action: &AuthzenAction,
    resource: &AuthzenResource,
    context: Option<&Value>,
) -> Result<AuthzenEvaluationResponse, AppError> {
    let principal = EntityRef {
        entity_type: subject.subject_type.clone(),
        entity_id: require(subject.id.as_deref(), "Subject id")?,
    };
    let action_ref = action_ref(&require(action.name.as_deref(), "Action name")?);
    let resource_ref = EntityRef {
        entity_type: resource.resource_type.clone(),
        entity_id: require(resource.id.as_deref(), "Resource id")?,
    };

    // Map subject/resource properties into Cedar transient entity attributes (ABAC)
    let additional_entities: Vec<StoredEntity> = [
        (&principal, subject.properties.as_ref()),
        (&resource_ref, resource.properties.as_ref()),
    ]
    .into_iter()
    .filter_map(|(entity, props)| props.map(|p| transient_entity(space_id, entity, p)))
    .collect();

    let context_json = context.map_or_else(|| "{}".to_string(), ToString::to_string);

    let outcome = space.evaluate(&AuthorizationQuery {
        principal: &principal,
        action: &action_ref,
        resource: &resource_ref,
        context_json: &context_json,
        additional_entities: &additional_entities,
    })?;

    let reason = if outcome.allowed {
        if outcome.determining_policies.is_empty() {
            "Explicit permit".to_string()
        } else {
            format!("Permitted by policies: {:?}", outcome.determining_policies)
        }
    } else if outcome.errors.is_empty() {
        "Access denied by policy or default deny".to_string()
    } else {
        format!("Evaluation errors: {:?}", outcome.errors)
    };

    Ok(AuthzenEvaluationResponse {
        decision: outcome.allowed,
        context: Some(json!({
            "reason": reason,
            "determining_policies": outcome.determining_policies,
            "errors": outcome.errors,
        })),
    })
}

/// Picks the item value if non-blank, otherwise the batch default if non-blank.
fn pick<'a>(
    item: Option<&'a str>,
    default: Option<&'a str>,
    what: &str,
) -> Result<&'a str, AppError> {
    non_blank(item)
        .or_else(|| non_blank(default))
        .ok_or_else(|| AppError::invalid(format!("{what} missing in batch item and default")))
}

/// Resolves the effective subject, action, resource and context of a batch item
/// by inheriting missing fields from the batch-level defaults.
fn resolve_batch_item(
    batch: &AuthzenBatchRequest,
    item: &AuthzenBatchItemRequest,
) -> Result<
    (
        AuthzenSubject,
        AuthzenAction,
        AuthzenResource,
        Option<Value>,
    ),
    AppError,
> {
    let (item_s, batch_s) = (item.subject.as_ref(), batch.subject.as_ref());
    let subject = AuthzenSubject {
        subject_type: pick(
            item_s.map(|s| s.subject_type.as_str()),
            batch_s.map(|s| s.subject_type.as_str()),
            "Subject type",
        )?
        .to_string(),
        id: Some(
            pick(
                item_s.and_then(|s| s.id.as_deref()),
                batch_s.and_then(|s| s.id.as_deref()),
                "Subject id",
            )?
            .to_string(),
        ),
        properties: merge_properties(
            batch_s.and_then(|s| s.properties.as_ref()),
            item_s.and_then(|s| s.properties.as_ref()),
        ),
    };

    let (item_a, batch_a) = (item.action.as_ref(), batch.action.as_ref());
    let action = AuthzenAction {
        name: Some(
            pick(
                item_a.and_then(|a| a.name.as_deref()),
                batch_a.and_then(|a| a.name.as_deref()),
                "Action name",
            )?
            .to_string(),
        ),
        properties: merge_properties(
            batch_a.and_then(|a| a.properties.as_ref()),
            item_a.and_then(|a| a.properties.as_ref()),
        ),
    };

    let (item_r, batch_r) = (item.resource.as_ref(), batch.resource.as_ref());
    let resource = AuthzenResource {
        resource_type: pick(
            item_r.map(|r| r.resource_type.as_str()),
            batch_r.map(|r| r.resource_type.as_str()),
            "Resource type",
        )?
        .to_string(),
        id: Some(
            pick(
                item_r.and_then(|r| r.id.as_deref()),
                batch_r.and_then(|r| r.id.as_deref()),
                "Resource id",
            )?
            .to_string(),
        ),
        properties: merge_properties(
            batch_r.and_then(|r| r.properties.as_ref()),
            item_r.and_then(|r| r.properties.as_ref()),
        ),
    };

    let context = merge_properties(batch.context.as_ref(), item.context.as_ref());
    Ok((subject, action, resource, context))
}

/// Shallow-merges two JSON values: object keys from `override_val` win; any other
/// non-null override replaces the base entirely.
fn merge_properties(base: Option<&Value>, override_val: Option<&Value>) -> Option<Value> {
    match (base, override_val) {
        (Some(Value::Object(b_map)), Some(Value::Object(o_map))) => {
            let mut merged = b_map.clone();
            merged.extend(o_map.iter().map(|(k, v)| (k.clone(), v.clone())));
            Some(Value::Object(merged))
        }
        (_, Some(o)) => Some(o.clone()),
        (b, None) => b.cloned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_properties_overrides_keys_and_falls_back() {
        let base = json!({"a": 1, "b": 2});
        let over = json!({"b": 3, "c": 4});
        assert_eq!(
            merge_properties(Some(&base), Some(&over)),
            Some(json!({"a": 1, "b": 3, "c": 4}))
        );
        assert_eq!(merge_properties(Some(&base), None), Some(base.clone()));
        assert_eq!(merge_properties(None, Some(&over)), Some(over.clone()));
        assert_eq!(
            merge_properties(Some(&base), Some(&json!(5))),
            Some(json!(5))
        );
        assert_eq!(merge_properties(None, None), None);
    }

    #[test]
    fn action_ref_handles_plain_and_qualified_names() {
        assert_eq!(
            action_ref("read"),
            EntityRef {
                entity_type: "Action".into(),
                entity_id: "read".into()
            }
        );
        assert_eq!(
            action_ref(r#"App::Action::"read""#),
            EntityRef {
                entity_type: "App".into(),
                entity_id: "Action::read".into()
            }
        );
    }

    #[test]
    fn batch_items_inherit_and_override_defaults() {
        let batch: AuthzenBatchRequest = serde_json::from_value(json!({
            "subject": {"type": "User", "id": "alice", "properties": {"dept": "eng", "lvl": 1}},
            "action": {"name": "read"},
            "context": {"ip": "10.0.0.1"},
            "evaluations": [
                {"resource": {"type": "Document", "id": "d1"},
                 "subject": {"type": "", "properties": {"lvl": 2}}},
                {"resource": {"type": "Document"}}
            ]
        }))
        .unwrap();

        let (subject, action, resource, context) =
            resolve_batch_item(&batch, &batch.evaluations[0]).unwrap();
        assert_eq!(subject.subject_type, "User");
        assert_eq!(subject.id.as_deref(), Some("alice"));
        assert_eq!(subject.properties, Some(json!({"dept": "eng", "lvl": 2})));
        assert_eq!(action.name.as_deref(), Some("read"));
        assert_eq!(resource.id.as_deref(), Some("d1"));
        assert_eq!(context, Some(json!({"ip": "10.0.0.1"})));

        let err = resolve_batch_item(&batch, &batch.evaluations[1]).unwrap_err();
        assert!(err.to_string().contains("Resource id missing"));
    }
}
