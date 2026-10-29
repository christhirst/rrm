use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid, Policy,
    PolicyId, PolicySet, Request, RestrictedExpression,
};
use serde_json::Value;

use crate::error::AppError;
use crate::models::{EntityRef, StoredEntity, StoredPolicy, StoredUser};

#[derive(Debug, Clone)]
pub struct EvaluationInput<'a> {
    pub principal: &'a EntityRef,
    pub action: &'a EntityRef,
    pub resource: &'a EntityRef,
    pub context_json: &'a str,
    pub policies: &'a [StoredPolicy],
    pub users: &'a [StoredUser],
    pub stored_entities: &'a [StoredEntity],
    pub additional_entities: &'a [StoredEntity],
}

#[derive(Debug, Clone)]
pub struct EvaluationOutcome {
    pub allowed: bool,
    pub decision: Decision,
    pub determining_policies: Vec<String>,
    pub errors: Vec<String>,
}

/// Parses an `EntityUid` from `entity_type` (e.g. `"User"`, `"App::Document"`)
/// and `entity_id` (e.g. `"alice"`).
pub fn parse_entity_uid(entity_type: &str, entity_id: &str) -> Result<EntityUid, AppError> {
    if entity_type.trim().is_empty() {
        return Err(AppError::InvalidArgument(
            "entity_type cannot be empty".to_string(),
        ));
    }
    let type_name = EntityTypeName::from_str(entity_type.trim()).map_err(|e| {
        AppError::InvalidArgument(format!("Invalid Cedar entity type '{entity_type}': {e}"))
    })?;
    let id = EntityId::from_str(entity_id).map_err(|e| {
        AppError::InvalidArgument(format!("Invalid Cedar entity id '{entity_id}': {e}"))
    })?;
    Ok(EntityUid::from_type_name_and_id(type_name, id))
}

/// Validates and parses a single Cedar policy with a given `policy_id`.
pub fn validate_and_parse_policy(policy_id: &str, cedar_text: &str) -> Result<Policy, AppError> {
    if policy_id.trim().is_empty() {
        return Err(AppError::InvalidArgument(
            "policy_id cannot be empty".to_string(),
        ));
    }
    if cedar_text.trim().is_empty() {
        return Err(AppError::InvalidArgument(
            "cedar_text cannot be empty".to_string(),
        ));
    }
    Policy::parse(Some(PolicyId::new(policy_id)), cedar_text)
        .map_err(|e| AppError::CedarPolicy(format!("Invalid Cedar policy '{policy_id}': {e}")))
}

/// Builds a `PolicySet` from the stored policies of a space.
pub fn build_policy_set(policies: &[StoredPolicy]) -> Result<PolicySet, AppError> {
    let mut policy_set = PolicySet::new();
    for stored in policies {
        let policy = validate_and_parse_policy(&stored.policy_id, &stored.cedar_text)?;
        policy_set.add(policy).map_err(|e| {
            AppError::CedarPolicy(format!(
                "Failed to add policy '{}' to PolicySet: {e}",
                stored.policy_id
            ))
        })?;
    }
    Ok(policy_set)
}

/// Converts a `serde_json::Value` into a Cedar `RestrictedExpression`.
///
/// Supported JSON representations:
/// - `bool` -> `RestrictedExpression::new_bool`
/// - `i64` -> `RestrictedExpression::new_long`
/// - `string` -> `RestrictedExpression::new_string`
/// - `array` -> `RestrictedExpression::new_set`
/// - `{"__entity": {"type": "User", "id": "alice"}}` -> `RestrictedExpression::new_entity_uid`
/// - `{"__ip": "10.0.0.1"}` -> `RestrictedExpression::new_ip`
/// - `{"__decimal": "12.34"}` -> `RestrictedExpression::new_decimal`
/// - `{"__datetime": "2026-01-01T00:00:00Z"}` -> `RestrictedExpression::new_datetime`
/// - general JSON `object` -> `RestrictedExpression::new_record`
pub fn json_value_to_restricted_expr(value: &Value) -> Result<RestrictedExpression, AppError> {
    match value {
        Value::Bool(b) => Ok(RestrictedExpression::new_bool(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(RestrictedExpression::new_long(i))
            } else {
                Err(AppError::InvalidArgument(format!(
                    "Cedar integer attributes require 64-bit signed integers; got '{n}' (use {{\"__decimal\": \"{n}\"}} for decimals)"
                )))
            }
        }
        Value::String(s) => Ok(RestrictedExpression::new_string(s.clone())),
        Value::Array(items) => {
            let mut exprs = Vec::with_capacity(items.len());
            for item in items {
                exprs.push(json_value_to_restricted_expr(item)?);
            }
            Ok(RestrictedExpression::new_set(exprs))
        }
        Value::Object(map) => {
            if map.len() == 1 {
                if let Some(Value::Object(entity_obj)) = map.get("__entity")
                    && let (Some(Value::String(t)), Some(Value::String(id))) =
                        (entity_obj.get("type"), entity_obj.get("id"))
                {
                    let uid = parse_entity_uid(t, id)?;
                    return Ok(RestrictedExpression::new_entity_uid(uid));
                }
                if let Some(Value::String(ip_str)) = map.get("__ip") {
                    return Ok(RestrictedExpression::new_ip(ip_str));
                }
                if let Some(Value::String(dec_str)) = map.get("__decimal") {
                    return Ok(RestrictedExpression::new_decimal(dec_str));
                }
                if let Some(Value::String(dt_str)) = map.get("__datetime") {
                    return Ok(RestrictedExpression::new_datetime(dt_str));
                }
            }

            let mut fields = Vec::with_capacity(map.len());
            for (k, v) in map {
                if v.is_null() {
                    continue;
                }
                fields.push((k.clone(), json_value_to_restricted_expr(v)?));
            }
            RestrictedExpression::new_record(fields).map_err(|e| {
                AppError::InvalidArgument(format!("Failed to construct Cedar record: {e}"))
            })
        }
        Value::Null => Err(AppError::InvalidArgument(
            "Cedar attributes cannot be top-level null".to_string(),
        )),
    }
}

/// Parses a JSON object string into a map of Cedar `RestrictedExpression`s.
pub fn parse_attributes_json(
    attributes_json: &str,
) -> Result<HashMap<String, RestrictedExpression>, AppError> {
    let trimmed = attributes_json.trim();
    if trimmed.is_empty() {
        return Ok(HashMap::new());
    }

    let parsed: Value = serde_json::from_str(trimmed).map_err(|e| {
        AppError::InvalidArgument(format!("Invalid JSON in attributes/context: {e}"))
    })?;

    let Value::Object(map) = parsed else {
        return Err(AppError::InvalidArgument(
            "Attributes and context JSON must be a JSON object".to_string(),
        ));
    };

    let mut out = HashMap::with_capacity(map.len());
    for (k, v) in map {
        if v.is_null() {
            continue;
        }
        out.insert(k, json_value_to_restricted_expr(&v)?);
    }
    Ok(out)
}

/// Builds a Cedar `Context` from an optional JSON object string.
pub fn build_context(context_json: &str) -> Result<Context, AppError> {
    let attrs = parse_attributes_json(context_json)?;
    if attrs.is_empty() {
        return Ok(Context::empty());
    }
    Context::from_pairs(attrs)
        .map_err(|e| AppError::InvalidArgument(format!("Invalid Cedar context: {e}")))
}

/// Combines SurrealDB `StoredUser` records, `StoredEntity` records, and transient
/// request-time entities into a Cedar `Entities` graph.
pub fn build_entities(
    users: &[StoredUser],
    stored_entities: &[StoredEntity],
    additional_entities: &[StoredEntity],
) -> Result<Entities, AppError> {
    let mut entity_map: HashMap<EntityUid, Entity> = HashMap::new();
    let mut referenced_parents: HashSet<EntityUid> = HashSet::new();

    // 1. Add generic stored entities first
    for item in stored_entities.iter().chain(additional_entities.iter()) {
        let uid = parse_entity_uid(&item.entity_type, &item.entity_id)?;
        let attrs = parse_attributes_json(&item.attributes_json)?;
        let mut parents = HashSet::with_capacity(item.parents.len());
        for parent_ref in &item.parents {
            let parent_uid = parse_entity_uid(&parent_ref.entity_type, &parent_ref.entity_id)?;
            referenced_parents.insert(parent_uid.clone());
            parents.insert(parent_uid);
        }

        let entity = Entity::new(uid.clone(), attrs, parents).map_err(|e| {
            AppError::CedarPolicy(format!("Failed to construct entity '{uid}': {e}"))
        })?;
        entity_map.insert(uid, entity);
    }

    // 2. Project StoredUser records into `User::"<user_id>"` entities
    for user in users {
        let uid = parse_entity_uid("User", &user.user_id)?;
        let mut attrs = parse_attributes_json(&user.attributes_json)?;
        if !user.email.is_empty() {
            attrs
                .entry("email".to_string())
                .or_insert_with(|| RestrictedExpression::new_string(user.email.clone()));
        }
        attrs.entry("roles".to_string()).or_insert_with(|| {
            RestrictedExpression::new_set(
                user.roles
                    .iter()
                    .cloned()
                    .map(RestrictedExpression::new_string),
            )
        });
        attrs.entry("groups".to_string()).or_insert_with(|| {
            RestrictedExpression::new_set(
                user.groups
                    .iter()
                    .cloned()
                    .map(RestrictedExpression::new_string),
            )
        });

        let mut parents = HashSet::new();
        for role in &user.roles {
            if !role.trim().is_empty() {
                let role_uid = parse_entity_uid("Role", role)?;
                referenced_parents.insert(role_uid.clone());
                parents.insert(role_uid);
            }
        }
        for group in &user.groups {
            if !group.trim().is_empty() {
                let group_uid = parse_entity_uid("Group", group)?;
                referenced_parents.insert(group_uid.clone());
                parents.insert(group_uid);
            }
        }

        let entity = Entity::new(uid.clone(), attrs, parents).map_err(|e| {
            AppError::CedarPolicy(format!("Failed to construct user entity '{uid}': {e}"))
        })?;
        entity_map.insert(uid, entity);
    }

    // 3. Ensure any parent EntityUid referenced by a User or Entity exists in the graph
    for parent_uid in referenced_parents {
        entity_map
            .entry(parent_uid.clone())
            .or_insert_with(|| Entity::with_uid(parent_uid));
    }

    Entities::from_entities(entity_map.into_values(), None)
        .map_err(|e| AppError::CedarPolicy(format!("Failed to build Cedar entity graph: {e}")))
}

/// Evaluates an authorization request against the space's policies and entities.
pub fn evaluate_authorization(input: &EvaluationInput<'_>) -> Result<EvaluationOutcome, AppError> {
    let principal = parse_entity_uid(&input.principal.entity_type, &input.principal.entity_id)?;
    let action = parse_entity_uid(&input.action.entity_type, &input.action.entity_id)?;
    let resource = parse_entity_uid(&input.resource.entity_type, &input.resource.entity_id)?;
    let context = build_context(input.context_json)?;

    let request = Request::new(principal, action, resource, context, None).map_err(|e| {
        AppError::InvalidArgument(format!("Failed to construct Cedar request: {e}"))
    })?;

    let policy_set = build_policy_set(input.policies)?;
    let entities = build_entities(
        input.users,
        input.stored_entities,
        input.additional_entities,
    )?;

    let authorizer = Authorizer::new();
    let response = authorizer.is_authorized(&request, &policy_set, &entities);

    let decision = response.decision();
    let allowed = decision == Decision::Allow;
    let determining_policies = response
        .diagnostics()
        .reason()
        .map(ToString::to_string)
        .collect();
    let errors = response
        .diagnostics()
        .errors()
        .map(ToString::to_string)
        .collect();

    Ok(EvaluationOutcome {
        allowed,
        decision,
        determining_policies,
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_rbac_and_abac_with_user_and_resource_should_allow_and_deny_appropriately() {
        let policies = vec![
            StoredPolicy {
                space_id: "billing".to_string(),
                policy_id: "allow-editors-same-dept".to_string(),
                description: "Editors in the same department can edit documents".to_string(),
                cedar_text: r#"
                    permit(
                        principal in Role::"editor",
                        action == Action::"edit",
                        resource is Document
                    ) when {
                        principal.department == resource.department
                    };
                "#
                .to_string(),
                updated_at: "1".to_string(),
            },
            StoredPolicy {
                space_id: "billing".to_string(),
                policy_id: "forbid-archived".to_string(),
                description: "Cannot edit archived documents".to_string(),
                cedar_text: r#"
                    forbid(
                        principal,
                        action == Action::"edit",
                        resource is Document
                    ) when {
                        resource.archived == true
                    };
                "#
                .to_string(),
                updated_at: "1".to_string(),
            },
        ];

        let users = vec![StoredUser {
            space_id: "billing".to_string(),
            user_id: "alice".to_string(),
            email: "alice@example.com".to_string(),
            roles: vec!["editor".to_string()],
            groups: vec!["engineering".to_string()],
            attributes_json: r#"{"department": "finance", "clearance": 5}"#.to_string(),
            updated_at: "1".to_string(),
        }];

        let entities = vec![
            StoredEntity {
                space_id: "billing".to_string(),
                entity_type: "Document".to_string(),
                entity_id: "report-q1".to_string(),
                parents: vec![],
                attributes_json: r#"{"department": "finance", "archived": false}"#.to_string(),
                updated_at: "1".to_string(),
            },
            StoredEntity {
                space_id: "billing".to_string(),
                entity_type: "Document".to_string(),
                entity_id: "report-archived".to_string(),
                parents: vec![],
                attributes_json: r#"{"department": "finance", "archived": true}"#.to_string(),
                updated_at: "1".to_string(),
            },
        ];

        let outcome_allow = evaluate_authorization(&EvaluationInput {
            principal: &EntityRef {
                entity_type: "User".to_string(),
                entity_id: "alice".to_string(),
            },
            action: &EntityRef {
                entity_type: "Action".to_string(),
                entity_id: "edit".to_string(),
            },
            resource: &EntityRef {
                entity_type: "Document".to_string(),
                entity_id: "report-q1".to_string(),
            },
            context_json: "{}",
            policies: &policies,
            users: &users,
            stored_entities: &entities,
            additional_entities: &[],
        })
        .expect("evaluation should succeed");

        assert!(outcome_allow.allowed);
        assert_eq!(
            outcome_allow.determining_policies,
            vec!["allow-editors-same-dept".to_string()]
        );

        let outcome_deny = evaluate_authorization(&EvaluationInput {
            principal: &EntityRef {
                entity_type: "User".to_string(),
                entity_id: "alice".to_string(),
            },
            action: &EntityRef {
                entity_type: "Action".to_string(),
                entity_id: "edit".to_string(),
            },
            resource: &EntityRef {
                entity_type: "Document".to_string(),
                entity_id: "report-archived".to_string(),
            },
            context_json: "{}",
            policies: &policies,
            users: &users,
            stored_entities: &entities,
            additional_entities: &[],
        })
        .expect("evaluation should succeed");

        assert!(!outcome_deny.allowed);
        assert_eq!(
            outcome_deny.determining_policies,
            vec!["forbid-archived".to_string()]
        );
    }
}
