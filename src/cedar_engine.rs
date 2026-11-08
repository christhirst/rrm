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

/// A single authorization request against an already prepared space.
#[derive(Debug, Clone, Copy)]
pub struct AuthorizationQuery<'a> {
    pub principal: &'a EntityRef,
    pub action: &'a EntityRef,
    pub resource: &'a EntityRef,
    pub context_json: &'a str,
    /// Transient request-time entities (override stored entities with the same uid).
    pub additional_entities: &'a [StoredEntity],
}

#[derive(Debug, Clone)]
pub struct EvaluationOutcome {
    pub allowed: bool,
    pub decision: Decision,
    pub determining_policies: Vec<String>,
    pub errors: Vec<String>,
}

impl EntityRef {
    /// Parses this reference into a Cedar `EntityUid`.
    pub fn to_uid(&self) -> Result<EntityUid, AppError> {
        parse_entity_uid(&self.entity_type, &self.entity_id)
    }
}

/// Parses an `EntityUid` from `entity_type` (e.g. `"User"`, `"App::Document"`)
/// and `entity_id` (e.g. `"alice"`).
pub fn parse_entity_uid(entity_type: &str, entity_id: &str) -> Result<EntityUid, AppError> {
    if entity_type.trim().is_empty() {
        return Err(AppError::invalid("entity_type cannot be empty"));
    }
    let type_name = EntityTypeName::from_str(entity_type.trim()).map_err(|e| {
        AppError::invalid(format!("Invalid Cedar entity type '{entity_type}': {e}"))
    })?;
    let id = EntityId::from_str(entity_id)
        .map_err(|e| AppError::invalid(format!("Invalid Cedar entity id '{entity_id}': {e}")))?;
    Ok(EntityUid::from_type_name_and_id(type_name, id))
}

/// Validates and parses a single Cedar policy with a given `policy_id`.
pub fn validate_and_parse_policy(policy_id: &str, cedar_text: &str) -> Result<Policy, AppError> {
    if policy_id.trim().is_empty() {
        return Err(AppError::invalid("policy_id cannot be empty"));
    }
    if cedar_text.trim().is_empty() {
        return Err(AppError::invalid("cedar_text cannot be empty"));
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
        Value::Number(n) => n.as_i64().map(RestrictedExpression::new_long).ok_or_else(|| {
            AppError::invalid(format!(
                "Cedar integer attributes require 64-bit signed integers; got '{n}' (use {{\"__decimal\": \"{n}\"}} for decimals)"
            ))
        }),
        Value::String(s) => Ok(RestrictedExpression::new_string(s.clone())),
        Value::Array(items) => items
            .iter()
            .map(json_value_to_restricted_expr)
            .collect::<Result<Vec<_>, _>>()
            .map(RestrictedExpression::new_set),
        Value::Object(map) => {
            if let Some(expr) = extension_value_to_restricted_expr(map)? {
                return Ok(expr);
            }
            let fields = map
                .iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| Ok((k.clone(), json_value_to_restricted_expr(v)?)))
                .collect::<Result<Vec<_>, AppError>>()?;
            RestrictedExpression::new_record(fields)
                .map_err(|e| AppError::invalid(format!("Failed to construct Cedar record: {e}")))
        }
        Value::Null => Err(AppError::invalid(
            "Cedar attributes cannot be top-level null",
        )),
    }
}

/// Recognizes the single-key escape objects (`__entity`, `__ip`, `__decimal`,
/// `__datetime`). Returns `Ok(None)` for ordinary records.
fn extension_value_to_restricted_expr(
    map: &serde_json::Map<String, Value>,
) -> Result<Option<RestrictedExpression>, AppError> {
    let mut entries = map.iter();
    let (Some((key, value)), None) = (entries.next(), entries.next()) else {
        return Ok(None);
    };
    let expr = match (key.as_str(), value) {
        ("__entity", Value::Object(entity_obj)) => {
            match (entity_obj.get("type"), entity_obj.get("id")) {
                (Some(Value::String(t)), Some(Value::String(id))) => {
                    RestrictedExpression::new_entity_uid(parse_entity_uid(t, id)?)
                }
                _ => return Ok(None),
            }
        }
        ("__ip", Value::String(s)) => RestrictedExpression::new_ip(s),
        ("__decimal", Value::String(s)) => RestrictedExpression::new_decimal(s),
        ("__datetime", Value::String(s)) => RestrictedExpression::new_datetime(s),
        _ => return Ok(None),
    };
    Ok(Some(expr))
}

/// Parses a JSON object string into a map of Cedar `RestrictedExpression`s.
pub fn parse_attributes_json(
    attributes_json: &str,
) -> Result<HashMap<String, RestrictedExpression>, AppError> {
    let trimmed = attributes_json.trim();
    if trimmed.is_empty() {
        return Ok(HashMap::new());
    }

    let parsed: Value = serde_json::from_str(trimmed)
        .map_err(|e| AppError::invalid(format!("Invalid JSON in attributes/context: {e}")))?;

    let Value::Object(map) = parsed else {
        return Err(AppError::invalid(
            "Attributes and context JSON must be a JSON object",
        ));
    };

    map.into_iter()
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| Ok((k, json_value_to_restricted_expr(&v)?)))
        .collect()
}

/// Builds a Cedar `Context` from an optional JSON object string.
pub fn build_context(context_json: &str) -> Result<Context, AppError> {
    let attrs = parse_attributes_json(context_json)?;
    if attrs.is_empty() {
        return Ok(Context::empty());
    }
    Context::from_pairs(attrs).map_err(|e| AppError::invalid(format!("Invalid Cedar context: {e}")))
}

/// Accumulates Cedar entities keyed by uid and remembers every referenced parent
/// so that missing parents can be materialized as attribute-less entities.
#[derive(Debug, Clone, Default)]
struct EntityGraph {
    entities: HashMap<EntityUid, Entity>,
    referenced_parents: HashSet<EntityUid>,
}

impl EntityGraph {
    fn insert(&mut self, entity: Entity) {
        self.entities.insert(entity.uid(), entity);
    }

    fn add_stored(&mut self, item: &StoredEntity) -> Result<(), AppError> {
        let uid = parse_entity_uid(&item.entity_type, &item.entity_id)?;
        let attrs = parse_attributes_json(&item.attributes_json)?;
        let parents = item
            .parents
            .iter()
            .map(EntityRef::to_uid)
            .collect::<Result<HashSet<_>, _>>()?;
        self.referenced_parents.extend(parents.iter().cloned());

        let entity = Entity::new(uid.clone(), attrs, parents).map_err(|e| {
            AppError::CedarPolicy(format!("Failed to construct entity '{uid}': {e}"))
        })?;
        self.insert(entity);
        Ok(())
    }

    /// Projects a `StoredUser` into a `User::"<user_id>"` entity whose parents are
    /// its `Role::"…"` and `Group::"…"` memberships.
    fn add_user(&mut self, user: &StoredUser) -> Result<(), AppError> {
        let uid = parse_entity_uid("User", &user.user_id)?;
        let mut attrs = parse_attributes_json(&user.attributes_json)?;
        if !user.email.is_empty() {
            attrs
                .entry("email".to_string())
                .or_insert_with(|| RestrictedExpression::new_string(user.email.clone()));
        }
        for (name, values) in [("roles", &user.roles), ("groups", &user.groups)] {
            attrs.entry(name.to_string()).or_insert_with(|| {
                RestrictedExpression::new_set(
                    values.iter().cloned().map(RestrictedExpression::new_string),
                )
            });
        }

        let memberships = [("Role", &user.roles), ("Group", &user.groups)];
        let parents = memberships
            .iter()
            .flat_map(|(ty, ids)| ids.iter().map(move |id| (*ty, id)))
            .filter(|(_, id)| !id.trim().is_empty())
            .map(|(ty, id)| parse_entity_uid(ty, id))
            .collect::<Result<HashSet<_>, _>>()?;
        self.referenced_parents.extend(parents.iter().cloned());

        let entity = Entity::new(uid.clone(), attrs, parents).map_err(|e| {
            AppError::CedarPolicy(format!("Failed to construct user entity '{uid}': {e}"))
        })?;
        self.insert(entity);
        Ok(())
    }

    fn into_entities(mut self) -> Result<Entities, AppError> {
        // Ensure any parent EntityUid referenced by a User or Entity exists in the graph
        for parent_uid in self.referenced_parents {
            self.entities
                .entry(parent_uid.clone())
                .or_insert_with(|| Entity::with_uid(parent_uid));
        }
        Entities::from_entities(self.entities.into_values(), None)
            .map_err(|e| AppError::CedarPolicy(format!("Failed to build Cedar entity graph: {e}")))
    }
}

/// Combines `SurrealDB` `StoredUser` records, `StoredEntity` records, and transient
/// request-time entities into a Cedar `Entities` graph.
///
/// Precedence on uid conflicts: users > additional entities > stored entities.
pub fn build_entities(
    users: &[StoredUser],
    stored_entities: &[StoredEntity],
    additional_entities: &[StoredEntity],
) -> Result<Entities, AppError> {
    let mut graph = EntityGraph::default();
    for item in stored_entities.iter().chain(additional_entities) {
        graph.add_stored(item)?;
    }
    for user in users {
        graph.add_user(user)?;
    }
    graph.into_entities()
}

/// A space's policies and persisted entities, parsed once and reusable across
/// many authorization requests (e.g. `AuthZEN` batch evaluations).
#[derive(Debug, Clone)]
pub struct PreparedSpace {
    policy_set: PolicySet,
    stored: EntityGraph,
    users: EntityGraph,
}

impl PreparedSpace {
    pub fn new(
        policies: &[StoredPolicy],
        users: &[StoredUser],
        stored_entities: &[StoredEntity],
    ) -> Result<Self, AppError> {
        let mut stored = EntityGraph::default();
        for item in stored_entities {
            stored.add_stored(item)?;
        }
        let mut user_graph = EntityGraph::default();
        for user in users {
            user_graph.add_user(user)?;
        }
        Ok(Self {
            policy_set: build_policy_set(policies)?,
            stored,
            users: user_graph,
        })
    }

    /// Evaluates a single request against this space.
    pub fn evaluate(&self, query: &AuthorizationQuery<'_>) -> Result<EvaluationOutcome, AppError> {
        let request = Request::new(
            query.principal.to_uid()?,
            query.action.to_uid()?,
            query.resource.to_uid()?,
            build_context(query.context_json)?,
            None,
        )
        .map_err(|e| AppError::invalid(format!("Failed to construct Cedar request: {e}")))?;

        // Same precedence as `build_entities`: users > additional > stored.
        let mut graph = self.stored.clone();
        for item in query.additional_entities {
            graph.add_stored(item)?;
        }
        graph.entities.extend(
            self.users
                .entities
                .iter()
                .map(|(uid, e)| (uid.clone(), e.clone())),
        );
        graph
            .referenced_parents
            .extend(self.users.referenced_parents.iter().cloned());
        let entities = graph.into_entities()?;

        let response = Authorizer::new().is_authorized(&request, &self.policy_set, &entities);
        let decision = response.decision();
        Ok(EvaluationOutcome {
            allowed: decision == Decision::Allow,
            decision,
            determining_policies: response
                .diagnostics()
                .reason()
                .map(ToString::to_string)
                .collect(),
            errors: response
                .diagnostics()
                .errors()
                .map(ToString::to_string)
                .collect(),
        })
    }
}

/// Evaluates an authorization request against the space's policies and entities.
pub fn evaluate_authorization(input: &EvaluationInput<'_>) -> Result<EvaluationOutcome, AppError> {
    PreparedSpace::new(input.policies, input.users, input.stored_entities)?.evaluate(
        &AuthorizationQuery {
            principal: input.principal,
            action: input.action,
            resource: input.resource,
            context_json: input.context_json,
            additional_entities: input.additional_entities,
        },
    )
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
