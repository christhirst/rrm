use serde::{Deserialize, Serialize};
use surrealdb::types::SurrealValue;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, SurrealValue)]
pub struct EntityRef {
    pub entity_type: String,
    pub entity_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct SpaceRecord {
    pub space_id: String,
    pub name: String,
    pub description: String,
    pub api_token: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct StoredPolicy {
    pub space_id: String,
    pub policy_id: String,
    pub description: String,
    pub cedar_text: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct StoredUser {
    pub space_id: String,
    pub user_id: String,
    pub email: String,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub attributes_json: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct StoredEntity {
    pub space_id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub parents: Vec<EntityRef>,
    pub attributes_json: String,
    pub updated_at: String,
}
