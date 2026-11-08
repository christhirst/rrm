use std::time::{SystemTime, UNIX_EPOCH};

use surrealdb::Surreal;
use surrealdb::engine::any::{Any, connect};
use surrealdb::opt::auth::Root;
use surrealdb::types::{Array, RecordId};
use uuid::Uuid;

use crate::auth::NATIVE_TOKEN_PREFIX;
use crate::config::SurrealDbConfig;
use crate::error::AppError;
use crate::models::{EntityRef, SpaceRecord, StoredEntity, StoredPolicy, StoredUser};

const SPACES: &str = "spaces";
const POLICIES: &str = "policies";
const USERS: &str = "users";
const ENTITIES: &str = "entities";

/// Maximum accepted length of a `space_id`.
const MAX_SPACE_ID_LEN: usize = 128;

#[derive(Debug, Clone)]
pub struct Store {
    db: Surreal<Any>,
}

/// Validates that a `space_id` is non-empty, reasonably short and consists only of
/// ASCII alphanumerics, `-` and `_`.
pub fn validate_space_id(space_id: &str) -> Result<(), AppError> {
    if space_id.is_empty() {
        return Err(AppError::invalid("space_id cannot be empty"));
    }
    if space_id.len() > MAX_SPACE_ID_LEN {
        return Err(AppError::invalid(format!(
            "space_id must be at most {MAX_SPACE_ID_LEN} characters"
        )));
    }
    if !space_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(AppError::invalid(
            "space_id may only contain ASCII letters, digits, '-' and '_'",
        ));
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<(), AppError> {
    if value.trim().is_empty() {
        Err(AppError::invalid(format!("{field} cannot be empty")))
    } else {
        Ok(())
    }
}

/// Empty attribute strings are stored as an empty JSON object.
fn normalize_attrs(attributes_json: &str) -> String {
    if attributes_json.trim().is_empty() {
        "{}".to_string()
    } else {
        attributes_json.to_string()
    }
}

fn now_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        .to_string()
}

/// Builds a composite record id (`table:[part, ...]`). Array keys are unambiguous,
/// unlike string concatenation with a separator that may appear in the parts
/// (e.g. namespaced Cedar entity types like `App::Document`).
fn record_id(table: &str, parts: &[&str]) -> RecordId {
    let key: Array = parts.iter().map(|p| (*p).to_owned()).collect();
    RecordId::new(table, key)
}

impl Store {
    /// Connects to `SurrealDB` (embedded `memory` or remote `ws://` / `http://`)
    /// and selects the configured namespace and database.
    pub async fn connect(cfg: &SurrealDbConfig) -> Result<Self, AppError> {
        let db = connect(&cfg.endpoint).await?;

        if let (Some(username), Some(password)) = (&cfg.username, &cfg.password)
            && !username.is_empty()
        {
            db.signin(Root {
                username: username.clone(),
                password: password.clone(),
            })
            .await?;
        }

        db.use_ns(&cfg.namespace).use_db(&cfg.database).await?;

        db.query(
            "DEFINE TABLE IF NOT EXISTS spaces; \
             DEFINE TABLE IF NOT EXISTS policies; \
             DEFINE TABLE IF NOT EXISTS users; \
             DEFINE TABLE IF NOT EXISTS entities; \
             DEFINE INDEX IF NOT EXISTS policies_space ON policies FIELDS space_id; \
             DEFINE INDEX IF NOT EXISTS users_space ON users FIELDS space_id; \
             DEFINE INDEX IF NOT EXISTS entities_space ON entities FIELDS space_id, entity_type;",
        )
        .await?
        .check()?;

        Ok(Self { db })
    }

    /// Upserts `record` under `id`, returning the stored version.
    async fn put<T>(&self, id: RecordId, record: T) -> Result<T, AppError>
    where
        T: surrealdb::types::SurrealValue + Clone,
    {
        let saved: Option<T> = self.db.upsert(id).content(record.clone()).await?;
        Ok(saved.unwrap_or(record))
    }

    /// Deletes the record at `id`, returning whether it existed.
    async fn remove<T>(&self, id: RecordId) -> Result<bool, AppError>
    where
        T: surrealdb::types::SurrealValue,
    {
        let deleted: Option<T> = self.db.delete(id).await?;
        Ok(deleted.is_some())
    }

    /// Runs a single `SELECT` scoped to a space and returns its rows.
    async fn select_in_space<T>(&self, sql: &str, space_id: &str) -> Result<Vec<T>, AppError>
    where
        T: surrealdb::types::SurrealValue,
    {
        let rows: Vec<T> = self
            .db
            .query(sql)
            .bind(("space_id", space_id.to_owned()))
            .await?
            .take(0)?;
        Ok(rows)
    }

    // ========================================================================
    // Space Operations
    // ========================================================================

    pub async fn create_space(
        &self,
        space_id: &str,
        name: &str,
        description: &str,
    ) -> Result<SpaceRecord, AppError> {
        validate_space_id(space_id)?;

        let existing: Option<SpaceRecord> = self.db.select((SPACES, space_id)).await?;
        if existing.is_some() {
            return Err(AppError::AlreadyExists(format!(
                "Space '{space_id}' already exists"
            )));
        }

        let record = SpaceRecord {
            space_id: space_id.to_string(),
            name: if name.trim().is_empty() {
                space_id.to_string()
            } else {
                name.to_string()
            },
            description: description.to_string(),
            api_token: format!(
                "{NATIVE_TOKEN_PREFIX}{space_id}_{}",
                Uuid::new_v4().simple()
            ),
            created_at: now_timestamp(),
        };

        self.put(RecordId::new(SPACES, space_id), record).await
    }

    pub async fn get_space(&self, space_id: &str) -> Result<SpaceRecord, AppError> {
        let space: Option<SpaceRecord> = self.db.select((SPACES, space_id)).await?;
        space.ok_or_else(|| AppError::not_found(format!("Space '{space_id}' not found")))
    }

    pub async fn list_spaces(&self) -> Result<Vec<SpaceRecord>, AppError> {
        let mut spaces: Vec<SpaceRecord> = self.db.select(SPACES).await?;
        spaces.sort_by(|a, b| a.space_id.cmp(&b.space_id));
        Ok(spaces)
    }

    pub async fn delete_space(&self, space_id: &str) -> Result<bool, AppError> {
        if !self
            .remove::<SpaceRecord>(RecordId::new(SPACES, space_id))
            .await?
        {
            return Ok(false);
        }

        // Clean up policies, users, and entities belonging to this space
        self.db
            .query(
                "DELETE policies WHERE space_id = $space_id; \
                 DELETE users WHERE space_id = $space_id; \
                 DELETE entities WHERE space_id = $space_id;",
            )
            .bind(("space_id", space_id.to_string()))
            .await?
            .check()?;

        Ok(true)
    }

    // ========================================================================
    // Policy Operations
    // ========================================================================

    pub async fn upsert_policy(
        &self,
        space_id: &str,
        policy_id: &str,
        description: &str,
        cedar_text: &str,
    ) -> Result<StoredPolicy, AppError> {
        require_non_empty("policy_id", policy_id)?;

        let record = StoredPolicy {
            space_id: space_id.to_string(),
            policy_id: policy_id.to_string(),
            description: description.to_string(),
            cedar_text: cedar_text.to_string(),
            updated_at: now_timestamp(),
        };
        self.put(record_id(POLICIES, &[space_id, policy_id]), record)
            .await
    }

    pub async fn clear_space_policies(&self, space_id: &str) -> Result<(), AppError> {
        self.db
            .query("DELETE policies WHERE space_id = $space_id")
            .bind(("space_id", space_id.to_string()))
            .await?
            .check()?;
        Ok(())
    }

    pub async fn get_policy(
        &self,
        space_id: &str,
        policy_id: &str,
    ) -> Result<StoredPolicy, AppError> {
        let policy: Option<StoredPolicy> = self
            .db
            .select(record_id(POLICIES, &[space_id, policy_id]))
            .await?;
        policy.ok_or_else(|| {
            AppError::not_found(format!(
                "Policy '{policy_id}' not found in space '{space_id}'"
            ))
        })
    }

    pub async fn list_policies(&self, space_id: &str) -> Result<Vec<StoredPolicy>, AppError> {
        self.select_in_space(
            "SELECT * FROM policies WHERE space_id = $space_id ORDER BY policy_id",
            space_id,
        )
        .await
    }

    pub async fn delete_policy(&self, space_id: &str, policy_id: &str) -> Result<bool, AppError> {
        self.remove::<StoredPolicy>(record_id(POLICIES, &[space_id, policy_id]))
            .await
    }

    // ========================================================================
    // User Operations (SurrealDB Entity Store)
    // ========================================================================

    pub async fn upsert_user(
        &self,
        space_id: &str,
        user_id: &str,
        email: &str,
        roles: Vec<String>,
        groups: Vec<String>,
        attributes_json: &str,
    ) -> Result<StoredUser, AppError> {
        require_non_empty("user_id", user_id)?;

        let record = StoredUser {
            space_id: space_id.to_string(),
            user_id: user_id.to_string(),
            email: email.to_string(),
            roles,
            groups,
            attributes_json: normalize_attrs(attributes_json),
            updated_at: now_timestamp(),
        };
        self.put(record_id(USERS, &[space_id, user_id]), record)
            .await
    }

    pub async fn get_user(&self, space_id: &str, user_id: &str) -> Result<StoredUser, AppError> {
        let user: Option<StoredUser> = self
            .db
            .select(record_id(USERS, &[space_id, user_id]))
            .await?;
        user.ok_or_else(|| {
            AppError::not_found(format!("User '{user_id}' not found in space '{space_id}'"))
        })
    }

    pub async fn list_users(&self, space_id: &str) -> Result<Vec<StoredUser>, AppError> {
        self.select_in_space(
            "SELECT * FROM users WHERE space_id = $space_id ORDER BY user_id",
            space_id,
        )
        .await
    }

    pub async fn delete_user(&self, space_id: &str, user_id: &str) -> Result<bool, AppError> {
        self.remove::<StoredUser>(record_id(USERS, &[space_id, user_id]))
            .await
    }

    // ========================================================================
    // Generic Cedar Entity Operations (SurrealDB Entity Store)
    // ========================================================================

    pub async fn upsert_entity(
        &self,
        space_id: &str,
        entity_type: &str,
        entity_id: &str,
        parents: Vec<EntityRef>,
        attributes_json: &str,
    ) -> Result<StoredEntity, AppError> {
        if entity_type.trim().is_empty() || entity_id.trim().is_empty() {
            return Err(AppError::invalid(
                "entity_type and entity_id cannot be empty",
            ));
        }

        let record = StoredEntity {
            space_id: space_id.to_string(),
            entity_type: entity_type.to_string(),
            entity_id: entity_id.to_string(),
            parents,
            attributes_json: normalize_attrs(attributes_json),
            updated_at: now_timestamp(),
        };
        self.put(
            record_id(ENTITIES, &[space_id, entity_type, entity_id]),
            record,
        )
        .await
    }

    pub async fn get_entity(
        &self,
        space_id: &str,
        entity_type: &str,
        entity_id: &str,
    ) -> Result<StoredEntity, AppError> {
        let entity: Option<StoredEntity> = self
            .db
            .select(record_id(ENTITIES, &[space_id, entity_type, entity_id]))
            .await?;
        entity.ok_or_else(|| {
            AppError::not_found(format!(
                "Entity '{entity_type}::\"{entity_id}\"' not found in space '{space_id}'"
            ))
        })
    }

    /// Lists entities of a space, optionally restricted to a single entity type
    /// (a blank filter is treated as no filter).
    pub async fn list_entities(
        &self,
        space_id: &str,
        entity_type_filter: Option<&str>,
    ) -> Result<Vec<StoredEntity>, AppError> {
        match entity_type_filter.map(str::trim).filter(|t| !t.is_empty()) {
            None => {
                self.select_in_space(
                    "SELECT * FROM entities WHERE space_id = $space_id \
                     ORDER BY entity_type, entity_id",
                    space_id,
                )
                .await
            }
            Some(entity_type) => {
                let rows: Vec<StoredEntity> = self
                    .db
                    .query(
                        "SELECT * FROM entities \
                         WHERE space_id = $space_id AND entity_type = $entity_type \
                         ORDER BY entity_id",
                    )
                    .bind(("space_id", space_id.to_owned()))
                    .bind(("entity_type", entity_type.to_owned()))
                    .await?
                    .take(0)?;
                Ok(rows)
            }
        }
    }

    pub async fn delete_entity(
        &self,
        space_id: &str,
        entity_type: &str,
        entity_id: &str,
    ) -> Result<bool, AppError> {
        self.remove::<StoredEntity>(record_id(ENTITIES, &[space_id, entity_type, entity_id]))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn memory_store() -> Store {
        Store::connect(&SurrealDbConfig {
            endpoint: "memory".to_string(),
            namespace: "store_test".to_string(),
            database: "store_test".to_string(),
            username: None,
            password: None,
        })
        .await
        .expect("in-memory surrealdb should connect")
    }

    #[test]
    fn validate_space_id_accepts_safe_ids_and_rejects_others() {
        assert!(validate_space_id("billing").is_ok());
        assert!(validate_space_id("team_a-1").is_ok());
        assert!(validate_space_id("").is_err());
        assert!(validate_space_id("a::b").is_err());
        assert!(validate_space_id("has space").is_err());
        assert!(validate_space_id(&"x".repeat(MAX_SPACE_ID_LEN + 1)).is_err());
    }

    #[tokio::test]
    async fn entity_keys_with_separators_do_not_collide() {
        let store = memory_store().await;
        store
            .upsert_entity("s", "A", "B::C", vec![], r#"{"n": 1}"#)
            .await
            .unwrap();
        store
            .upsert_entity("s", "A::B", "C", vec![], r#"{"n": 2}"#)
            .await
            .unwrap();

        let first = store.get_entity("s", "A", "B::C").await.unwrap();
        let second = store.get_entity("s", "A::B", "C").await.unwrap();
        assert_eq!(first.attributes_json, r#"{"n": 1}"#);
        assert_eq!(second.attributes_json, r#"{"n": 2}"#);
        assert_eq!(store.list_entities("s", None).await.unwrap().len(), 2);
        assert_eq!(store.list_entities("s", Some("A")).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn list_queries_are_scoped_to_space_and_sorted() {
        let store = memory_store().await;
        for (space, id) in [("s1", "b"), ("s1", "a"), ("s2", "c")] {
            store
                .upsert_policy(space, id, "", "permit(principal, action, resource);")
                .await
                .unwrap();
            store
                .upsert_user(space, id, "", vec![], vec![], "")
                .await
                .unwrap();
        }

        let policies = store.list_policies("s1").await.unwrap();
        let ids: Vec<_> = policies.iter().map(|p| p.policy_id.as_str()).collect();
        assert_eq!(ids, ["a", "b"]);

        let users = store.list_users("s2").await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].attributes_json, "{}");

        assert!(store.delete_policy("s1", "a").await.unwrap());
        assert!(!store.delete_policy("s1", "a").await.unwrap());
    }
}
