use std::time::{SystemTime, UNIX_EPOCH};

use surrealdb::Surreal;
use surrealdb::engine::any::{Any, connect};
use surrealdb::opt::auth::Root;
use uuid::Uuid;

use crate::config::SurrealDbConfig;
use crate::error::AppError;
use crate::models::{EntityRef, SpaceRecord, StoredEntity, StoredPolicy, StoredUser};

#[derive(Debug, Clone)]
pub struct Store {
    db: Surreal<Any>,
}

impl Store {
    /// Connects to SurrealDB (embedded `memory` or remote `ws://` / `http://`)
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
             DEFINE TABLE IF NOT EXISTS entities;",
        )
        .await?
        .check()?;

        Ok(Self { db })
    }

    fn now_timestamp() -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        secs.to_string()
    }

    fn policy_key(space_id: &str, policy_id: &str) -> String {
        format!("{space_id}::{policy_id}")
    }

    fn user_key(space_id: &str, user_id: &str) -> String {
        format!("{space_id}::{user_id}")
    }

    fn entity_key(space_id: &str, entity_type: &str, entity_id: &str) -> String {
        format!("{space_id}::{entity_type}::{entity_id}")
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
        if space_id.trim().is_empty() {
            return Err(AppError::InvalidArgument(
                "space_id cannot be empty".to_string(),
            ));
        }

        let existing: Option<SpaceRecord> = self.db.select(("spaces", space_id)).await?;
        if existing.is_some() {
            return Err(AppError::AlreadyExists(format!(
                "Space '{space_id}' already exists"
            )));
        }

        let api_token = format!("rrm_sp_{}_{}", space_id, Uuid::new_v4().simple());
        let record = SpaceRecord {
            space_id: space_id.to_string(),
            name: if name.trim().is_empty() {
                space_id.to_string()
            } else {
                name.to_string()
            },
            description: description.to_string(),
            api_token,
            created_at: Self::now_timestamp(),
        };

        let created: Option<SpaceRecord> = self
            .db
            .upsert(("spaces", space_id))
            .content(record.clone())
            .await?;

        Ok(created.unwrap_or(record))
    }

    pub async fn get_space(&self, space_id: &str) -> Result<SpaceRecord, AppError> {
        let space: Option<SpaceRecord> = self.db.select(("spaces", space_id)).await?;
        space.ok_or_else(|| AppError::NotFound(format!("Space '{space_id}' not found")))
    }

    pub async fn list_spaces(&self) -> Result<Vec<SpaceRecord>, AppError> {
        let mut spaces: Vec<SpaceRecord> = self.db.select("spaces").await?;
        spaces.sort_by(|a, b| a.space_id.cmp(&b.space_id));
        Ok(spaces)
    }

    pub async fn delete_space(&self, space_id: &str) -> Result<bool, AppError> {
        let deleted: Option<SpaceRecord> = self.db.delete(("spaces", space_id)).await?;
        if deleted.is_none() {
            return Ok(false);
        }

        // Clean up policies, users, and entities belonging to this space
        self.db
            .query("DELETE policies WHERE space_id = $space_id; DELETE users WHERE space_id = $space_id; DELETE entities WHERE space_id = $space_id;")
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
        if policy_id.trim().is_empty() {
            return Err(AppError::InvalidArgument(
                "policy_id cannot be empty".to_string(),
            ));
        }

        let key = Self::policy_key(space_id, policy_id);
        let record = StoredPolicy {
            space_id: space_id.to_string(),
            policy_id: policy_id.to_string(),
            description: description.to_string(),
            cedar_text: cedar_text.to_string(),
            updated_at: Self::now_timestamp(),
        };

        let saved: Option<StoredPolicy> = self
            .db
            .upsert(("policies", key))
            .content(record.clone())
            .await?;

        Ok(saved.unwrap_or(record))
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
        let key = Self::policy_key(space_id, policy_id);
        let policy: Option<StoredPolicy> = self.db.select(("policies", key)).await?;
        policy.ok_or_else(|| {
            AppError::NotFound(format!(
                "Policy '{policy_id}' not found in space '{space_id}'"
            ))
        })
    }

    pub async fn list_policies(&self, space_id: &str) -> Result<Vec<StoredPolicy>, AppError> {
        let all: Vec<StoredPolicy> = self.db.select("policies").await?;
        let mut filtered: Vec<StoredPolicy> = all
            .into_iter()
            .filter(|p| p.space_id == space_id)
            .collect();
        filtered.sort_by(|a, b| a.policy_id.cmp(&b.policy_id));
        Ok(filtered)
    }

    pub async fn delete_policy(&self, space_id: &str, policy_id: &str) -> Result<bool, AppError> {
        let key = Self::policy_key(space_id, policy_id);
        let deleted: Option<StoredPolicy> = self.db.delete(("policies", key)).await?;
        Ok(deleted.is_some())
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
        if user_id.trim().is_empty() {
            return Err(AppError::InvalidArgument(
                "user_id cannot be empty".to_string(),
            ));
        }

        let normalized_attrs = if attributes_json.trim().is_empty() {
            "{}".to_string()
        } else {
            attributes_json.to_string()
        };

        let key = Self::user_key(space_id, user_id);
        let record = StoredUser {
            space_id: space_id.to_string(),
            user_id: user_id.to_string(),
            email: email.to_string(),
            roles,
            groups,
            attributes_json: normalized_attrs,
            updated_at: Self::now_timestamp(),
        };

        let saved: Option<StoredUser> = self
            .db
            .upsert(("users", key))
            .content(record.clone())
            .await?;

        Ok(saved.unwrap_or(record))
    }

    pub async fn get_user(&self, space_id: &str, user_id: &str) -> Result<StoredUser, AppError> {
        let key = Self::user_key(space_id, user_id);
        let user: Option<StoredUser> = self.db.select(("users", key)).await?;
        user.ok_or_else(|| {
            AppError::NotFound(format!("User '{user_id}' not found in space '{space_id}'"))
        })
    }

    pub async fn list_users(&self, space_id: &str) -> Result<Vec<StoredUser>, AppError> {
        let all: Vec<StoredUser> = self.db.select("users").await?;
        let mut filtered: Vec<StoredUser> =
            all.into_iter().filter(|u| u.space_id == space_id).collect();
        filtered.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        Ok(filtered)
    }

    pub async fn delete_user(&self, space_id: &str, user_id: &str) -> Result<bool, AppError> {
        let key = Self::user_key(space_id, user_id);
        let deleted: Option<StoredUser> = self.db.delete(("users", key)).await?;
        Ok(deleted.is_some())
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
            return Err(AppError::InvalidArgument(
                "entity_type and entity_id cannot be empty".to_string(),
            ));
        }

        let normalized_attrs = if attributes_json.trim().is_empty() {
            "{}".to_string()
        } else {
            attributes_json.to_string()
        };

        let key = Self::entity_key(space_id, entity_type, entity_id);
        let record = StoredEntity {
            space_id: space_id.to_string(),
            entity_type: entity_type.to_string(),
            entity_id: entity_id.to_string(),
            parents,
            attributes_json: normalized_attrs,
            updated_at: Self::now_timestamp(),
        };

        let saved: Option<StoredEntity> = self
            .db
            .upsert(("entities", key))
            .content(record.clone())
            .await?;

        Ok(saved.unwrap_or(record))
    }

    pub async fn get_entity(
        &self,
        space_id: &str,
        entity_type: &str,
        entity_id: &str,
    ) -> Result<StoredEntity, AppError> {
        let key = Self::entity_key(space_id, entity_type, entity_id);
        let entity: Option<StoredEntity> = self.db.select(("entities", key)).await?;
        entity.ok_or_else(|| {
            AppError::NotFound(format!(
                "Entity '{}::\"{}\"' not found in space '{space_id}'",
                entity_type, entity_id
            ))
        })
    }

    pub async fn list_entities(
        &self,
        space_id: &str,
        entity_type_filter: Option<&str>,
    ) -> Result<Vec<StoredEntity>, AppError> {
        let all: Vec<StoredEntity> = self.db.select("entities").await?;
        let mut filtered: Vec<StoredEntity> = all
            .into_iter()
            .filter(|e| {
                e.space_id == space_id
                    && entity_type_filter
                        .filter(|t| !t.trim().is_empty())
                        .is_none_or(|t| e.entity_type == t)
            })
            .collect();
        filtered.sort_by(|a, b| {
            a.entity_type
                .cmp(&b.entity_type)
                .then_with(|| a.entity_id.cmp(&b.entity_id))
        });
        Ok(filtered)
    }

    pub async fn delete_entity(
        &self,
        space_id: &str,
        entity_type: &str,
        entity_id: &str,
    ) -> Result<bool, AppError> {
        let key = Self::entity_key(space_id, entity_type, entity_id);
        let deleted: Option<StoredEntity> = self.db.delete(("entities", key)).await?;
        Ok(deleted.is_some())
    }
}
