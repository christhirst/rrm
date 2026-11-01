use std::path::Path;

use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};

/// Top-level application configuration loaded from `config/default.toml`,
/// optional `config/local.toml`, and `RRM__` environment variables.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub surrealdb: SurrealDbConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    #[serde(default = "default_http_listen_addr")]
    pub http_listen_addr: String,
}

fn default_http_listen_addr() -> String {
    "0.0.0.0:8080".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub admin_token: String,
    #[serde(default)]
    pub oauth: OAuthConfig,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct OAuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub jwks_url: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default = "default_space_claim")]
    pub space_claim: String,
    /// Optional PEM public key or secret string for offline / self-contained JWT validation
    #[serde(default)]
    pub secret_or_public_key: Option<String>,
}

fn default_space_claim() -> String {
    "space_id".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SurrealDbConfig {
    pub endpoint: String,
    pub namespace: String,
    pub database: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                listen_addr: "0.0.0.0:50051".to_string(),
                http_listen_addr: "0.0.0.0:8080".to_string(),
            },
            auth: AuthConfig {
                admin_token: "admin-secret-token".to_string(),
                oauth: OAuthConfig::default(),
            },
            surrealdb: SurrealDbConfig {
                endpoint: "memory".to_string(),
                namespace: "rrm".to_string(),
                database: "authz".to_string(),
                username: None,
                password: None,
            },
        }
    }
}

impl AppConfig {
    /// Loads configuration from `config/default.toml`, `config/local.toml`,
    /// optional `RRM_CONFIG_PATH`, and `RRM_` environment variables (using `__` separator).
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from_dir(Path::new("config"))
    }

    /// Loads configuration from a specified directory and `RRM_` environment variables.
    pub fn load_from_dir(config_dir: &Path) -> Result<Self, ConfigError> {
        let default_file = config_dir.join("default");
        let local_file = config_dir.join("local");

        let mut builder = Config::builder()
            .set_default("server.listen_addr", "0.0.0.0:50051")?
            .set_default("server.http_listen_addr", "0.0.0.0:8080")?
            .set_default("auth.admin_token", "admin-secret-token")?
            .set_default("auth.oauth.enabled", false)?
            .set_default("surrealdb.endpoint", "memory")?
            .set_default("surrealdb.namespace", "rrm")?
            .set_default("surrealdb.database", "authz")?
            .add_source(File::from(default_file).required(false))
            .add_source(File::from(local_file).required(false));

        if let Ok(custom_path) = std::env::var("RRM_CONFIG_PATH") {
            builder = builder.add_source(File::with_name(&custom_path).required(true));
        }

        builder = builder.add_source(
            Environment::with_prefix("RRM")
                .prefix_separator("_")
                .separator("__")
                .try_parsing(true),
        );

        builder.build()?.try_deserialize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_default_config_from_config_folder_should_succeed() {
        let cfg = AppConfig::load().expect("should load default.toml");
        assert_eq!(cfg.server.listen_addr, "0.0.0.0:50051");
        assert_eq!(cfg.server.http_listen_addr, "0.0.0.0:8080");
        assert!(!cfg.auth.oauth.enabled);
        assert_eq!(cfg.surrealdb.endpoint, "memory");
        assert_eq!(cfg.surrealdb.namespace, "rrm");
        assert_eq!(cfg.surrealdb.database, "authz");
        assert!(!cfg.auth.admin_token.is_empty());
    }
}
