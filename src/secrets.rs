use anyhow::anyhow;
use std::{
    collections::HashMap,
    env::{self, VarError},
};
use thiserror::Error;

use crate::newtypes::Opaque;

/// Defines the SecretsManager trait for secret retrieval
pub trait SecretsManager: Send + Sync + 'static {
    /// Get a secret associated to a setup key
    /// # Arguments
    /// * `k` - The key associated to the secret
    fn get(&self, k: SecretKey) -> Result<Opaque<String>, SecretsManagerError>;
}

#[derive(Debug, Error)]
pub enum SecretsManagerError {
    #[error("Secret not found")]
    NotFound,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum SecretKey {
    /// Database connection URL
    /// Format: `postgresql://<Postgres user>:<Postgres password>@<Postgres host>:<Postgres port>/<Postgres DB>`
    DatabaseUrl,
    /// JWT secret key
    /// Used to sign and verify JWT tokens
    JwtSecret,
}

pub struct InMemorySecretsManager {
    secrets: HashMap<SecretKey, Opaque<String>>,
}

impl SecretsManager for InMemorySecretsManager {
    fn get(&self, k: SecretKey) -> Result<Opaque<String>, SecretsManagerError> {
        self.secrets
            .get(&k)
            .cloned()
            .ok_or(SecretsManagerError::NotFound)
    }
}

impl InMemorySecretsManager {
    pub fn new_from_env() -> Result<Self, Vec<anyhow::Error>> {
        let mut errors = Vec::new();
        let mut secrets = HashMap::new();

        match parse_required_env_variable("DATABASE_URL") {
            Ok(v) => {
                secrets.insert(SecretKey::DatabaseUrl, v.into());
            }
            Err(e) => {
                errors.push(e);
            }
        };

        match parse_required_env_variable("JWT_SECRET") {
            Ok(v) => {
                secrets.insert(SecretKey::JwtSecret, v.into());
            }
            Err(e) => {
                errors.push(e);
            }
        };

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(Self { secrets })
    }
}

fn parse_required_env_variable(key: &str) -> Result<String, anyhow::Error> {
    match env::var(key) {
        Ok(v) => {
            if v.is_empty() {
                Err(anyhow!("[{key}]: empty value not allowed"))
            } else {
                Ok(v)
            }
        }
        Err(VarError::NotPresent) => Err(anyhow!("[{key}]: required")),
        Err(e) => Err(anyhow!("[{key}]: error \"{e}\"")),
    }
}
