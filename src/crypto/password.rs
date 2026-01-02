use super::argon2instance;
use anyhow::anyhow;
use argon2::{
    PasswordHash,
    password_hash::{PasswordHasher, PasswordVerifier, Salt},
};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use fake::rand;

use crate::newtypes::{Opaque, Password};

/// Defines operations for password hashing and verification
pub trait PasswordOps {
    /// Hash the password using Argon2id algorithm, returning the formatted hash string.
    fn hash(&self) -> Result<String, anyhow::Error>;
    /// Verify the password against the provided Argon2id formatted hash.
    /// # Arguments
    /// * `hash` - Argon2id formatted hash to verify against
    fn verify(&self, hash: &Opaque<String>) -> Result<(), anyhow::Error>;
}

impl PasswordOps for Password {
    fn hash(&self) -> Result<String, anyhow::Error> {
        let salt: [u8; 16] = rand::random();
        let base64_salt = BASE64_STANDARD_NO_PAD.encode(salt);
        let argon_salt = Salt::from_b64(&base64_salt).map_err(|e| {
            anyhow!(e).context("failed to build Salt struct from base64 salt string")
        })?;
        argon2instance::argon2_instance()
            .hash_password(self.unsafe_inner().as_bytes(), argon_salt)
            .map_err(|e| anyhow!(e).context("failed to hash password"))
            .map(|v| v.to_string())
    }

    fn verify(&self, hash: &Opaque<String>) -> Result<(), anyhow::Error> {
        let parsed_hash = PasswordHash::new(hash.unsafe_inner())
            .map_err(|e| anyhow!(e).context("failed to parse stored password hash"))?;
        match argon2instance::argon2_instance()
            .verify_password(self.unsafe_inner().as_bytes(), &parsed_hash)
        {
            Ok(_) => Ok(()),
            Err(argon2::password_hash::Error::Password) => Err(anyhow!("invalid password")),
            Err(e) => Err(anyhow!(e).context("failed to verify password")),
        }
    }
}
