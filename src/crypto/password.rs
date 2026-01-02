use super::argon2instance;
use anyhow::anyhow;
use argon2::{
    PasswordHash,
    password_hash::{PasswordHasher, PasswordVerifier, Salt},
};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use fake::rand;

use crate::newtypes::{Opaque, Password};

// REMIND ME: think about trait
/// Hash a password using the Argon2id algorithm. The returned string is a argon2-formatted hash.
///
/// # Arguments
/// * `password` - Password to verify
pub fn hash_password(password: &Password) -> Result<String, anyhow::Error> {
    let salt: [u8; 16] = rand::random();
    let base64_salt = BASE64_STANDARD_NO_PAD.encode(salt);
    let argon_salt = Salt::from_b64(&base64_salt)
        .map_err(|e| anyhow!(e).context("failed to build Salt struct from base64 salt string"))?;
    argon2instance::argon2_instance()
        .hash_password(password.unsafe_inner().as_bytes(), argon_salt)
        .map_err(|e| anyhow!(e).context("failed to hash password"))
        .map(|v| v.to_string())
}

// REMIND ME: think about trait
/// Verify a password validity against an Argon2id formatted key
///
/// # Arguments
/// * `hash` - Argon2id formatted hash to verify against
/// * `password` - Password to verify
pub fn verify_password(hash: &Opaque<String>, password: &Password) -> Result<(), anyhow::Error> {
    let parsed_hash = PasswordHash::new(hash.unsafe_inner())
        .map_err(|e| anyhow!(e).context("failed to parse stored password hash"))?;
    match argon2instance::argon2_instance()
        .verify_password(password.unsafe_inner().as_bytes(), &parsed_hash)
    {
        Ok(_) => Ok(()),
        Err(argon2::password_hash::Error::Password) => Err(anyhow!("invalid password")),
        Err(e) => Err(anyhow!(e).context("failed to verify password")),
    }
}
