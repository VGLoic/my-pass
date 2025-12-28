use anyhow::anyhow;
use argon2::{
    Algorithm, Argon2, Params, PasswordHash, Version,
    password_hash::{PasswordHasher, PasswordVerifier, Salt},
};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use fake::rand;

// REMIND ME: think about password type
pub fn hash_password(password: &str) -> Result<String, anyhow::Error> {
    let salt: [u8; 16] = rand::random();
    let base64_salt = BASE64_STANDARD_NO_PAD.encode(salt);
    let argon_salt = Salt::from_b64(&base64_salt)
        .map_err(|e| anyhow!(e).context("failed to build Salt struct from base64 salt string"))?;
    argon2_instance()
        .hash_password(password.as_bytes(), argon_salt)
        .map_err(|e| anyhow!(e).context("failed to hash password"))
        .map(|v| v.to_string())
}

// REMIND ME: think about password type
pub fn verify_password(hash: &str, password: &str) -> Result<(), anyhow::Error> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| anyhow!(e).context("failed to parse stored password hash"))?;
    match argon2_instance().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(()),
        Err(argon2::password_hash::Error::Password) => Err(anyhow!("invalid password")),
        Err(e) => Err(anyhow!(e).context("failed to verify password")),
    }
}

const ARGON2_MEMORY_COST: u32 = Params::DEFAULT_M_COST;
const ARGON2_TIME_COST: u32 = Params::DEFAULT_T_COST;
const ARGON2_PARALLELISM: u32 = Params::DEFAULT_P_COST;

pub fn argon2_instance() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            ARGON2_MEMORY_COST,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            None,
        )
        .expect("Invalid Argon2 parameters"),
    )
}
