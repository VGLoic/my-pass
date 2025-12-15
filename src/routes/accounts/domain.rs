use crate::newtypes::{Email, Opaque};
use sqlx::prelude::FromRow;
use thiserror::Error;

// ##################################################
// ############### ACCOUNT DEFINITION ###############
// ##################################################

#[derive(Debug, Clone, FromRow)]
pub struct Account {
    pub id: uuid::Uuid,
    pub email: Email,
    #[allow(dead_code)]
    pub password_hash: Opaque<String>,
    pub symmetric_key_salt: Opaque<[u8; 16]>,
    pub encrypted_private_key_nonce: Opaque<[u8; 12]>,
    pub encrypted_private_key: Opaque<String>,
    pub public_key: Opaque<[u8; 32]>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

// #######################################
// ############### SIGN UP ###############
// #######################################

pub struct SignupRequest {
    pub email: Email,
    pub password_hash: Opaque<String>,
    pub symmetric_key_salt: Opaque<[u8; 16]>,
    pub encrypted_private_key_nonce: Opaque<[u8; 12]>,
    pub encrypted_private_key: Opaque<String>,
    pub public_key: Opaque<[u8; 32]>,
}

#[derive(Debug, Error)]
pub enum SignupRequestError {
    #[error("Invalid email format: {0}")]
    InvalidEmailFormat(String),
    #[error("Invalid password format: {0}")]
    InvalidPasswordFormat(String),
    #[error("Invalid symmetric key salt format: {0}")]
    InvalidSymmetricKeySaltFormat(String),
    #[error("Invalid encrypted private key nonce format: {0}")]
    InvalidEncryptedPrivateKeyNonceFormat(String),
    #[error("Invalid encrypted private key format: {0}")]
    InvalidEncryptedPrivateKeyFormat(String),
    #[error("Invalid public key format: {0}")]
    InvalidPublicKeyFormat(String),
    #[error("Invalid key pair or nonce")]
    InvalidKeyPair,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

impl SignupRequest {
    pub fn new(
        email: Email,
        password_hash: Opaque<String>,
        symmetric_key_salt: Opaque<[u8; 16]>,
        encrypted_private_key_nonce: Opaque<[u8; 12]>,
        encrypted_private_key: Opaque<String>,
        public_key: Opaque<[u8; 32]>,
    ) -> Self {
        SignupRequest {
            email,
            password_hash,
            symmetric_key_salt,
            encrypted_private_key_nonce,
            encrypted_private_key,
            public_key,
        }
    }
}

#[derive(Debug, Error)]
pub enum CreateAccountError {
    #[error("An account with the given email already exists")]
    EmailAlreadyCreated,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

// #################################################
// ############### ACCOUNT RETRIEVAL ###############
// #################################################

#[derive(Debug, Error)]
pub enum GetAccountError {
    #[error("Account not found")]
    NotFound,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}
