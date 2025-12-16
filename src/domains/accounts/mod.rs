use crate::newtypes::{Email, Opaque};
use base64::{Engine, prelude::BASE64_URL_SAFE};
use sqlx::prelude::FromRow;
use thiserror::Error;

pub mod notifier;
pub mod repository;

// ##################################################
// ############### ACCOUNT DEFINITION ###############
// ##################################################

#[derive(Debug, Clone, FromRow)]
pub struct Account {
    pub id: uuid::Uuid,
    pub email: Email,
    #[allow(dead_code)]
    pub password_hash: Opaque<String>,
    pub verified: bool,
    pub symmetric_key_salt: Opaque<[u8; 16]>,
    pub encrypted_private_key_nonce: Opaque<[u8; 12]>,
    pub encrypted_private_key: Opaque<String>,
    pub public_key: Opaque<[u8; 32]>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct VerificationTicket {
    pub id: uuid::Uuid,
    pub account_id: uuid::Uuid,
    pub token: Opaque<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub cancelled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub used_at: Option<chrono::DateTime<chrono::Utc>>,
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
    pub verification_ticket_token: Opaque<String>,
    pub verification_ticket_expires_at: chrono::DateTime<chrono::Utc>,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        email: Email,
        password_hash: Opaque<String>,
        symmetric_key_salt: Opaque<[u8; 16]>,
        encrypted_private_key_nonce: Opaque<[u8; 12]>,
        encrypted_private_key: Opaque<String>,
        public_key: Opaque<[u8; 32]>,
        verification_ticket_token: Opaque<[u8; 32]>,
        verification_ticket_lifetime: chrono::Duration,
    ) -> Self {
        let verification_ticket_token =
            BASE64_URL_SAFE.encode(verification_ticket_token.unsafe_inner());
        let verification_ticket_expires_at = chrono::Utc::now() + verification_ticket_lifetime;

        SignupRequest {
            email,
            password_hash,
            symmetric_key_salt,
            encrypted_private_key_nonce,
            encrypted_private_key,
            public_key,
            verification_ticket_token: verification_ticket_token.into(),
            verification_ticket_expires_at,
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

// #######################################################
// ############### USE VERIFICATION TICKET ###############
// #######################################################

pub struct UseVerificationTicketRequest {
    pub account_id: uuid::Uuid,
    pub valid_ticket_id: uuid::Uuid,
}

#[derive(Debug, Error)]
pub enum UseVerificationTicketRequestError {
    #[error("Account is already verified")]
    AlreadyVerified,
    #[error("Verification ticket already used")]
    AlreadyUsed,
    #[error("Verification ticket cancelled")]
    Cancelled,
    #[error("Verification ticket is expired")]
    Expired,
    #[error("Invalid verification ticket token")]
    InvalidToken,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

impl UseVerificationTicketRequest {
    pub fn new(account_id: uuid::Uuid, valid_ticket_id: uuid::Uuid) -> Self {
        UseVerificationTicketRequest {
            account_id,
            valid_ticket_id,
        }
    }
}

#[derive(Debug, Error)]
pub enum UseVerificationTicketError {
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

// #############################################
// ############### ACCOUNT LOGIN ###############
// #############################################

pub struct LoginRequest {
    pub account_id: uuid::Uuid,
    pub access_token: Opaque<String>,
}

impl LoginRequest {
    pub fn new(account_id: uuid::Uuid, access_token: Opaque<String>) -> Self {
        LoginRequest {
            account_id,
            access_token,
        }
    }
}

#[derive(Debug, Error)]
pub enum LoginRequestError {
    #[error("Invalid password format: {0}")]
    InvalidPasswordFormat(String),
    #[error("Password hash does not match")]
    InvalidPassword,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

// #################################################
// ############### ACCOUNT RETRIEVAL ###############
// #################################################

#[derive(Debug, Error)]
pub enum FindAccountError {
    #[error("Account not found")]
    NotFound,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

// #############################################################
// ############### VERIFICATION TICKET RETRIEVAL ###############
// #############################################################

#[derive(Debug, Error)]
pub enum FindLastVerificationTicketError {
    #[error("Account not found")]
    AccountNotFound,
    #[error("No verification ticket found")]
    NoVerificationTicket,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}
