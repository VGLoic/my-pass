use crate::{
    crypto::keypair::EncryptedKeyPair,
    newtypes::{Email, Opaque},
};
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
    pub private_key_symmetric_key_salt: Opaque<[u8; 16]>,
    pub private_key_encryption_nonce: Opaque<[u8; 12]>,
    pub private_key_ciphertext: Opaque<Vec<u8>>,
    pub public_key: Opaque<[u8; 32]>,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
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
    email: Email,
    password_hash: Opaque<String>,
    encrypted_key_pair: EncryptedKeyPair,
    verification_ticket_token: Opaque<String>,
    verification_ticket_expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Error)]
pub enum SignupRequestError {
    #[error("Invalid email format: {0}")]
    InvalidEmailFormat(String),
    #[error("Invalid password format: {0}")]
    InvalidPasswordFormat(String),
    #[error("Invalid symmetric key salt format: {0}")]
    InvalidSymmetricKeySaltFormat(String),
    #[error("Invalid encryption nonce format: {0}")]
    InvalidEncryptionNonceFormat(String),
    #[error("Invalid private key ciphertext format: {0}")]
    InvalidPrivateKeyCiphertextFormat(String),
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
        encrypted_key_pair: EncryptedKeyPair,
        verification_ticket_token: Opaque<[u8; 32]>,
        verification_ticket_lifetime: chrono::Duration,
    ) -> Self {
        let verification_ticket_token =
            BASE64_URL_SAFE.encode(verification_ticket_token.unsafe_inner());
        let verification_ticket_expires_at = chrono::Utc::now() + verification_ticket_lifetime;

        SignupRequest {
            email,
            password_hash,
            encrypted_key_pair,
            verification_ticket_token: verification_ticket_token.into(),
            verification_ticket_expires_at,
        }
    }

    pub fn email(&self) -> &Email {
        &self.email
    }
    pub fn password_hash(&self) -> &Opaque<String> {
        &self.password_hash
    }
    pub fn encrypted_key_pair(&self) -> &EncryptedKeyPair {
        &self.encrypted_key_pair
    }
    pub fn verification_ticket_token(&self) -> &Opaque<String> {
        &self.verification_ticket_token
    }
    pub fn verification_ticket_expires_at(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.verification_ticket_expires_at
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
    account_id: uuid::Uuid,
    valid_ticket_id: uuid::Uuid,
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

    pub fn account_id(&self) -> &uuid::Uuid {
        &self.account_id
    }
    pub fn valid_ticket_id(&self) -> &uuid::Uuid {
        &self.valid_ticket_id
    }
}

#[derive(Debug, Error)]
pub enum UseVerificationTicketError {
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

// #######################################################
// ############### NEW VERIFICATION TICKET ###############
// #######################################################

pub struct NewVerificationTicketRequest {
    account_id: uuid::Uuid,
    ticket_id_to_cancel: Option<uuid::Uuid>,
    verification_ticket_token: Opaque<String>,
    verification_ticket_expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Error)]
pub enum NewVerificationTicketRequestError {
    #[error("Invalid password format: {0}")]
    InvalidPasswordFormat(String),
    #[error("Password hash does not match")]
    InvalidPassword,
    #[error("Account is already verified")]
    AlreadyVerified,
    #[error("Not enough time has passed since the last ticket was created")]
    NotEnoughTimePassed,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

impl NewVerificationTicketRequest {
    pub fn new(
        account_id: uuid::Uuid,
        ticket_id_to_cancel: Option<uuid::Uuid>,
        verification_ticket_token: Opaque<[u8; 32]>,
        verification_ticket_lifetime: chrono::Duration,
    ) -> Self {
        let verification_ticket_token =
            BASE64_URL_SAFE.encode(verification_ticket_token.unsafe_inner());
        let verification_ticket_expires_at = chrono::Utc::now() + verification_ticket_lifetime;

        NewVerificationTicketRequest {
            account_id,
            ticket_id_to_cancel,
            verification_ticket_token: verification_ticket_token.into(),
            verification_ticket_expires_at,
        }
    }

    pub fn account_id(&self) -> &uuid::Uuid {
        &self.account_id
    }
    pub fn ticket_id_to_cancel(&self) -> &Option<uuid::Uuid> {
        &self.ticket_id_to_cancel
    }
    pub fn verification_ticket_token(&self) -> &Opaque<String> {
        &self.verification_ticket_token
    }
    pub fn verification_ticket_expires_at(&self) -> &chrono::DateTime<chrono::Utc> {
        &self.verification_ticket_expires_at
    }
}

#[derive(Debug, Error)]
pub enum NewVerificationTicketError {
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

// #############################################
// ############### ACCOUNT LOGIN ###############
// #############################################

pub struct LoginRequest {
    account_id: uuid::Uuid,
    access_token: Opaque<String>,
}

impl LoginRequest {
    pub fn new(account_id: uuid::Uuid, access_token: Opaque<String>) -> Self {
        LoginRequest {
            account_id,
            access_token,
        }
    }

    pub fn account_id(&self) -> &uuid::Uuid {
        &self.account_id
    }
    pub fn access_token(&self) -> &Opaque<String> {
        &self.access_token
    }
}

#[derive(Debug, Error)]
pub enum LoginRequestError {
    #[error("Invalid password format: {0}")]
    InvalidPasswordFormat(String),
    #[error("Password hash does not match")]
    InvalidPassword,
    #[error("Account is not verified")]
    AccountNotVerified,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum LoginError {
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
    NoVerificationTicket(Account),
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}
