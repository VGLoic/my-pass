use crate::{
    crypto::{jwt, keypair::EncryptedKeyPair, password::PasswordOps},
    newtypes::{Email, Opaque, Password},
};
use base64::{Engine, prelude::BASE64_URL_SAFE};
use fake::rand;
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
        password: Password,
        account: &Account,
        last_ticket: &Option<VerificationTicket>,
    ) -> Result<Self, NewVerificationTicketRequestError> {
        if password.verify(&account.password_hash).is_err() {
            return Err(NewVerificationTicketRequestError::InvalidPassword);
        }

        if account.verified {
            return Err(NewVerificationTicketRequestError::AlreadyVerified);
        }

        if let Some(existing_ticket) = last_ticket {
            let min_interval = chrono::Duration::minutes(5);
            let now = chrono::Utc::now();
            if existing_ticket.created_at + min_interval > now {
                return Err(NewVerificationTicketRequestError::NotEnoughTimePassed);
            }
        }

        // Verification token is a base64url-encoded random 32-byte value
        let verification_ticket_token = BASE64_URL_SAFE.encode(rand::random::<[u8; 32]>());
        let verification_ticket_lifetime = chrono::Duration::minutes(15);
        let verification_ticket_expires_at = chrono::Utc::now() + verification_ticket_lifetime;

        Ok(NewVerificationTicketRequest {
            account_id: account.id,
            ticket_id_to_cancel: last_ticket.as_ref().map(|t| t.id),
            verification_ticket_token: verification_ticket_token.into(),
            verification_ticket_expires_at,
        })
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
    pub fn new(
        password: Password,
        account: &Account,
        jwt_secret: Opaque<String>,
    ) -> Result<Self, LoginRequestError> {
        if !account.verified {
            return Err(LoginRequestError::AccountNotVerified);
        }

        if password.verify(&account.password_hash).is_err() {
            return Err(LoginRequestError::InvalidPassword);
        }

        let access_token = jwt::encode_jwt(account.id, &jwt_secret).map_err(|e| {
            LoginRequestError::Unknown(anyhow::Error::new(e).context("failed to generate token"))
        })?;

        Ok(LoginRequest {
            account_id: account.id,
            access_token,
        })
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

#[cfg(test)]
mod tests {
    use base64::prelude::BASE64_URL_SAFE;
    use fake::{Fake, Faker};

    use super::*;

    #[test]
    fn test_invalid_new_verification_ticket_request_invalid_password() {
        let account = fake_account();
        let password = Faker.fake::<Password>();
        let last_ticket = None;
        let result = NewVerificationTicketRequest::new(password, &account, &last_ticket);
        assert!(result.is_err());
        match result.err().unwrap() {
            NewVerificationTicketRequestError::InvalidPassword => {}
            _ => panic!("Expected InvalidPassword error"),
        };
    }

    #[test]
    fn test_invalid_new_verification_ticket_request_account_already_verified() {
        let mut account = fake_account();
        let password = Faker.fake::<Password>();
        account.password_hash = password.hash().unwrap().into();
        account.verified = true;
        let last_ticket = None;
        let result = NewVerificationTicketRequest::new(password, &account, &last_ticket);
        assert!(result.is_err());
        match result.err().unwrap() {
            NewVerificationTicketRequestError::AlreadyVerified => {}
            _ => panic!("Expected AlreadyVerified error"),
        };
    }

    #[test]
    fn test_invalid_new_verification_ticket_request_not_enough_time_passed() {
        let mut account = fake_account();
        let password = Faker.fake::<Password>();
        account.password_hash = password.hash().unwrap().into();
        let mut last_ticket = fake_verification_ticket(account.id);
        last_ticket.created_at = chrono::Utc::now() - chrono::Duration::minutes(4);
        last_ticket.expires_at = chrono::Utc::now() + chrono::Duration::minutes(11);
        let result = NewVerificationTicketRequest::new(password, &account, &Some(last_ticket));
        assert!(result.is_err());
        match result.err().unwrap() {
            NewVerificationTicketRequestError::NotEnoughTimePassed => {}
            _ => panic!("Expected NotEnoughTimePassed error"),
        };
    }

    // ################ LOGIN TESTS ################

    #[test]
    fn test_valid_new_verification_ticket_request_without_last_ticket() {
        let mut account = fake_account();
        let password = Faker.fake::<Password>();
        account.password_hash = password.hash().unwrap().into();
        let last_ticket = None;
        let result = NewVerificationTicketRequest::new(password, &account, &last_ticket);
        assert!(result.is_ok());
        let new_ticket_request = result.unwrap();
        assert_eq!(new_ticket_request.account_id(), &account.id);
        assert_eq!(new_ticket_request.ticket_id_to_cancel(), &None);
        assert!(
            !new_ticket_request
                .verification_ticket_token()
                .unsafe_inner()
                .is_empty()
        );
        assert!(new_ticket_request.verification_ticket_expires_at() > &chrono::Utc::now());
    }

    #[test]
    fn test_valid_new_verification_ticket_request_with_last_ticket() {
        let mut account = fake_account();
        let password = Faker.fake::<Password>();
        account.password_hash = password.hash().unwrap().into();
        let mut last_ticket = fake_verification_ticket(account.id);
        last_ticket.created_at = chrono::Utc::now() - chrono::Duration::minutes(6);
        last_ticket.expires_at = chrono::Utc::now() + chrono::Duration::minutes(9);

        let result =
            NewVerificationTicketRequest::new(password, &account, &Some(last_ticket.clone()));
        assert!(result.is_ok());
        let new_ticket_request = result.unwrap();
        assert_eq!(new_ticket_request.account_id(), &account.id);
        assert_eq!(
            new_ticket_request.ticket_id_to_cancel(),
            &Some(last_ticket.id)
        );
        assert!(
            !new_ticket_request
                .verification_ticket_token()
                .unsafe_inner()
                .is_empty()
        );
        assert!(new_ticket_request.verification_ticket_expires_at() > &chrono::Utc::now());
    }

    #[test]
    fn test_valid_login_request() {
        let password = Faker.fake::<Password>();
        let mut account = fake_account();
        account.password_hash = password.hash().unwrap().into();
        account.verified = true;
        let jwt_secret = Opaque::new(Faker.fake::<String>());
        let result = LoginRequest::new(password, &account, jwt_secret.clone());
        assert!(result.is_ok());
        let login_request = result.unwrap();
        assert_eq!(login_request.account_id(), &account.id);
        assert!(jwt::decode_and_validate_jwt(login_request.access_token(), &jwt_secret).is_ok());
    }

    #[test]
    fn test_unverified_account_login_request() {
        let password = Faker.fake::<Password>();
        let mut account = fake_account();
        account.password_hash = password.hash().unwrap().into();
        account.verified = false;
        let jwt_secret = Opaque::new(Faker.fake::<String>());
        let result = LoginRequest::new(password, &account, jwt_secret);
        assert!(result.is_err());
        match result.err().unwrap() {
            LoginRequestError::AccountNotVerified => {}
            _ => panic!("Expected AccountNotVerified error"),
        };
    }

    #[test]
    fn test_invalid_password_login_request() {
        let mut account = fake_account();
        account.verified = true;
        let password = Faker.fake::<Password>();
        let jwt_secret = Opaque::new(Faker.fake::<String>());
        let result = LoginRequest::new(password, &account, jwt_secret);
        assert!(result.is_err());
        match result.err().unwrap() {
            LoginRequestError::InvalidPassword => {}
            _ => panic!("Expected InvalidPassword error"),
        };
    }

    fn fake_account() -> Account {
        let password = Faker.fake::<Password>();
        Account {
            id: uuid::Uuid::new_v4(),
            email: Faker.fake(),
            password_hash: password.hash().unwrap().into(),
            verified: false,
            private_key_symmetric_key_salt: Opaque::new(Faker.fake::<[u8; 16]>()),
            private_key_encryption_nonce: Opaque::new(Faker.fake::<[u8; 12]>()),
            private_key_ciphertext: Opaque::new(vec![0u8; 64]),
            public_key: Opaque::new(Faker.fake::<[u8; 32]>()),
            last_login_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn fake_verification_ticket(account_id: uuid::Uuid) -> VerificationTicket {
        VerificationTicket {
            id: uuid::Uuid::new_v4(),
            account_id,
            token: Opaque::new(BASE64_URL_SAFE.encode(Faker.fake::<[u8; 32]>())),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(15),
            created_at: chrono::Utc::now(),
            cancelled_at: None,
            used_at: None,
            updated_at: chrono::Utc::now(),
        }
    }
}
