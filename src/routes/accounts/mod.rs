use crate::newtypes::{self, Email, EmailError, Opaque, Password, PasswordError};

use super::{ApiError, AppState};
use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, Nonce},
};
use anyhow::anyhow;
use argon2::Argon2;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use ed25519_dalek::SigningKey;
use fake::{Dummy, Fake, Faker};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use thiserror::Error;
use tracing::warn;

pub mod repository;

pub fn accounts_router() -> Router<AppState> {
    Router::new()
        .route("/signup", post(sign_up))
        // Added a test route for checking user existence
        .route("/{email}/test-exists", get(test_user_exists))
}

// ##################################################
// ############### ACCOUNT DEFINITION ###############
// ##################################################

#[derive(Debug, Clone, FromRow)]
pub struct Account {
    id: uuid::Uuid,
    email: String,
    password_hash: Opaque<String>,
    symmetric_key_salt: Opaque<[u8; 16]>,
    encrypted_private_key: Opaque<String>,
    public_key: Opaque<[u8; 32]>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

// #######################################
// ############### SIGN UP ###############
// #######################################

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignUpRequestHttpBody {
    /// Email of the user
    pub email: String,
    /// Password of the user
    pub password: Opaque<String>,
    /// Salt used for deriving the symmetric key from the password, must be base64 encoded
    pub symmetric_key_salt: Opaque<String>,
    /// Encrypted Ed25519 private key of the user using AES-256-GCM with a key derived from the password and symmetric_key_salt, must be base64 encoded
    pub encrypted_private_key: Opaque<String>,
    /// Nonce used for the encryption of the private key, must be 12 bytes encoded in base64
    pub encrypted_private_key_nonce: Opaque<String>,
    /// Public key of the user, must be base64 encoded
    pub public_key: Opaque<String>,
}

impl<T> Dummy<T> for SignUpRequestHttpBody {
    fn dummy_with_rng<R: fake::Rng + ?Sized>(_config: &T, rng: &mut R) -> Self {
        let email: newtypes::Email = Faker.fake_with_rng(rng);
        let password: newtypes::Password = Faker.fake_with_rng(rng);

        let private_key_bytes: [u8; 32] = Faker.fake_with_rng(rng);
        let ed25519_secret_key = SigningKey::from_bytes(&private_key_bytes);
        let ed25519_public_key = ed25519_secret_key.verifying_key();
        let public_key_b64 = BASE64_STANDARD.encode(ed25519_public_key.to_bytes());

        let symmetric_key_salt_bytes: [u8; 16] = Faker.fake_with_rng(rng);
        let symmetric_key_salt_b64 = BASE64_STANDARD.encode(symmetric_key_salt_bytes);

        let mut symmetric_key_material = [0u8; 32];
        Argon2::default()
            .hash_password_into(
                password.unsafe_inner().as_bytes(),
                &symmetric_key_salt_bytes,
                &mut symmetric_key_material,
            )
            .unwrap();
        let aes_gcm_key = Key::<Aes256Gcm>::from_slice(&symmetric_key_material);
        let cipher = Aes256Gcm::new(aes_gcm_key);

        let encrypted_private_key_nonce_bytes: [u8; 12] = Faker.fake_with_rng(rng);
        let encrypted_private_key_nonce =
            Nonce::<Aes256Gcm>::from_slice(&encrypted_private_key_nonce_bytes);
        let encrypted_private_key = cipher
            .encrypt(encrypted_private_key_nonce, private_key_bytes.as_ref())
            .unwrap();
        let encrypted_private_key_b64 = BASE64_STANDARD.encode(encrypted_private_key);
        let encrypted_private_key_nonce_b64 =
            BASE64_STANDARD.encode(encrypted_private_key_nonce_bytes);

        SignUpRequestHttpBody {
            email: email.to_string(),
            password: password.unsafe_inner().to_owned().into(),
            symmetric_key_salt: symmetric_key_salt_b64.into(),
            encrypted_private_key: encrypted_private_key_b64.into(),
            encrypted_private_key_nonce: encrypted_private_key_nonce_b64.into(),
            public_key: public_key_b64.into(),
        }
    }
}

async fn sign_up(
    State(app_state): State<AppState>,
    Json(body): Json<SignUpRequestHttpBody>,
) -> Result<(StatusCode, Json<AccountResponse>), ApiError> {
    let _signup_request = SignupRequest::try_from_http_body(body).map_err(|e| match e {
        SignupRequestError::InvalidEmailFormat(msg) => {
            ApiError::BadRequest(format!("invalid email format: {msg}"))
        }
        SignupRequestError::InvalidPasswordFormat(msg) => {
            ApiError::BadRequest(format!("invalid password format: {msg}"))
        }
        SignupRequestError::InvalidSymmetricKeySaltFormat(msg) => {
            ApiError::BadRequest(format!("invalid symmetric key salt format: {msg}"))
        }
        SignupRequestError::InvalidEncryptedPrivateKeyNonceFormat(msg) => {
            ApiError::BadRequest(format!("invalid encrypted private key nonce format: {msg}"))
        }
        SignupRequestError::InvalidEncryptedPrivateKeyFormat(msg) => {
            ApiError::BadRequest(format!("invalid encrypted private key format: {msg}"))
        }
        SignupRequestError::InvalidPublicKeyFormat(msg) => {
            ApiError::BadRequest(format!("invalid public key format: {msg}"))
        }
        SignupRequestError::InvalidKeyPair => {
            ApiError::BadRequest("invalid key pair or nonce".to_string())
        }
        SignupRequestError::Unknown(e) => ApiError::InternalServerError(e),
    })?;

    let created_account = app_state
        .accounts_repository
        .create_account(&_signup_request)
        .await
        .map_err(|e| match e {
            CreateAccountError::EmailAlreadyCreated => {
                ApiError::BadRequest("an account with the given email already exists".to_string())
            }
            CreateAccountError::Unknown(err) => ApiError::InternalServerError(err),
        })?;

    Ok((
        StatusCode::CREATED,
        Json(AccountResponse::from(created_account)),
    ))
}

#[allow(dead_code)]
pub struct SignupRequest {
    email: String,
    password_hash: Opaque<String>,
    symmetric_key_salt: Opaque<[u8; 16]>,
    encrypted_private_key: Opaque<String>,
    public_key: Opaque<[u8; 32]>,
}

#[derive(Debug, Error)]
enum SignupRequestError {
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
    fn try_from_http_body(body: SignUpRequestHttpBody) -> Result<Self, SignupRequestError> {
        let email = Email::new(&body.email)
            .map_err(|e| match e {
                EmailError::Empty => {
                    SignupRequestError::InvalidEmailFormat("Email cannot be empty".to_string())
                }
                EmailError::InvalidFormat => {
                    SignupRequestError::InvalidEmailFormat("Email format is invalid".to_string())
                }
            })?
            .to_string();
        let password = Password::new(body.password.unsafe_inner()).map_err(|e| match e {
            PasswordError::Empty => {
                SignupRequestError::InvalidPasswordFormat("Password cannot be empty".to_string())
            }
            PasswordError::InvalidPassword(reason) => {
                SignupRequestError::InvalidPasswordFormat(reason)
            }
        })?;

        let decoded_symmetric_key_salt = BASE64_STANDARD
            .decode(body.symmetric_key_salt.unsafe_inner())
            .map_err(|e| {
                SignupRequestError::InvalidSymmetricKeySaltFormat(format!(
                    "Invalid base64 format: {}",
                    e
                ))
            })?;
        if decoded_symmetric_key_salt.len() != 16 {
            return Err(SignupRequestError::InvalidSymmetricKeySaltFormat(
                "Symmetric key salt must be 16 bytes long".to_string(),
            ));
        }
        let decoded_symmetric_key_salt: [u8; 16] = {
            let mut array = [0u8; 16];
            array.clone_from_slice(&decoded_symmetric_key_salt);
            array
        };
        let mut symmetric_key_material = [0u8; 32];
        Argon2::default()
            .hash_password_into(
                password.unsafe_inner().as_bytes(),
                &decoded_symmetric_key_salt,
                &mut symmetric_key_material,
            )
            .map_err(|e| anyhow!("{e}").context("Failed to generate symmetric key material"))?;

        let aes_gcm_key = Key::<Aes256Gcm>::from_slice(&symmetric_key_material);
        let cipher = Aes256Gcm::new(aes_gcm_key);

        let decoded_encrypted_private_key_nonce = BASE64_STANDARD
            .decode(body.encrypted_private_key_nonce.unsafe_inner())
            .map_err(|e| {
                SignupRequestError::InvalidEncryptedPrivateKeyNonceFormat(format!(
                    "Invalid base64 format: {}",
                    e
                ))
            })?;
        if decoded_encrypted_private_key_nonce.len() != 12 {
            return Err(SignupRequestError::InvalidEncryptedPrivateKeyNonceFormat(
                "Encrypted private key nonce must be 12 bytes long".to_string(),
            ));
        }
        let decoded_encrypted_private_key_nonce =
            Nonce::<Aes256Gcm>::from_slice(&decoded_encrypted_private_key_nonce);

        let decoded_encrypted_private_key = BASE64_STANDARD
            .decode(body.encrypted_private_key.unsafe_inner())
            .map_err(|e| {
                SignupRequestError::InvalidEncryptedPrivateKeyFormat(format!(
                    "Invalid base64 format: {}",
                    e
                ))
            })?;

        let decrypted_private_key = cipher
            .decrypt(
                decoded_encrypted_private_key_nonce,
                decoded_encrypted_private_key.as_ref(),
            )
            .map_err(|e| {
                warn!("Private key decryption error: {}", e);
                SignupRequestError::InvalidKeyPair
            })?;

        if decrypted_private_key.len() != 32 {
            warn!(
                "Decrypted private key has invalid length: {}",
                decrypted_private_key.len()
            );
            return Err(SignupRequestError::InvalidKeyPair);
        }
        let decrypted_private_key: [u8; 32] = decrypted_private_key
            .as_slice()
            .try_into()
            .map_err(|_| SignupRequestError::InvalidKeyPair)?;

        let ed25519_secret_key = SigningKey::from_bytes(&decrypted_private_key);
        let ed25519_public_key = ed25519_secret_key.verifying_key();

        let decoded_public_key = BASE64_STANDARD
            .decode(body.public_key.unsafe_inner())
            .map_err(|e| {
                SignupRequestError::InvalidPublicKeyFormat(format!("Invalid base64 format: {}", e))
            })?;
        if decoded_public_key.len() != 32 {
            return Err(SignupRequestError::InvalidPublicKeyFormat(
                "Public key must be 32 bytes long".to_string(),
            ));
        }
        let decoded_public_key: [u8; 32] = {
            let mut array = [0u8; 32];
            array.clone_from_slice(&decoded_public_key);
            array
        };

        if ed25519_public_key.to_bytes().as_slice() != decoded_public_key.as_slice() {
            return Err(SignupRequestError::InvalidKeyPair);
        }

        let password_hash = password
            .hash()
            .map_err(|e| anyhow!("{e}").context("Failed to hash password"))?;

        Ok(SignupRequest {
            email,
            password_hash: password_hash.into(),
            symmetric_key_salt: decoded_symmetric_key_salt.into(),
            encrypted_private_key: BASE64_STANDARD.encode(decoded_encrypted_private_key).into(),
            public_key: decoded_public_key.into(),
        })
    }
}

#[derive(Debug, Error)]
pub enum CreateAccountError {
    #[error("An account with the given email already exists")]
    EmailAlreadyCreated,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

#[derive(Debug, Serialize, Deserialize)]
struct AccountResponse {
    pub id: uuid::Uuid,
    pub email: String,
    pub symmetric_key_salt: Opaque<String>,
    pub encrypted_private_key: Opaque<String>,
    pub public_key: Opaque<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<Account> for AccountResponse {
    fn from(account: Account) -> Self {
        AccountResponse {
            id: account.id,
            email: account.email,
            symmetric_key_salt: BASE64_STANDARD
                .encode(account.symmetric_key_salt.unsafe_inner())
                .into(),
            encrypted_private_key: account.encrypted_private_key,
            public_key: BASE64_STANDARD
                .encode(account.public_key.unsafe_inner())
                .into(),
            created_at: account.created_at,
            updated_at: account.updated_at,
        }
    }
}

// ##############################################################
// ############### TEST EXISTENCE - TO BE REMOVED ###############
// ##############################################################

async fn test_user_exists(Path(_email): Path<String>) -> Result<StatusCode, ApiError> {
    Ok(StatusCode::OK)
}

#[derive(Debug, Error)]
pub enum GetAccountError {
    #[error("Account not found")]
    NotFound,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_signup_request() {
        let http_signup_request: SignUpRequestHttpBody = Faker.fake();
        let result = SignupRequest::try_from_http_body(http_signup_request.clone());
        assert!(result.is_ok());
        let signup_request = result.unwrap();
        assert_eq!(signup_request.email, signup_request.email);
        assert_eq!(
            signup_request.public_key.unsafe_inner(),
            BASE64_STANDARD
                .decode(http_signup_request.public_key.unsafe_inner())
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            signup_request.symmetric_key_salt.unsafe_inner(),
            BASE64_STANDARD
                .decode(http_signup_request.symmetric_key_salt.unsafe_inner())
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_invalid_email_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        signup_request.email = "invalid-email-format".to_string();
        let result = SignupRequest::try_from_http_body(signup_request);
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidEmailFormat(_) => {}
            _ => panic!("Expected InvalidEmailFormat error"),
        };
    }

    #[test]
    fn test_invalid_password_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        signup_request.password = Opaque::new("abc".to_string());
        let result = SignupRequest::try_from_http_body(signup_request);
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidPasswordFormat(_) => {}
            _ => panic!("Expected InvalidPasswordFormat error"),
        };
    }

    #[test]
    fn test_invalid_symmetric_key_salt_base64_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        signup_request.symmetric_key_salt = Opaque::new("invalid-base64".to_string());
        let result = SignupRequest::try_from_http_body(signup_request);
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidSymmetricKeySaltFormat(_) => {}
            _ => panic!("Expected InvalidSymmetricKeySaltFormat error"),
        };
    }

    #[test]
    fn test_invalid_symmetric_key_salt_wrong_length_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        let invalid_salt = BASE64_STANDARD.encode(vec![0u8; 10]); // 10 bytes instead of 16
        signup_request.symmetric_key_salt = Opaque::new(invalid_salt);
        let result = SignupRequest::try_from_http_body(signup_request);
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidSymmetricKeySaltFormat(_) => {}
            _ => panic!("Expected InvalidSymmetricKeySaltFormat error"),
        };
    }

    #[test]
    fn test_invalid_encrypted_private_key_nonce_base64_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        signup_request.encrypted_private_key_nonce = Opaque::new("invalid-base64".to_string());
        let result = SignupRequest::try_from_http_body(signup_request);
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidEncryptedPrivateKeyNonceFormat(_) => {}
            _ => panic!("Expected InvalidEncryptedPrivateKeyNonceFormat error"),
        };
    }

    #[test]
    fn test_invalid_encrypted_private_key_nonce_wrong_length_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        let invalid_nonce = BASE64_STANDARD.encode(vec![0u8; 10]); // 10 bytes instead of 12
        signup_request.encrypted_private_key_nonce = Opaque::new(invalid_nonce);
        let result = SignupRequest::try_from_http_body(signup_request);
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidEncryptedPrivateKeyNonceFormat(_) => {}
            _ => panic!("Expected InvalidEncryptedPrivateKeyNonceFormat error"),
        };
    }

    #[test]
    fn test_invalid_encrypted_private_key_base64_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        signup_request.encrypted_private_key = Opaque::new("invalid-base64".to_string());
        let result = SignupRequest::try_from_http_body(signup_request);
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidEncryptedPrivateKeyFormat(_) => {}
            _ => panic!("Expected InvalidEncryptedPrivateKeyFormat error"),
        };
    }

    #[test]
    fn test_invalid_public_key_base64_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        signup_request.public_key = Opaque::new("invalid-base64".to_string());
        let result = SignupRequest::try_from_http_body(signup_request);
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidPublicKeyFormat(_) => {}
            _ => panic!("Expected InvalidPublicKeyFormat error"),
        };
    }

    #[test]
    fn test_invalid_public_key() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        // Corrupt the public key by changing a character
        let corrupted_public_key = flip_first_byte(signup_request.public_key.unsafe_inner());
        signup_request.public_key = Opaque::new(corrupted_public_key);
        let result = SignupRequest::try_from_http_body(signup_request);
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidKeyPair => {}
            _ => panic!("Expected InvalidKeyPair error"),
        };
    }

    #[test]
    fn test_invalid_encrypted_private_key() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        // Corrupt the encrypted private key by changing a character
        let corrupted_encrypted_private_key =
            flip_first_byte(signup_request.encrypted_private_key.unsafe_inner());
        signup_request.encrypted_private_key = Opaque::new(corrupted_encrypted_private_key);
        let result = SignupRequest::try_from_http_body(signup_request);
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidKeyPair => {}
            _ => panic!("Expected InvalidKeyPair error"),
        };
    }

    #[test]
    fn test_invalid_encrypted_private_key_nonce() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        // Corrupt the encrypted private key nonce by changing a character
        let corrupted_encrypted_private_key_nonce =
            flip_first_byte(signup_request.encrypted_private_key_nonce.unsafe_inner());
        signup_request.encrypted_private_key_nonce =
            Opaque::new(corrupted_encrypted_private_key_nonce);
        let result = SignupRequest::try_from_http_body(signup_request);
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidKeyPair => {}
            e => {
                panic!("Expected InvalidKeyPair error: {:?}", e)
            }
        };
    }

    fn flip_first_byte(base64_str: &str) -> String {
        let mut bytes = BASE64_STANDARD.decode(base64_str).unwrap();
        bytes[0] ^= 0xFF; // Flip some bits
        BASE64_STANDARD.encode(bytes)
    }
}
