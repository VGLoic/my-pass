use crate::newtypes::{Email, EmailError, Opaque, Password};

use super::{ApiError, AppState};
use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, Nonce},
};
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

pub mod domain;
pub mod repository;
use domain::{Account, CreateAccountError, GetAccountError, SignupRequest, SignupRequestError};
use tracing::info;

pub fn accounts_router() -> Router<AppState> {
    Router::new()
        .route("/signup", post(sign_up))
        // Added a test route for checking user existence
        .route("/{email}/test-exists", get(test_user_exists))
}

// #######################################
// ############### SIGN UP ###############
// #######################################

async fn sign_up(
    State(app_state): State<AppState>,
    Json(body): Json<SignUpRequestHttpBody>,
) -> Result<(StatusCode, Json<AccountResponse>), ApiError> {
    let signup_request = SignupRequest::try_from_http_body(body).map_err(|e| match e {
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
        .create_account(&signup_request)
        .await
        .map_err(|e| match e {
            CreateAccountError::EmailAlreadyCreated => {
                ApiError::BadRequest("an account with the given email already exists".to_string())
            }
            CreateAccountError::Unknown(err) => ApiError::InternalServerError(err),
        })?;

    info!("Account created with email: {}", created_account.email);

    Ok((
        StatusCode::CREATED,
        Json(AccountResponse::from(created_account)),
    ))
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignUpRequestHttpBody {
    /// Email of the user
    pub email: String,
    /// Password of the user
    pub password: Opaque<String>,
    /// Salt used for deriving the symmetric key from the password, must be base64 encoded
    pub symmetric_key_salt: Opaque<String>,
    /// Nonce used for the encryption of the private key, must be 12 bytes encoded in base64
    pub encrypted_private_key_nonce: Opaque<String>,
    /// Encrypted Ed25519 private key of the user using AES-256-GCM with a key derived from the password and symmetric_key_salt, the used nonce is `encryptedPrivateKeyNonce`.
    /// It must be base64 encoded
    pub encrypted_private_key: Opaque<String>,
    /// Public key of the user, must be base64 encoded
    pub public_key: Opaque<String>,
}

impl<T> Dummy<T> for SignUpRequestHttpBody {
    fn dummy_with_rng<R: fake::Rng + ?Sized>(_config: &T, rng: &mut R) -> Self {
        let email: Email = Faker.fake_with_rng(rng);
        let password: Password = Faker.fake_with_rng(rng);

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

#[derive(Debug, Serialize, Deserialize)]
struct AccountResponse {
    pub id: uuid::Uuid,
    pub email: String,
    pub symmetric_key_salt: Opaque<String>,
    pub encrypted_private_key_nonce: Opaque<String>,
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
            encrypted_private_key_nonce: BASE64_STANDARD
                .encode(account.encrypted_private_key_nonce.unsafe_inner())
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

async fn test_user_exists(
    State(app_state): State<AppState>,
    Path(email): Path<String>,
) -> Result<StatusCode, ApiError> {
    let email = Email::new(&email).map_err(|e| match e {
        EmailError::Empty => ApiError::BadRequest("Email cannot be empty".to_string()),
        EmailError::InvalidFormat => ApiError::BadRequest("Email format is invalid".to_string()),
    })?;
    match app_state
        .accounts_repository
        .get_account_by_email(&email)
        .await
    {
        Ok(_) => Ok(StatusCode::OK),
        Err(GetAccountError::NotFound) => Ok(StatusCode::NOT_FOUND),
        Err(e) => Err(ApiError::InternalServerError(e.into())),
    }
}
