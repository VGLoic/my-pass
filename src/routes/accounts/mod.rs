use crate::newtypes::{self, Email, EmailError, Opaque, Password, PasswordError};

use super::ApiError;
use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, Nonce},
};
use argon2::Argon2;
use axum::{
    Json, Router,
    extract::Path,
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use ed25519_dalek::SigningKey;
use fake::{Dummy, Fake, Faker, faker};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub fn accounts_router() -> Router {
    Router::new()
        .route("/signup", post(sign_up))
        // Added a test route for checking user existence
        .route("/{email}/test-exists", get(test_user_exists))
}

// #######################################
// ############### SIGN UP ###############
// #######################################

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpRequestHttpBody {
    // Email of the user
    pub email: String,
    // Password of the user
    pub password: Opaque<String>,
    // Salt used for deriving the symmetric key from the password, must be base64 encoded
    pub symmetric_key_salt: Opaque<String>,
    // Encrypted Ed25519 private key of the user using AES-256-GCM with a key derived from the password and symmetric_key_salt, must be base64 encoded
    pub encrypted_private_key: Opaque<String>,
    // Nonce used for the encryption of the private key, must be 12 bytes encoded in base64
    pub encrypted_private_key_nonce: Opaque<String>,
    // Public key of the user, must be base64 encoded
    pub public_key: Opaque<String>,
}

impl<T> Dummy<T> for SignUpRequestHttpBody {
    fn dummy_with_rng<R: fake::Rng + ?Sized>(_config: &T, rng: &mut R) -> Self {
        let email: newtypes::Email = Faker.fake_with_rng(rng);
        let mut password: String = faker::internet::en::Password(10..36).fake_with_rng(rng);
        password += "{&";
        password += "24";

        let private_key_bytes: [u8; 32] = Faker.fake_with_rng(rng);
        let ed25519_secret_key = SigningKey::from_bytes(&private_key_bytes);
        let ed25519_public_key = ed25519_secret_key.verifying_key();
        let public_key_b64 = BASE64_STANDARD.encode(ed25519_public_key.to_bytes());

        let symmetric_key_salt_bytes: [u8; 16] = Faker.fake_with_rng(rng);
        let symmetric_key_salt_b64 = BASE64_STANDARD.encode(symmetric_key_salt_bytes);

        let mut symmetric_key_material = [0u8; 32];
        Argon2::default()
            .hash_password_into(
                password.as_bytes(),
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
            password: password.into(),
            symmetric_key_salt: symmetric_key_salt_b64.into(),
            encrypted_private_key: encrypted_private_key_b64.into(),
            encrypted_private_key_nonce: encrypted_private_key_nonce_b64.into(),
            public_key: public_key_b64.into(),
        }
    }
}

async fn sign_up(
    Json(body): Json<SignUpRequestHttpBody>,
) -> Result<(StatusCode, &'static str), ApiError> {
    let _signup_request = SignupRequest::try_from_http_body(body).map_err(|e| match e {
        SignupRequestError::InvalidEmailFormat(msg) => {
            ApiError::BadRequest(format!("invalid email format: {msg}"))
        }
        SignupRequestError::InvalidPasswordFormat(msg) => {
            ApiError::BadRequest(format!("invalid password format: {msg}"))
        }
        SignupRequestError::InvalidKeyPair(msg) => {
            ApiError::BadRequest(format!("invalid key pair: {msg}"))
        }
    })?;
    Ok((StatusCode::CREATED, "Account created"))
}

// REMIND ME TO REMOVE
#[allow(dead_code)]
struct SignupRequest {
    email: String,
    password_hash: Opaque<String>,
    symmetric_key_salt: Opaque<String>,
    encrypted_private_key: Opaque<String>,
    public_key: Opaque<String>,
}

#[derive(Debug, Error)]
enum SignupRequestError {
    #[error("Invalid email format: {0}")]
    InvalidEmailFormat(String),
    #[error("Invalid password format: {0}")]
    InvalidPasswordFormat(String),
    #[error("Invalid key pair: {0}")]
    InvalidKeyPair(String),
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
                SignupRequestError::InvalidKeyPair(format!(
                    "Failed to decode symmetric key salt from base64: {}",
                    e
                ))
            })?;
        let mut symmetric_key_material = [0u8; 32];
        Argon2::default()
            .hash_password_into(
                body.password.unsafe_inner().as_bytes(),
                &decoded_symmetric_key_salt,
                &mut symmetric_key_material,
            )
            .map_err(|e| {
                SignupRequestError::InvalidKeyPair(format!("Failed to hash password: {}", e))
            })?;

        let aes_gcm_key = Key::<Aes256Gcm>::from_slice(&symmetric_key_material);
        let cipher = Aes256Gcm::new(aes_gcm_key);

        let decoded_encrypted_private_key_nonce = BASE64_STANDARD
            .decode(body.encrypted_private_key_nonce.unsafe_inner())
            .map_err(|e| {
                SignupRequestError::InvalidKeyPair(format!(
                    "Failed to decode encrypted private key nonce from base64: {}",
                    e
                ))
            })?;
        if decoded_encrypted_private_key_nonce.len() != 12 {
            return Err(SignupRequestError::InvalidKeyPair(
                "Encrypted private key nonce must be 12 bytes long".to_string(),
            ));
        }
        let decoded_encrypted_private_key_nonce =
            Nonce::<Aes256Gcm>::from_slice(&decoded_encrypted_private_key_nonce);

        let decoded_encrypted_private_key = BASE64_STANDARD
            .decode(body.encrypted_private_key.unsafe_inner())
            .map_err(|e| {
                SignupRequestError::InvalidKeyPair(format!(
                    "Failed to decode encrypted private key from base64: {}",
                    e
                ))
            })?;

        let decrypted_private_key = cipher
            .decrypt(
                decoded_encrypted_private_key_nonce,
                decoded_encrypted_private_key.as_ref(),
            )
            .map_err(|e| {
                SignupRequestError::InvalidKeyPair(format!("Failed to decrypt private key: {}", e))
            })?;

        if decrypted_private_key.len() != 32 {
            return Err(SignupRequestError::InvalidKeyPair(
                "Decrypted private key must be 32 bytes long".to_string(),
            ));
        }
        let decrypted_private_key: [u8; 32] =
            decrypted_private_key.as_slice().try_into().map_err(|_| {
                SignupRequestError::InvalidKeyPair(
                    "Failed to convert decrypted private key to array".to_string(),
                )
            })?;

        let ed25519_secret_key = SigningKey::from_bytes(&decrypted_private_key);
        let ed25519_public_key = ed25519_secret_key.verifying_key();

        let decoded_public_key = BASE64_STANDARD
            .decode(body.public_key.unsafe_inner())
            .map_err(|e| {
                SignupRequestError::InvalidKeyPair(format!(
                    "Failed to decode public key from base64: {}",
                    e
                ))
            })?;

        if ed25519_public_key.to_bytes().as_slice() != decoded_public_key.as_slice() {
            return Err(SignupRequestError::InvalidKeyPair(
                "Public key does not match the private key".to_string(),
            ));
        }

        let password_hash = password.hash().map_err(|e| {
            SignupRequestError::InvalidKeyPair(format!("Failed to hash password: {}", e))
        })?;

        Ok(SignupRequest {
            email,
            password_hash: password_hash.into(),
            symmetric_key_salt: BASE64_STANDARD.encode(decoded_symmetric_key_salt).into(),
            encrypted_private_key: BASE64_STANDARD.encode(decoded_encrypted_private_key).into(),
            public_key: BASE64_STANDARD.encode(decoded_public_key).into(),
        })
    }
}

// ##############################################################
// ############### TEST EXISTENCE - TO BE REMOVED ###############
// ##############################################################

async fn test_user_exists(Path(_email): Path<String>) -> Result<StatusCode, ApiError> {
    Ok(StatusCode::OK)
}
