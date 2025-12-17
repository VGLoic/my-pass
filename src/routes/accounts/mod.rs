use crate::{
    argon2instance::argon2_instance,
    newtypes::{Email, EmailError, Opaque, Password, PasswordError},
};

use super::{ApiError, AppState, jwt};
use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{Aead, Nonce},
};
use anyhow::anyhow;
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::{
    Engine,
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE},
};
use ed25519_dalek::SigningKey;
use fake::{Dummy, Fake, Faker, rand};
use serde::{Deserialize, Serialize};

use crate::domains::accounts::{
    Account, CreateAccountError, FindAccountError, FindLastVerificationTicketError, LoginError,
    LoginRequest, LoginRequestError, SignupRequest, SignupRequestError, UseVerificationTicketError,
    UseVerificationTicketRequest, UseVerificationTicketRequestError, VerificationTicket,
};
use tracing::info;

pub fn accounts_router(jwt_secret: &Opaque<String>) -> Router<AppState> {
    Router::new()
        .route("/signup", post(sign_up))
        .route("/verification-tickets/use", post(use_verification_ticket))
        .route("/login", post(login).layer(Extension(jwt_secret.clone())))
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
    let signup_request = body.try_into_domain().map_err(|e| match e {
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

    let (created_account, created_ticket) = app_state
        .accounts_repository
        .create_account(&signup_request)
        .await
        .map_err(|e| match e {
            CreateAccountError::EmailAlreadyCreated => {
                ApiError::BadRequest("an account with the given email already exists".to_string())
            }
            CreateAccountError::Unknown(err) => ApiError::InternalServerError(err),
        })?;

    app_state
        .accounts_notifier
        .account_signed_up(&created_account, &created_ticket)
        .await;

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

impl SignUpRequestHttpBody {
    pub fn try_into_domain(self) -> Result<SignupRequest, SignupRequestError> {
        let email = Email::new(&self.email).map_err(|e| match e {
            EmailError::Empty => {
                SignupRequestError::InvalidEmailFormat("Email cannot be empty".to_string())
            }
            EmailError::InvalidFormat => {
                SignupRequestError::InvalidEmailFormat("Email format is invalid".to_string())
            }
        })?;
        let password = Password::new(self.password.unsafe_inner()).map_err(|e| match e {
            PasswordError::Empty => {
                SignupRequestError::InvalidPasswordFormat("Password cannot be empty".to_string())
            }
            PasswordError::InvalidPassword(reason) => {
                SignupRequestError::InvalidPasswordFormat(reason)
            }
        })?;

        let decoded_symmetric_key_salt = BASE64_STANDARD
            .decode(self.symmetric_key_salt.unsafe_inner())
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
        let decoded_symmetric_key_salt: [u8; 16] = slice_to_array(&decoded_symmetric_key_salt);

        let decoded_encrypted_private_key_nonce = BASE64_STANDARD
            .decode(self.encrypted_private_key_nonce.unsafe_inner())
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
        let decoded_encrypted_private_key_nonce: [u8; 12] =
            slice_to_array(&decoded_encrypted_private_key_nonce);

        let decoded_encrypted_private_key = BASE64_STANDARD
            .decode(self.encrypted_private_key.unsafe_inner())
            .map_err(|e| {
                SignupRequestError::InvalidEncryptedPrivateKeyFormat(format!(
                    "Invalid base64 format: {}",
                    e
                ))
            })?;

        let decoded_public_key = BASE64_STANDARD
            .decode(self.public_key.unsafe_inner())
            .map_err(|e| {
                SignupRequestError::InvalidPublicKeyFormat(format!("Invalid base64 format: {}", e))
            })?;
        if decoded_public_key.len() != 32 {
            return Err(SignupRequestError::InvalidPublicKeyFormat(
                "Public key must be 32 bytes long".to_string(),
            ));
        }
        let decoded_public_key: [u8; 32] = slice_to_array(&decoded_public_key);

        if verify_key_material(
            &password,
            &decoded_symmetric_key_salt,
            &decoded_encrypted_private_key_nonce,
            &decoded_encrypted_private_key,
            &decoded_public_key,
        )
        .is_err()
        {
            return Err(SignupRequestError::InvalidKeyPair);
        }

        // Verification token is a base64url-encoded random 32-byte value
        let verification_ticket_token: [u8; 32] = rand::random();

        let verification_ticket_lifetime = chrono::Duration::minutes(15);

        let password_hash = password
            .hash()
            .map_err(|e| e.context("Failed to hash password"))?;

        Ok(SignupRequest::new(
            email,
            password_hash.into(),
            Opaque::new(decoded_symmetric_key_salt),
            Opaque::new(decoded_encrypted_private_key_nonce),
            self.encrypted_private_key,
            Opaque::new(decoded_public_key),
            verification_ticket_token.into(),
            verification_ticket_lifetime,
        ))
    }
}

fn verify_key_material(
    password: &Password,
    symmetric_key_salt: &[u8; 16],
    encrypted_private_key_nonce: &[u8; 12],
    encrypted_private_key: &[u8],
    public_key: &[u8; 32],
) -> Result<(), anyhow::Error> {
    let mut symmetric_key_material = [0u8; 32];
    argon2_instance()
        .hash_password_into(
            password.unsafe_inner().as_bytes(),
            symmetric_key_salt,
            &mut symmetric_key_material,
        )
        .map_err(|e| anyhow!("{e}").context("Failed to generate symmetric key material"))?;

    let aes_gcm_key = Key::<Aes256Gcm>::from_slice(&symmetric_key_material);
    let cipher = Aes256Gcm::new(aes_gcm_key);

    let encrypted_private_key_nonce_aes_formatted =
        Nonce::<Aes256Gcm>::from_slice(encrypted_private_key_nonce);

    let decrypted_private_key = cipher
        .decrypt(
            encrypted_private_key_nonce_aes_formatted,
            encrypted_private_key,
        )
        .map_err(|e| anyhow!("{e}").context("Failed to decrypt private key"))?;

    if decrypted_private_key.len() != 32 {
        return Err(anyhow!("Invalid decrypted private key length"));
    }

    let decrypted_private_key: [u8; 32] = slice_to_array(&decrypted_private_key);

    let ed25519_secret_key = SigningKey::from_bytes(&decrypted_private_key);
    let ed25519_public_key = ed25519_secret_key.verifying_key();

    if ed25519_public_key.to_bytes().as_slice() != public_key.as_slice() {
        return Err(anyhow!("Public key does not match decrypted private key"));
    }

    Ok(())
}

fn slice_to_array<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut array = [0u8; N];
    array.copy_from_slice(slice);
    array
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
        argon2_instance()
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
#[serde(rename_all = "camelCase")]
pub struct AccountResponse {
    pub email: String,
    pub symmetric_key_salt: Opaque<String>,
    pub encrypted_private_key_nonce: Opaque<String>,
    pub encrypted_private_key: Opaque<String>,
    pub public_key: Opaque<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<Account> for AccountResponse {
    fn from(account: Account) -> Self {
        AccountResponse {
            email: account.email.to_string(),
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
        }
    }
}

// #######################################################
// ############### USE VERIFICATION TICKET ###############
// #######################################################

async fn use_verification_ticket(
    State(app_state): State<AppState>,
    Json(body): Json<UseVerificationTicketRequestHttpBody>,
) -> Result<StatusCode, ApiError> {
    let email = Email::new(&body.email).map_err(|e| match e {
        EmailError::Empty => ApiError::BadRequest("Email cannot be empty".to_string()),
        EmailError::InvalidFormat => ApiError::BadRequest("Email format is invalid".to_string()),
    })?;
    let (account, ticket) = app_state
        .accounts_repository
        .find_account_and_last_verification_ticket_by_email(&email)
        .await
        .map_err(|e| match e {
            FindLastVerificationTicketError::AccountNotFound => ApiError::NotFound,
            FindLastVerificationTicketError::NoVerificationTicket => {
                ApiError::BadRequest("No verification ticket has been found".to_string())
            }
            FindLastVerificationTicketError::Unknown(err) => ApiError::InternalServerError(err),
        })?;

    let use_verification_ticket_request =
        body.try_into_domain(account, ticket).map_err(|e| match e {
            UseVerificationTicketRequestError::AlreadyVerified => {
                ApiError::BadRequest("Account is already verified".to_string())
            }
            UseVerificationTicketRequestError::AlreadyUsed => {
                ApiError::BadRequest("Verification ticket has already been used".to_string())
            }
            UseVerificationTicketRequestError::Cancelled => {
                ApiError::BadRequest("Verification ticket has been cancelled".to_string())
            }
            UseVerificationTicketRequestError::Expired => {
                ApiError::BadRequest("Verification ticket has expired".to_string())
            }
            UseVerificationTicketRequestError::InvalidToken => {
                ApiError::BadRequest("Invalid verification ticket token".to_string())
            }
            UseVerificationTicketRequestError::Unknown(err) => ApiError::InternalServerError(err),
        })?;

    app_state
        .accounts_repository
        .verify_account(&use_verification_ticket_request)
        .await
        .map_err(|e| match e {
            UseVerificationTicketError::Unknown(err) => ApiError::InternalServerError(err),
        })?;

    info!("Account with email {} verified", &email);

    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UseVerificationTicketRequestHttpBody {
    pub email: String,
    pub token: Opaque<String>,
}

impl UseVerificationTicketRequestHttpBody {
    pub fn try_into_domain(
        self,
        account: Account,
        verification_ticket: VerificationTicket,
    ) -> Result<UseVerificationTicketRequest, UseVerificationTicketRequestError> {
        if account.verified {
            return Err(UseVerificationTicketRequestError::AlreadyVerified);
        }

        if verification_ticket.used_at.is_some() {
            return Err(UseVerificationTicketRequestError::AlreadyUsed);
        }

        if verification_ticket.cancelled_at.is_some() {
            return Err(UseVerificationTicketRequestError::Cancelled);
        }

        if verification_ticket.expires_at < chrono::Utc::now() {
            return Err(UseVerificationTicketRequestError::Expired);
        }

        // Constant time comparison to prevent timing attacks
        let decoded_input = BASE64_URL_SAFE
            .decode(self.token.unsafe_inner())
            .map_err(|_| UseVerificationTicketRequestError::InvalidToken)?;
        let decoded_stored = BASE64_URL_SAFE
            .decode(verification_ticket.token.unsafe_inner())
            .map_err(|_| UseVerificationTicketRequestError::InvalidToken)?;

        let compared_input = if decoded_input.len() != decoded_stored.len() {
            // If lengths differ, create a dummy vector of the same length as stored token
            vec![0u8; decoded_stored.len()]
        } else {
            decoded_input
        };
        let equal_side_by_side = compared_input
            .iter()
            .zip(decoded_stored.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
        if !equal_side_by_side {
            return Err(UseVerificationTicketRequestError::InvalidToken);
        }

        Ok(UseVerificationTicketRequest::new(
            account.id,
            verification_ticket.id,
        ))
    }
}

// #####################################
// ############### LOGIN ###############
// #####################################

async fn login(
    State(app_state): State<AppState>,
    Extension(jwt_secret): Extension<Opaque<String>>,
    Json(body): Json<LoginRequestHttpBody>,
) -> Result<(StatusCode, Json<LoginResponse>), ApiError> {
    let email = Email::new(&body.email).map_err(|e| match e {
        EmailError::Empty => ApiError::BadRequest("Email cannot be empty".to_string()),
        EmailError::InvalidFormat => ApiError::BadRequest("Email format is invalid".to_string()),
    })?;
    let account = app_state
        .accounts_repository
        .find_account_by_email(&email)
        .await
        .map_err(|e| match e {
            FindAccountError::NotFound => {
                ApiError::BadRequest("Invalid email or password".to_string())
            }
            FindAccountError::Unknown(err) => ApiError::InternalServerError(err),
        })?;

    let login_request = body
        .try_into_domain(&account, jwt_secret)
        .map_err(|e| match e {
            LoginRequestError::InvalidPassword => {
                ApiError::BadRequest("Invalid email or password".to_string())
            }
            LoginRequestError::InvalidPasswordFormat(msg) => {
                ApiError::BadRequest(format!("invalid password format: {msg}"))
            }
            LoginRequestError::Unknown(err) => ApiError::InternalServerError(err),
        })?;

    app_state
        .accounts_repository
        .record_login(account.id)
        .await
        .map_err(|e| match e {
            LoginError::Unknown(err) => ApiError::InternalServerError(err),
        })?;
    // REMIND ME
    // - Add notifier

    Ok((
        StatusCode::OK,
        Json(LoginResponse {
            access_token: login_request.access_token,
        }),
    ))
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoginRequestHttpBody {
    pub email: String,
    pub password: Opaque<String>,
}

impl LoginRequestHttpBody {
    fn try_into_domain(
        self,
        account: &Account,
        jwt_secret: Opaque<String>,
    ) -> Result<LoginRequest, LoginRequestError> {
        let password = Password::new(self.password.unsafe_inner()).map_err(|e| match e {
            PasswordError::Empty => {
                LoginRequestError::InvalidPasswordFormat("Password cannot be empty".to_string())
            }
            PasswordError::InvalidPassword(reason) => {
                LoginRequestError::InvalidPasswordFormat(reason)
            }
        })?;

        if password
            .verify(account.password_hash.unsafe_inner())
            .is_err()
        {
            return Err(LoginRequestError::InvalidPassword);
        }

        let access_token = jwt::encode_jwt(account.id, &jwt_secret).map_err(|e| {
            LoginRequestError::Unknown(anyhow::Error::new(e).context("failed to generate token"))
        })?;

        Ok(LoginRequest::new(account.id, access_token))
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginResponse {
    pub access_token: Opaque<String>,
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
        .find_account_by_email(&email)
        .await
    {
        Ok(_) => Ok(StatusCode::OK),
        Err(FindAccountError::NotFound) => Ok(StatusCode::NOT_FOUND),
        Err(e) => Err(ApiError::InternalServerError(e.into())),
    }
}

#[cfg(test)]
mod tests {
    use base64::prelude::BASE64_URL_SAFE;
    use fake::{Fake, Faker};

    use super::*;

    #[test]
    fn test_valid_signup_request() {
        let http_signup_request: SignUpRequestHttpBody = Faker.fake();
        let result = http_signup_request.clone().try_into_domain();
        assert!(result.is_ok());
        let signup_request = result.unwrap();
        assert_eq!(
            signup_request.email.as_str(),
            http_signup_request.email.as_str()
        );
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
        assert_eq!(
            signup_request.encrypted_private_key_nonce.unsafe_inner(),
            BASE64_STANDARD
                .decode(
                    http_signup_request
                        .encrypted_private_key_nonce
                        .unsafe_inner()
                )
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            signup_request.encrypted_private_key.unsafe_inner(),
            http_signup_request.encrypted_private_key.unsafe_inner()
        );
        let password = Password::new(http_signup_request.password.unsafe_inner()).unwrap();
        assert!(
            password
                .verify(signup_request.password_hash.unsafe_inner())
                .is_ok()
        );

        assert!(
            !signup_request
                .verification_ticket_token
                .unsafe_inner()
                .is_empty()
        );
        assert!(signup_request.verification_ticket_expires_at > chrono::Utc::now());
    }

    #[test]
    fn test_invalid_email_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        signup_request.email = "invalid-email-format".to_string();
        let result = signup_request.try_into_domain();
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
        let result = signup_request.try_into_domain();
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
        let result = signup_request.try_into_domain();
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
        let result = signup_request.try_into_domain();
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
        let result = signup_request.try_into_domain();
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
        let result = signup_request.try_into_domain();
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
        let result = signup_request.try_into_domain();
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
        let result = signup_request.try_into_domain();
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
        let result = signup_request.try_into_domain();
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
        let result = signup_request.try_into_domain();
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
        let result = signup_request.try_into_domain();
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidKeyPair => {}
            e => {
                panic!("Expected InvalidKeyPair error: {:?}", e)
            }
        };
    }

    #[test]
    fn test_valid_use_verification_ticket_request() {
        let account = fake_account();
        let verification_ticket = fake_verification_ticket(account.id);
        let http_request = UseVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            token: verification_ticket.token.clone(),
        };
        let result = http_request.try_into_domain(account.clone(), verification_ticket.clone());
        assert!(result.is_ok());
        let use_verification_ticket_request = result.unwrap();
        assert_eq!(use_verification_ticket_request.account_id, account.id);
        assert_eq!(
            use_verification_ticket_request.valid_ticket_id,
            verification_ticket.id
        );
    }

    #[test]
    fn test_invalid_token_use_verification_ticket_request() {
        let account = fake_account();
        let verification_ticket = fake_verification_ticket(account.id);
        let mut http_request = UseVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            token: verification_ticket.token.clone(),
        };
        // Corrupt the token
        let corrupted_token = {
            let mut token_bytes = BASE64_URL_SAFE
                .decode(http_request.token.unsafe_inner())
                .unwrap();
            token_bytes[0] ^= 0xFF; // Flip some bits
            BASE64_URL_SAFE.encode(token_bytes)
        };
        http_request.token = Opaque::new(corrupted_token);
        let result = http_request.try_into_domain(account.clone(), verification_ticket.clone());
        assert!(result.is_err());
        match result.err().unwrap() {
            UseVerificationTicketRequestError::InvalidToken => {}
            _ => panic!("Expected InvalidToken error"),
        };
    }

    #[test]
    fn test_account_already_verified_use_verification_ticket_request() {
        let mut account = fake_account();
        account.verified = true;
        let verification_ticket = fake_verification_ticket(account.id);
        let http_request = UseVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            token: verification_ticket.token.clone(),
        };
        let result = http_request.try_into_domain(account.clone(), verification_ticket.clone());
        assert!(result.is_err());
        match result.err().unwrap() {
            UseVerificationTicketRequestError::AlreadyVerified => {}
            _ => panic!("Expected AlreadyVerified error"),
        };
    }

    #[test]
    fn test_ticket_already_used_use_verification_ticket_request() {
        let account = fake_account();
        let mut verification_ticket = fake_verification_ticket(account.id);
        verification_ticket.used_at = Some(chrono::Utc::now());
        let http_request = UseVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            token: verification_ticket.token.clone(),
        };
        let result = http_request.try_into_domain(account.clone(), verification_ticket.clone());
        assert!(result.is_err());
        match result.err().unwrap() {
            UseVerificationTicketRequestError::AlreadyUsed => {}
            _ => panic!("Expected AlreadyUsed error"),
        };
    }

    #[test]
    fn test_ticket_cancelled_use_verification_ticket_request() {
        let account = fake_account();
        let mut verification_ticket = fake_verification_ticket(account.id);
        verification_ticket.cancelled_at = Some(chrono::Utc::now());
        let http_request = UseVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            token: verification_ticket.token.clone(),
        };
        let result = http_request.try_into_domain(account.clone(), verification_ticket.clone());
        assert!(result.is_err());
        match result.err().unwrap() {
            UseVerificationTicketRequestError::Cancelled => {}
            _ => panic!("Expected Cancelled error"),
        };
    }

    #[test]
    fn test_ticket_expired_use_verification_ticket_request() {
        let account = fake_account();
        let mut verification_ticket = fake_verification_ticket(account.id);
        verification_ticket.expires_at = chrono::Utc::now() - chrono::Duration::minutes(1);
        let http_request = UseVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            token: verification_ticket.token.clone(),
        };
        let result = http_request.try_into_domain(account.clone(), verification_ticket.clone());
        assert!(result.is_err());
        match result.err().unwrap() {
            UseVerificationTicketRequestError::Expired => {}
            _ => panic!("Expected Expired error"),
        };
    }

    fn flip_first_byte(base64_str: &str) -> String {
        let mut bytes = BASE64_STANDARD.decode(base64_str).unwrap();
        bytes[0] ^= 0xFF; // Flip some bits
        BASE64_STANDARD.encode(bytes)
    }

    fn fake_account() -> Account {
        let password = Faker.fake::<Password>();
        Account {
            id: uuid::Uuid::new_v4(),
            email: Faker.fake(),
            password_hash: password.hash().unwrap().into(),
            verified: false,
            symmetric_key_salt: Opaque::new(Faker.fake::<[u8; 16]>()),
            encrypted_private_key_nonce: Opaque::new(Faker.fake::<[u8; 12]>()),
            encrypted_private_key: Opaque::new(BASE64_STANDARD.encode(vec![0u8; 64])),
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
