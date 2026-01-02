use crate::{
    crypto::{
        keypair::{EncryptedKeyPair, KeyPair},
        password,
    },
    newtypes::{Email, EmailError, Opaque, Password, PasswordError},
    secrets,
};

use super::{ApiError, AppState, AuthorizedAccount, jwt};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use base64::{
    Engine,
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE},
};
use fake::{Dummy, Fake, Faker, rand};
use serde::{Deserialize, Serialize};

use crate::domains::accounts::{
    Account, CreateAccountError, FindAccountError, FindLastVerificationTicketError, LoginError,
    LoginRequest, LoginRequestError, NewVerificationTicketError, NewVerificationTicketRequest,
    NewVerificationTicketRequestError, SignupRequest, SignupRequestError,
    UseVerificationTicketError, UseVerificationTicketRequest, UseVerificationTicketRequestError,
    VerificationTicket,
};
use tracing::info;

pub fn accounts_router() -> Router<AppState> {
    Router::new()
        .route("/signup", post(sign_up))
        .route("/verification-tickets/use", post(use_verification_ticket))
        .route("/verification-tickets", post(new_verification_ticket))
        .route("/login", post(login))
        .route("/me", get(get_me))
}

// #######################################
// ############### SIGN UP ###############
// #######################################

async fn sign_up(
    State(app_state): State<AppState>,
    Json(body): Json<SignUpRequestHttpBody>,
) -> Result<StatusCode, ApiError> {
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
        SignupRequestError::InvalidEncryptionNonceFormat(msg) => {
            ApiError::BadRequest(format!("invalid encryption nonce format: {msg}"))
        }
        SignupRequestError::InvalidPrivateKeyCiphertextFormat(msg) => {
            ApiError::BadRequest(format!("invalid ciphertext format: {msg}"))
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

    Ok(StatusCode::CREATED)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignUpRequestHttpBody {
    /// Email of the user
    pub email: String,
    /// Password of the user
    pub password: Opaque<String>,
    /// Encrypted key pair of the user, see [EncryptedKeyPairHttpBody] for more details
    pub encrypted_key_pair: EncryptedKeyPairHttpBody,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedKeyPairHttpBody {
    /// Salt used for deriving the symmetric key from the password, must be base64 encoded
    pub symmetric_key_salt: Opaque<String>,
    /// Nonce used for the encryption of the private key, must be 12 bytes encoded in base64
    pub encryption_nonce: Opaque<String>,
    /// Encrypted Ed25519 private key of the user using AES-256-GCM with a key derived from the password and symmetric_key_salt, the used nonce is `encryptedPrivateKeyNonce`.
    /// It must be base64 encoded
    pub ciphertext: Opaque<String>,
    /// Public Ed25519 key of the user, must be base64 encoded
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
            .decode(self.encrypted_key_pair.symmetric_key_salt.unsafe_inner())
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

        let decoded_encryption_nonce = BASE64_STANDARD
            .decode(self.encrypted_key_pair.encryption_nonce.unsafe_inner())
            .map_err(|e| {
                SignupRequestError::InvalidEncryptionNonceFormat(format!(
                    "Invalid base64 format: {}",
                    e
                ))
            })?;
        if decoded_encryption_nonce.len() != 12 {
            return Err(SignupRequestError::InvalidEncryptionNonceFormat(
                "Encryption nonce must be 12 bytes long".to_string(),
            ));
        }
        let decoded_encryption_nonce: [u8; 12] = slice_to_array(&decoded_encryption_nonce);

        let decoded_encrypted_key_pair = BASE64_STANDARD
            .decode(self.encrypted_key_pair.ciphertext.unsafe_inner())
            .map_err(|e| {
                SignupRequestError::InvalidPrivateKeyCiphertextFormat(format!(
                    "Invalid base64 format: {}",
                    e
                ))
            })?;

        let decoded_public_key = BASE64_STANDARD
            .decode(self.encrypted_key_pair.public_key.unsafe_inner())
            .map_err(|e| {
                SignupRequestError::InvalidPublicKeyFormat(format!("Invalid base64 format: {}", e))
            })?;
        if decoded_public_key.len() != 32 {
            return Err(SignupRequestError::InvalidPublicKeyFormat(
                "Public key must be 32 bytes long".to_string(),
            ));
        }
        let decoded_public_key: [u8; 32] = slice_to_array(&decoded_public_key);
        let encrypted_key_pair = EncryptedKeyPair::new(
            decoded_symmetric_key_salt.into(),
            decoded_encryption_nonce.into(),
            decoded_encrypted_key_pair.into(),
            decoded_public_key.into(),
            &password,
        )
        .map_err(|_e| SignupRequestError::InvalidKeyPair)?;

        // Verification token is a base64url-encoded random 32-byte value
        let verification_ticket_token: [u8; 32] = rand::random();

        let verification_ticket_lifetime = chrono::Duration::minutes(15);

        let password_hash =
            password::hash_password(&password).map_err(|e| e.context("Failed to hash password"))?;

        Ok(SignupRequest::new(
            email,
            password_hash.into(),
            encrypted_key_pair,
            verification_ticket_token.into(),
            verification_ticket_lifetime,
        ))
    }
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

        let key_pair = KeyPair::generate();
        let encrypted_key_pair = key_pair.encrypt(&password).unwrap();

        SignUpRequestHttpBody {
            email: email.to_string(),
            password: password.unsafe_inner().to_owned().into(),
            encrypted_key_pair: EncryptedKeyPairHttpBody {
                symmetric_key_salt: BASE64_STANDARD
                    .encode(encrypted_key_pair.symmetric_key_salt.unsafe_inner())
                    .into(),
                ciphertext: BASE64_STANDARD
                    .encode(encrypted_key_pair.ciphertext.unsafe_inner())
                    .into(),
                encryption_nonce: BASE64_STANDARD
                    .encode(encrypted_key_pair.encryption_nonce.unsafe_inner())
                    .into(),
                public_key: BASE64_STANDARD
                    .encode(encrypted_key_pair.public_key.unsafe_inner())
                    .into(),
            },
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
            FindLastVerificationTicketError::NoVerificationTicket(_) => {
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

// #######################################################
// ############### NEW VERIFICATION TICKET ###############
// #######################################################

async fn new_verification_ticket(
    State(app_state): State<AppState>,
    Json(body): Json<NewVerificationTicketRequestHttpBody>,
) -> Result<StatusCode, ApiError> {
    let email = Email::new(&body.email).map_err(|e| match e {
        EmailError::Empty => ApiError::BadRequest("Email cannot be empty".to_string()),
        EmailError::InvalidFormat => ApiError::BadRequest("Email format is invalid".to_string()),
    })?;
    let (account, last_verification_ticket) = match app_state
        .accounts_repository
        .find_account_and_last_verification_ticket_by_email(&email)
        .await
    {
        Ok((account, last_verification_ticket)) => (account, Some(last_verification_ticket)),
        Err(e) => match e {
            FindLastVerificationTicketError::AccountNotFound => {
                return Err(ApiError::NotFound);
            }
            FindLastVerificationTicketError::NoVerificationTicket(account) => (account, None),
            FindLastVerificationTicketError::Unknown(err) => {
                return Err(ApiError::InternalServerError(err));
            }
        },
    };

    // Map to domain
    let domain_request = body
        .try_into_domain(&account, &last_verification_ticket)
        .map_err(|e| match e {
            NewVerificationTicketRequestError::InvalidPasswordFormat(msg) => {
                ApiError::BadRequest(format!("invalid password format: {msg}"))
            }
            NewVerificationTicketRequestError::InvalidPassword => {
                ApiError::BadRequest("Invalid password".to_string())
            }
            NewVerificationTicketRequestError::AlreadyVerified => {
                ApiError::BadRequest("Account is already verified".to_string())
            }
            NewVerificationTicketRequestError::NotEnoughTimePassed => ApiError::BadRequest(
                "Not enough time has passed since the last ticket was created".to_string(),
            ),
            NewVerificationTicketRequestError::Unknown(err) => ApiError::InternalServerError(err),
        })?;

    // Cancel existing ticket if any and create a new one
    let verification_ticket = app_state
        .accounts_repository
        .create_new_verification_ticket(&domain_request)
        .await
        .map_err(|e| match e {
            NewVerificationTicketError::Unknown(err) => ApiError::InternalServerError(err),
        })?;

    app_state
        .accounts_notifier
        .new_verification_ticket_created(&account, &verification_ticket)
        .await;

    Ok(StatusCode::CREATED)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NewVerificationTicketRequestHttpBody {
    pub email: String,
    pub password: Opaque<String>,
}

impl NewVerificationTicketRequestHttpBody {
    fn try_into_domain(
        self,
        account: &Account,
        ticket: &Option<VerificationTicket>,
    ) -> Result<NewVerificationTicketRequest, NewVerificationTicketRequestError> {
        let password = Password::new(self.password.unsafe_inner()).map_err(|e| match e {
            PasswordError::Empty => NewVerificationTicketRequestError::InvalidPasswordFormat(
                "Password cannot be empty".to_string(),
            ),
            PasswordError::InvalidPassword(reason) => {
                NewVerificationTicketRequestError::InvalidPasswordFormat(reason)
            }
        })?;

        if password::verify_password(&account.password_hash, &password).is_err() {
            return Err(NewVerificationTicketRequestError::InvalidPassword);
        }

        if account.verified {
            return Err(NewVerificationTicketRequestError::AlreadyVerified);
        }

        if let Some(existing_ticket) = ticket {
            let min_interval = chrono::Duration::minutes(5);
            let now = chrono::Utc::now();
            if existing_ticket.created_at + min_interval > now {
                return Err(NewVerificationTicketRequestError::NotEnoughTimePassed);
            }
        }

        // Verification token is a base64url-encoded random 32-byte value
        let verification_ticket_token: [u8; 32] = rand::random();

        let verification_ticket_lifetime = chrono::Duration::minutes(15);

        Ok(NewVerificationTicketRequest::new(
            account.id,
            ticket.as_ref().map(|t| t.id),
            verification_ticket_token.into(),
            verification_ticket_lifetime,
        ))
    }
}

// #####################################
// ############### LOGIN ###############
// #####################################

async fn login(
    State(app_state): State<AppState>,
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

    let jwt_secret = app_state
        .secrets_manager
        .get(secrets::SecretKey::JwtSecret)
        .map_err(|e| {
            anyhow::anyhow!("{e}").context("Failed to get JWT secret from secrets manager")
        })?;

    let login_request = body
        .try_into_domain(&account, &jwt_secret)
        .map_err(|e| match e {
            LoginRequestError::InvalidPassword => {
                ApiError::BadRequest("Invalid email or password".to_string())
            }
            LoginRequestError::InvalidPasswordFormat(msg) => {
                ApiError::BadRequest(format!("invalid password format: {msg}"))
            }
            LoginRequestError::AccountNotVerified => {
                ApiError::BadRequest("Account is not verified".to_string())
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

    app_state
        .accounts_notifier
        .account_logged_in(&account)
        .await;

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
        jwt_secret: &Opaque<String>,
    ) -> Result<LoginRequest, LoginRequestError> {
        let password = Password::new(self.password.unsafe_inner()).map_err(|e| match e {
            PasswordError::Empty => {
                LoginRequestError::InvalidPasswordFormat("Password cannot be empty".to_string())
            }
            PasswordError::InvalidPassword(reason) => {
                LoginRequestError::InvalidPasswordFormat(reason)
            }
        })?;
        if !account.verified {
            return Err(LoginRequestError::AccountNotVerified);
        }

        if password::verify_password(&account.password_hash, &password).is_err() {
            return Err(LoginRequestError::InvalidPassword);
        }

        let access_token = jwt::encode_jwt(account.id, jwt_secret).map_err(|e| {
            LoginRequestError::Unknown(anyhow::Error::new(e).context("failed to generate token"))
        })?;

        Ok(LoginRequest::new(account.id, access_token))
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginResponse {
    pub access_token: Opaque<String>,
}

// ################################
// ############## ME ##############
// ################################

async fn get_me(
    State(app_state): State<AppState>,
    authorized_account: AuthorizedAccount,
) -> Result<Json<MeResponse>, ApiError> {
    let account = app_state
        .accounts_repository
        .find_account_by_id(authorized_account.account_id)
        .await
        .map_err(|e| match e {
            FindAccountError::NotFound => ApiError::NotFound,
            FindAccountError::Unknown(err) => ApiError::InternalServerError(err),
        })?;

    Ok(Json(account.into()))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeResponse {
    pub email: String,
    pub encrypted_key_pair: EncryptedKeyPairResponse,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedKeyPairResponse {
    pub symmetric_key_salt: Opaque<String>,
    pub encryption_nonce: Opaque<String>,
    pub ciphertext: Opaque<String>,
    pub public_key: Opaque<String>,
}

impl From<Account> for MeResponse {
    fn from(account: Account) -> Self {
        MeResponse {
            email: account.email.to_string(),
            encrypted_key_pair: EncryptedKeyPairResponse {
                symmetric_key_salt: BASE64_STANDARD
                    .encode(account.private_key_symmetric_key_salt.unsafe_inner())
                    .into(),
                encryption_nonce: BASE64_STANDARD
                    .encode(account.private_key_encryption_nonce.unsafe_inner())
                    .into(),
                ciphertext: BASE64_STANDARD
                    .encode(account.private_key_ciphertext.unsafe_inner())
                    .into(),
                public_key: BASE64_STANDARD
                    .encode(account.public_key.unsafe_inner())
                    .into(),
            },
            created_at: account.created_at,
        }
    }
}

// #####################################
// ############### TESTS ###############
// #####################################

#[cfg(test)]
mod tests {
    use base64::prelude::BASE64_URL_SAFE;
    use fake::{Fake, Faker};

    use super::*;

    // ################ SIGNUP TESTS ################

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
            signup_request.encrypted_key_pair.public_key.unsafe_inner(),
            BASE64_STANDARD
                .decode(
                    http_signup_request
                        .encrypted_key_pair
                        .public_key
                        .unsafe_inner()
                )
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            signup_request
                .encrypted_key_pair
                .symmetric_key_salt
                .unsafe_inner(),
            BASE64_STANDARD
                .decode(
                    http_signup_request
                        .encrypted_key_pair
                        .symmetric_key_salt
                        .unsafe_inner()
                )
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            signup_request
                .encrypted_key_pair
                .encryption_nonce
                .unsafe_inner(),
            BASE64_STANDARD
                .decode(
                    http_signup_request
                        .encrypted_key_pair
                        .encryption_nonce
                        .unsafe_inner()
                )
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            signup_request.encrypted_key_pair.ciphertext.unsafe_inner(),
            BASE64_STANDARD
                .decode(
                    http_signup_request
                        .encrypted_key_pair
                        .ciphertext
                        .unsafe_inner()
                )
                .unwrap()
                .as_slice()
        );
        let password = Password::new(http_signup_request.password.unsafe_inner()).unwrap();
        assert!(password::verify_password(&signup_request.password_hash, &password).is_ok());

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
        signup_request.encrypted_key_pair.symmetric_key_salt =
            Opaque::new("invalid-base64".to_string());
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
        signup_request.encrypted_key_pair.symmetric_key_salt = Opaque::new(invalid_salt);
        let result = signup_request.try_into_domain();
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidSymmetricKeySaltFormat(_) => {}
            _ => panic!("Expected InvalidSymmetricKeySaltFormat error"),
        };
    }

    #[test]
    fn test_invalid_encryption_nonce_base64_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        signup_request.encrypted_key_pair.encryption_nonce =
            Opaque::new("invalid-base64".to_string());
        let result = signup_request.try_into_domain();
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidEncryptionNonceFormat(_) => {}
            _ => panic!("Expected InvalidEncryptionNonceFormat error"),
        };
    }

    #[test]
    fn test_invalid_encryption_nonce_wrong_length_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        let invalid_nonce = BASE64_STANDARD.encode(vec![0u8; 10]); // 10 bytes instead of 12
        signup_request.encrypted_key_pair.encryption_nonce = Opaque::new(invalid_nonce);
        let result = signup_request.try_into_domain();
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidEncryptionNonceFormat(_) => {}
            _ => panic!("Expected InvalidEncryptionNonceFormat error"),
        };
    }

    #[test]
    fn test_invalid_encrypted_key_pair_base64_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        signup_request.encrypted_key_pair.ciphertext = Opaque::new("invalid-base64".to_string());
        let result = signup_request.try_into_domain();
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidPrivateKeyCiphertextFormat(_) => {}
            _ => panic!("Expected InvalidPrivateKeyCiphertextFormat error"),
        };
    }

    #[test]
    fn test_invalid_public_key_base64_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        signup_request.encrypted_key_pair.public_key = Opaque::new("invalid-base64".to_string());
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
        let corrupted_public_key =
            flip_first_byte(signup_request.encrypted_key_pair.public_key.unsafe_inner());
        signup_request.encrypted_key_pair.public_key = Opaque::new(corrupted_public_key);
        let result = signup_request.try_into_domain();
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidKeyPair => {}
            _ => panic!("Expected InvalidKeyPair error"),
        };
    }

    #[test]
    fn test_invalid_encrypted_key_pair() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        // Corrupt the encrypted private key by changing a character
        let corrupted_encrypted_key_pair =
            flip_first_byte(signup_request.encrypted_key_pair.ciphertext.unsafe_inner());
        signup_request.encrypted_key_pair.ciphertext = Opaque::new(corrupted_encrypted_key_pair);
        let result = signup_request.try_into_domain();
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidKeyPair => {}
            _ => panic!("Expected InvalidKeyPair error"),
        };
    }

    #[test]
    fn test_invalid_encryption_nonce() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        // Corrupt the encrypted private key nonce by changing a character
        let corrupted_encryption_nonce = flip_first_byte(
            signup_request
                .encrypted_key_pair
                .encryption_nonce
                .unsafe_inner(),
        );
        signup_request.encrypted_key_pair.encryption_nonce =
            Opaque::new(corrupted_encryption_nonce);
        let result = signup_request.try_into_domain();
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestError::InvalidKeyPair => {}
            e => {
                panic!("Expected InvalidKeyPair error: {:?}", e)
            }
        };
    }

    // ################ USE VERIFICATION TICKET TESTS ################

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

    // ################ LOGIN TESTS ################

    #[test]
    fn test_valid_login_request() {
        let password = Faker.fake::<Password>();
        let mut account = fake_account();
        account.password_hash = password::hash_password(&password).unwrap().into();
        account.verified = true;
        let http_request = LoginRequestHttpBody {
            email: account.email.to_string(),
            password: password.unsafe_inner().to_owned().into(),
        };
        let jwt_secret = Opaque::new(Faker.fake::<String>());
        let result = http_request.try_into_domain(&account, &jwt_secret);
        assert!(result.is_ok());
        let login_request = result.unwrap();
        assert_eq!(login_request.account_id, account.id);
        assert!(jwt::decode_and_validate_jwt(&login_request.access_token, &jwt_secret).is_ok());
    }

    #[test]
    fn test_unverified_account_login_request() {
        let password = Faker.fake::<Password>();
        let mut account = fake_account();
        account.password_hash = password::hash_password(&password).unwrap().into();
        account.verified = false;
        let http_request = LoginRequestHttpBody {
            email: account.email.to_string(),
            password: password.unsafe_inner().to_owned().into(),
        };
        let jwt_secret = Opaque::new(Faker.fake::<String>());
        let result = http_request.try_into_domain(&account, &jwt_secret);
        assert!(result.is_err());
        match result.err().unwrap() {
            LoginRequestError::AccountNotVerified => {}
            _ => panic!("Expected AccountNotVerified error"),
        };
    }

    #[test]
    fn test_invalid_password_format_login_request() {
        let password = Faker.fake::<Password>();
        let mut account = fake_account();
        account.password_hash = password::hash_password(&password).unwrap().into();
        account.verified = true;
        let http_request = LoginRequestHttpBody {
            email: account.email.to_string(),
            password: Opaque::new("".to_string()), // Empty password
        };
        let jwt_secret = Opaque::new(Faker.fake::<String>());
        let result = http_request.try_into_domain(&account, &jwt_secret);
        assert!(result.is_err());
        match result.err().unwrap() {
            LoginRequestError::InvalidPasswordFormat(_) => {}
            _ => panic!("Expected InvalidPasswordFormat error"),
        };
    }

    #[test]
    fn test_invalid_password_login_request() {
        let mut account = fake_account();
        account.verified = true;
        let password = Faker.fake::<Password>();
        let http_request = LoginRequestHttpBody {
            email: account.email.to_string(),
            password: password.unsafe_inner().to_owned().into(),
        };
        let jwt_secret = Opaque::new(Faker.fake::<String>());
        let result = http_request.try_into_domain(&account, &jwt_secret);
        assert!(result.is_err());
        match result.err().unwrap() {
            LoginRequestError::InvalidPassword => {}
            _ => panic!("Expected InvalidPassword error"),
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
            password_hash: password::hash_password(&password).unwrap().into(),
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

    // ################ NEW VERIFICATION TICKET TESTS ################

    #[test]
    fn test_valid_new_verification_ticket_request_without_last_ticket() {
        let mut account = fake_account();
        let password = Faker.fake::<Password>();
        account.password_hash = password::hash_password(&password).unwrap().into();
        let http_request = NewVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            password: password.unsafe_inner().to_owned().into(),
        };
        let last_ticket = None;
        let result = http_request.try_into_domain(&account, &last_ticket);
        assert!(result.is_ok());
        let new_ticket_request = result.unwrap();
        assert_eq!(new_ticket_request.account_id, account.id);
        assert_eq!(new_ticket_request.ticket_id_to_cancel, None);
        assert!(
            !new_ticket_request
                .verification_ticket_token
                .unsafe_inner()
                .is_empty()
        );
        assert!(new_ticket_request.verification_ticket_expires_at > chrono::Utc::now());
    }

    #[test]
    fn test_valid_new_verification_ticket_request_with_last_ticket() {
        let mut account = fake_account();
        let password = Faker.fake::<Password>();
        account.password_hash = password::hash_password(&password).unwrap().into();
        let mut last_ticket = fake_verification_ticket(account.id);
        last_ticket.created_at = chrono::Utc::now() - chrono::Duration::minutes(6);
        last_ticket.expires_at = chrono::Utc::now() + chrono::Duration::minutes(9);
        let http_request = NewVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            password: password.unsafe_inner().to_owned().into(),
        };

        let result = http_request.try_into_domain(&account, &Some(last_ticket.clone()));
        assert!(result.is_ok());
        let new_ticket_request = result.unwrap();
        assert_eq!(new_ticket_request.account_id, account.id);
        assert_eq!(new_ticket_request.ticket_id_to_cancel, Some(last_ticket.id));
        assert!(
            !new_ticket_request
                .verification_ticket_token
                .unsafe_inner()
                .is_empty()
        );
        assert!(new_ticket_request.verification_ticket_expires_at > chrono::Utc::now());
    }

    #[test]
    fn test_invalid_new_verification_ticket_request_invalid_password_format() {
        let mut account = fake_account();
        let password = Faker.fake::<Password>();
        account.password_hash = password::hash_password(&password).unwrap().into();
        let http_request = NewVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            password: Opaque::new("".to_string()), // Empty password
        };
        let last_ticket = None;
        let result = http_request.try_into_domain(&account, &last_ticket);
        assert!(result.is_err());
        match result.err().unwrap() {
            NewVerificationTicketRequestError::InvalidPasswordFormat(_) => {}
            _ => panic!("Expected InvalidPasswordFormat error"),
        };
    }

    #[test]
    fn test_invalid_new_verification_ticket_request_invalid_password() {
        let account = fake_account();
        let password = Faker.fake::<Password>();
        let http_request = NewVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            password: password.unsafe_inner().to_owned().into(), // Different password
        };
        let last_ticket = None;
        let result = http_request.try_into_domain(&account, &last_ticket);
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
        account.password_hash = password::hash_password(&password).unwrap().into();
        account.verified = true;
        let http_request = NewVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            password: password.unsafe_inner().to_owned().into(),
        };
        let last_ticket = None;
        let result = http_request.try_into_domain(&account, &last_ticket);
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
        account.password_hash = password::hash_password(&password).unwrap().into();
        let mut last_ticket = fake_verification_ticket(account.id);
        last_ticket.created_at = chrono::Utc::now() - chrono::Duration::minutes(4);
        last_ticket.expires_at = chrono::Utc::now() + chrono::Duration::minutes(11);
        let http_request = NewVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            password: password.unsafe_inner().to_owned().into(),
        };
        let result = http_request.try_into_domain(&account, &Some(last_ticket.clone()));
        assert!(result.is_err());
        match result.err().unwrap() {
            NewVerificationTicketRequestError::NotEnoughTimePassed => {}
            _ => panic!("Expected NotEnoughTimePassed error"),
        };
    }
}
