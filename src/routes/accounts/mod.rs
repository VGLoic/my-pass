use crate::{
    crypto::keypair::{EncryptedKeyPair, KeyPair},
    newtypes::{Email, EmailError, Opaque, Password, PasswordError},
    secrets,
};

use super::{ApiError, AppState, AuthorizedAccount};
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
use fake::{Dummy, Fake, Faker};
use serde::{Deserialize, Serialize};

use crate::domains::accounts::models::{
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
    let request = body.try_into_domain().map_err(|e| match e {
        SignupRequestMappingError::EmailFormat(msg) => {
            ApiError::BadRequest(format!("invalid email format: {msg}"))
        }
        SignupRequestMappingError::PasswordFormat(msg) => {
            ApiError::BadRequest(format!("invalid password format: {msg}"))
        }
        SignupRequestMappingError::SymmetricKeySaltFormat(msg) => {
            ApiError::BadRequest(format!("invalid symmetric key salt format: {msg}"))
        }
        SignupRequestMappingError::EncryptionNonceFormat(msg) => {
            ApiError::BadRequest(format!("invalid encryption nonce format: {msg}"))
        }
        SignupRequestMappingError::PrivateKeyCiphertextFormat(msg) => {
            ApiError::BadRequest(format!("invalid ciphertext format: {msg}"))
        }
        SignupRequestMappingError::PublicKeyFormat(msg) => {
            ApiError::BadRequest(format!("invalid public key format: {msg}"))
        }
        SignupRequestMappingError::KeyPair => {
            ApiError::BadRequest("invalid key pair or nonce".to_string())
        }
        SignupRequestMappingError::Request(e) => match e {
            SignupRequestError::Unknown(e) => ApiError::InternalServerError(e),
        },
    })?;

    let _ = app_state
        .accounts_service
        .signup(request)
        .await
        .map_err(|e| match e {
            CreateAccountError::EmailAlreadyCreated => {
                ApiError::BadRequest("an account with the given email already exists".to_string())
            }
            CreateAccountError::Unknown(err) => ApiError::InternalServerError(err),
        })?;

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
    /// Encrypted Ed25519 private key of the user using AES-256-GCM with a key derived from the password and symmetric_key_salt, the used nonce is `encryption_nonce`.
    /// It must be base64 encoded
    pub ciphertext: Opaque<String>,
    /// Public Ed25519 key of the user, must be base64 encoded
    pub public_key: Opaque<String>,
}

#[derive(Debug)]
enum SignupRequestMappingError {
    EmailFormat(String),
    PasswordFormat(String),
    SymmetricKeySaltFormat(String),
    EncryptionNonceFormat(String),
    PrivateKeyCiphertextFormat(String),
    PublicKeyFormat(String),
    KeyPair,
    Request(SignupRequestError),
}

impl SignUpRequestHttpBody {
    fn try_into_domain(self) -> Result<SignupRequest, SignupRequestMappingError> {
        let email = Email::new(&self.email).map_err(|e| match e {
            EmailError::Empty => {
                SignupRequestMappingError::EmailFormat("Email cannot be empty".to_string())
            }
            EmailError::InvalidFormat => {
                SignupRequestMappingError::EmailFormat("Email format is invalid".to_string())
            }
        })?;
        let password = Password::new(self.password.unsafe_inner()).map_err(|e| match e {
            PasswordError::Empty => {
                SignupRequestMappingError::PasswordFormat("Password cannot be empty".to_string())
            }
            PasswordError::InvalidPassword(reason) => {
                SignupRequestMappingError::PasswordFormat(reason)
            }
        })?;

        let decoded_symmetric_key_salt =
            base64_to_array::<16>(self.encrypted_key_pair.symmetric_key_salt.unsafe_inner())
                .map_err(SignupRequestMappingError::SymmetricKeySaltFormat)?;

        let decoded_encryption_nonce =
            base64_to_array::<12>(self.encrypted_key_pair.encryption_nonce.unsafe_inner())
                .map_err(SignupRequestMappingError::EncryptionNonceFormat)?;

        let decoded_encrypted_key_pair = BASE64_STANDARD
            .decode(self.encrypted_key_pair.ciphertext.unsafe_inner())
            .map_err(|e| {
                SignupRequestMappingError::PrivateKeyCiphertextFormat(format!(
                    "Invalid base64 format: {}",
                    e
                ))
            })?;

        let decoded_public_key =
            base64_to_array::<32>(self.encrypted_key_pair.public_key.unsafe_inner())
                .map_err(SignupRequestMappingError::PublicKeyFormat)?;

        let encrypted_key_pair = EncryptedKeyPair::new(
            password,
            decoded_symmetric_key_salt.into(),
            decoded_encryption_nonce.into(),
            decoded_encrypted_key_pair.into(),
            decoded_public_key.into(),
        )
        .map_err(|_e| SignupRequestMappingError::KeyPair)?;

        SignupRequest::new(email, encrypted_key_pair).map_err(SignupRequestMappingError::Request)
    }
}

fn base64_to_array<const N: usize>(base64_str: &str) -> Result<[u8; N], String> {
    let decoded = BASE64_STANDARD
        .decode(base64_str)
        .map_err(|e| format!("Invalid base64 format: {}", e))?;
    if decoded.len() != N {
        return Err(format!("Decoded data must be {} bytes long", N));
    }
    let array: [u8; N] = {
        let mut array = [0u8; N];
        array.copy_from_slice(&decoded);
        array
    };
    Ok(array)
}

impl<T> Dummy<T> for SignUpRequestHttpBody {
    fn dummy_with_rng<R: fake::Rng + ?Sized>(_config: &T, rng: &mut R) -> Self {
        let email: Email = Faker.fake_with_rng(rng);
        let password: Password = Faker.fake_with_rng(rng);

        let key_pair = KeyPair::generate();
        let encrypted_key_pair = key_pair.encrypt(password.clone()).unwrap();

        SignUpRequestHttpBody {
            email: email.to_string(),
            password: password.unsafe_inner().to_owned().into(),
            encrypted_key_pair: EncryptedKeyPairHttpBody {
                symmetric_key_salt: BASE64_STANDARD
                    .encode(encrypted_key_pair.symmetric_key_salt().unsafe_inner())
                    .into(),
                ciphertext: BASE64_STANDARD
                    .encode(encrypted_key_pair.ciphertext().unsafe_inner())
                    .into(),
                encryption_nonce: BASE64_STANDARD
                    .encode(encrypted_key_pair.encryption_nonce().unsafe_inner())
                    .into(),
                public_key: BASE64_STANDARD
                    .encode(encrypted_key_pair.public_key().unsafe_inner())
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
            UseVerificationTicketRequestMappingError::InvalidTokenFormat(_msg) => {
                ApiError::BadRequest("Invalid verification ticket token".to_string())
            }
            UseVerificationTicketRequestMappingError::InvalidRequest(e) => match e {
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
                UseVerificationTicketRequestError::Unknown(err) => {
                    ApiError::InternalServerError(err)
                }
            },
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

#[derive(Debug)]
enum UseVerificationTicketRequestMappingError {
    InvalidTokenFormat(String),
    InvalidRequest(UseVerificationTicketRequestError),
}

impl UseVerificationTicketRequestHttpBody {
    fn try_into_domain(
        self,
        account: Account,
        verification_ticket: VerificationTicket,
    ) -> Result<UseVerificationTicketRequest, UseVerificationTicketRequestMappingError> {
        let decoded_input = BASE64_URL_SAFE
            .decode(self.token.unsafe_inner())
            .map_err(|_| {
                UseVerificationTicketRequestMappingError::InvalidTokenFormat(
                    "Invalid token format".to_string(),
                )
            })?;

        UseVerificationTicketRequest::new(account, verification_ticket, decoded_input.into())
            .map_err(UseVerificationTicketRequestMappingError::InvalidRequest)
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
            NewVerificationTicketRequestMappingError::InvalidPasswordFormat(msg) => {
                ApiError::BadRequest(format!("invalid password format: {msg}"))
            }
            NewVerificationTicketRequestMappingError::InvalidRequest(e) => match e {
                NewVerificationTicketRequestError::InvalidPassword => {
                    ApiError::BadRequest("Invalid password".to_string())
                }
                NewVerificationTicketRequestError::AlreadyVerified => {
                    ApiError::BadRequest("Account is already verified".to_string())
                }
                NewVerificationTicketRequestError::NotEnoughTimePassed => ApiError::BadRequest(
                    "Not enough time has passed since the last ticket was created".to_string(),
                ),
                NewVerificationTicketRequestError::Unknown(err) => {
                    ApiError::InternalServerError(err)
                }
            },
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

#[derive(Debug)]
enum NewVerificationTicketRequestMappingError {
    InvalidPasswordFormat(String),
    InvalidRequest(NewVerificationTicketRequestError),
}

impl NewVerificationTicketRequestHttpBody {
    fn try_into_domain(
        self,
        account: &Account,
        ticket: &Option<VerificationTicket>,
    ) -> Result<NewVerificationTicketRequest, NewVerificationTicketRequestMappingError> {
        let password = Password::new(self.password.unsafe_inner()).map_err(|e| match e {
            PasswordError::Empty => {
                NewVerificationTicketRequestMappingError::InvalidPasswordFormat(
                    "Password cannot be empty".to_string(),
                )
            }
            PasswordError::InvalidPassword(reason) => {
                NewVerificationTicketRequestMappingError::InvalidPasswordFormat(reason)
            }
        })?;

        NewVerificationTicketRequest::new(password, account, ticket)
            .map_err(NewVerificationTicketRequestMappingError::InvalidRequest)
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
        .try_into_domain(&account, jwt_secret)
        .map_err(|e| match e {
            LoginRequestMappingError::InvalidPasswordFormat(msg) => {
                ApiError::BadRequest(format!("invalid password format: {msg}"))
            }
            LoginRequestMappingError::InvalidRequest(e) => match e {
                LoginRequestError::InvalidPassword => {
                    ApiError::BadRequest("Invalid email or password".to_string())
                }
                LoginRequestError::AccountNotVerified => {
                    ApiError::BadRequest("Account is not verified".to_string())
                }
                LoginRequestError::Unknown(err) => ApiError::InternalServerError(err),
            },
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
            access_token: login_request.access_token().clone(),
        }),
    ))
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoginRequestHttpBody {
    pub email: String,
    pub password: Opaque<String>,
}

#[derive(Debug)]
enum LoginRequestMappingError {
    InvalidPasswordFormat(String),
    InvalidRequest(LoginRequestError),
}

impl LoginRequestHttpBody {
    fn try_into_domain(
        self,
        account: &Account,
        jwt_secret: Opaque<String>,
    ) -> Result<LoginRequest, LoginRequestMappingError> {
        let password = Password::new(self.password.unsafe_inner()).map_err(|e| match e {
            PasswordError::Empty => LoginRequestMappingError::InvalidPasswordFormat(
                "Password cannot be empty".to_string(),
            ),
            PasswordError::InvalidPassword(reason) => {
                LoginRequestMappingError::InvalidPasswordFormat(reason)
            }
        })?;

        LoginRequest::new(password, account, jwt_secret)
            .map_err(LoginRequestMappingError::InvalidRequest)
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
#[serde(rename_all = "camelCase")]
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
    use fake::{Fake, Faker};

    use crate::crypto::password::PasswordOps;
    use crate::domains::accounts::testutil::{fake_account, fake_verification_ticket};

    use super::*;

    // ################ SIGNUP TESTS ################

    #[test]
    fn test_valid_signup_request() {
        let http_signup_request: SignUpRequestHttpBody = Faker.fake();
        assert!(http_signup_request.try_into_domain().is_ok());
    }

    #[test]
    fn test_invalid_email_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        signup_request.email = "invalid-email-format".to_string();
        let result = signup_request.try_into_domain();
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestMappingError::EmailFormat(_) => {}
            _ => panic!("Expected EmailFormat error"),
        };
    }

    #[test]
    fn test_invalid_password_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        signup_request.password = Opaque::new("abc".to_string());
        let result = signup_request.try_into_domain();
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestMappingError::PasswordFormat(_) => {}
            _ => panic!("Expected PasswordFormat error"),
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
            SignupRequestMappingError::SymmetricKeySaltFormat(_) => {}
            _ => panic!("Expected SymmetricKeySaltFormat error"),
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
            SignupRequestMappingError::SymmetricKeySaltFormat(_) => {}
            _ => panic!("Expected SymmetricKeySaltFormat error"),
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
            SignupRequestMappingError::EncryptionNonceFormat(_) => {}
            _ => panic!("Expected EncryptionNonceFormat error"),
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
            SignupRequestMappingError::EncryptionNonceFormat(_) => {}
            _ => panic!("Expected EncryptionNonceFormat error"),
        };
    }

    #[test]
    fn test_invalid_encrypted_key_pair_base64_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        signup_request.encrypted_key_pair.ciphertext = Opaque::new("invalid-base64".to_string());
        let result = signup_request.try_into_domain();
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestMappingError::PrivateKeyCiphertextFormat(_) => {}
            _ => panic!("Expected PrivateKeyCiphertextFormat error"),
        };
    }

    #[test]
    fn test_invalid_public_key_base64_signup_request() {
        let mut signup_request: SignUpRequestHttpBody = Faker.fake();
        signup_request.encrypted_key_pair.public_key = Opaque::new("invalid-base64".to_string());
        let result = signup_request.try_into_domain();
        assert!(result.is_err());
        match result.err().unwrap() {
            SignupRequestMappingError::PublicKeyFormat(_) => {}
            _ => panic!("Expected PublicKeyFormat error"),
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
            SignupRequestMappingError::KeyPair => {}
            _ => panic!("Expected KeyPair error"),
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
            SignupRequestMappingError::KeyPair => {}
            _ => panic!("Expected KeyPair error"),
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
            SignupRequestMappingError::KeyPair => {}
            e => {
                panic!("Expected KeyPair error: {:?}", e)
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
        assert!(
            http_request
                .try_into_domain(account, verification_ticket)
                .is_ok()
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
        // Badly encoded token
        let badly_encoded_token = "!!!invalid_base64!!!".to_string();
        http_request.token = Opaque::new(badly_encoded_token);
        let result = http_request.try_into_domain(account, verification_ticket);
        assert!(result.is_err());
        match result.err().unwrap() {
            UseVerificationTicketRequestMappingError::InvalidTokenFormat(_) => {}
            _ => panic!("Expected InvalidTokenFormat error"),
        };
    }

    // ################ LOGIN TESTS ################

    #[test]
    fn test_valid_login_request() {
        let password = Faker.fake::<Password>();
        let mut account = fake_account();
        account.password_hash = password.hash().unwrap().into();
        account.verified = true;
        let http_request = LoginRequestHttpBody {
            email: account.email.to_string(),
            password: password.unsafe_inner().to_owned().into(),
        };
        let jwt_secret = Opaque::new(Faker.fake::<String>());
        assert!(http_request.try_into_domain(&account, jwt_secret).is_ok());
    }

    #[test]
    fn test_invalid_password_format_login_request() {
        let password = Faker.fake::<Password>();
        let mut account = fake_account();
        account.password_hash = password.hash().unwrap().into();
        account.verified = true;
        let http_request = LoginRequestHttpBody {
            email: account.email.to_string(),
            password: Opaque::new("".to_string()), // Empty password
        };
        let jwt_secret = Opaque::new(Faker.fake::<String>());
        let result = http_request.try_into_domain(&account, jwt_secret);
        assert!(result.is_err());
        match result.err().unwrap() {
            LoginRequestMappingError::InvalidPasswordFormat(_) => {}
            _ => panic!("Expected InvalidPasswordFormat error"),
        };
    }

    fn flip_first_byte(base64_str: &str) -> String {
        let mut bytes = BASE64_STANDARD.decode(base64_str).unwrap();
        bytes[0] ^= 0xFF; // Flip some bits
        BASE64_STANDARD.encode(bytes)
    }

    // ################ NEW VERIFICATION TICKET TESTS ################

    #[test]
    fn test_valid_new_verification_ticket_request_without_last_ticket() {
        let mut account = fake_account();
        let password = Faker.fake::<Password>();
        account.password_hash = password.hash().unwrap().into();
        let http_request = NewVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            password: password.unsafe_inner().to_owned().into(),
        };
        let last_ticket = None;
        assert!(http_request.try_into_domain(&account, &last_ticket).is_ok());
    }

    #[test]
    fn test_valid_new_verification_ticket_request_with_last_ticket() {
        let mut account = fake_account();
        let password = Faker.fake::<Password>();
        account.password_hash = password.hash().unwrap().into();
        let mut last_ticket = fake_verification_ticket(account.id);
        last_ticket.created_at = chrono::Utc::now() - chrono::Duration::minutes(6);
        last_ticket.expires_at = chrono::Utc::now() + chrono::Duration::minutes(9);
        let http_request = NewVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            password: password.unsafe_inner().to_owned().into(),
        };

        assert!(
            http_request
                .try_into_domain(&account, &Some(last_ticket.clone()))
                .is_ok()
        );
    }

    #[test]
    fn test_invalid_new_verification_ticket_request_invalid_password_format() {
        let mut account = fake_account();
        let password = Faker.fake::<Password>();
        account.password_hash = password.hash().unwrap().into();
        let http_request = NewVerificationTicketRequestHttpBody {
            email: account.email.to_string(),
            password: Opaque::new("".to_string()), // Empty password
        };
        let last_ticket = None;
        let result = http_request.try_into_domain(&account, &last_ticket);
        assert!(result.is_err());
        match result.err().unwrap() {
            NewVerificationTicketRequestMappingError::InvalidPasswordFormat(_) => {}
            _ => panic!("Expected InvalidPasswordFormat error"),
        };
    }
}
