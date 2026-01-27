#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

use crate::{config::Config, output::CliError};
use anyhow::{Context, anyhow};
use base64::{Engine, prelude::BASE64_STANDARD};
use my_pass::{
    crypto::keypair::PrivateKey,
    newtypes::{Email, Opaque, Password},
    routes::accounts::{
        EncryptedKeyPairHttpBody, SignUpRequestHttpBody, UseVerificationTicketRequestHttpBody,
    },
};
use reqwest::{
    Client, Url,
    header::{HeaderMap, HeaderValue},
};

#[allow(dead_code)]
pub const KEYRING_SERVICE: &str = "my-pass-cli";

/// Abstraction for loading and storing JWTs
#[allow(dead_code)]
pub trait TokenStore: Send + Sync {
    /// Retrieve a stored JWT for the given email, or `None` if missing/empty.
    fn load(&self, email: &str) -> anyhow::Result<Option<String>>;

    /// Persist a JWT for the given email in a secure backing store.
    fn save(&self, email: &str, token: &str) -> anyhow::Result<()>;

    /// Remove any stored JWT for the given email.
    fn clear(&self, email: &str) -> anyhow::Result<()>;
}

/// Token storage backed by the OS keyring
pub struct KeyringTokenStore;

impl TokenStore for KeyringTokenStore {
    fn load(&self, email: &str) -> anyhow::Result<Option<String>> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, email)
            .context("Failed to access keyring entry")?;
        match entry.get_password() {
            Ok(token) if token.is_empty() => Ok(None),
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow!(e)).context("Failed to read token from keyring"),
        }
    }

    fn save(&self, email: &str, token: &str) -> anyhow::Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, email)
            .context("Failed to access keyring entry")?;
        entry
            .set_password(token)
            .map_err(|e| anyhow!(e))
            .context("Failed to write token to keyring")
    }

    fn clear(&self, email: &str) -> anyhow::Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, email)
            .context("Failed to access keyring entry")?;
        entry
            .delete_credential()
            .map_err(|e| anyhow!(e))
            .context("Failed to delete token from keyring")
    }
}

/// API client wrapper with token management and request ID extraction
pub struct ApiClient<T: TokenStore> {
    base_url: Url,
    http: Client,
    #[allow(dead_code)]
    tokens: T,
}

impl<T: TokenStore> ApiClient<T> {
    pub fn new(config: &Config, tokens: T) -> Result<Self, CliError> {
        let base_url = Url::parse(config.server_url())
            .context("Invalid server URL")
            .map_err(CliError::from)?;

        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("Failed to build HTTP client")
            .map_err(CliError::from)?;

        Ok(Self {
            base_url,
            http,
            tokens,
        })
    }

    /// Build a full URL from a path (e.g., "/api/accounts/me")
    pub fn url(&self, path: &str) -> anyhow::Result<Url> {
        self.base_url
            .join(path)
            .map_err(|e| anyhow!(e))
            .context("Failed to build URL")
    }

    /// Extract request ID from response headers
    pub fn request_id(headers: &HeaderMap) -> Option<String> {
        headers
            .get("x-request-id")
            .and_then(|v: &HeaderValue| v.to_str().ok())
            .map(str::to_string)
    }

    /// Sign up a new account by generating an encrypted key pair and sending it to the server
    pub async fn signup(&self, email: Email, password: Password) -> Result<(), CliError> {
        let private_key = PrivateKey::generate();
        let encrypted_key_pair = private_key
            .encrypt_key_pair_with_password(password.clone())
            .context("failed to encrypt key pair with password")
            .map_err(CliError::from)?;

        let payload = SignUpRequestHttpBody {
            email: email.as_str().to_string(),
            password: password.unsafe_inner().to_owned().into(),
            encrypted_key_pair: EncryptedKeyPairHttpBody {
                symmetric_key_salt: BASE64_STANDARD
                    .encode(encrypted_key_pair.symmetric_key_salt().unsafe_inner())
                    .into(),
                encryption_nonce: BASE64_STANDARD
                    .encode(encrypted_key_pair.encryption_nonce().unsafe_inner())
                    .into(),
                ciphertext: BASE64_STANDARD
                    .encode(encrypted_key_pair.ciphertext().unsafe_inner())
                    .into(),
                public_key: BASE64_STANDARD
                    .encode(encrypted_key_pair.public_key().unsafe_inner())
                    .into(),
            },
        };
        let url = self.url("/api/accounts/signup")?;

        let response = self
            .http
            .post(url)
            .json(&payload)
            .send()
            .await
            .context("failed to execute signup request")
            .map_err(CliError::from)?;

        if response.status().is_success() {
            self.tokens.clear(email.as_str()).map_err(CliError::from)?;
            return Ok(());
        }

        let status = response.status();
        let request_id = Self::request_id(response.headers());
        let body = response.text().await.unwrap_or_default();
        Err(http_error_with_request_id(
            format!("signup failed ({status})"),
            body,
            request_id,
        ))
    }

    /// Verify an account using the email and verification token
    pub async fn verify(&self, email: Email, token: String) -> Result<(), CliError> {
        let payload = UseVerificationTicketRequestHttpBody {
            email: email.as_str().to_string(),
            token: Opaque::from(token),
        };
        let url = self.url("/api/accounts/verification-tickets/use")?;

        let response = self
            .http
            .post(url)
            .json(&payload)
            .send()
            .await
            .context("failed to execute verification request")
            .map_err(CliError::from)?;

        if response.status().is_success() {
            self.tokens.clear(email.as_str()).map_err(CliError::from)?;
            return Ok(());
        }

        let status = response.status();
        let request_id = Self::request_id(response.headers());
        let body = response.text().await.unwrap_or_default();
        Err(http_error_with_request_id(
            format!("verification failed ({status})"),
            body,
            request_id,
        ))
    }
}

fn http_error_with_request_id(
    message: String,
    body: String,
    request_id: Option<String>,
) -> CliError {
    let mut err = CliError::new(format!("{message}: {body}"));
    if let Some(id) = request_id {
        err = err.with_request_id(id);
    }
    err
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemoryTokenStore {
        inner: Mutex<HashMap<String, String>>,
    }

    impl MemoryTokenStore {
        fn new() -> Self {
            Self {
                inner: Mutex::new(HashMap::new()),
            }
        }
    }

    impl TokenStore for MemoryTokenStore {
        fn load(&self, email: &str) -> anyhow::Result<Option<String>> {
            let guard = self.inner.lock().unwrap();
            Ok(guard.get(email).cloned())
        }

        fn save(&self, email: &str, token: &str) -> anyhow::Result<()> {
            let mut guard = self.inner.lock().unwrap();
            guard.insert(email.to_string(), token.to_string());
            Ok(())
        }

        fn clear(&self, email: &str) -> anyhow::Result<()> {
            let mut guard = self.inner.lock().unwrap();
            guard.remove(email);
            Ok(())
        }
    }

    #[test]
    fn test_url_builder() {
        let config = Config::with_server_url("http://localhost:3000");
        let client = ApiClient::new(&config, MemoryTokenStore::new()).unwrap();
        let url = client.url("/api/accounts/me").unwrap();
        assert_eq!(url.as_str(), "http://localhost:3000/api/accounts/me");
    }

    #[test]
    fn test_request_id_extraction() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", "abc-123".parse().unwrap());
        let request_id = ApiClient::<MemoryTokenStore>::request_id(&headers);
        assert_eq!(request_id.as_deref(), Some("abc-123"));
    }

    #[test]
    fn test_memory_token_store() {
        let store = MemoryTokenStore::new();
        assert!(store.load("user@example.com").unwrap().is_none());

        store
            .save("user@example.com", "token123")
            .expect("save token");
        assert_eq!(
            store.load("user@example.com").unwrap().as_deref(),
            Some("token123")
        );

        store.clear("user@example.com").expect("clear token");
        assert!(store.load("user@example.com").unwrap().is_none());
    }
}
