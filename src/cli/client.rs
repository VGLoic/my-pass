#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

use super::{config::Config, tokenstore::TokenStore};
use crate::{
    crypto::keypair::PrivateKey,
    newtypes::{Email, Opaque, Password},
    routes::accounts::{
        EncryptedKeyPairHttpBody, SignUpRequestHttpBody, UseVerificationTicketRequestHttpBody,
    },
};
use anyhow::{Context, anyhow};
use base64::{Engine, prelude::BASE64_STANDARD};
use reqwest::{
    Url,
    blocking::Client,
    header::{HeaderMap, HeaderValue},
};
use thiserror::Error;

/// CLI client wrapper with token management and request ID extraction
pub struct CliClient<T: TokenStore> {
    base_url: Url,
    http: Client,
    #[allow(dead_code)]
    tokens: T,
}

#[derive(Debug, Error)]
pub enum CliClientError {
    #[error("HTTP error: {message} - {body} - Request ID: {request_id:?}")]
    Http {
        request_id: Option<String>,
        body: String,
        message: String,
    },
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

impl<T: TokenStore> CliClient<T> {
    pub fn new(config: &Config, tokens: T) -> Result<Self, CliClientError> {
        let base_url = Url::parse(config.server_url()).context("Invalid server URL")?;

        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            base_url,
            http,
            tokens,
        })
    }

    /// Build a full URL from a path (e.g., "/api/accounts/me")
    fn url(&self, path: &str) -> anyhow::Result<Url> {
        self.base_url
            .join(path)
            .map_err(|e| anyhow!(e))
            .context("Failed to build URL")
    }

    /// Extract request ID from response headers
    fn request_id(headers: &HeaderMap) -> Option<String> {
        headers
            .get("x-request-id")
            .and_then(|v: &HeaderValue| v.to_str().ok())
            .map(str::to_string)
    }

    /// Sign up a new account by generating an encrypted key pair and sending it to the server
    pub fn signup(&self, email: Email, password: Password) -> Result<(), CliClientError> {
        let private_key = PrivateKey::generate();
        let encrypted_key_pair = private_key
            .encrypt_key_pair_with_password(password.clone())
            .context("failed to encrypt key pair with password")?;

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
            .context("failed to execute signup request")?;

        if response.status().is_success() {
            self.tokens
                .clear(email.as_str())
                .context("failed to clear tokens")?;
            return Ok(());
        }

        let status = response.status();
        let request_id = Self::request_id(response.headers());
        let body = response.text().unwrap_or_default();
        Err(CliClientError::Http {
            message: format!("signup failed ({status})"),
            body,
            request_id,
        })
    }

    /// Verify an account using the email and verification token
    pub fn verify(&self, email: Email, token: String) -> Result<(), CliClientError> {
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
            .context("failed to execute verification request")?;

        if response.status().is_success() {
            self.tokens
                .clear(email.as_str())
                .context("failed to clear tokens")?;
            return Ok(());
        }

        let status = response.status();
        let request_id = Self::request_id(response.headers());
        let body = response.text().unwrap_or_default();
        Err(CliClientError::Http {
            request_id,
            body,
            message: format!("verification failed ({status})"),
        })
    }
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
        let client = CliClient::new(&config, MemoryTokenStore::new()).unwrap();
        let url = client.url("/api/accounts/me").unwrap();
        assert_eq!(url.as_str(), "http://localhost:3000/api/accounts/me");
    }

    #[test]
    fn test_request_id_extraction() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", "abc-123".parse().unwrap());
        let request_id = CliClient::<MemoryTokenStore>::request_id(&headers);
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
