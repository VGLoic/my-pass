#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

use super::{config::Config, tokenstore::TokenStore};
use crate::{
    crypto::keypair::{EncryptedKeyPair, PrivateKey, SymmetricKey},
    newtypes::{Email, Opaque, Password},
    routes::accounts::{
        EncryptedKeyPairHttpBody, LoginRequestHttpBody, LoginResponse, MeResponse,
        NewVerificationTicketRequestHttpBody, SignUpRequestHttpBody,
        UseVerificationTicketRequestHttpBody,
    },
    routes::items::ItemResponse,
};
use anyhow::{Context, anyhow};
use base64::{Engine, prelude::BASE64_STANDARD};
use reqwest::{
    Client, Url,
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
        let base_url = Url::parse(&config.server_url).context("Invalid server URL")?;

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

    /// Load a token for the given email
    pub async fn get_token(&self, email: &str) -> Result<Option<String>, CliClientError> {
        self.tokens.load(email).map_err(CliClientError::from)
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
    pub async fn signup(&self, email: Email, password: Password) -> Result<(), CliClientError> {
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
            .await
            .context("failed to execute signup request")?;

        if response.status().is_success() {
            self.tokens
                .clear(email.as_str())
                .context("failed to clear tokens")?;
            return Ok(());
        }

        let status = response.status();
        let request_id = Self::request_id(response.headers());
        let body = response.text().await.unwrap_or_default();
        Err(CliClientError::Http {
            message: format!("signup failed ({status})"),
            body,
            request_id,
        })
    }

    /// Verify an account using the email and verification token
    pub async fn verify(&self, email: Email, token: String) -> Result<(), CliClientError> {
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
            .context("failed to execute verification request")?;

        if response.status().is_success() {
            self.tokens
                .clear(email.as_str())
                .context("failed to clear tokens")?;
            return Ok(());
        }

        let status = response.status();
        let request_id = Self::request_id(response.headers());
        let body = response.text().await.unwrap_or_default();
        Err(CliClientError::Http {
            request_id,
            body,
            message: format!("verification failed ({status})"),
        })
    }

    /// Login with email and password, storing the JWT for future authenticated requests
    pub async fn login(&self, email: Email, password: Password) -> Result<(), CliClientError> {
        let payload = LoginRequestHttpBody {
            email: email.as_str().to_string(),
            password: Opaque::from(password.unsafe_inner().to_owned()),
        };
        let url = self.url("/api/accounts/login")?;

        let response = self
            .http
            .post(url)
            .json(&payload)
            .send()
            .await
            .context("failed to execute login request")?;

        if response.status().is_success() {
            let response_body = response
                .json::<LoginResponse>()
                .await
                .context("failed to parse login response")?;

            self.tokens
                .save(email.as_str(), response_body.access_token.unsafe_inner())
                .context("failed to save token")?;
            return Ok(());
        }

        let status = response.status();
        let request_id = Self::request_id(response.headers());
        let body = response.text().await.unwrap_or_default();
        Err(CliClientError::Http {
            request_id,
            body,
            message: format!("login failed ({status})"),
        })
    }

    /// Fetch current account information using stored JWT
    pub async fn me(&self, email: &str) -> Result<MeResponse, CliClientError> {
        let token = self
            .tokens
            .load(email)
            .context("failed to load token")?
            .ok_or_else(|| anyhow!("no token found - please login first"))?;

        let url = self.url("/api/accounts/me")?;

        let response = self
            .http
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .context("failed to execute me request")?;

        if response.status().is_success() {
            let response_body = response
                .json::<MeResponse>()
                .await
                .context("failed to parse me response")?;
            return Ok(response_body);
        }

        let status = response.status();
        let request_id = Self::request_id(response.headers());
        let body = response.text().await.unwrap_or_default();
        Err(CliClientError::Http {
            request_id,
            body,
            message: format!("me failed ({status})"),
        })
    }

    /// Request a new verification ticket by providing email and password
    pub async fn request_verification(
        &self,
        email: Email,
        password: Password,
    ) -> Result<(), CliClientError> {
        let payload = NewVerificationTicketRequestHttpBody {
            email: email.as_str().to_string(),
            password: Opaque::from(password.unsafe_inner().to_owned()),
        };
        let url = self.url("/api/accounts/verification-tickets")?;

        let response = self
            .http
            .post(url)
            .json(&payload)
            .send()
            .await
            .context("failed to execute request verification request")?;

        if response.status().is_success() {
            return Ok(());
        }

        let status = response.status();
        let request_id = Self::request_id(response.headers());
        let body = response.text().await.unwrap_or_default();
        Err(CliClientError::Http {
            request_id,
            body,
            message: format!("request verification failed ({status})"),
        })
    }

    /// Add a new encrypted item to the vault
    async fn add_item(
        &self,
        email: &str,
        plaintext: &[u8],
        private_key: &PrivateKey,
    ) -> Result<(), CliClientError> {
        let token = self
            .tokens
            .load(email)
            .context("failed to load token")?
            .ok_or_else(|| anyhow!("no token found - please login first"))?;

        // Encrypt the item data
        let encapsulated_symmetric_key =
            SymmetricKey::encapsulate(&private_key.encapsulation_public_key())
                .context("failed to encapsulate symmetric key")?;
        let encryption_nonce: [u8; 12] = fake::rand::random();
        let ciphertext = encapsulated_symmetric_key
            .symmetric_key()
            .encrypt(plaintext, &encryption_nonce)
            .context("failed to encrypt item")?;
        let (signature_r, signature_s) = private_key
            .sign(&ciphertext)
            .context("failed to sign item")?;
        let mut signature = Vec::new();
        signature.extend_from_slice(&signature_r);
        signature.extend_from_slice(&signature_s);

        let payload = serde_json::json!({
            "ciphertext": BASE64_STANDARD.encode(&ciphertext),
            "encryptionNonce": BASE64_STANDARD.encode(encryption_nonce),
            "ephemeralPublicKey": BASE64_STANDARD.encode(
                encapsulated_symmetric_key.ephemeral_public_key().to_bytes().unsafe_inner()
            ),
            "signature": BASE64_STANDARD.encode(&signature),
        });

        let url = self.url("/api/items")?;

        let response = self
            .http
            .post(url)
            .bearer_auth(&token)
            .json(&payload)
            .send()
            .await
            .context("failed to execute add item request")?;

        if response.status().is_success() {
            return Ok(());
        }

        let status = response.status();
        let request_id = Self::request_id(response.headers());
        let body = response.text().await.unwrap_or_default();
        Err(CliClientError::Http {
            request_id,
            body,
            message: format!("add item failed ({status})"),
        })
    }

    /// Derive the private key from ME response and password
    async fn derive_private_key_from_password(
        &self,
        email: &str,
        password: Password,
    ) -> Result<PrivateKey, CliClientError> {
        // Get the encrypted key pair from the account
        let me_response = self.me(email).await?;

        // Decode the encrypted key pair from base64
        let symmetric_key_salt = BASE64_STANDARD
            .decode(
                me_response
                    .encrypted_key_pair
                    .symmetric_key_salt
                    .unsafe_inner(),
            )
            .context("failed to decode symmetric_key_salt")?;
        let encryption_nonce = BASE64_STANDARD
            .decode(
                me_response
                    .encrypted_key_pair
                    .encryption_nonce
                    .unsafe_inner(),
            )
            .context("failed to decode encryption_nonce")?;
        let ciphertext = BASE64_STANDARD
            .decode(me_response.encrypted_key_pair.ciphertext.unsafe_inner())
            .context("failed to decode ciphertext")?;
        let public_key = BASE64_STANDARD
            .decode(me_response.encrypted_key_pair.public_key.unsafe_inner())
            .context("failed to decode public_key")?;

        // Convert arrays
        let symmetric_key_salt: [u8; 16] = symmetric_key_salt
            .try_into()
            .map_err(|_| anyhow!("symmetric_key_salt must be 16 bytes"))?;
        let encryption_nonce: [u8; 12] = encryption_nonce
            .try_into()
            .map_err(|_| anyhow!("encryption_nonce must be 12 bytes"))?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| anyhow!("public_key must be 32 bytes"))?;

        // Create EncryptedKeyPair and decrypt
        let encrypted_key_pair = EncryptedKeyPair::new(
            password,
            Opaque::new(symmetric_key_salt),
            Opaque::new(encryption_nonce),
            Opaque::new(ciphertext),
            Opaque::new(public_key),
        )
        .context("failed to create encrypted key pair")?;

        encrypted_key_pair
            .decrypt_private_key()
            .context("failed to decrypt private key")
            .map_err(CliClientError::from)
    }

    /// Add a new encrypted item to the vault by automatically retrieving and decrypting the private key
    pub async fn add_item_with_password(
        &self,
        email: &str,
        plaintext: &[u8],
        password: Password,
    ) -> Result<(), CliClientError> {
        let private_key = self
            .derive_private_key_from_password(email, password)
            .await?;
        self.add_item(email, plaintext, &private_key).await
    }

    /// Fetch and decrypt all items for the user
    async fn fetch_items(&self, email: &str) -> Result<Vec<ItemResponse>, CliClientError> {
        let token = self
            .tokens
            .load(email)
            .context("failed to load token")?
            .ok_or_else(|| anyhow!("no token found - please login first"))?;

        let url = self.url("/api/items")?;

        let response = self
            .http
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .context("failed to execute list items request")?;

        if response.status().is_success() {
            let items = response
                .json::<Vec<ItemResponse>>()
                .await
                .context("failed to parse items response")?;
            return Ok(items);
        }

        let status = response.status();
        let request_id = Self::request_id(response.headers());
        let body = response.text().await.unwrap_or_default();
        Err(CliClientError::Http {
            request_id,
            body,
            message: format!("list items failed ({status})"),
        })
    }

    /// List and decrypt all items for the user
    pub async fn list_items_with_password(
        &self,
        email: &str,
        password: Password,
    ) -> Result<Vec<(ItemResponse, String)>, CliClientError> {
        let private_key = self
            .derive_private_key_from_password(email, password)
            .await?;

        // Fetch encrypted items
        let items = self.fetch_items(email).await?;

        // Decrypt each item
        let mut decrypted_items = Vec::new();
        for item in items {
            let ephemeral_public_key_bytes = BASE64_STANDARD
                .decode(&item.ephemeral_public_key)
                .context("failed to decode ephemeral_public_key")?;
            let ephemeral_public_key: [u8; 32] = ephemeral_public_key_bytes
                .try_into()
                .map_err(|_| anyhow!("ephemeral_public_key must be 32 bytes"))?;

            let ciphertext_bytes = BASE64_STANDARD
                .decode(&item.ciphertext)
                .context("failed to decode ciphertext")?;

            let encryption_nonce_bytes = BASE64_STANDARD
                .decode(&item.encryption_nonce)
                .context("failed to decode encryption_nonce")?;
            let encryption_nonce: [u8; 12] = encryption_nonce_bytes
                .try_into()
                .map_err(|_| anyhow!("encryption_nonce must be 12 bytes"))?;

            // Decapsulate the symmetric key using our private key
            let encapsulation_public_key = crate::crypto::keypair::EncapsulationPublicKey::new(
                Opaque::new(ephemeral_public_key),
            );
            let symmetric_key = private_key
                .decapsulate(&encapsulation_public_key)
                .context("failed to decapsulate symmetric key")?;

            // Decrypt the item plaintext
            let plaintext = symmetric_key
                .decrypt(&ciphertext_bytes, &encryption_nonce)
                .context("failed to decrypt item")?;

            let plaintext_string =
                String::from_utf8(plaintext).context("item plaintext is not valid UTF-8")?;

            decrypted_items.push((item, plaintext_string));
        }

        Ok(decrypted_items)
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
        let config = Config {
            server_url: "http://localhost:3000".to_owned(),
        };
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
