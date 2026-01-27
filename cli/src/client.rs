#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, anyhow};
use reqwest::{
    Client, Url,
    header::{HeaderMap, HeaderValue},
};

use crate::config::Config;

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
#[allow(dead_code)]
pub struct ApiClient<T: TokenStore> {
    base_url: Url,
    http: Client,
    tokens: T,
}

impl<T: TokenStore> ApiClient<T> {
    #[allow(dead_code)]
    pub fn new(config: &Config, tokens: T) -> anyhow::Result<Self> {
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
    #[allow(dead_code)]
    pub fn url(&self, path: &str) -> anyhow::Result<Url> {
        self.base_url
            .join(path)
            .map_err(|e| anyhow!(e))
            .context("Failed to build URL")
    }

    /// Extract request ID from response headers
    #[allow(dead_code)]
    pub fn request_id(headers: &HeaderMap) -> Option<String> {
        headers
            .get("x-request-id")
            .and_then(|v: &HeaderValue| v.to_str().ok())
            .map(str::to_string)
    }

    #[allow(dead_code)]
    pub fn http(&self) -> &Client {
        &self.http
    }

    #[allow(dead_code)]
    pub fn tokens(&self) -> &T {
        &self.tokens
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
