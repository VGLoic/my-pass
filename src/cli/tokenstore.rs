use anyhow::{Context, anyhow};

#[allow(dead_code)]
pub const KEYRING_SERVICE: &str = "my-pass-cli";

/// Abstraction for loading and storing JWTs
#[allow(dead_code)]
pub trait TokenStore {
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
