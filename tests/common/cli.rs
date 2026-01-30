use std::{collections::HashMap, sync::Mutex};

use super::InstanceState;
use anyhow::Context;
use my_pass::cli::{client::CliClient, config::Config, tokenstore::TokenStore};

#[allow(dead_code)]
pub fn cli_config_from_instance_state(state: &InstanceState) -> Config {
    Config {
        server_url: state.server_url.clone(),
    }
}

#[allow(dead_code)]
pub fn setup_cli_client(config: Config) -> Result<CliClient<MemoryTokenStore>, anyhow::Error> {
    let token_store = MemoryTokenStore::new();
    let cli_client = CliClient::new(&config, token_store).context("failed to build CLI client")?;
    Ok(cli_client)
}

#[allow(dead_code)]
pub struct MemoryTokenStore {
    inner: Mutex<HashMap<String, String>>,
}

impl MemoryTokenStore {
    #[allow(dead_code)]
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
