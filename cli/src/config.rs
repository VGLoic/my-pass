use std::env;

/// Configuration for the CLI
#[derive(Debug, Clone)]
pub struct Config {
    /// Base URL of the my-pass server
    server_url: String,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let server_url =
            env::var("MY_PASS_SERVER_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

        Self { server_url }
    }

    /// Get the base URL for the server
    pub fn server_url(&self) -> &str {
        &self.server_url
    }
}

#[cfg(test)]
impl Config {
    pub fn with_server_url(url: impl Into<String>) -> Self {
        Self {
            server_url: url.into(),
        }
    }
}
