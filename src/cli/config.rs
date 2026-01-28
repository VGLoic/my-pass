use std::env;

/// Configuration for the CLI
#[derive(Debug, Clone)]
pub struct Config {
    /// Base URL of the my-pass server
    pub server_url: String,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let server_url =
            env::var("MY_PASS_SERVER_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

        Self { server_url }
    }
}
