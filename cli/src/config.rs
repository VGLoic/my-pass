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
        let server_url = env::var("MY_PASS_SERVER_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());

        Self { server_url }
    }

    /// Get the base URL for the server
    pub fn server_url(&self) -> &str {
        &self.server_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_server_url() {
        unsafe { env::remove_var("MY_PASS_SERVER_URL"); }
        let config = Config::from_env();
        assert_eq!(config.server_url(), "http://localhost:3000");
    }

    #[test]
    fn test_custom_server_url() {
        unsafe {
            env::set_var("MY_PASS_SERVER_URL", "https://api.example.com");
        }
        let config = Config::from_env();
        assert_eq!(config.server_url(), "https://api.example.com");
        unsafe {
            env::remove_var("MY_PASS_SERVER_URL");
        }
    }
}
