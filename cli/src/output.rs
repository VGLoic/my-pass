use serde::Serialize;
use std::fmt;

/// Output formatter that supports both human-readable and JSON formats
pub struct Output {
    json_mode: bool,
}

impl Output {
    pub fn new(json_mode: bool) -> Self {
        Self { json_mode }
    }

    /// Print a success message
    pub fn success<T: Serialize + fmt::Display>(&self, data: &T) {
        if self.json_mode {
            self.print_json(data);
        } else {
            println!("{}", data);
        }
    }

    /// Print an error message
    pub fn error(&self, error: &CliError) {
        if self.json_mode {
            self.print_json(&ErrorOutput {
                error: error.message().to_string(),
                request_id: error.request_id().map(|s| s.to_string()),
            });
        } else {
            eprintln!("Error: {}", error.message());
            if let Some(request_id) = error.request_id() {
                eprintln!("Request ID: {}", request_id);
            }
        }
    }

    fn print_json<T: Serialize>(&self, data: &T) {
        match serde_json::to_string_pretty(data) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("Failed to serialize JSON: {}", e),
        }
    }
}

#[derive(Serialize)]
struct ErrorOutput {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

/// CLI error with optional request ID for debugging
#[derive(Debug)]
pub struct CliError {
    message: String,
    request_id: Option<String>,
}

impl CliError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            request_id: None,
        }
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CliError {}

impl From<anyhow::Error> for CliError {
    fn from(err: anyhow::Error) -> Self {
        Self {
            message: err.to_string(),
            request_id: None,
        }
    }
}

impl From<reqwest::Error> for CliError {
    fn from(err: reqwest::Error) -> Self {
        CliError::new(format!("HTTP error: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_error_creation() {
        let error = CliError::new("Something went wrong");
        assert_eq!(error.message(), "Something went wrong");
        assert_eq!(error.request_id(), None);
    }

    #[test]
    fn test_cli_error_with_request_id() {
        let error = CliError::new("API error").with_request_id("req-123");
        assert_eq!(error.message(), "API error");
        assert_eq!(error.request_id(), Some("req-123"));
    }
}
