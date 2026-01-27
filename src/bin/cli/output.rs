use my_pass::cli::client::CliClientError;
use serde::Serialize;
use std::fmt;
use thiserror::Error;

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
        match error {
            CliError::Unknown(err) => {
                eprintln!("Error: {}", err);
            }
            CliError::Client(err) => match err {
                CliClientError::Http {
                    request_id,
                    body,
                    message,
                } => {
                    if self.json_mode {
                        self.print_json(&ErrorOutput {
                            error: message.clone(),
                            request_id: request_id.clone(),
                        });
                    } else {
                        eprintln!("Error: {} - {}", message, body);
                        if let Some(request_id) = request_id {
                            eprintln!("Request ID: {}", request_id);
                        }
                    }
                }
                CliClientError::Unknown(err) => {
                    eprintln!("Error: {}", err);
                }
            },
        };
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
#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Client(#[from] CliClientError),
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}
