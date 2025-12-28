use std::{
    env::{self, VarError},
    str::FromStr,
};

use tracing::Level;
mod argon2instance;
pub mod domains;
pub mod newtypes;
pub mod routes;
pub mod secrets;

// ############################################
// ################## CONFIG ##################
// ############################################

pub struct Config {
    /// Server port
    pub port: u16,
    /// Application log level, has priority over `RUST_LOG` environment variable
    pub log_level: Level,
}

impl Config {
    pub fn new_from_env() -> Result<Self, Vec<anyhow::Error>> {
        let mut errors = Vec::new();

        let port = match parse_env_variable::<u16>("PORT") {
            Ok(v) => v.unwrap_or(3000),
            Err(e) => {
                errors.push(e);
                0
            }
        };

        let log_level = match parse_env_variable::<Level>("LOG_LEVEL") {
            Ok(v) => v.unwrap_or(Level::INFO),
            Err(e) => {
                errors.push(e);
                Level::INFO
            }
        };

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(Config { port, log_level })
    }
}

fn parse_env_variable<T>(key: &str) -> Result<Option<T>, anyhow::Error>
where
    T: FromStr,
    <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    fn map_err<E>(key: &str, e: E) -> anyhow::Error
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        anyhow::anyhow!("[{key}]: {e}")
    }

    let env_value = match env::var(key) {
        Ok(v) => {
            if v.is_empty() {
                Ok(None)
            } else {
                Ok(Some(v))
            }
        }
        Err(e) => {
            if e == VarError::NotPresent {
                Ok(None)
            } else {
                Err(map_err(key, e))
            }
        }
    }?;
    env_value
        .map(|v| v.parse::<T>().map_err(|e| map_err(key, e)))
        .transpose()
}
