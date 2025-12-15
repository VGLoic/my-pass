use std::{
    env::{self, VarError},
    str::FromStr,
};

use tracing::Level;
mod argon2instance;
pub mod domains;
pub mod newtypes;
pub mod routes;

// ############################################
// ################## CONFIG ##################
// ############################################

pub struct Config {
    /// Server port
    pub port: u16,
    /// Application log level, has priority over `RUST_LOG` environment variable
    pub log_level: Level,
    /// Database connection URL
    /// Format: `postgresql://<Postgres user>:<Postgres password>@<Postgres host>:<Postgres port>/<Postgres DB>`
    pub database_url: newtypes::Opaque<String>,
}

impl Config {
    pub fn parse_environment() -> Result<Self, Vec<anyhow::Error>> {
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

        let database_url = match parse_required_env_variable::<String>("DATABASE_URL") {
            Ok(v) => newtypes::Opaque::new(v),
            Err(e) => {
                errors.push(e);
                newtypes::Opaque::new(String::new())
            }
        };

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(Config {
            port,
            log_level,
            database_url,
        })
    }
}

fn parse_required_env_variable<T>(key: &str) -> Result<T, anyhow::Error>
where
    T: FromStr,
    <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    parse_env_variable::<T>(key)?.ok_or_else(|| {
        anyhow::anyhow!(
            "Required environment variable `{}` is missing or empty",
            key
        )
    })
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
