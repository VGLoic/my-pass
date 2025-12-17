use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::newtypes::Opaque;

const AUDIENCE: &str = "my-pass.api";

#[derive(Debug, Error)]
pub enum JwtEncodeError {
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

/// Encodes a JWT token for the given account ID using the provided secret.
pub fn encode_jwt(
    account_id: Uuid,
    secret: &Opaque<String>,
) -> Result<Opaque<String>, JwtEncodeError> {
    let claims = Claims::new(account_id);
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.unsafe_inner().as_bytes()),
    )
    .map(|t| t.into())
    .map_err(|e| JwtEncodeError::Unknown(anyhow::Error::new(e).context("failed to encode token")))
}

// REMIND ME: remove allow dead code once used
#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum JwtDecodeError {
    #[error(transparent)]
    InvalidToken(#[from] anyhow::Error),
}

/// Decodes the given JWT token using the provided secret and returns the account ID if valid.
// REMIND ME: remove allow dead code once used
#[allow(dead_code)]
pub fn decode_jwt(token: Opaque<&str>, secret: Opaque<&str>) -> Result<Uuid, JwtDecodeError> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&[AUDIENCE.to_string()]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "nbf", "sub", "aud"]);
    let token_data = jsonwebtoken::decode::<Claims>(
        token.unsafe_inner(),
        &jsonwebtoken::DecodingKey::from_secret(secret.unsafe_inner().as_bytes()),
        &validation,
    )
    .map_err(|e| {
        JwtDecodeError::InvalidToken(anyhow::Error::new(e).context("failed to decode token"))
    })?;

    Ok(token_data.claims.sub)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Claims {
    /// Subject - the account ID
    sub: Uuid,
    /// Audience - the intended audience of the token - must be "my-pass.api"
    aud: String,
    /// Expires at - the timestamp when the token expires
    exp: i64,
    /// Not before - the timestamp before which the token is not valid
    nbf: i64,
}

impl Claims {
    pub fn new(account_id: Uuid) -> Self {
        // Token is valid for 1 hour
        let validity_duration_secs = 60 * 60;
        let exp =
            (chrono::Utc::now() + chrono::Duration::seconds(validity_duration_secs)).timestamp();
        Claims {
            sub: account_id,
            aud: AUDIENCE.to_string(),
            exp,
            nbf: chrono::Utc::now().timestamp(),
        }
    }
}
