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

#[derive(Debug, Error)]
pub enum JwtDecodeError {
    #[error(transparent)]
    InvalidToken(#[from] anyhow::Error),
}
// REMIND ME: REMOVE THIS FILE?

/// Decodes the given JWT token using the provided secret, validates it and returns the account ID if valid.
pub fn decode_and_validate_jwt(
    token: &Opaque<String>,
    secret: &Opaque<String>,
) -> Result<Uuid, JwtDecodeError> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&[AUDIENCE.to_string()]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 60; // allow 60 seconds clock skew
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "my-test-secret";

    #[test]
    fn test_jwt_encode_decode() {
        let account_id = Uuid::new_v4();
        let secret: Opaque<String> = Opaque::new(TEST_SECRET.to_string());
        let token = encode_jwt(account_id, &secret).expect("failed to encode JWT");
        let decoded_account_id =
            decode_and_validate_jwt(&token, &secret).expect("failed to decode JWT");
        assert_eq!(account_id, decoded_account_id);
    }

    #[test]
    fn test_jwt_decode_invalid_token() {
        let secret: Opaque<String> = Opaque::new(TEST_SECRET.to_string());
        let invalid_token: Opaque<String> = Opaque::new("invalid.token.here".to_string());
        let result = decode_and_validate_jwt(&invalid_token, &secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_decode_wrong_secret() {
        let account_id = Uuid::new_v4();
        let secret: Opaque<String> = Opaque::new(TEST_SECRET.to_string());
        let token = encode_jwt(account_id, &secret).expect("failed to encode JWT");
        let wrong_secret: Opaque<String> = Opaque::new("wrong-secret".to_string());
        let result = decode_and_validate_jwt(&token, &wrong_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_decode_wrong_audience() {
        let account_id = Uuid::new_v4();
        let secret: Opaque<String> = Opaque::new(TEST_SECRET.to_string());
        // Manually decode the token to modify the audience
        let claims = Claims {
            sub: account_id,
            aud: "wrong-audience".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::seconds(3600)).timestamp(),
            nbf: chrono::Utc::now().timestamp(),
        };
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let wrong_token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.unsafe_inner().as_bytes()),
        )
        .expect("failed to encode modified JWT");
        let result = decode_and_validate_jwt(&wrong_token.into(), &secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_decode_expired_token() {
        let account_id = Uuid::new_v4();
        let secret: Opaque<String> = Opaque::new(TEST_SECRET.to_string());
        // Manually create an expired token
        let claims = Claims {
            sub: account_id,
            aud: AUDIENCE.to_string(),
            exp: (chrono::Utc::now() - chrono::Duration::seconds(70)).timestamp(), // expired 70 seconds ago, taking leeway into account
            nbf: (chrono::Utc::now() - chrono::Duration::seconds(3600)).timestamp(),
        };
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let expired_token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.unsafe_inner().as_bytes()),
        )
        .expect("failed to encode expired JWT");
        let result = decode_and_validate_jwt(&expired_token.into(), &secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_decode_not_yet_valid_token() {
        let account_id = Uuid::new_v4();
        let secret: Opaque<String> = Opaque::new(TEST_SECRET.to_string());
        // Manually create a token that is not yet valid
        let claims = Claims {
            sub: account_id,
            aud: AUDIENCE.to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::seconds(3600)).timestamp(),
            nbf: (chrono::Utc::now() + chrono::Duration::seconds(70)).timestamp(), // not valid for another 70 seconds, taking leeway into account
        };
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let not_yet_valid_token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.unsafe_inner().as_bytes()),
        )
        .expect("failed to encode jwt");
        let result = decode_and_validate_jwt(&not_yet_valid_token.into(), &secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_decode_invalid_sub() {
        let secret: Opaque<String> = Opaque::new(TEST_SECRET.to_string());

        #[derive(Serialize, Deserialize)]
        struct InvalidClaims {
            sub: String, // invalid type
            aud: String,
            exp: i64,
            nbf: i64,
        }
        let claims = InvalidClaims {
            sub: "not-a-uuid".to_string(),
            aud: AUDIENCE.to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::seconds(3600)).timestamp(),
            nbf: chrono::Utc::now().timestamp(),
        };
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let invalid_sub_token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.unsafe_inner().as_bytes()),
        )
        .expect("failed to encode jwt");
        let result = decode_and_validate_jwt(&invalid_sub_token.into(), &secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_decode_missing_sub() {
        let secret: Opaque<String> = Opaque::new(TEST_SECRET.to_string());

        #[derive(Serialize, Deserialize)]
        struct InvalidClaims {
            aud: String,
            exp: i64,
            nbf: i64,
        }
        let claims = InvalidClaims {
            aud: AUDIENCE.to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::seconds(3600)).timestamp(),
            nbf: chrono::Utc::now().timestamp(),
        };
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let missing_sub_token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.unsafe_inner().as_bytes()),
        )
        .expect("failed to encode jwt");
        let result = decode_and_validate_jwt(&missing_sub_token.into(), &secret);
        assert!(result.is_err());
    }
}
