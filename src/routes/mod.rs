use std::sync::Arc;

use axum::{
    Json, Router,
    extract::FromRequestParts,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, warn};

use crate::{
    Config,
    domains::accounts::{notifier::AccountsNotifier, repository::AccountsRepository},
    newtypes::Opaque,
};

pub mod accounts;
mod jwt;

pub fn app_router(
    config: &Config,
    accounts_repository: impl AccountsRepository,
    accounts_notifier: impl AccountsNotifier,
) -> Router {
    let app_state = AppState {
        accounts_repository: Arc::new(accounts_repository),
        accounts_notifier: Arc::new(accounts_notifier),
        jwt_secret: config.jwt_secret.clone(),
    };
    Router::new()
        .route("/health", get(get_healthcheck))
        .nest("/api/accounts", accounts::accounts_router())
        .fallback(not_found)
        .with_state(app_state)
}

#[derive(Clone)]
pub struct AppState {
    accounts_repository: Arc<dyn AccountsRepository>,
    accounts_notifier: Arc<dyn AccountsNotifier>,
    jwt_secret: Opaque<String>,
}

#[derive(Serialize, Deserialize)]
pub struct GetHealthcheckResponse {
    pub ok: bool,
}
async fn get_healthcheck() -> (StatusCode, Json<GetHealthcheckResponse>) {
    (StatusCode::OK, Json(GetHealthcheckResponse { ok: true }))
}

async fn not_found() -> impl IntoResponse {
    ApiError::NotFound
}

// ############################################
// ################## ERRORS ##################
// ############################################

#[derive(Debug)]
pub enum ApiError {
    NotFound,
    InternalServerError(anyhow::Error),
    BadRequest(String),
    Unauthorized(String),
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        ApiError::InternalServerError(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::NotFound => (StatusCode::NOT_FOUND, "Not found").into_response(),
            Self::InternalServerError(e) => {
                error!("Internal server error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
            }
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            Self::Unauthorized(msg) => {
                warn!("Unauthorized access attempt: {}", msg);
                StatusCode::UNAUTHORIZED.into_response()
            }
        }
    }
}

// ##########################################
// ################## AUTH ##################
// ##########################################

pub struct AuthorizedAccount {
    pub account_id: uuid::Uuid,
}

impl FromRequestParts<AppState> for AuthorizedAccount {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let authorization_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|header_value| header_value.to_str().ok())
            .ok_or(AuthError::MissingToken)?;

        let token = authorization_header
            .strip_prefix("Bearer ")
            .map(|s| s.to_string())
            .ok_or(AuthError::MissingToken)?;

        let account_id = jwt::decode_and_validate_jwt(&token.into(), &state.jwt_secret).map_err(
            |e| match e {
                jwt::JwtDecodeError::InvalidToken(err) => {
                    AuthError::InvalidToken(format!("{:?}", err))
                }
            },
        )?;
        Ok(AuthorizedAccount { account_id })
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing token")]
    MissingToken,
    #[error("invalid token: {0}")]
    InvalidToken(String),
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
            AuthError::InvalidToken(msg) => {
                warn!("Invalid token: {}", msg);
                (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
            }
            AuthError::Unknown(e) => {
                error!("Authentication error: {e:?}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
            }
        }
    }
}
