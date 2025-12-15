use std::sync::Arc;

use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use crate::domains::accounts::repository::AccountsRepository;

pub mod accounts;

pub fn app_router(accounts_repository: impl AccountsRepository) -> Router {
    let app_state = AppState {
        accounts_repository: Arc::new(accounts_repository),
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
