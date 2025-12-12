use super::ApiError;
use axum::{
    Router,
    extract::Path,
    http::StatusCode,
    routing::{get, post},
};

pub fn accounts_router() -> Router {
    Router::new()
        .route("/signup", post(sign_up))
        // Added a test route for checking user existence
        .route("/{email}/test-exists", get(test_user_exists))
}

async fn sign_up() -> Result<(StatusCode, &'static str), ApiError> {
    Ok((StatusCode::CREATED, "Account created"))
}

async fn test_user_exists(Path(_email): Path<String>) -> Result<StatusCode, ApiError> {
    Ok(StatusCode::OK)
}
