use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::{Deserialize, Serialize};

use super::{ApiError, AppState, AuthorizedAccount};

pub fn items_router() -> Router<AppState> {
    Router::new().route("/", post(create_item).get(list_items))
}

// ###########################################
// ############### CREATE ITEM ###############
// ###########################################

async fn create_item(
    State(_app_state): State<AppState>,
    _authorized_account: AuthorizedAccount,
) -> Result<(StatusCode, Json<ItemResponse>), ApiError> {
    Err(ApiError::NotFound)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateItemRequestHttpBody {
    /// The encrypted item data - encoded in base64
    pub ciphertext: String,
    /// The nonce used for encryption - encoded in base64
    pub encryption_nonce: String,
    /// The encrypted symmetric key used for item encryption - encoded in base64
    pub encrypted_symmetric_key: String,
    /// The signature of the ciphertext - encoded in base64
    pub signature: String,
}

// #########################################
// ############### GET ITEMS ###############
// #########################################

async fn list_items(
    State(_app_state): State<AppState>,
    _authorized_account: AuthorizedAccount,
) -> Result<Json<Vec<ItemResponse>>, ApiError> {
    let items = vec![];
    Ok(Json(items))
}

// ######################################
// ############### COMMON ###############
// ######################################

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemResponse {
    pub id: uuid::Uuid,
    /// The encrypted item data - encoded in base64
    pub ciphertext: String,
    /// The nonce used for encryption - encoded in base64
    pub encryption_nonce: String,
    /// The encrypted symmetric key used for item encryption - encoded in base64
    pub encrypted_symmetric_key: String,
    /// The signature of the ciphertext - encoded in base64
    pub signature: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
