use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use base64::{Engine, prelude::BASE64_STANDARD};
use serde::{Deserialize, Serialize};

use super::{ApiError, AppState, AuthorizedAccount};
use crate::domains::items::models::{FindItemsError, Item};

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
    State(app_state): State<AppState>,
    authorized_account: AuthorizedAccount,
) -> Result<Json<Vec<ItemResponse>>, ApiError> {
    let items = app_state
        .items_service
        .find_items_by_account_id(authorized_account.account_id)
        .await
        .map_err(|e| match e {
            FindItemsError::AccountNotFound => ApiError::NotFound,
            FindItemsError::Unknown(e) => {
                ApiError::InternalServerError(e.context("failed to list items"))
            }
        })?;
    Ok(Json(items.into_iter().map(ItemResponse::from).collect()))
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

impl From<Item> for ItemResponse {
    fn from(item: Item) -> Self {
        Self {
            id: item.id,
            ciphertext: BASE64_STANDARD.encode(item.ciphertext.unsafe_inner()),
            encryption_nonce: BASE64_STANDARD.encode(item.encryption_nonce.unsafe_inner()),
            encrypted_symmetric_key: BASE64_STANDARD
                .encode(item.encrypted_symmetric_key.unsafe_inner()),
            signature: BASE64_STANDARD.encode(item.signature.unsafe_inner()),
            created_at: item.created_at,
            updated_at: item.updated_at,
        }
    }
}
