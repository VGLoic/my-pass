// ###############################################
// ############### ITEM DEFINITION ###############
// ###############################################

use sqlx::prelude::FromRow;
use thiserror::Error;

use crate::newtypes::Opaque;

#[derive(Debug, Clone, FromRow)]
pub struct Item {
    pub id: uuid::Uuid,
    pub account_id: uuid::Uuid,
    pub ciphertext: Opaque<Vec<u8>>,
    pub encryption_nonce: Opaque<[u8; 12]>,
    pub encrypted_symmetric_key: Opaque<Vec<u8>>,
    pub signature: Opaque<Vec<u8>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

// ##############################################
// ############### ITEM RETRIEVAL ###############
// ##############################################

#[derive(Debug, Error)]
pub enum FindItemsError {
    #[error("Account not found")]
    AccountNotFound,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}
