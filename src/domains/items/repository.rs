use sqlx::query_as;

use super::models::{FindItemsError, Item};

/// Defines the ItemsRepository trait for items-related database operations
#[async_trait::async_trait]
pub trait ItemsRepository: Send + Sync + 'static {
    /// Finds items by the given account ID.
    ///
    /// # Arguments
    /// * `account_id` - The UUID of the account whose items are to be retrieved.
    ///
    /// # Returns
    /// A Result containing a vector of Item structs, ordered by creation date descending
    ///
    /// # Errors
    /// MUST return FindItemsError::AccountNotFound if the account does not exist.
    /// MUST return FindItemsError::Unknown for any other errors encountered during the operation.
    async fn find_items_by_account_id(
        &self,
        account_id: uuid::Uuid,
    ) -> Result<Vec<Item>, FindItemsError>;
}

#[derive(Clone)]
pub struct PsqlItemsRepository {
    pub pool: sqlx::PgPool,
}

impl PsqlItemsRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl ItemsRepository for PsqlItemsRepository {
    async fn find_items_by_account_id(
        &self,
        account_id: uuid::Uuid,
    ) -> Result<Vec<Item>, FindItemsError> {
        let items = query_as::<_, Item>(
            r#"
            SELECT 
                id, 
                account_id, 
                ciphertext, 
                encryption_nonce, 
                encrypted_symmetric_key, 
                signature_r, 
                signature_s, 
                created_at, 
                updated_at
            FROM items
            WHERE account_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::RowNotFound = e {
                FindItemsError::AccountNotFound
            } else {
                FindItemsError::Unknown(
                    anyhow::Error::new(e).context("failed to find items by account ID"),
                )
            }
        })?;

        Ok(items)
    }
}
