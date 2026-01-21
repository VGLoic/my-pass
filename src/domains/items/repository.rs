use sqlx::query_as;

use super::models::{CreateItemError, CreateItemRequest, FindItemsError, Item};

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

    /// Creates a new item in the repository.
    /// An item is associated with an account via the account_id field.
    /// # Arguments
    /// * `request` - The CreateItemRequest containing the item details to be created.
    /// # Returns
    /// The created Item.
    /// # Errors
    /// MUST return CreateItemError::AccountNotFound if the account does not exist.
    /// MUST return CreateItemError::Unknown for any other errors encountered during the operation.
    async fn create_item(&self, request: CreateItemRequest) -> Result<Item, CreateItemError>;
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

    async fn create_item(&self, request: CreateItemRequest) -> Result<Item, CreateItemError> {
        let mut transaction = self.pool.begin().await.map_err(|e| {
            CreateItemError::Unknown(anyhow::Error::new(e).context("failed to begin transaction"))
        })?;

        let account_exists = query_as::<_, (i64,)>(
            r#"
            SELECT COUNT(1)
            FROM accounts 
            WHERE id = $1
            "#,
        )
        .bind(request.account_id())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|e| {
            CreateItemError::Unknown(
                anyhow::Error::new(e).context("failed to check account existence"),
            )
        })?;
        if account_exists.0 == 0 {
            return Err(CreateItemError::AccountNotFound);
        }
        let item = query_as::<_, Item>(
            r#"
            INSERT INTO items (
                account_id, 
                ciphertext, 
                encryption_nonce, 
                encrypted_symmetric_key, 
                signature_r, 
                signature_s
            ) VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING 
                id, 
                account_id, 
                ciphertext, 
                encryption_nonce, 
                encrypted_symmetric_key, 
                signature_r, 
                signature_s, 
                created_at, 
                updated_at
            "#,
        )
        .bind(request.account_id())
        .bind(request.ciphertext())
        .bind(request.encryption_nonce())
        .bind(request.encrypted_symmetric_key())
        .bind(request.signature_r())
        .bind(request.signature_s())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|e| {
            CreateItemError::Unknown(anyhow::Error::new(e).context("failed to create item"))
        })?;
        transaction.commit().await.map_err(|e| {
            CreateItemError::Unknown(anyhow::Error::new(e).context("failed to commit transaction"))
        })?;
        Ok(item)
    }
}
