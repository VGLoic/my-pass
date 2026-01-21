use tracing::info;

use super::models::{CreateItemError, CreateItemRequest, FindItemsError, Item};
use super::repository::ItemsRepository;

/// Service trait for managing items.
#[async_trait::async_trait]
pub trait ItemsService: Send + Sync + 'static {
    /// Finds items by the given account ID.
    ///
    /// # Arguments
    /// * `account_id` - The UUID of the account whose items are to be retrieved
    ///
    /// # Returns
    /// * List of [Item] associated with the account ID, ordered by creation date descending.
    ///
    /// # Errors
    /// MUST return FindItemsError::AccountNotFound if the account does not exist.
    /// MUST return FindItemsError::Unknown for any other errors encountered during the operation.
    async fn find_items_by_account_id(
        &self,
        account_id: uuid::Uuid,
    ) -> Result<Vec<Item>, FindItemsError>;

    /// Creates a new item for the given account.
    ///
    /// # Arguments
    /// * `request` - The CreateItemRequest containing the item details to be created.
    ///
    /// # Returns
    /// * The created [Item].
    ///
    /// # Errors
    /// MUST return CreateItemError::AccountNotFound if the account does not exist.
    /// MUST return CreateItemError::Unknown for any other errors encountered during the operation.
    async fn create_item(&self, request: CreateItemRequest) -> Result<Item, CreateItemError>;
}

pub struct DefaultItemsService<R: ItemsRepository> {
    repository: R,
}

impl<R: ItemsRepository> DefaultItemsService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }
}

#[async_trait::async_trait]
impl<R: ItemsRepository> ItemsService for DefaultItemsService<R> {
    async fn find_items_by_account_id(
        &self,
        account_id: uuid::Uuid,
    ) -> Result<Vec<Item>, FindItemsError> {
        self.repository.find_items_by_account_id(account_id).await
    }

    async fn create_item(&self, request: CreateItemRequest) -> Result<Item, CreateItemError> {
        let item = self.repository.create_item(request).await?;

        info!(
            "Created item with ID {} for account ID {}",
            item.id, item.account_id
        );

        Ok(item)
    }
}
