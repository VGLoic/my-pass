use super::models::Item;
use tracing::info;

/// Defines the ItemsNotifier trait for item-related notifications.
#[async_trait::async_trait]
pub trait ItemsNotifier: Send + Sync + 'static {
    /// Triggers a notification when a new item has been created.
    /// # Arguments
    /// * `item` - A reference to the [Item] that has been created
    async fn item_created(&self, item: &Item);
}

#[derive(Clone)]
pub struct DummyItemsNotifier;

#[async_trait::async_trait]
impl ItemsNotifier for DummyItemsNotifier {
    async fn item_created(&self, item: &Item) {
        // No-op
        // We log the event for demonstration purposes, this is not safe for production use
        info!(
            "Triggered item_created notification for item with id \"{}\"",
            item.id
        );
    }
}
