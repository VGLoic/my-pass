use tracing::info;

use super::Account;

/// Defines the AccountsNotifier trait for account-related notifications.
#[async_trait::async_trait]
pub trait AccountsNotifier: Send + Sync + 'static {
    /// Triggers a notification when a new account has been signed up.
    ///
    /// # Arguments
    /// * `account` - A reference to the [Account] that has been signed up
    async fn account_signed_up(&self, account: &Account);
}

pub struct DummyAccountsNotifier;

#[async_trait::async_trait]
impl AccountsNotifier for DummyAccountsNotifier {
    async fn account_signed_up(&self, _account: &Account) {
        // No-op
        info!("DummyAccountsNotifier: account_signed_up called");
    }
}
