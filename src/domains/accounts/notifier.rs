use tracing::info;

use super::{Account, VerificationTicket};

/// Defines the AccountsNotifier trait for account-related notifications.
#[async_trait::async_trait]
pub trait AccountsNotifier: Send + Sync + 'static {
    /// Triggers a notification when a new account has been signed up.
    ///
    /// # Arguments
    /// * `account` - A reference to the [Account] that has been signed up
    /// * `verification_ticket` - A reference to the associated [VerificationTicket]
    async fn account_signed_up(&self, account: &Account, verification_ticket: &VerificationTicket);
}

pub struct DummyAccountsNotifier;

#[async_trait::async_trait]
impl AccountsNotifier for DummyAccountsNotifier {
    async fn account_signed_up(&self, account: &Account, verification_ticket: &VerificationTicket) {
        // No-op
        // We log the event for demonstration purposes, this is not safe for production use
        info!(
            "Triggered account_signed_up notification for email \"{}\" with ticket \"{}\"",
            account.email,
            verification_ticket.token.unsafe_inner()
        );
    }
}
