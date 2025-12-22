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

    /// Triggers a notification when an account has logged in.
    /// # Arguments
    /// * `account` - A reference to the [Account] that has logged in
    async fn account_logged_in(&self, account: &Account);

    /// Triggers a notification when a new verification ticket has been created.
    /// # Arguments
    /// * `account` - A reference to the [Account] for which the ticket was created
    /// * `verification_ticket` - A reference to the newly created [VerificationTicket]
    async fn new_verification_ticket_created(
        &self,
        account: &Account,
        verification_ticket: &VerificationTicket,
    );
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

    async fn account_logged_in(&self, account: &Account) {
        // No-op
        // We log the event for demonstration purposes, this is not safe for production use
        info!(
            "Triggered account_logged_in notification for email \"{}\"",
            account.email
        );
    }

    async fn new_verification_ticket_created(
        &self,
        account: &Account,
        verification_ticket: &VerificationTicket,
    ) {
        // No-op
        // We log the event for demonstration purposes, this is not safe for production use
        info!(
            "Triggered new_verification_ticket_created notification for email \"{}\" with ticket \"{}\"",
            account.email,
            verification_ticket.token.unsafe_inner()
        );
    }
}
