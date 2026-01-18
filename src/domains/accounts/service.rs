use super::models::{
    Account, CreateAccountError, SignupRequest, UseVerificationTicketError,
    UseVerificationTicketRequest, VerificationTicket,
};
use super::notifier::AccountsNotifier;
use super::repository::AccountsRepository;
use tracing::info;

/// Service trait for managing accounts.
#[async_trait::async_trait]
pub trait AccountsService: Send + Sync + 'static {
    /// Signs up a new account with the given signup request.
    /// Returns the created [Account] and [VerificationTicket] on success.
    /// # Arguments
    /// * `request` - The [SignupRequest] containing account details.
    /// # Errors
    /// Returns [CreateAccountError] if account creation fails.
    /// * [CreateAccountError::EmailAlreadyCreated] - If an account with the given email already exists.
    /// * [CreateAccountError::Unknown] - If an unknown error occurs during account creation.
    async fn signup(
        &self,
        request: SignupRequest,
    ) -> Result<(Account, VerificationTicket), CreateAccountError>;

    /// Uses a valid verification ticket to verify an account.
    /// Returns the updated [Account] and [VerificationTicket] on success.
    /// # Arguments
    /// * `request` - The [UseVerificationTicketRequest] containing the verification ticket details.
    /// # Errors
    /// Returns [UseVerificationTicketError] if verification fails.
    /// * [UseVerificationTicketError::Unknown] - If an unknown error occurs during verification.
    async fn use_verification_ticket(
        &self,
        request: UseVerificationTicketRequest,
    ) -> Result<(Account, VerificationTicket), UseVerificationTicketError>;
}

pub struct DefaultAccountsService<Repository: AccountsRepository, Notifier: AccountsNotifier> {
    repository: Repository,
    notifier: Notifier,
}

impl<Repository: AccountsRepository, Notifier: AccountsNotifier>
    DefaultAccountsService<Repository, Notifier>
{
    pub fn new(repository: Repository, notifier: Notifier) -> Self {
        Self {
            repository,
            notifier,
        }
    }
}

#[async_trait::async_trait]
impl<Repository, Notifier> AccountsService for DefaultAccountsService<Repository, Notifier>
where
    Repository: AccountsRepository,
    Notifier: AccountsNotifier,
{
    async fn signup(
        &self,
        request: SignupRequest,
    ) -> Result<(Account, VerificationTicket), CreateAccountError> {
        let (created_account, created_ticket) = self.repository.create_account(&request).await?;

        self.notifier
            .account_signed_up(&created_account, &created_ticket)
            .await;

        info!("Account created with email: {}", created_account.email);

        Ok((created_account, created_ticket))
    }

    async fn use_verification_ticket(
        &self,
        request: UseVerificationTicketRequest,
    ) -> Result<(Account, VerificationTicket), UseVerificationTicketError> {
        let (updated_account, updated_ticket) = self.repository.verify_account(&request).await?;

        self.notifier
            .account_verified(&updated_account, &updated_ticket)
            .await;

        info!("Account with email {} verified", &updated_account.email);

        Ok((updated_account, updated_ticket))
    }
}
