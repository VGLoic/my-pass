use super::models::{Account, CreateAccountError, SignupRequest};
use super::notifier::AccountsNotifier;
use super::repository::AccountsRepository;
use tracing::info;

/// Service trait for managing accounts.
#[async_trait::async_trait]
pub trait AccountsService: Send + Sync + 'static {
    /// Signs up a new account with the given signup request.
    /// Returns the created Account on success.
    /// # Arguments
    /// * `request` - The [SignupRequest] containing account details.
    /// # Errors
    /// Returns [CreateAccountError] if account creation fails.
    /// * [CreateAccountError::EmailAlreadyCreated] - If an account with the given email already exists.
    /// * [CreateAccountError::Unknown] - If an unknown error occurs during account creation.
    async fn signup(&self, request: SignupRequest) -> Result<Account, CreateAccountError>;
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
    async fn signup(&self, request: SignupRequest) -> Result<Account, CreateAccountError> {
        let (created_account, created_ticket) = self.repository.create_account(&request).await?;

        self.notifier
            .account_signed_up(&created_account, &created_ticket)
            .await;

        info!("Account created with email: {}", created_account.email);

        Ok(created_account)
    }
}
