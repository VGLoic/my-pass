use super::{Account, CreateAccountError, GetAccountError, SignupRequest};

/// Defines the AccountsRepository trait for account-related database operations.
pub trait AccountsRepository: Send + Sync {
    /// Creates a new [Account] in the repository.
    /// # Arguments
    /// * `signup_request` - A reference to the [SignupRequest] containing account details.
    /// # Returns
    /// * `Account` - The created [Account].
    /// # Errors
    /// - MUST return [CreateAccountError::EmailAlreadyCreated] if an account with the given email already exists.
    /// - MUST return [CreateAccountError::Unknown] for any other errors encountered during account creation.
    async fn create_account(
        &self,
        signup_request: &SignupRequest,
    ) -> Result<Account, CreateAccountError>;

    /// Retrieves an [Account] by its email.
    /// # Arguments
    /// * `email` - A string slice representing the email of the account to retrieve.
    /// # Returns
    /// * `Account` - The retrieved [Account].
    /// # Errors
    /// - MUST return [GetAccountError::NotFound] if no account with the given email exists.
    /// - MUST return [GetAccountError::Unknown] for any other errors encountered during retrieval.
    async fn get_account_by_email(&self, email: &str) -> Result<Account, GetAccountError>;
}
