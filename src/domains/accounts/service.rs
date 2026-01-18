use super::models::{Account, CreateAccountError, SignupRequest};

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
