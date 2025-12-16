use anyhow::anyhow;
use sqlx::{Pool, Postgres, query_as};

use super::{Account, CreateAccountError, GetAccountError, SignupRequest, VerificationTicket};
use crate::newtypes::Email;

/// Defines the AccountsRepository trait for account-related database operations.
#[async_trait::async_trait]
pub trait AccountsRepository: Send + Sync + 'static {
    /// Creates a new [Account] in the repository. Creates a new [VerificationTicket] as part of the process.
    ///
    /// # Arguments
    /// * `signup_request` - A reference to the [SignupRequest] containing account and ticket details.
    ///
    /// # Returns
    /// * `Account` - The created [Account].
    /// * `VerificationTicket` - The created [VerificationTicket].
    ///
    /// # Errors
    /// - MUST return [CreateAccountError::EmailAlreadyCreated] if an account with the given email already exists.
    /// - MUST return [CreateAccountError::Unknown] for any other errors encountered during account creation.
    async fn create_account(
        &self,
        signup_request: &SignupRequest,
    ) -> Result<(Account, VerificationTicket), CreateAccountError>;

    /// Retrieves an [Account] by its email.
    ///
    /// # Arguments
    /// * `email` - A string slice representing the email of the account to retrieve.
    ///
    /// # Returns
    /// * `Account` - The retrieved [Account].
    ///
    /// # Errors
    /// - MUST return [GetAccountError::NotFound] if no account with the given email exists.
    /// - MUST return [GetAccountError::Unknown] for any other errors encountered during retrieval.
    async fn get_account_by_email(&self, email: &Email) -> Result<Account, GetAccountError>;
}

#[derive(Clone)]
pub struct PsqlAccountsRepository {
    pool: Pool<Postgres>,
}

impl PsqlAccountsRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl AccountsRepository for PsqlAccountsRepository {
    async fn create_account(
        &self,
        signup_request: &SignupRequest,
    ) -> Result<(Account, VerificationTicket), CreateAccountError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|e| anyhow!(e).context("failed to start transaction"))?;

        let account = query_as::<_, Account>(
            r#"
            INSERT INTO account (
                email,
                password_hash,
                symmetric_key_salt,
                encrypted_private_key_nonce,
                encrypted_private_key,
                public_key
            ) VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING
                id,
                email,
                password_hash,
                verified,
                symmetric_key_salt,
                encrypted_private_key_nonce,
                encrypted_private_key,
                public_key,
                created_at,
                updated_at
        "#,
        )
        .bind(&signup_request.email)
        .bind(&signup_request.password_hash)
        .bind(&signup_request.symmetric_key_salt)
        .bind(&signup_request.encrypted_private_key_nonce)
        .bind(&signup_request.encrypted_private_key)
        .bind(&signup_request.public_key)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db_err) = &e
                // 23505 is the PostgreSQL error code for unique_violation
                && db_err.code() == Some("23505".into())
                && db_err.message().contains("email")
            {
                CreateAccountError::EmailAlreadyCreated
            } else {
                anyhow::Error::new(e).context("creating account").into()
            }
        })?;

        let verification_ticket = query_as::<_, VerificationTicket>(
            r#"
            INSERT INTO verification_ticket (
                account_id,
                token,
                expires_at
            ) VALUES ($1, $2, $3)
             RETURNING
                id,
                account_id,
                token,
                expires_at,
                created_at,
                expires_at,
                cancelled_at,
                used_at,
                updated_at
        "#,
        )
        .bind(account.id)
        .bind(&signup_request.verification_ticket_token)
        .bind(signup_request.verification_ticket_expires_at)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|e| anyhow!(e).context("failed to create verification ticket"))?;

        transaction
            .commit()
            .await
            .map_err(|e| anyhow!(e).context("failed to commit transaction"))?;

        Ok((account, verification_ticket))
    }

    async fn get_account_by_email(&self, email: &Email) -> Result<Account, GetAccountError> {
        // The `r` is for raw string literals in Rust, allowing us to write SQL queries without caring about escaping characters.
        // The `#` is a delimiter that allows us to include double quotes in the SQL query without needing to escape them.
        let query_result = query_as::<_, Account>(
            r#"
            SELECT
                id,
                email,
                password_hash,
                verified,
                symmetric_key_salt,
                encrypted_private_key_nonce,
                encrypted_private_key,
                public_key,
                created_at,
                updated_at
            FROM account
            WHERE email = $1
        "#,
        )
        .bind(email)
        .fetch_one(&self.pool)
        .await;
        match query_result {
            Ok(account) => Ok(account),
            Err(sqlx::Error::RowNotFound) => Err(GetAccountError::NotFound),
            Err(e) => Err(GetAccountError::Unknown(
                anyhow::Error::new(e).context("retrieving account by email"),
            )),
        }
    }
}
