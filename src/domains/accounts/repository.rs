use anyhow::anyhow;
use sqlx::{Pool, Postgres, Row, query, query_as};

use super::{
    Account, CreateAccountError, FindAccountError, FindLastVerificationTicketError, LoginError,
    NewVerificationTicketError, NewVerificationTicketRequest, SignupRequest,
    UseVerificationTicketError, UseVerificationTicketRequest, VerificationTicket,
};
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

    /// Creates a new [VerificationTicket] for an existing account.
    /// If there is an existing active ticket, it is cancelled.
    /// # Arguments
    /// * `new_verification_ticket_request` - A reference to the [NewVerificationTicketRequest] containing details for the new ticket.
    /// # Returns
    /// * `VerificationTicket` - The created [VerificationTicket].
    /// # Errors
    /// - MUST return [CreateAccountError::Unknown] for any errors encountered during ticket creation
    async fn create_new_verification_ticket(
        &self,
        new_verification_ticket_request: &NewVerificationTicketRequest,
    ) -> Result<VerificationTicket, NewVerificationTicketError>;

    /// Retrieves an [Account] by its email.
    ///
    /// # Arguments
    /// * `email` - A string slice representing the email of the account to retrieve.
    ///
    /// # Returns
    /// * `Account` - The retrieved [Account].
    ///
    /// # Errors
    /// - MUST return [FindAccountError::NotFound] if no account with the given email exists.
    /// - MUST return [FindAccountError::Unknown] for any other errors encountered during retrieval.
    async fn find_account_by_email(&self, email: &Email) -> Result<Account, FindAccountError>;

    /// Retrieves an [Account] by its ID.
    /// # Arguments
    /// * `account_id` - The UUID of the account to retrieve.
    /// # Returns
    /// * `Account` - The retrieved [Account].
    /// # Errors
    /// - MUST return [FindAccountError::NotFound] if no account with the given ID exists.
    /// - MUST return [FindAccountError::Unknown] for any other errors encountered during retrieval.
    async fn find_account_by_id(&self, account_id: uuid::Uuid)
    -> Result<Account, FindAccountError>;

    /// Retrieves an [Account] along with its last [VerificationTicket] by email.
    /// # Arguments
    /// * `email` - A string slice representing the email of the account to retrieve.
    /// # Returns
    /// * `Account` - The retrieved [Account]
    /// * `VerificationTicket` - The last [VerificationTicket] associated with the account.
    /// # Errors
    /// - MUST return [FindLastVerificationTicketError::AccountNotFound] if no account with the given email exists,
    /// - MUST return [FindLastVerificationTicketError::NoVerificationTicket] if the account exists but has no associated verification tickets,
    /// - MUST return [FindLastVerificationTicketError::Unknown] for any other errors encountered during retrieval.
    async fn find_account_and_last_verification_ticket_by_email(
        &self,
        email: &Email,
    ) -> Result<(Account, VerificationTicket), FindLastVerificationTicketError>;

    /// Verifies an account and marks the associated verification ticket as used.
    /// # Arguments
    /// * `request` - A [UseVerificationTicketRequest] containing the account ID and valid ticket ID.
    /// # Returns
    /// * `()` - Indicates successful verification.
    /// # Errors
    /// - MUST return [UseVerificationTicketError::Unknown] for any errors encountered during verification
    async fn verify_account(
        &self,
        request: &UseVerificationTicketRequest,
    ) -> Result<(), UseVerificationTicketError>;

    /// Records a login event for the specified account.
    /// # Arguments
    /// * `account_id` - The UUID of the account that has logged in.
    /// # Returns
    /// * `()` - Indicates successful recording of the login event.
    /// # Errors
    /// - MUST return [LoginError::Unknown] for any errors encountered during the login recording process.
    async fn record_login(&self, account_id: uuid::Uuid) -> Result<(), LoginError>;
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
                private_key_symmetric_key_salt,
                private_key_encryption_nonce,
                private_key_ciphertext,
                public_key
            ) VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING
                id,
                email,
                password_hash,
                verified,
                private_key_symmetric_key_salt,
                private_key_encryption_nonce,
                private_key_ciphertext,
                public_key,
                last_login_at,
                created_at,
                updated_at
        "#,
        )
        .bind(&signup_request.email)
        .bind(&signup_request.password_hash)
        .bind(&signup_request.encrypted_private_key.symmetric_key_salt)
        .bind(&signup_request.encrypted_private_key.encryption_nonce)
        .bind(&signup_request.encrypted_private_key.ciphertext)
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

    async fn create_new_verification_ticket(
        &self,
        new_verification_ticket_request: &NewVerificationTicketRequest,
    ) -> Result<VerificationTicket, NewVerificationTicketError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|e| anyhow!(e).context("failed to start transaction"))?;

        if let Some(ticket_id_to_cancel) = new_verification_ticket_request.ticket_id_to_cancel {
            // Cancel existing active ticket
            let update_result = query(
                r#"
                UPDATE verification_ticket
                SET cancelled_at = NOW()
                WHERE id = $1 AND account_id = $2 AND used_at IS NULL AND cancelled_at IS NULL
            "#,
            )
            .bind(ticket_id_to_cancel)
            .bind(new_verification_ticket_request.account_id)
            .execute(&mut *transaction)
            .await
            .map_err(|e| anyhow!(e).context("failed to cancel existing verification tickets"))?;

            if update_result.rows_affected() != 1 {
                return Err(anyhow!("no rows updated")
                    .context("failed to cancel existing verification ticket")
                    .into());
            }
        }

        // Create new ticket
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
        .bind(new_verification_ticket_request.account_id)
        .bind(&new_verification_ticket_request.verification_ticket_token)
        .bind(new_verification_ticket_request.verification_ticket_expires_at)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|e| anyhow!(e).context("failed to create new verification ticket"))?;

        transaction
            .commit()
            .await
            .map_err(|e| anyhow!(e).context("failed to commit transaction"))?;

        Ok(verification_ticket)
    }

    async fn find_account_by_email(&self, email: &Email) -> Result<Account, FindAccountError> {
        // The `r` is for raw string literals in Rust, allowing us to write SQL queries without caring about escaping characters.
        // The `#` is a delimiter that allows us to include double quotes in the SQL query without needing to escape them.
        let query_result = query_as::<_, Account>(
            r#"
            SELECT
                id,
                email,
                password_hash,
                verified,
                private_key_symmetric_key_salt,
                private_key_encryption_nonce,
                private_key_ciphertext,
                public_key,
                last_login_at,
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
            Err(sqlx::Error::RowNotFound) => Err(FindAccountError::NotFound),
            Err(e) => Err(FindAccountError::Unknown(
                anyhow::Error::new(e).context("retrieving account by email"),
            )),
        }
    }

    async fn find_account_by_id(
        &self,
        account_id: uuid::Uuid,
    ) -> Result<Account, FindAccountError> {
        let query_result = query_as::<_, Account>(
            r#"
            SELECT
                id,
                email,
                password_hash,
                verified,
                private_key_symmetric_key_salt,
                private_key_encryption_nonce,
                private_key_ciphertext,
                public_key,
                last_login_at,
                created_at,
                updated_at
            FROM account
            WHERE id = $1
        "#,
        )
        .bind(account_id)
        .fetch_one(&self.pool)
        .await;
        match query_result {
            Ok(account) => Ok(account),
            Err(sqlx::Error::RowNotFound) => Err(FindAccountError::NotFound),
            Err(e) => Err(FindAccountError::Unknown(
                anyhow::Error::new(e).context("retrieving account by id"),
            )),
        }
    }

    async fn find_account_and_last_verification_ticket_by_email(
        &self,
        email: &Email,
    ) -> Result<(Account, VerificationTicket), FindLastVerificationTicketError> {
        let query_result = query(
            r#"
            SELECT
                a.id,
                a.email,
                a.password_hash,
                a.verified,
                a.private_key_symmetric_key_salt,
                a.private_key_encryption_nonce,
                a.private_key_ciphertext,
                a.public_key,
                a.last_login_at,
                a.created_at,
                a.updated_at,
                vt.id,
                vt.account_id,
                vt.token,
                vt.created_at,
                vt.expires_at,
                vt.cancelled_at,
                vt.used_at,
                vt.updated_at
            FROM account a
            LEFT JOIN verification_ticket vt ON a.id = vt.account_id
            WHERE a.email = $1
            ORDER BY vt.created_at DESC
            LIMIT 1
        "#,
        )
        .bind(email)
        .fetch_one(&self.pool)
        .await;

        match query_result {
            Ok(row) => {
                let account = Account {
                    id: row
                        .try_get(0)
                        .map_err(|e| anyhow::Error::new(e).context("parsing account id"))?,
                    email: row
                        .try_get(1)
                        .map_err(|e| anyhow::Error::new(e).context("parsing account email"))?,
                    password_hash: row.try_get(2).map_err(|e| {
                        anyhow::Error::new(e).context("parsing account password_hash")
                    })?,
                    verified: row
                        .try_get(3)
                        .map_err(|e| anyhow::Error::new(e).context("parsing account verified"))?,
                    private_key_symmetric_key_salt: row.try_get(4).map_err(|e| {
                        anyhow::Error::new(e)
                            .context("parsing account private_key_symmetric_key_salt")
                    })?,
                    private_key_encryption_nonce: row.try_get(5).map_err(|e| {
                        anyhow::Error::new(e)
                            .context("parsing account private_key_encryption_nonce")
                    })?,
                    private_key_ciphertext: row.try_get(6).map_err(|e| {
                        anyhow::Error::new(e).context("parsing account private_key_ciphertext")
                    })?,
                    public_key: row
                        .try_get(7)
                        .map_err(|e| anyhow::Error::new(e).context("parsing account public_key"))?,
                    last_login_at: row.try_get(8).map_err(|e| {
                        anyhow::Error::new(e).context("parsing account last_login_at")
                    })?,
                    created_at: row
                        .try_get(9)
                        .map_err(|e| anyhow::Error::new(e).context("parsing account created_at"))?,
                    updated_at: row
                        .try_get(10)
                        .map_err(|e| anyhow::Error::new(e).context("parsing account updated_at"))?,
                };

                let verification_ticket_exists: Option<uuid::Uuid> =
                    row.try_get(11).map_err(|e| {
                        anyhow::Error::new(e).context("checking verification ticket existence")
                    })?;
                if verification_ticket_exists.is_none() {
                    return Err(FindLastVerificationTicketError::NoVerificationTicket(
                        account,
                    ));
                }

                let ticket = VerificationTicket {
                    id: row
                        .try_get(11)
                        .map_err(|e| anyhow::Error::new(e).context("parsing ticket id"))?,
                    account_id: row
                        .try_get(12)
                        .map_err(|e| anyhow::Error::new(e).context("parsing ticket account_id"))?,
                    token: row
                        .try_get(13)
                        .map_err(|e| anyhow::Error::new(e).context("parsing ticket token"))?,
                    created_at: row
                        .try_get(14)
                        .map_err(|e| anyhow::Error::new(e).context("parsing ticket created_at"))?,
                    expires_at: row
                        .try_get(15)
                        .map_err(|e| anyhow::Error::new(e).context("parsing ticket expires_at"))?,
                    cancelled_at: row.try_get(16).map_err(|e| {
                        anyhow::Error::new(e).context("parsing ticket cancelled_at")
                    })?,
                    used_at: row
                        .try_get(17)
                        .map_err(|e| anyhow::Error::new(e).context("parsing ticket used_at"))?,
                    updated_at: row
                        .try_get(18)
                        .map_err(|e| anyhow::Error::new(e).context("parsing ticket updated_at"))?,
                };

                Ok((account, ticket))
            }
            Err(sqlx::Error::RowNotFound) => Err(FindLastVerificationTicketError::AccountNotFound),
            Err(e) => Err(FindLastVerificationTicketError::Unknown(
                anyhow::Error::new(e)
                    .context("retrieving account and last verification ticket by email"),
            )),
        }
    }

    async fn verify_account(
        &self,
        request: &UseVerificationTicketRequest,
    ) -> Result<(), UseVerificationTicketError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|e| anyhow!(e).context("failed to start transaction"))?;

        // Mark the account as verified
        // We only update the account if it is not already verified, we verify that the number of affected rows is 1
        let updated_row = query(
            r#"
            UPDATE account
            SET verified = TRUE
            WHERE id = $1 AND verified = FALSE
        "#,
        )
        .bind(request.account_id)
        .execute(&mut *transaction)
        .await
        .map_err(|e| anyhow!(e).context("failed to verify account"))?;
        if updated_row.rows_affected() != 1 {
            return Err(anyhow!("no rows updated")
                .context("account is already verified")
                .into());
        }

        // Mark the verification ticket as used
        // We only update the ticket if it is unused and not cancelled, we verify that the number of affected rows is 1
        let updated_row = query(
            r#"
            UPDATE verification_ticket
            SET used_at = NOW()
            WHERE id = $1 AND account_id = $2 AND used_at IS NULL AND cancelled_at IS NULL
        "#,
        )
        .bind(request.valid_ticket_id)
        .bind(request.account_id)
        .execute(&mut *transaction)
        .await
        .map_err(|e| anyhow!(e).context("failed to mark verification ticket as used"))?;

        if updated_row.rows_affected() != 1 {
            return Err(anyhow!("no rows updated")
                .context("verification ticket was already used or cancelled")
                .into());
        }

        transaction
            .commit()
            .await
            .map_err(|e| anyhow!(e).context("failed to commit transaction"))?;

        Ok(())
    }

    async fn record_login(&self, account_id: uuid::Uuid) -> Result<(), LoginError> {
        let result = query(
            r#"
            UPDATE account
            SET last_login_at = NOW()
            WHERE id = $1
        "#,
        )
        .bind(account_id)
        .execute(&self.pool)
        .await
        .map_err(|e| anyhow!(e).context("failed to register account login"))?;

        if result.rows_affected() != 1 {
            return Err(anyhow!("no rows updated")
                .context("account not found when registering login")
                .into());
        }

        Ok(())
    }
}
