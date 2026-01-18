# MyPass

This repository contains the source code for MyPass, a password and secret manager. It aims to be a playground for end to end encryption techniques and secure storage solutions.

The specifications for MyPass can be found in the [specifications document](SPECIFICATIONS.md).

## Local development

To get started with local development, you'll need to set up your environment. Follow these steps:

1. Make sure you have [Rust](https://www.rust-lang.org/tools/install) installed on your machine. Cargo version at the time of writing is 1.88.0.
    ```bash
    cargo --version
    ```

2. Set up the environment variables in a `.env` file, the required ones are indicated with the `REQUIRED` label.
    ```bash
    cp .env.example .env
    ```

3. Verify that the unit tests are running:
    ```bash
    cargo test --lib
    ```

4. Verify that the integration tests are running:
    ```bash
    cargo test --test tests
    ```

5. Launch a local instance of PostgreSQL using Docker:
    ```bash
    docker compose up
    ```

6. Run the application
    ```bash
    cargo run .
    ```

The application can also be run using a single `docker compose` command:
```bash
docker compose -f compose.app.yaml up --build
```

### Integration tests

Integration tests require a database running and exposed on port 5433, use the related docker compose for it:
```bash
docker compose -f compose.integration.yaml up
```

Once the database is up, integration tests can be run:
```bash
cargo test --tests
```

Alternatively, a script has been added in order to wrap the tests with the database container mounting and unmounting:
```bash
# Allow the script to run
chmod +x scripts/integration-test.sh
./scripts/integration-test.sh
```

### Database interaction and migration

This repository uses [`sqlx`](https://github.com/launchbadge/sqlx) for database connectivity and migrations.

#### Migration commands

- **Create a new migration (no running database required):**
    ```bash
    cargo sqlx migrate add <migration_name>
    ```

- **Run and check migrations (requires running database):**
    - Ensure your database connection is configured in `.env` (see `.env.example` for required variables, e.g. `DATABASE_URL`).
    - Run migrations:
        ```bash
        cargo sqlx migrate run
        ```
    - Check migration status:
        ```bash
        cargo sqlx migrate info
        ```
    - Revert the last migration:
        ```bash
        cargo sqlx migrate revert
        ```

#### Troubleshooting

- If you encounter connection errors, verify that your database is running and your `.env` configuration is correct.
- For more details, see the [`sqlx-cli` documentation](https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md) and the [`sqlx` docs](https://github.com/launchbadge/sqlx).

## Architecture: Domain-Driven Design

This project follows a domain-driven architecture that separates concerns across distinct layers:

### Layer Structure

1. **Routes Layer** - HTTP handlers that orchestrate requests
2. **Domain Layer** - Business logic encapsulated in models and services
3. **Repository Layer** - Data persistence abstraction
4. **Notifier Layer** - External notifications (e.g., email)

The architecture follows the principles of the [Master hexagonal architecture in Rust](https://www.howtocodeit.com/guides/master-hexagonal-architecture-in-rust#top).

### Request Flow

The typical request flow follows this pattern:

```
HTTP Request → Route Handler (parsing) → Domain Model (business logic validation) 
→ Service → Repository → Database
```

### Example: Signup Request

**1. Route Handler** - Parses HTTP body and deserializes data:
```rust
async fn sign_up(
    State(app_state): State<AppState>,
    Json(body): Json<SignUpRequestHttpBody>,  // ← Deserialization happens here
) -> Result<StatusCode, ApiError> {
    // Parsing: convert base64 strings to byte arrays
    let email = Email::new(&body.email)
        .map_err(|e| /* map parsing errors to HTTP errors */)?;
    
    // Pass parsed data to domain constructor
    let domain_request = body.try_into_domain()
        .map_err(|e| /* map domain errors to HTTP errors */)?;
    
    app_state.accounts_service.signup(domain_request).await?;
    Ok(StatusCode::CREATED)
}
```

**2. Domain Model** - Encapsulates business logic validation:
```rust
impl SignupRequest {
    pub fn new(
        email: Email,
        encrypted_key_pair: EncryptedKeyPair,
    ) -> Result<Self, SignupRequestError> {
        // Business logic: generate verification token and calculate expiry
        let verification_ticket_token = BASE64_URL_SAFE.encode(rand::random::<[u8; 32]>());
        let verification_ticket_lifetime = chrono::Duration::minutes(15);
        let verification_ticket_expires_at = chrono::Utc::now() + verification_ticket_lifetime;
        
        // Construct request with validated/derived state
        Ok(SignupRequest { /* ... */ })
    }
}
```

**3. Service** - Orchestrates repository and notifier:
```rust
async fn signup(
    &self,
    request: SignupRequest,
) -> Result<(Account, VerificationTicket), CreateAccountError> {
    let (account, ticket) = self.repository.create_account(&request).await?;
    self.notifier.account_signed_up(&account, &ticket).await;
    info!("Account created with email: {}", account.email);
    Ok((account, ticket))
}
```

### Separation of Concerns

- **Route Handler**: Responsible for HTTP parsing and deserialization (base64 decoding, format validation)
- **Domain Constructor**: Responsible for business logic validation and state preparation (token generation, expiry calculation)
- **Service**: Responsible for orchestrating repository and notification operations
