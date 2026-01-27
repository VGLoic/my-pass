# Copilot Instructions for my-pass

## Code Quality Standards

### Domain-Driven Design
- Every modification must respect the domain-driven design of the application
- Maintain clear separation between domain logic, application services, and infrastructure layers
- Keep domain entities and value objects focused on their specific responsibilities
- Organize code according to the existing domain structure in the `src/domains/` directory

### Code Formatting
All code must be formatted using:
```bash
cargo fmt
```

### Linting and Code Analysis
All code must pass linting checks using:
```bash
cargo clippy --all-targets --all-features --workspace
```

### Testing

#### Unit Tests
Run unit tests with:
```bash
cargo test --lib
```

#### Integration Tests
Run integration tests with:
```bash
scripts/integration-test.sh
```

### Error Handling
- No `unwrap` allowed - all errors must be handled properly
- Use `anyhow` error for simple and local cases
- Use error enums for broader error handling across modules, with an `Unknown` variant as an `anyhow` error wrapper for unexpected cases

### Logging Standards
- Log entry and exit of sensitive operations (authentication, crypto, data access)
- Use appropriate log levels: `error` for failures, `warn` for suspicious activity, `info` for important events, `debug` for detailed tracing
- **Never log passwords, secrets, tokens, or private keys**
- Include context in logs (user IDs, operation types) but sanitize sensitive data
- Log all security-relevant events (login attempts, verification failures, access denials)

### Security Guidelines
- Validate all user inputs before processing
- Never store or log credentials, secrets, or sensitive tokens
- Use secure defaults for all cryptographic operations
- Ensure sensitive data in memory is properly handled (consider clearing after use)
- Implement proper access control for all endpoints and operations
- Follow the principle of least privilege - grant minimum necessary permissions
- Regularly review and audit security-sensitive code paths

## Before Submitting Changes
1. Ensure code follows domain-driven design principles
2. Run `cargo fmt` to format the code
3. Run `cargo clippy --all-targets --all-features` and resolve any warnings
4. Run `cargo test --lib` to verify unit tests pass
5. Run `scripts/integration-test.sh` to verify integration tests pass

## Plan Mode

- Make the plan extremely concise. Sacrifice grammar for the sake of concision.
- At the end of each plan, give me a list of unresolved questions to answer, if any.
