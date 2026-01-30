use axum::http::StatusCode;
use base64::{Engine, prelude::BASE64_URL_SAFE};
use fake::{Fake, Faker};

mod common;
use common::{default_test_config, setup_instance};
use my_pass::{
    cli::client::CliClientError,
    newtypes::{Email, Password},
    routes::accounts::{SignUpRequestHttpBody, UseVerificationTicketRequestHttpBody},
};

use crate::common::default_test_secrets_manager;

#[tokio::test]
async fn test_signup_api() {
    let instance_state = setup_instance(default_test_config(), default_test_secrets_manager())
        .await
        .unwrap();

    let signup_body = Faker.fake::<SignUpRequestHttpBody>();
    assert_eq!(
        instance_state
            .reqwest_client
            .post(format!(
                "{}/api/accounts/signup",
                &instance_state.server_url
            ))
            .json(&signup_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );

    let verification_tickets = instance_state
        .accounts_notifier
        .get_signed_up_tickets(&signup_body.email);
    assert_eq!(verification_tickets.len(), 1);
    let last_ticket = verification_tickets.last().unwrap();

    let use_ticket_body = UseVerificationTicketRequestHttpBody {
        email: signup_body.email.clone(),
        token: last_ticket.token.clone(),
    };

    assert_eq!(
        instance_state
            .reqwest_client
            .post(format!(
                "{}/api/accounts/verification-tickets/use",
                &instance_state.server_url
            ))
            .json(&use_ticket_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    assert!(
        instance_state
            .accounts_notifier
            .get_verified_tickets(&signup_body.email)
            .iter()
            .any(
                |(account, ticket)| account.email.to_string() == signup_body.email.to_lowercase()
                    && ticket.id == last_ticket.id
            )
    );
}

#[tokio::test]
async fn test_signup_cli() {
    let instance_state = setup_instance(default_test_config(), default_test_secrets_manager())
        .await
        .unwrap();
    let cli_client =
        common::cli::setup_cli_client(common::cli::cli_config_from_instance_state(&instance_state))
            .unwrap();

    let email = Faker.fake::<Email>();
    let password = Faker.fake::<Password>();
    assert!(cli_client.signup(email.clone(), password).await.is_ok());

    let verification_tickets = instance_state
        .accounts_notifier
        .get_signed_up_tickets(email.as_str());
    assert_eq!(verification_tickets.len(), 1);
    let last_ticket = verification_tickets.last().unwrap();

    assert!(
        cli_client
            .verify(email.clone(), last_ticket.token.unsafe_inner().to_string())
            .await
            .is_ok()
    );

    assert!(
        instance_state
            .accounts_notifier
            .get_verified_tickets(email.as_str())
            .iter()
            .any(|(account, ticket)| account.email == email && ticket.id == last_ticket.id)
    );
}

#[tokio::test]
async fn test_successive_signup_fail_api() {
    let instance_state = setup_instance(default_test_config(), default_test_secrets_manager())
        .await
        .unwrap();

    let signup_body = Faker.fake::<SignUpRequestHttpBody>();

    assert_eq!(
        instance_state
            .reqwest_client
            .post(format!(
                "{}/api/accounts/signup",
                &instance_state.server_url
            ))
            .json(&signup_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );

    assert_eq!(
        instance_state
            .reqwest_client
            .post(format!(
                "{}/api/accounts/signup",
                &instance_state.server_url
            ))
            .json(&signup_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );

    assert_eq!(
        instance_state
            .accounts_notifier
            .get_signed_up_tickets(&signup_body.email)
            .len(),
        1
    );
}

#[tokio::test]
async fn test_successive_signup_fail_cli() {
    let instance_state = setup_instance(default_test_config(), default_test_secrets_manager())
        .await
        .unwrap();
    let cli_client =
        common::cli::setup_cli_client(common::cli::cli_config_from_instance_state(&instance_state))
            .unwrap();

    let email = Faker.fake::<Email>();
    let password = Faker.fake::<Password>();

    assert!(cli_client.signup(email.clone(), password).await.is_ok());

    match cli_client
        .signup(email.clone(), Faker.fake::<Password>())
        .await
        .unwrap_err()
    {
        CliClientError::Http { request_id, .. } => {
            assert!(request_id.is_some());
        }
        other => panic!("unexpected error variant: {:?}", other),
    };

    assert_eq!(
        instance_state
            .accounts_notifier
            .get_signed_up_tickets(email.as_str())
            .len(),
        1
    );
}

#[tokio::test]
async fn test_successive_verification_ticket_use_fail_api() {
    let instance_state = setup_instance(default_test_config(), default_test_secrets_manager())
        .await
        .unwrap();

    let signup_body = Faker.fake::<SignUpRequestHttpBody>();

    assert_eq!(
        instance_state
            .reqwest_client
            .post(format!(
                "{}/api/accounts/signup",
                &instance_state.server_url
            ))
            .json(&signup_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );

    let verification_tickets = instance_state
        .accounts_notifier
        .get_signed_up_tickets(&signup_body.email);
    assert_eq!(verification_tickets.len(), 1);
    let last_ticket = verification_tickets.last().unwrap();

    let use_ticket_body = UseVerificationTicketRequestHttpBody {
        email: signup_body.email.clone(),
        token: last_ticket.token.clone(),
    };

    assert_eq!(
        instance_state
            .reqwest_client
            .post(format!(
                "{}/api/accounts/verification-tickets/use",
                &instance_state.server_url
            ))
            .json(&use_ticket_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    assert_eq!(
        instance_state
            .reqwest_client
            .post(format!(
                "{}/api/accounts/verification-tickets/use",
                &instance_state.server_url
            ))
            .json(&use_ticket_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn test_successive_verification_ticket_use_fail_cli() {
    let instance_state = setup_instance(default_test_config(), default_test_secrets_manager())
        .await
        .unwrap();
    let cli_client =
        common::cli::setup_cli_client(common::cli::cli_config_from_instance_state(&instance_state))
            .unwrap();

    let email = Faker.fake::<Email>();
    let password = Faker.fake::<Password>();
    assert!(cli_client.signup(email.clone(), password).await.is_ok());

    let verification_tickets = instance_state
        .accounts_notifier
        .get_signed_up_tickets(email.as_str());
    assert_eq!(verification_tickets.len(), 1);
    let last_ticket = verification_tickets.last().unwrap();

    assert!(
        cli_client
            .verify(email.clone(), last_ticket.token.unsafe_inner().to_string())
            .await
            .is_ok()
    );

    match cli_client
        .verify(email.clone(), last_ticket.token.unsafe_inner().to_string())
        .await
        .unwrap_err()
    {
        CliClientError::Http { request_id, .. } => {
            assert!(request_id.is_some());
        }
        other => panic!("unexpected error variant: {:?}", other),
    };
}

#[tokio::test]
async fn test_invalid_verification_ticket_use_api() {
    let instance_state = setup_instance(default_test_config(), default_test_secrets_manager())
        .await
        .unwrap();

    let signup_body = Faker.fake::<SignUpRequestHttpBody>();

    assert_eq!(
        instance_state
            .reqwest_client
            .post(format!(
                "{}/api/accounts/signup",
                &instance_state.server_url
            ))
            .json(&signup_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );

    let token: [u8; 32] = Faker.fake();

    let use_ticket_body = UseVerificationTicketRequestHttpBody {
        email: signup_body.email.clone(),
        token: BASE64_URL_SAFE.encode(token).into(),
    };

    assert_eq!(
        instance_state
            .reqwest_client
            .post(format!(
                "{}/api/accounts/verification-tickets/use",
                &instance_state.server_url
            ))
            .json(&use_ticket_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn test_invalid_verification_ticket_use_cli() {
    let instance_state = setup_instance(default_test_config(), default_test_secrets_manager())
        .await
        .unwrap();
    let cli_client =
        common::cli::setup_cli_client(common::cli::cli_config_from_instance_state(&instance_state))
            .unwrap();

    let email = Faker.fake::<Email>();
    let password = Faker.fake::<Password>();
    assert!(cli_client.signup(email.clone(), password).await.is_ok());

    let token: [u8; 32] = Faker.fake();

    match cli_client
        .verify(email.clone(), BASE64_URL_SAFE.encode(token))
        .await
        .unwrap_err()
    {
        CliClientError::Http { request_id, .. } => {
            assert!(request_id.is_some());
        }
        other => panic!("unexpected error variant: {:?}", other),
    };
}
