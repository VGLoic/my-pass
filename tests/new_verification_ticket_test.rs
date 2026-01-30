use axum::http::StatusCode;
use fake::{Fake, Faker};
use my_pass::cli::client::CliClientError;
use my_pass::newtypes::{Email, Password};

mod common;
use common::{default_test_config, setup_instance};
use my_pass::routes::accounts::{NewVerificationTicketRequestHttpBody, SignUpRequestHttpBody};

use crate::common::default_test_secrets_manager;

#[tokio::test]
async fn test_new_verification_ticket_too_soon_api() {
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

    let new_verification_ticket_body = NewVerificationTicketRequestHttpBody {
        email: signup_body.email.clone(),
        password: signup_body.password.clone(),
    };
    assert_eq!(
        instance_state
            .reqwest_client
            .post(format!(
                "{}/api/accounts/verification-tickets",
                &instance_state.server_url
            ))
            .json(&new_verification_ticket_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );

    let verification_tickets = instance_state
        .accounts_notifier
        .get_signed_up_tickets(&signup_body.email);
    assert_eq!(verification_tickets.len(), 1);
}

#[tokio::test]
async fn test_new_verification_ticket_too_soon_cli() {
    let instance_state = setup_instance(default_test_config(), default_test_secrets_manager())
        .await
        .unwrap();
    let cli_client =
        common::cli::setup_cli_client(common::cli::cli_config_from_instance_state(&instance_state))
            .unwrap();

    let email = Faker.fake::<Email>();
    let password = Faker.fake::<Password>();

    assert!(
        cli_client
            .signup(email.clone(), password.clone())
            .await
            .is_ok()
    );

    match cli_client
        .request_verification(email.clone(), password)
        .await
        .unwrap_err()
    {
        CliClientError::Http { request_id, .. } => {
            assert!(request_id.is_some());
        }
        other => panic!("unexpected error variant: {:?}", other),
    };

    let verification_tickets = instance_state
        .accounts_notifier
        .get_signed_up_tickets(email.as_str());
    assert_eq!(verification_tickets.len(), 1);
}
