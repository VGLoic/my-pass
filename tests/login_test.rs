use axum::http::StatusCode;
use fake::{Fake, Faker};
use my_pass::cli::client::CliClientError;
use my_pass::newtypes::{Email, Password};

mod common;
use common::{default_test_config, setup_instance};
use my_pass::routes::accounts::{
    LoginRequestHttpBody, LoginResponse, SignUpRequestHttpBody,
    UseVerificationTicketRequestHttpBody,
};

use crate::common::default_test_secrets_manager;

#[tokio::test]
async fn test_login_api() {
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

    let login_body = LoginRequestHttpBody {
        email: signup_body.email.clone(),
        password: signup_body.password.clone(),
    };

    let response = instance_state
        .reqwest_client
        .post(format!("{}/api/accounts/login", &instance_state.server_url))
        .json(&login_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let response_body = response.json::<LoginResponse>().await.unwrap();
    assert!(!response_body.access_token.unsafe_inner().is_empty());

    assert!(
        instance_state
            .accounts_notifier
            .get_logins(&signup_body.email)
            .len()
            == 1
    );

    let access_token = response_body.access_token;
    assert_eq!(
        instance_state
            .reqwest_client
            .get(format!("{}/api/accounts/me", &instance_state.server_url))
            .bearer_auth(access_token.unsafe_inner())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn test_login_unverified_account_api() {
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

    let login_body = LoginRequestHttpBody {
        email: signup_body.email.clone(),
        password: signup_body.password.clone(),
    };

    assert_eq!(
        instance_state
            .reqwest_client
            .post(format!("{}/api/accounts/login", &instance_state.server_url))
            .json(&login_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn test_login_cli() {
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

    assert!(cli_client.login(email.clone(), password).await.is_ok());

    assert_eq!(
        instance_state
            .accounts_notifier
            .get_logins(email.as_str())
            .len(),
        1
    );
}

#[tokio::test]
async fn test_login_unverified_account_cli() {
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

    match cli_client.login(email, password).await.unwrap_err() {
        CliClientError::Http { request_id, .. } => {
            assert!(request_id.is_some());
        }
        other => panic!("unexpected error variant: {:?}", other),
    };
}
