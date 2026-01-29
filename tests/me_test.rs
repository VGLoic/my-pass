use axum::http::StatusCode;
use base64::{Engine, prelude::BASE64_STANDARD};
use fake::{Fake, Faker};
use my_pass::newtypes::{Email, Password};

mod common;
use common::{default_test_config, setup_instance};
use my_pass::routes::accounts::{
    LoginRequestHttpBody, LoginResponse, MeResponse, SignUpRequestHttpBody,
    UseVerificationTicketRequestHttpBody,
};

use crate::common::default_test_secrets_manager;

#[tokio::test]
async fn test_me_api() {
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
    let me_response = instance_state
        .reqwest_client
        .get(format!("{}/api/accounts/me", &instance_state.server_url))
        .bearer_auth(access_token.unsafe_inner())
        .send()
        .await
        .unwrap();
    assert_eq!(me_response.status(), StatusCode::OK);
    let me_response_body = me_response.json::<MeResponse>().await.unwrap();
    assert_eq!(me_response_body.email, signup_body.email);
    assert_eq!(
        me_response_body
            .encrypted_key_pair
            .ciphertext
            .unsafe_inner(),
        signup_body.encrypted_key_pair.ciphertext.unsafe_inner()
    );
    assert_eq!(
        me_response_body
            .encrypted_key_pair
            .symmetric_key_salt
            .unsafe_inner(),
        signup_body
            .encrypted_key_pair
            .symmetric_key_salt
            .unsafe_inner()
    );
    assert_eq!(
        me_response_body
            .encrypted_key_pair
            .encryption_nonce
            .unsafe_inner(),
        signup_body
            .encrypted_key_pair
            .encryption_nonce
            .unsafe_inner()
    );
    assert_eq!(
        me_response_body
            .encrypted_key_pair
            .public_key
            .unsafe_inner(),
        signup_body.encrypted_key_pair.public_key.unsafe_inner()
    );
}

#[tokio::test]
async fn test_me_unauthorized_api() {
    let instance_state = setup_instance(default_test_config(), default_test_secrets_manager())
        .await
        .unwrap();

    assert_eq!(
        instance_state
            .reqwest_client
            .get(format!("{}/api/accounts/me", &instance_state.server_url))
            .bearer_auth(BASE64_STANDARD.encode("invalid token"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn test_me_cli() {
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

    let me_response = cli_client.me(email.as_str()).await.unwrap();
    assert_eq!(me_response.email, email.to_string());
}

#[tokio::test]
async fn test_me_cli_no_token() {
    let instance_state = setup_instance(default_test_config(), default_test_secrets_manager())
        .await
        .unwrap();
    let cli_client =
        common::cli::setup_cli_client(common::cli::cli_config_from_instance_state(&instance_state))
            .unwrap();

    let email = Faker.fake::<Email>();

    match cli_client.me(email.as_str()).await {
        Err(_) => {
            // Expected: no token found for this email
        }
        Ok(_) => panic!("Expected error but me() succeeded"),
    };
}
