use axum::http::StatusCode;
use base64::{Engine, prelude::BASE64_STANDARD};
use fake::{Fake, Faker};

mod common;
use common::{default_test_config, setup_instance};
use my_pass::routes::accounts::{
    LoginRequestHttpBody, LoginResponse, SignUpRequestHttpBody,
    UseVerificationTicketRequestHttpBody,
};

use crate::common::default_test_secrets_manager;

#[tokio::test]
async fn test_item_creation() {
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

    let access_token = response_body.access_token;

    assert_eq!(
        instance_state
            .reqwest_client
            .post(format!("{}/api/items", &instance_state.server_url))
            .bearer_auth(access_token.unsafe_inner())
            .json(&serde_json::json!({
                "ciphertext": BASE64_STANDARD.encode("some_ciphertext"),
                "encryptionNonce": BASE64_STANDARD.encode("some_nonce"),
                "encryptedSymmetricKey": BASE64_STANDARD.encode("some_encrypted_symmetric_key"),
                "signature": BASE64_STANDARD.encode("some_signature"),
            }))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );

    assert_eq!(
        instance_state
            .reqwest_client
            .get(format!("{}/api/items", &instance_state.server_url))
            .bearer_auth(access_token.unsafe_inner())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}
