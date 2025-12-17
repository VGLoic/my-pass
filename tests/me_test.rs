use axum::http::StatusCode;
use base64::{Engine, prelude::BASE64_STANDARD};
use fake::{Fake, Faker};

mod common;
use common::{default_test_config, setup_instance};
use my_pass::routes::accounts::{
    LoginRequestHttpBody, LoginResponse, MeResponse, SignUpRequestHttpBody,
    UseVerificationTicketRequestHttpBody,
};

#[tokio::test]
async fn test_me() {
    let instance_state = setup_instance(default_test_config()).await.unwrap();

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
        me_response_body.encrypted_private_key.unsafe_inner(),
        signup_body.encrypted_private_key.unsafe_inner()
    );
    assert_eq!(
        me_response_body.symmetric_key_salt.unsafe_inner(),
        signup_body.symmetric_key_salt.unsafe_inner()
    );
    assert_eq!(
        me_response_body.encrypted_private_key_nonce.unsafe_inner(),
        signup_body.encrypted_private_key_nonce.unsafe_inner()
    );
    assert_eq!(
        me_response_body.public_key.unsafe_inner(),
        signup_body.public_key.unsafe_inner()
    );
}

#[tokio::test]
async fn test_me_unauthorized() {
    let instance_state = setup_instance(default_test_config()).await.unwrap();

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
