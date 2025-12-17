use axum::http::StatusCode;
use fake::{Fake, Faker};

mod common;
use common::{default_test_config, setup_instance};
use my_pass::routes::accounts::{
    LoginRequestHttpBody, LoginResponse, SignUpRequestHttpBody,
    UseVerificationTicketRequestHttpBody,
};

#[tokio::test]
async fn test_login() {
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
}

#[tokio::test]
async fn test_login_unverified_account() {
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
