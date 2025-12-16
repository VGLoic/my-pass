use axum::http::StatusCode;
use fake::{Fake, Faker};

mod common;
use common::{default_test_config, setup_instance};
use my_pass::routes::accounts::{SignUpRequestHttpBody, UseVerificationTicketRequestHttpBody};

#[tokio::test]
async fn test_signup() {
    let instance_state = setup_instance(default_test_config()).await.unwrap();

    let signup_body = Faker.fake::<SignUpRequestHttpBody>();

    let response = instance_state
        .reqwest_client
        .post(format!(
            "{}/api/accounts/signup",
            &instance_state.server_url
        ))
        .json(&signup_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    assert_eq!(
        instance_state
            .reqwest_client
            .get(format!(
                "{}/api/accounts/{}/test-exists",
                &instance_state.server_url, signup_body.email
            ))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    let verification_tickets = instance_state
        .accounts_notifier
        .get_account_tickets(&signup_body.email);
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
}

#[tokio::test]
async fn test_successive_signup() {
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
            .get_account_tickets(&signup_body.email)
            .len(),
        1
    );
}
