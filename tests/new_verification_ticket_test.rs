use axum::http::StatusCode;
use fake::{Fake, Faker};

mod common;
use common::{default_test_config, setup_instance};
use my_pass::routes::accounts::{NewVerificationTicketRequestHttpBody, SignUpRequestHttpBody};

#[tokio::test]
async fn test_new_verification_ticket_too_soon() {
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
