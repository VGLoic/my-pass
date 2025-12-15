use axum::http::StatusCode;
use fake::{Fake, Faker};

mod common;
use common::{default_test_config, setup_instance};
use my_pass::routes::accounts::SignUpRequestHttpBody;

#[tokio::test]
async fn test_signup() {
    let instance_state = setup_instance(default_test_config()).await.unwrap();

    let signup_body = Faker.fake::<SignUpRequestHttpBody>();

    let response = instance_state
        .reqwest_client
        .post(format!("{}/accounts/signup", &instance_state.server_url))
        .json(&signup_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    assert_eq!(
        instance_state
            .reqwest_client
            .get(format!(
                "{}/accounts/{}/test-exists",
                &instance_state.server_url, signup_body.email
            ))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    )
}

#[tokio::test]
async fn test_successive_signup() {
    let instance_state = setup_instance(default_test_config()).await.unwrap();

    let signup_body = Faker.fake::<SignUpRequestHttpBody>();

    let _ = instance_state
        .reqwest_client
        .post(format!("{}/accounts/signup", &instance_state.server_url))
        .json(&signup_body)
        .send()
        .await;

    assert_eq!(
        instance_state
            .reqwest_client
            .post(format!("{}/accounts/signup", &instance_state.server_url))
            .json(&signup_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
}
