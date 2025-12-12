use axum::http::StatusCode;
use fake::{Dummy, Fake, Faker};

mod common;
use common::{default_test_config, setup_instance};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignupBody {
    email: String,
    password: String,
    encrypted_private_key: String,
    symmetric_key_salt: String,
    public_key: String,
    signature: String,
}

impl<T> Dummy<T> for SignupBody {
    fn dummy_with_rng<R: fake::Rng + ?Sized>(_config: &T, rng: &mut R) -> Self {
        let email: String = fake::faker::internet::en::SafeEmail().fake_with_rng(rng);
        let password: String = fake::faker::internet::en::Password(12..20).fake_with_rng(rng);

        let private_key: String = fake::faker::lorem::en::Sentence(1..3).fake_with_rng(rng);
        let salt: String = fake::faker::lorem::en::Sentence(1..3).fake_with_rng(rng);
        let public_key: String = fake::faker::lorem::en::Sentence(1..3).fake_with_rng(rng);
        let signature: String = fake::faker::lorem::en::Sentence(1..3).fake_with_rng(rng);

        SignupBody {
            email,
            password,
            encrypted_private_key: private_key,
            symmetric_key_salt: salt,
            public_key,
            signature,
        }
    }
}

#[tokio::test]
async fn test_signup() {
    let instance_state = setup_instance(default_test_config()).await.unwrap();

    let signup_body = Faker.fake::<SignupBody>();

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
            .json(&signup_body)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    )
}
