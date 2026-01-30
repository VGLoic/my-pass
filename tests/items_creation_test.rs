use axum::http::StatusCode;
use base64::{Engine, prelude::BASE64_STANDARD};
use fake::{Fake, Faker, faker};

mod common;
use common::{default_test_config, setup_instance};
use my_pass::{
    crypto::keypair::PrivateKey,
    newtypes::{Email, Opaque, Password},
    routes::{
        accounts::{
            EncryptedKeyPairHttpBody, LoginRequestHttpBody, LoginResponse, SignUpRequestHttpBody,
            UseVerificationTicketRequestHttpBody,
        },
        items::ItemResponse,
    },
};

use crate::common::default_test_secrets_manager;

#[tokio::test]
async fn test_item_creation_api() {
    let instance_state = setup_instance(default_test_config(), default_test_secrets_manager())
        .await
        .unwrap();

    let email = Faker.fake::<Email>();
    let password = Faker.fake::<Password>();
    let private_key = PrivateKey::generate();
    let encrypted_key_pair = private_key
        .encrypt_key_pair_with_password(password.clone())
        .unwrap();

    let signup_body = SignUpRequestHttpBody {
        email: email.to_string(),
        password: password.unsafe_inner().to_owned().into(),
        encrypted_key_pair: EncryptedKeyPairHttpBody {
            ciphertext: Opaque::new(
                BASE64_STANDARD.encode(encrypted_key_pair.ciphertext().unsafe_inner()),
            ),
            symmetric_key_salt: Opaque::new(
                BASE64_STANDARD.encode(encrypted_key_pair.symmetric_key_salt().unsafe_inner()),
            ),
            encryption_nonce: Opaque::new(
                BASE64_STANDARD.encode(encrypted_key_pair.encryption_nonce().unsafe_inner()),
            ),
            public_key: Opaque::new(
                BASE64_STANDARD.encode(encrypted_key_pair.public_key().unsafe_inner()),
            ),
        },
    };

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

    let item_plaintext: String = faker::lorem::en::Sentence(3..6).fake();
    let encapsulated_symmetric_key = my_pass::crypto::keypair::SymmetricKey::encapsulate(
        &private_key.encapsulation_public_key(),
    )
    .unwrap();
    let encryption_nonce: [u8; 12] = fake::rand::random();
    let ciphertext = encapsulated_symmetric_key
        .symmetric_key()
        .encrypt(item_plaintext.as_bytes(), &encryption_nonce)
        .unwrap();
    let (signature_r, signature_s) = private_key.sign(&ciphertext).unwrap();
    let mut signature = Vec::new();
    signature.extend_from_slice(&signature_r);
    signature.extend_from_slice(&signature_s);

    assert_eq!(
        instance_state
            .reqwest_client
            .post(format!("{}/api/items", &instance_state.server_url))
            .bearer_auth(access_token.unsafe_inner())
            .json(&serde_json::json!({
                "ciphertext": BASE64_STANDARD.encode(&ciphertext),
                "encryptionNonce": BASE64_STANDARD.encode(encryption_nonce),
                "ephemeralPublicKey": BASE64_STANDARD.encode(encapsulated_symmetric_key.ephemeral_public_key().to_bytes().unsafe_inner()),
                "signature": BASE64_STANDARD.encode(&signature),
            }))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );

    let get_items_response = instance_state
        .reqwest_client
        .get(format!("{}/api/items", &instance_state.server_url))
        .bearer_auth(access_token.unsafe_inner())
        .send()
        .await
        .unwrap();
    assert_eq!(get_items_response.status(), StatusCode::OK);
    let items = get_items_response
        .json::<Vec<ItemResponse>>()
        .await
        .unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].ciphertext, BASE64_STANDARD.encode(&ciphertext));
}

#[tokio::test]
async fn test_item_creation_cli() {
    let instance_state = setup_instance(default_test_config(), default_test_secrets_manager())
        .await
        .unwrap();

    let cli_client =
        common::cli::setup_cli_client(common::cli::cli_config_from_instance_state(&instance_state))
            .unwrap();

    let email = Faker.fake::<Email>();
    let password = Faker.fake::<Password>();

    // Sign up using CLI
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

    // Verify account using CLI
    assert!(
        cli_client
            .verify(email.clone(), last_ticket.token.unsafe_inner().clone())
            .await
            .is_ok()
    );

    // Login using CLI
    assert!(
        cli_client
            .login(email.clone(), password.clone())
            .await
            .is_ok()
    );

    // Add item using CLI (which will automatically decrypt the private key with the password)
    let item_plaintext = "my secret item";
    assert!(
        cli_client
            .add_item_with_password(email.as_str(), item_plaintext.as_bytes(), password.clone())
            .await
            .is_ok()
    );

    // Verify item was created by checking via API with token from store
    let token = cli_client.get_token(email.as_str()).await.unwrap().unwrap();

    let items_response = instance_state
        .reqwest_client
        .get(format!("{}/api/items", &instance_state.server_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(items_response.status(), StatusCode::OK);
    let items = items_response.json::<Vec<ItemResponse>>().await.unwrap();
    assert_eq!(items.len(), 1);

    // List items using CLI
    let listed_items = cli_client
        .list_items_with_password(email.as_str(), password)
        .await
        .unwrap();

    assert_eq!(listed_items.len(), 1);
    assert_eq!(listed_items[0].1, item_plaintext);
}
