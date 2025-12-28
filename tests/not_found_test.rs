use axum::http::StatusCode;
mod common;
use common::{default_test_config, setup_instance};

use crate::common::default_test_secrets_manager;

#[tokio::test]
async fn test_not_found() {
    let instance_state = setup_instance(default_test_config(), default_test_secrets_manager())
        .await
        .unwrap();

    let response = reqwest::get(format!("{}/unknown-route", &instance_state.server_url))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.text().await.unwrap(), "Not found");
}
