use std::time::Duration;

use anyhow::anyhow;
use dotenvy::dotenv;
use my_pass::{
    config::Config,
    httpserver::serve_http_server,
    secrets::{InMemorySecretsManager, SecretKey, SecretsManager},
};
use sqlx::postgres::PgPoolOptions;
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    if let Err(err) = dotenv()
        && !err.not_found()
    {
        return Err(anyhow::anyhow!("Error while loading .env file: {err}"));
    }

    let config = match Config::new_from_env() {
        Ok(c) => c,
        Err(errors) => {
            return Err(anyhow::anyhow!(
                "Failed to parse environment variables for configuration with errors: {}",
                errors
                    .into_iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
            ));
        }
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_filter(Into::<LevelFilter>::into(config.log_level)),
        )
        .init();

    let secrets_manager = match InMemorySecretsManager::new_from_env() {
        Ok(m) => m,
        Err(errors) => {
            return Err(anyhow::anyhow!(
                "Failed to parse environment variables for secrets with errors: {}",
                errors
                    .into_iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
            ));
        }
    };

    let pool = match PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(
            secrets_manager
                .get(SecretKey::DatabaseUrl)
                .map_err(|e| anyhow!("{e}").context("Failed to build database connection pool"))?
                .unsafe_inner(),
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            return Err(anyhow::Error::new(e).context("Failed to establish connection to database"));
        }
    };

    if let Err(e) = sqlx::migrate!("./migrations").run(&pool).await {
        return Err(anyhow!("{e}").context("Failed to run database migrations"));
    };

    info!("Successfully ran migrations");

    let accounts_repository =
        my_pass::domains::accounts::repository::PsqlAccountsRepository::new(pool.clone());
    let accounts_notifier = my_pass::domains::accounts::notifier::DummyAccountsNotifier;
    let accounts_service = my_pass::domains::accounts::service::DefaultAccountsService::new(
        accounts_repository,
        accounts_notifier,
    );

    let items_repository = my_pass::domains::items::repository::PsqlItemsRepository::new(pool);
    let items_notifier = my_pass::domains::items::notifier::DummyItemsNotifier;
    let items_service = my_pass::domains::items::service::DefaultItemsService::new(
        items_repository,
        items_notifier,
    );

    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|err| {
        anyhow::anyhow!("Error while binding the TCP listener to address {addr}: {err}")
    })?;

    info!(
        "Successfully bind the TCP listener to address {}\n",
        listener.local_addr().unwrap()
    );

    serve_http_server(listener, secrets_manager, accounts_service, items_service).await
}
