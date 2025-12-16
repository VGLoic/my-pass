use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    extract::MatchedPath,
    http::{Request, Response},
};
use my_pass::{
    Config,
    domains::accounts::{Account, VerificationTicket, notifier::AccountsNotifier},
    routes::app_router,
};
use sqlx::postgres::PgPoolOptions;
use tower_http::trace::TraceLayer;
use tracing::{Level, Span, error, info, info_span, level_filters::LevelFilter};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

#[allow(dead_code)]
pub struct InstanceState {
    pub reqwest_client: reqwest::Client,
    pub server_url: String,
    pub accounts_notifier: FakeAccountsNotifier,
}

#[allow(dead_code)]
pub fn default_test_config() -> Config {
    Config {
        port: 0,
        log_level: Level::WARN,
        database_url: "postgresql://admin:admin@localhost:5433/mypass"
            .to_string()
            .into(),
    }
}

pub async fn setup_instance(config: Config) -> Result<InstanceState, anyhow::Error> {
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer().with_filter(LevelFilter::from_level(config.log_level)),
        )
        .try_init();

    let pool = match PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(config.database_url.unsafe_inner())
        .await
    {
        Ok(c) => c,
        Err(e) => {
            let err = format!("Failed to establish connection to database {e}");
            error!(err);
            return Err(anyhow::anyhow!(err));
        }
    };

    if let Err(e) = sqlx::migrate!("./migrations").run(&pool).await {
        let err = format!("Failed to run database migrations: {e}");
        error!(err);
        return Err(anyhow::anyhow!(err));
    };

    let accounts_repository =
        my_pass::domains::accounts::repository::PsqlAccountsRepository::new(pool);
    let accounts_notifier = FakeAccountsNotifier::new();

    let app = app_router(accounts_repository, accounts_notifier.clone()).layer(
        TraceLayer::new_for_http()
            .make_span_with(|request: &Request<_>| {
                let matched_path = request
                    .extensions()
                    .get::<MatchedPath>()
                    .map(MatchedPath::as_str);

                info_span!(
                    "http_request",
                    method = ?request.method(),
                    matched_path,
                )
            })
            .on_response(
                |response: &Response<Body>, latency: Duration, _span: &Span| {
                    if response.status().is_server_error() {
                        error!("response: {} {latency:?}", response.status())
                    } else {
                        info!("response: {} {latency:?}", response.status())
                    }
                },
            ),
    );

    let listener = if config.port == 0 {
        bind_listener_to_free_port().await?
    } else {
        let addr = SocketAddr::from(([127, 0, 0, 1], config.port));
        tokio::net::TcpListener::bind(&addr).await.map_err(|err| {
            anyhow::anyhow!("Failed to bind the TCP listener to address {addr}: {err}")
        })?
    };

    let addr = listener.local_addr().unwrap();

    info!("Successfully bound the TCP listener to address {addr}\n");

    // Start a server, the handle is kept in order to abort it if needed
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    Ok(InstanceState {
        server_url: format!("http://{}:{}", addr.ip(), addr.port()),
        reqwest_client: reqwest::Client::new(),
        accounts_notifier,
    })
}

async fn bind_listener_to_free_port() -> Result<tokio::net::TcpListener, anyhow::Error> {
    for port in 51_000..60_000 {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => return Ok(listener),
            Err(_) => continue,
        }
    }
    Err(anyhow::anyhow!(
        "No free port found in the range 51000-60000"
    ))
}

/// Fake accounts notifier for tests
/// It stores the notifications in memory for later inspection
/// It implements the `AccountsNotifier` trait
#[derive(Clone)]
pub struct FakeAccountsNotifier {
    pub verification_tickets: Arc<Mutex<HashMap<String, Vec<VerificationTicket>>>>,
}

impl FakeAccountsNotifier {
    pub fn new() -> Self {
        Self {
            verification_tickets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[allow(dead_code)]
    pub fn get_account_tickets(&self, email: &str) -> Vec<VerificationTicket> {
        let lowercase_email = email.to_lowercase();
        let tickets = self.verification_tickets.lock().unwrap();
        tickets.get(&lowercase_email).cloned().unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl AccountsNotifier for FakeAccountsNotifier {
    async fn account_signed_up(&self, account: &Account, ticket: &VerificationTicket) {
        let mut tickets = self.verification_tickets.lock().unwrap();
        tickets
            .entry(account.email.to_string().to_lowercase())
            .or_default()
            .push(ticket.clone());
    }
}
