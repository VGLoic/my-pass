use my_pass::{
    config::Config,
    domains::accounts::{
        models::{Account, VerificationTicket},
        notifier::AccountsNotifier,
    },
    httpserver::serve_http_server,
    newtypes::Opaque,
    secrets::{SecretKey, SecretsManager, SecretsManagerError},
};
use sqlx::postgres::PgPoolOptions;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::{Level, error, level_filters::LevelFilter};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

pub mod cli;

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
    }
}

#[allow(dead_code)]
pub fn default_test_secrets_manager() -> FakeSecretsManager {
    let mut secrets = HashMap::new();
    secrets.insert(
        SecretKey::DatabaseUrl,
        "postgresql://admin:admin@localhost:5433/mypass"
            .to_string()
            .into(),
    );
    secrets.insert(
        SecretKey::JwtSecret,
        "my_jwt_secret_for_tests_only".to_string().into(),
    );

    FakeSecretsManager { secrets }
}

pub async fn setup_instance(
    config: Config,
    secrets_manager: impl SecretsManager,
) -> Result<InstanceState, anyhow::Error> {
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer().with_filter(LevelFilter::from_level(config.log_level)),
        )
        .try_init();

    let pool = match PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(
            secrets_manager
                .get(SecretKey::DatabaseUrl)
                .map_err(|e| {
                    anyhow::anyhow!("{e}")
                        .context("Failed to get database URL from secrets manager")
                })?
                .unsafe_inner(),
        )
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
        my_pass::domains::accounts::repository::PsqlAccountsRepository::new(pool.clone());
    let accounts_notifier = FakeAccountsNotifier::new();
    let accounts_service = my_pass::domains::accounts::service::DefaultAccountsService::new(
        accounts_repository,
        accounts_notifier.clone(),
    );

    let items_repository = my_pass::domains::items::repository::PsqlItemsRepository::new(pool);
    let items_notifier = my_pass::domains::items::notifier::DummyItemsNotifier;
    let items_service = my_pass::domains::items::service::DefaultItemsService::new(
        items_repository,
        items_notifier,
    );

    let listener = if config.port == 0 {
        bind_listener_to_free_port().await?
    } else {
        let addr = SocketAddr::from(([127, 0, 0, 1], config.port));
        tokio::net::TcpListener::bind(&addr).await.map_err(|err| {
            anyhow::anyhow!("Failed to bind the TCP listener to address {addr}: {err}")
        })?
    };

    let server_url = format!(
        "http://{}:{}",
        listener.local_addr().unwrap().ip(),
        listener.local_addr().unwrap().port()
    );

    tokio::spawn(async move {
        serve_http_server(listener, secrets_manager, accounts_service, items_service)
            .await
            .unwrap()
    });

    Ok(InstanceState {
        server_url,
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

pub struct FakeSecretsManager {
    secrets: HashMap<SecretKey, Opaque<String>>,
}

impl SecretsManager for FakeSecretsManager {
    fn get(&self, k: SecretKey) -> Result<Opaque<String>, SecretsManagerError> {
        self.secrets
            .get(&k)
            .cloned()
            .ok_or(SecretsManagerError::NotFound)
    }
}

#[derive(Clone, Debug)]
pub enum Notification {
    VerificationTicket(VerificationTicket),
    Login(Account),
    AccountVerified {
        account: Account,
        ticket: VerificationTicket,
    },
}

/// Fake accounts notifier for tests
/// It stores the notifications in memory for later inspection
/// It implements the `AccountsNotifier` trait
#[derive(Clone)]
pub struct FakeAccountsNotifier {
    pub notifications: Arc<Mutex<HashMap<String, Vec<Notification>>>>,
}

impl FakeAccountsNotifier {
    pub fn new() -> Self {
        Self {
            notifications: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_account_notifications(&self, email: &str) -> Vec<Notification> {
        let lowercase_email = email.to_lowercase();
        let notifications = self.notifications.lock().unwrap();
        notifications
            .get(&lowercase_email)
            .cloned()
            .unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn get_verified_tickets(&self, email: &str) -> Vec<(Account, VerificationTicket)> {
        let notifications = self.get_account_notifications(email);
        notifications
            .into_iter()
            .filter_map(|notification| match notification {
                Notification::AccountVerified { account, ticket } => Some((account, ticket)),
                _ => None,
            })
            .collect()
    }

    #[allow(dead_code)]
    pub fn get_signed_up_tickets(&self, email: &str) -> Vec<VerificationTicket> {
        let notifications = self.get_account_notifications(email);
        notifications
            .into_iter()
            .filter_map(|notification| match notification {
                Notification::VerificationTicket(ticket) => Some(ticket),
                _ => None,
            })
            .collect()
    }

    #[allow(dead_code)]
    pub fn get_logins(&self, email: &str) -> Vec<Account> {
        let notifications = self.get_account_notifications(email);
        notifications
            .into_iter()
            .filter_map(|notification| match notification {
                Notification::Login(account) => Some(account),
                _ => None,
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl AccountsNotifier for FakeAccountsNotifier {
    async fn account_signed_up(&self, account: &Account, ticket: &VerificationTicket) {
        let mut notifications = self.notifications.lock().unwrap();
        notifications
            .entry(account.email.to_string().to_lowercase())
            .or_default()
            .push(Notification::VerificationTicket(ticket.clone()));
    }

    async fn account_verified(&self, account: &Account, ticket: &VerificationTicket) {
        let mut notifications = self.notifications.lock().unwrap();
        notifications
            .entry(account.email.to_string().to_lowercase())
            .or_default()
            .push(Notification::AccountVerified {
                account: account.clone(),
                ticket: ticket.clone(),
            });
    }

    async fn account_logged_in(&self, account: &Account) {
        let mut notifications = self.notifications.lock().unwrap();
        notifications
            .entry(account.email.to_string().to_lowercase())
            .or_default()
            .push(Notification::Login(account.clone()));
    }

    async fn new_verification_ticket_created(
        &self,
        account: &Account,
        ticket: &VerificationTicket,
    ) {
        let mut notifications = self.notifications.lock().unwrap();
        notifications
            .entry(account.email.to_string().to_lowercase())
            .or_default()
            .push(Notification::VerificationTicket(ticket.clone()));
    }
}
