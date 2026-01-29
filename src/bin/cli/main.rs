use anyhow::anyhow;
use clap::{Parser, Subcommand};
use my_pass::cli::{client::CliClient, config::Config, tokenstore::KeyringTokenStore};
use my_pass::newtypes::{Email, EmailError};

mod output;
use output::{CliError, Output};
mod password;
use password::prompt_password;

#[derive(Parser)]
#[command(name = "mypass")]
#[command(about = "A secure password manager CLI", long_about = None)]
#[command(version)]
struct Cli {
    /// Output results in JSON format
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Account management commands
    #[command(subcommand)]
    Account(AccountCommands),

    /// Vault item management commands
    #[command(subcommand)]
    Item(ItemCommands),
}

#[derive(Subcommand)]
enum AccountCommands {
    /// Create a new account
    Signup {
        /// Email address
        #[arg(short, long)]
        email: String,
    },

    /// Verify account with token from email
    Verify {
        /// Email address
        #[arg(short, long)]
        email: String,

        /// Verification token
        #[arg(short, long)]
        token: String,
    },

    /// Login to your account
    Login {
        /// Email address
        #[arg(short, long)]
        email: String,
    },

    /// Request a new verification email
    RequestVerification {
        /// Email address
        #[arg(short, long)]
        email: String,
    },

    /// Get current account information
    Me,
}

#[derive(Subcommand)]
enum ItemCommands {
    /// Add a new vault item (reads JSON from stdin)
    Add,

    /// List all vault items
    List,

    /// Get a specific vault item by ID
    Get {
        /// Item ID
        id: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let config = Config::from_env();
    let output = Output::new(cli.json);
    let tokens = KeyringTokenStore;
    let cli_client = CliClient::new(&config, tokens)?;

    let result: Result<(), CliError> = match cli.command {
        Commands::Account(account_cmd) => match account_cmd {
            AccountCommands::Signup { email } => {
                let email = parse_email(&email)?;
                let password = prompt_password("Password: ")?;
                cli_client.signup(email, password).await?;
                output.success(&"Signup successful. Check your email for the verification token.");
                Ok(())
            }
            AccountCommands::Verify { email, token } => {
                let email = parse_email(&email)?;
                cli_client.verify(email, token).await?;
                output.success(&"Verification successful. You can now log in.");
                Ok(())
            }
            AccountCommands::Login { email } => {
                let email = parse_email(&email)?;
                let password = prompt_password("Password: ")?;
                cli_client.login(email, password).await?;
                output.success(&"Login successful. Your session is now stored securely.");
                Ok(())
            }
            AccountCommands::RequestVerification { email } => {
                println!("Request verification command: {}", email);
                println!("Not yet implemented");
                Ok(())
            }
            AccountCommands::Me => {
                println!("Me command");
                println!("Not yet implemented");
                Ok(())
            }
        },
        Commands::Item(item_cmd) => match item_cmd {
            ItemCommands::Add => {
                println!("Add command");
                println!("Not yet implemented");
                Ok(())
            }
            ItemCommands::List => {
                println!("List command");
                println!("Not yet implemented");
                Ok(())
            }
            ItemCommands::Get { id } => {
                println!("Get command: {}", id);
                println!("Not yet implemented");
                Ok(())
            }
        },
    };

    if let Err(e) = result {
        output.error(&e);
        std::process::exit(1);
    }

    Ok(())
}

fn parse_email(raw: &str) -> Result<Email, CliError> {
    Email::new(raw)
        .map_err(|e| match e {
            EmailError::Empty => anyhow!("Email cannot be empty"),
            EmailError::InvalidFormat => anyhow!("Email format is invalid"),
        })
        .map_err(CliError::from)
}
