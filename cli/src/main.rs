use clap::{Parser, Subcommand};

mod config;
mod output;
mod password;

use config::Config;
use output::Output;

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
async fn main() -> anyhow::Result<()> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let config = Config::from_env();
    let output = Output::new(cli.json);
    let _ = config.server_url();

    let result: anyhow::Result<()> = match cli.command {
        Commands::Account(account_cmd) => match account_cmd {
            AccountCommands::Signup { email } => {
                let _config = &config;
                let _output = &output;
                println!("Signup command: {}", email);
                println!("Not yet implemented");
                Ok(())
            }
            AccountCommands::Verify { email, token } => {
                println!("Verify command: {} {}", email, token);
                println!("Not yet implemented");
                Ok(())
            }
            AccountCommands::Login { email } => {
                println!("Login command: {}", email);
                println!("Not yet implemented");
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
        let cli_error = output::CliError::from(e);
        output.error(&cli_error);
        std::process::exit(1);
    }

    Ok(())
}
