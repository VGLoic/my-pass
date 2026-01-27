use my_pass::newtypes::Password;
use std::io::{self, Write};

/// Prompt the user to enter a password securely (hidden input)
pub fn prompt_password(prompt: &str) -> anyhow::Result<Password> {
    print!("{}", prompt);
    io::stdout().flush()?;

    let password_str = rpassword::read_password()?;
    if password_str.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }

    Password::new(&password_str).map_err(|e| anyhow::anyhow!("Invalid password: {:?}", e))
}
