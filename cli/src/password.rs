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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_wrapping() {
        // Test that valid passwords can be wrapped
        let valid_password = "ValidP@ss123!!";
        let result = Password::new(valid_password);
        assert!(result.is_ok());
    }
}
