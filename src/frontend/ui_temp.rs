//this is a temp ui file so that i can interact with the backend

use inquire::{Password, Text};

use secrecy::{ExposeSecret, SecretString};

use crate::backend::VaultError;

pub fn prompt_registration() -> Result<(String, SecretString), VaultError> {
    let username = Text::new("Choose a Username:").prompt()?;

    let pass_raw = Password::new("Choose your Master Password:")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .prompt()?;

    Ok((username, SecretString::from(pass_raw)))
}

pub fn prompt_login() -> Result<(String, SecretString), VaultError> {
    let username = Text::new("Username:").prompt()?;

    let pass_raw = Password::new("Master Password:").prompt()?;

    Ok((username, SecretString::from(pass_raw)))
}
