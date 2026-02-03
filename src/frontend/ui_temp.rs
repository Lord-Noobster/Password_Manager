//this is a temp ui file so that i can interact with the backend

use inquire::{Password, Text, validator::Validation};

use secrecy::{ExposeSecret, SecretString};

use crate::backend::VaultError;

pub fn prompt_registration() -> Result<(String, SecretString), VaultError> {
    let username = Text::new("Choose a Username:").prompt()?;
    // build manual password validator the build in confirmation will loop for ever if passwords
    // don't match
    let pass_raw = Password::new("Choose your Master Password:")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .prompt()?;

    Ok((username, SecretString::from(pass_raw)))
}

pub fn prompt_login() -> Result<(String, SecretString), VaultError> {
    let username = Text::new("Username:").prompt()?;

    let pass_raw = Password::new("Master Password:")
        .without_confirmation()
        .prompt()?;

    Ok((username, SecretString::from(pass_raw)))
}

pub fn prompt_store() -> Result<(String, String, SecretString), VaultError> {
    let service_name = Text::new("Service:")
        .with_validator(|input: &str| {
            if input.trim().is_empty() {
                Ok(Validation::Invalid("Field cannot be blank".into()))
            } else {
                Ok(Validation::Valid)
            }
        })
        .prompt()?;

    let username = Text::new("Username or Email:").prompt()?;

    let pass_raw = Password::new("Password:").prompt()?;

    Ok((service_name, username, SecretString::from(pass_raw)))
}

pub fn prompt_retrieve() -> Result<(String, String), VaultError> {
    let service_name = Text::new("Service:").prompt()?;

    let username = Text::new("Username or Email:").prompt()?;

    Ok((service_name, username))
}
