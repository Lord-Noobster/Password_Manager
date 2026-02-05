use thiserror::Error;

#[derive(Error, Debug)]

pub enum VaultError {
    #[error("Database error: {0}")]
    SqliteError(#[from] rusqlite::Error),

    #[error("Argon2 error: {0}")]
    Argon2Error(String),

    #[error("General Crypto error: {0}")]
    CryptoError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Authentication failed: Invalid Username or Password")]
    AuthFailure,

    #[error("Data corruption detected: {0}")]
    IntegrityError(String),

    #[error("User already exists")]
    UserExists,

    #[error("An entry for this service and username already exists")]
    EntryAlreadyExists,

    #[error("Invalid Input. {0}")]
    InvalidInput(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Password not found")]
    EntryNotFound,

    #[error("Input error: {0}")]
    UiError(#[from] inquire::InquireError),
}
