use secrecy::SecretString;

use rusqlite::Connection;

use std::path::Path;

use std::option::Option;

use std::result::Result;

pub mod crypto;

pub mod db;

pub mod error;

pub use error::VaultError;

pub use crypto::VaultKeys;

pub struct VaultManager {
    auth_db: rusqlite::Connection,
    vault_db: rusqlite::Connection,
    active_keys: Option<VaultKeys>, // Vaultkeys is a crypto variable containing a list with the
                                    // KEK and Search_key
}

impl VaultManager {
    pub fn init(auth_path: &Path, vault_path: &Path) -> Result<Self, VaultError> {
        let auth_conn = db::init_auth_db(auth_path)?;
        let vault_conn = db::init_vault_db(vault_path)?;

        Ok(Self {
            auth_db: auth_conn,
            vault_db: vault_conn,
            active_keys: None,
        })
    }

    pub fn handle_register(&self, user: &str, pass: &SecretString) -> Result<(), VaultError> {
        let salt = crypto::generate_random_salt();

        let keys = crypto::derive_keys(pass, salt.as_slice())?;

        db::save_new_user(&self.auth_db, user, &salt, &keys.k_auth)?;
        Ok(())
    }

    pub fn handle_login(&self, user: &str, pass: &SecretString) -> Result<(), VaultError> {
        // 1. db query username, fetch auth_hash and salt
        // 2. crypto pass auth_hash and salt to crypto derive hash from login password + salt and verify
        //    against auth_hash if it clears derive KEK and Search_key
        Ok(())
    }
}
