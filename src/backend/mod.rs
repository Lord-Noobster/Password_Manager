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
// TODO: (v0.5) Implement Argon2 parameter persistence in DB
// TODO: (v0.5) Sanitize usernames to prevent SQL injection/null-byte attacks
// TODO: (v0.5) Obfuscate AuthFailure to prevent Username Enumeration
// TODO: (v0.6) Implement hardware-backed entropy (USB Key Hardware ID) opt
// TODO: (v0.7) Implement rate-limiting/lockout for failed login attempts
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

    pub fn handle_login(&mut self, user: &str, pass: &SecretString) -> Result<(), VaultError> {
        let (salt, stored_auth_key) = db::get_user_auth_key(&self.auth_db, user)?;

        let keys = crypto::derive_keys(pass, &salt)?;

        if keys.k_auth == stored_auth_key.as_slice() {
            self.active_keys = Some(keys);
            Ok(())
        } else {
            Err(VaultError::AuthFailure)
        }
    }
    // logout function should ensure that the active_keys are dropped
    pub fn logout(&mut self) {
        self.active_keys = None;
    }
}
