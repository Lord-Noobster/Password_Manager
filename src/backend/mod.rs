use secrecy::{ExposeSecret, SecretBox, SecretString};

use rusqlite::Connection;

use std::path::Path;

use std::option::Option;

use std::result::Result;

pub mod crypto;

pub mod db;

pub mod error;

pub use error::VaultError;

pub use crypto::VaultKeys;

use crate::backend::crypto::SessionKeys;

pub struct VaultManager {
    auth_db: rusqlite::Connection,
    vault_db: rusqlite::Connection,
    active_session: Option<SessionKeys>, // Vaultkeys is a crypto variable containing a list with the
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
            active_session: None,
        })
    }

    pub fn format_secret_for_print(&self, secret: SecretString) -> String {
        format!("Your password is: {}", secret.expose_secret()) // Need to fix can't have expose in
        // manager was a mistake prob just need to move the function to crypto.rs and call it from
        // there
    }

    pub fn handle_register(&self, user: &str, pass: &SecretString) -> Result<(), VaultError> {
        let salt = crypto::generate_random_bytes::<12>();

        let keys = crypto::derive_keys(pass, salt.as_slice())?;

        db::save_new_user(&self.auth_db, user, &salt, &keys.k_auth)?;
        Ok(())
    }

    pub fn handle_login(&mut self, user: &str, pass: &SecretString) -> Result<(), VaultError> {
        let (salt, stored_auth_key) = db::get_user_auth_key(&self.auth_db, user)?;

        let keys = crypto::derive_keys(pass, &salt)?;

        if crypto::verify_k_auth(&keys.k_auth, &stored_auth_key) {
            self.active_session = Some(crypto::SessionKeys::from(keys));
            Ok(())
        } else {
            Err(VaultError::AuthFailure)
        }
    }

    pub fn handle_store(
        &mut self,
        service_name: &str,
        user: &str,
        pass: &SecretString,
    ) -> Result<(), VaultError> {
        let keys = self
            .active_session
            .as_ref()
            .ok_or(VaultError::AuthFailure)?;
        let secret_dek = crypto::generate_secret_dek()?;

        let payload_nonce = crypto::generate_random_bytes::<12>();

        let dek_nonce_bytes = crypto::generate_random_bytes::<12>();

        let encrypted_payload = crypto::encrypt_payload(pass, &payload_nonce, &secret_dek)?;

        let wrapped_dek = crypto::encrypt_dek(&secret_dek, &keys.kek, &dek_nonce_bytes)?;

        db::store_secret(
            &self.vault_db,
            service_name,
            user,
            encrypted_payload,
            &payload_nonce,
            wrapped_dek,
            &dek_nonce_bytes,
        )?;
        Ok(())
    }

    pub fn handle_retrieve(
        &self,
        service_name: &str,
        username: &str,
    ) -> Result<SecretString, VaultError> {
        let keys = self
            .active_session
            .as_ref()
            .ok_or(VaultError::AuthFailure)?;
        let entry = db::get_secret(&self.vault_db, service_name, username)?;
        let secret_dek = crypto::decrypt_dek(&entry.wrapped_dek, &keys.kek, &entry.dek_nonce)?;
        let secret_password =
            crypto::decrypt_payload(&entry.ciphertext, &entry.payload_nonce, &secret_dek)?;

        Ok(secret_password)
    }
    // logout function should ensure that the active_keys are dropped
    pub fn logout(&mut self) {
        self.active_session = None;
    }
}
