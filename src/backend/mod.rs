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
use crate::backend::db::VaultEntry;

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

    pub fn handle_register(&self, user: &str, pass: &SecretString) -> Result<String, VaultError> {
        let salt = crypto::generate_random_bytes::<12>();

        let p_len = pass.expose_secret().len();

        if pass.expose_secret().trim().is_empty() {
            return Err(VaultError::InvalidInput(
                "Blank passwords are not allowed".into(),
            ));
        }

        #[cfg(debug_assertions)]
        {
            if p_len < 2 {
                return Err(VaultError::InvalidInput(
                    "Test password should still be over 2 char idiot".into(),
                ));
            }
        }

        #[cfg(not(debug_assertions))]
        {
            if p_len < 12 {
                return Err(VaultError::InvalidInput(
                    "password must be 12 char or more".into(),
                ));
            }
        }

        let keys = crypto::derive_keys(pass, salt.as_slice())?;

        let save_user =
            db::save_new_user(&self.auth_db, user, &salt, keys.k_storage.expose_secret());

        if let Err(e) = save_user {
            if e.to_string().contains("UNIQUE constraint failed") {
                return Err(VaultError::UserExists);
            }
            return Err(e);
        }
        Ok("Registration complete please login to start using the vault.".to_string())
    }

    pub fn handle_login(&mut self, user: &str, pass: &SecretString) -> Result<(), VaultError> {
        let (salt, stored_auth_key) = db::get_user_auth_key(&self.auth_db, user)?;

        let mut keys = crypto::derive_keys(pass, &salt)?;

        if !crypto::verify_k_storage(keys.k_storage.expose_secret(), &stored_auth_key) {
            return Err(VaultError::AuthFailure);
        }

        if !crypto::verify_internal_handshake(&keys.k_auth, &salt, user) {
            return Err(VaultError::AuthFailure);
        }

        let owner_hash = crypto::obfuscate_data(&keys.search_key, user, "owner");

        keys.owner_id = Some(SecretString::from(owner_hash));

        self.active_session = Some(crypto::SessionKeys::from(keys));
        Ok(())
    }

    pub fn handle_store(
        &mut self,
        service_name: &str,
        user: &str,
        pass: &SecretString,
    ) -> Result<String, VaultError> {
        let keys = self
            .active_session
            .as_ref()
            .ok_or(VaultError::AuthFailure)?;

        let owner_id = keys.owner_id.expose_secret();

        let service_name_hash = crypto::obfuscate_data(&keys.search_key, service_name, "service");

        let username_hash = crypto::obfuscate_data(&keys.search_key, user, "account");

        let secret_dek = crypto::generate_secret_dek()?;

        let payload_nonce = crypto::generate_random_bytes::<12>();

        let dek_nonce_bytes = crypto::generate_random_bytes::<12>();

        let encrypted_payload = crypto::encrypt_payload(pass, &payload_nonce, &secret_dek)?;

        let wrapped_dek = crypto::encrypt_dek(&secret_dek, &keys.kek, &dek_nonce_bytes)?;

        let entry = VaultEntry {
            id: None,
            owner_id: owner_id.to_string(),
            service_name: service_name_hash,
            username: username_hash,
            ciphertext: encrypted_payload,
            payload_nonce,
            wrapped_dek,
            dek_nonce: dek_nonce_bytes,
        };

        if let Err(e) = db::store_secret(&self.vault_db, entry) {
            if e.to_string().contains("UNIQUE constraint failed") {
                return Err(VaultError::EntryAlreadyExists);
            }
            return Err(e);
        }

        Ok(format!(
            "Successfully entered credentials for {}",
            service_name
        ))
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
        let owner_id_hash = keys.owner_id.expose_secret();
        let service_name_hash = crypto::obfuscate_data(&keys.search_key, service_name, "service");
        let username_hash = crypto::obfuscate_data(&keys.search_key, username, "account");
        let entry = db::get_secret(
            &self.vault_db,
            owner_id_hash,
            &service_name_hash,
            &username_hash,
        )?;
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
