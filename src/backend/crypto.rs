// Cryptography module KDF derives, encryption and decryption goes here

use std::convert::TryFrom;

use std::pin::Pin;

use sha2::Sha256;

use hkdf::Hkdf;
use zeroize::{Zeroize, ZeroizeOnDrop};

use secrecy::{ExposeSecret, SecretString};

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit},
};

use argon2::{
    Argon2,
    password_hash::{
        PasswordHash, PasswordHasher, SaltString, rand_core::OsRng, rand_core::RngCore,
    },
};

// local error handling
use crate::backend::VaultError;

//should ensure that when the variables fall out of scope they will be zeroize in memory
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKeys {
    pub k_auth: [u8; 32],
    pub kek: [u8; 32],
    pub search_key: [u8; 32],
}

pub fn generate_random_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_keys(pass: &SecretString, salt: &[u8]) -> Result<VaultKeys, VaultError> {
    let password_bytes = pass.expose_secret().as_bytes(); // the pass is now exposed

    let salt = SaltString::encode_b64(salt)
        .map_err(|e: argon2::password_hash::Error| VaultError::Argon2Error(e.to_string()))?;
    // Argon2 flow
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password_bytes, &salt)
        .expect("KDF failed");

    let master_hash = hash.hash.expect("no hash output");

    let hk = Hkdf::<Sha256>::new(None, master_hash.as_ref());

    let mut k_auth = [0u8; 32];
    let mut kek = [0u8; 32];
    let mut search_key = [0u8; 32];

    hk.expand(b"vault auth key", &mut k_auth)
        .map_err(|_| VaultError::CryptoError("HKDF k_auth expansion failed".to_string()))?;

    hk.expand(b"vault encryption key", &mut kek)
        .map_err(|_| VaultError::CryptoError("HKDF kek expansion failed".to_string()))?;
    hk.expand(b"vault search key", &mut search_key)
        .map_err(|_| VaultError::CryptoError("HKDF search:key expansion failed".to_string()))?;

    let keys = VaultKeys {
        k_auth,
        kek,
        search_key,
    };

    Ok(keys)
}

pub fn verify_keys() {}
