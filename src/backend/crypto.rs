// Cryptography module KDF derives, encryption and decryption goes here

use std::convert::TryFrom;

use std::pin::Pin;

use sha2::Sha256;

use subtle::ConstantTimeEq;

use hkdf::Hkdf;
use zeroize::{Zeroize, ZeroizeOnDrop};

use secrecy::{ExposeSecret, SecretString};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
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

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub kek: [u8; 32],
    pub search_key: [u8; 32],
}

//ensures that k_auth is zeroized when its no longer needed
impl From<VaultKeys> for SessionKeys {
    fn from(vk: VaultKeys) -> Self {
        Self {
            kek: vk.kek,
            search_key: vk.search_key,
        }
    }
}

pub fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
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

pub fn verify_k_auth(attempted: &[u8], stored: &[u8]) -> bool {
    if attempted.len() != stored.len() {
        return false;
    }

    attempted.ct_eq(stored).into()
}

pub fn encrypt_payload(
    pass: &SecretString,
    nonce_bytes: &[u8; 12],
    dek: &[u8; 32],
) -> Result<Vec<u8>, VaultError> {
    let key = Key::<Aes256Gcm>::from_slice(dek);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, pass.expose_secret().as_bytes())
        .map_err(|e| VaultError::CryptoError(format!("Password encryption failed: {}", e)))?;
    Ok(ciphertext)
}

pub fn decrypt_payload(
    ciphertext: &Vec<u8>,
    nonce_bytes: &[u8; 12],
    dek: &SecretString,
) -> Result<SecretString, VaultError> {
    let key = Key::<Aes256Gcm>::from_slice(dek.expose_secret().as_bytes());
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(key);

    let decrypted_password_bytes = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|e| VaultError::CryptoError(format!("Decyption failed {}", e)))?;

    let decrypted_password_str = String::from_utf8(decrypted_password_bytes)
        .map_err(|_| VaultError::CryptoError("Invalid UTF-8".into()))?;
    Ok(SecretString::from(decrypted_password_str))
}
