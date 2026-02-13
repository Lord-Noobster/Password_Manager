// Cryptography module KDF derives, encryption and decryption goes here

use std::mem::ManuallyDrop;

use std::{convert::TryFrom, os::linux::raw};

use std::pin::Pin;

use digest::KeyInit;
use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;

use sha2::Sha256;

use subtle::ConstantTimeEq;

use hkdf::Hkdf;
use zeroize::{Zeroize, ZeroizeOnDrop};

use secrecy::{ExposeSecret, SecretBox, SecretString};

use aes_gcm::{Aes256Gcm, Key, Nonce, aead::Aead};

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
    pub k_storage: Option<SecretBox<[u8; 32]>>,
    pub k_auth: Option<SecretBox<[u8; 32]>>,
    pub kek: Option<SecretBox<[u8; 32]>>,
    pub search_key: Option<SecretBox<[u8; 32]>>,
    pub owner_id: Option<SecretString>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub kek: SecretBox<[u8; 32]>,
    pub search_key: SecretBox<[u8; 32]>,
    pub owner_id: SecretString,
}

//ensures that k_auth is zeroized when its no longer needed
impl From<VaultKeys> for SessionKeys {
    fn from(mut vk: VaultKeys) -> Self {
        if let Some(mut k) = vk.k_storage.take() {
            k.zeroize();
        }
        if let Some(mut k) = vk.k_auth.take() {
            k.zeroize();
        }

        let kek = vk.kek.take().expect("KEK missing");
        let search_key = vk.search_key.take().expect("Search key missing");
        let owner_id = vk.owner_id.take().expect("Owner ID missing");
        Self {
            kek,
            search_key,
            owner_id,
        }
    }
}

pub fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn obfuscate_data(search_key: &SecretBox<[u8; 32]>, data: &str, domain_tag: &str) -> String {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(search_key.expose_secret())
        .expect("HMAC-SHA256 accepts 32-byte keys");

    mac.update(domain_tag.as_bytes());
    mac.update(data.as_bytes());

    format!("{:x}", mac.finalize().into_bytes())
}

pub fn generate_secret_dek() -> Result<SecretBox<[u8; 32]>, VaultError> {
    let secret_dek = SecretBox::new(Box::new(generate_random_bytes::<32>()));

    Ok(secret_dek)
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

    let mut k_storage_raw = [0u8; 32];
    let mut k_auth_raw = [0u8; 32];
    let mut kek_raw = [0u8; 32];
    let mut search_raw = [0u8; 32];

    hk.expand(b"storage_verifier", &mut k_storage_raw)
        .map_err(|_| VaultError::CryptoError("HKDF k_storage expansion failed".to_string()))?;

    hk.expand(b"vault auth key", &mut k_auth_raw)
        .map_err(|_| VaultError::CryptoError("HKDF k_auth expansion failed".to_string()))?;

    hk.expand(b"vault encryption key", &mut kek_raw)
        .map_err(|_| VaultError::CryptoError("HKDF kek expansion failed".to_string()))?;
    hk.expand(b"vault search key", &mut search_raw)
        .map_err(|_| VaultError::CryptoError("HKDF search:key expansion failed".to_string()))?;

    let k_storage = SecretBox::new(Box::new(k_storage_raw));
    let k_auth = SecretBox::new(Box::new(k_auth_raw));
    let kek = SecretBox::new(Box::new(kek_raw));
    let search_key = SecretBox::new(Box::new(search_raw));

    let keys = VaultKeys {
        k_storage: Some(k_storage),
        k_auth: Some(k_auth),
        kek: Some(kek),
        search_key: Some(search_key),
        owner_id: None,
    };

    Ok(keys)
}

pub fn verify_k_storage(attempted: &[u8], stored: &[u8]) -> bool {
    if attempted.len() != stored.len() {
        //still run the check on it self to keep constant time even on a fail
        attempted.ct_eq(attempted);
        return false;
    }

    attempted.ct_eq(stored).into()
}

pub fn verify_internal_handshake(
    k_auth: &SecretBox<[u8; 32]>,
    salt: &[u8],
    username: &str,
) -> bool {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(k_auth.expose_secret())
        .expect("HMAC-SHA256 accepts 32-byte keys");

    mac.update(salt);
    mac.update(username.as_bytes());

    mac.update(b"internal_handshake_v1");

    let result = mac.finalize().into_bytes();

    !result.iter().all(|&x| x == 0)
}

pub fn encrypt_payload(
    pass: &SecretString,
    nonce_bytes: &[u8; 12],
    dek: &SecretBox<[u8; 32]>,
) -> Result<Vec<u8>, VaultError> {
    let key = Key::<Aes256Gcm>::from_slice(dek.expose_secret());
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
    dek: &SecretBox<[u8; 32]>,
) -> Result<SecretString, VaultError> {
    let key = Key::<Aes256Gcm>::from_slice(dek.expose_secret());
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(key);

    let decrypted_password_bytes = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| VaultError::CryptoError(format!("Decyption failed {}", e)))?;

    let decrypted_password_str = String::from_utf8(decrypted_password_bytes)
        .map_err(|_| VaultError::CryptoError("Invalid UTF-8".into()))?;
    Ok(SecretString::from(decrypted_password_str))
}

pub fn encrypt_dek(
    secret_dek: &SecretBox<[u8; 32]>,
    secret_kek: &SecretBox<[u8; 32]>,
    dek_nonce_bytes: &[u8; 12],
) -> Result<Vec<u8>, VaultError> {
    let key = Key::<Aes256Gcm>::from_slice(secret_kek.expose_secret());
    let nonce = Nonce::from_slice(dek_nonce_bytes);
    let cipher = Aes256Gcm::new(key);
    let cipher_dek = cipher
        .encrypt(nonce, secret_dek.expose_secret().as_ref())
        .map_err(|e| VaultError::CryptoError(format!("DEK encryption failed: {}", e)))?;
    Ok(cipher_dek)
}

pub fn decrypt_dek(
    cipher_dek: &Vec<u8>,
    secret_kek: &SecretBox<[u8; 32]>,
    dek_nonce_bytes: &[u8; 12],
) -> Result<SecretBox<[u8; 32]>, VaultError> {
    let key = Key::<Aes256Gcm>::from_slice(secret_kek.expose_secret());
    let nonce = Nonce::from_slice(dek_nonce_bytes);
    let cipher = Aes256Gcm::new(key);
    let raw_dek_vec: Vec<u8> = cipher
        .decrypt(nonce, cipher_dek.as_ref())
        .map_err(|e| VaultError::CryptoError(format!("DEK decryption failed: {}", e)))?;

    let dek_array: [u8; 32] = raw_dek_vec
        .try_into()
        .map_err(|_| VaultError::CryptoError("Corrupt DEK length".into()))?;
    let secret_dek = SecretBox::new(Box::new(dek_array));
    Ok(secret_dek)
}
