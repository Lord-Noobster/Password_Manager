// Cryptography module KDF derives, encryption and decryption goes here

use std::{convert::TryFrom, os::linux::raw}; // Depreciated

use std::pin::Pin; // pin variables to memory adresses

use digest::KeyInit;
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

use sha2::Sha256;

use subtle::ConstantTimeEq;

use hkdf::Hkdf;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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
    pub k_auth: Option<SecretBox<[u8; 32]>>,
    pub kek: Option<SecretBox<[u8; 32]>>,
    pub search_key: Option<SecretBox<[u8; 32]>>,
    pub owner_id: Option<SecretBox<[u8; 32]>>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub kek: SecretBox<[u8; 32]>,
    pub search_key: SecretBox<[u8; 32]>,
    pub owner_id: SecretBox<[u8; 32]>,
}

//ensures that k_auth is zeroized when its no longer needed
impl TryFrom<VaultKeys> for SessionKeys {
    type Error = VaultError;

    #[inline(never)]
    fn try_from(mut vk: VaultKeys) -> Result<Self, Self::Error> {
        let k_auth = vk.k_auth.take();

        let kek = vk.kek.take().ok_or_else(|| {
            VaultError::CryptoError("KEK missing under session conversion".into())
        })?;

        let search_key = vk.search_key.take().ok_or_else(|| {
            VaultError::CryptoError("Search key missing under session conversion".into())
        })?;

        let owner_id = vk.owner_id.take().ok_or_else(|| {
            VaultError::CryptoError("Owner id missing under session conversion".into())
        })?;

        Ok(Self {
            kek,
            search_key,
            owner_id,
        })
    }
}

pub fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn obfuscate_data(
    key: &SecretBox<[u8; 32]>,
    data: &str,
    domain_tag: &str,
    context: &str,
) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key.expose_secret())
        .expect("HMAC-SHA256 accepts 32-byte keys");

    mac.update(domain_tag.as_bytes());
    mac.update(context.as_bytes());
    mac.update(data.as_bytes());

    let mut output = Zeroizing::new([0u8; 32]);
    output.copy_from_slice(mac.finalize().into_bytes().as_slice());

    *output
}

pub fn generate_secret_dek() -> Result<SecretBox<[u8; 32]>, VaultError> {
    let mut raw_bytes = zeroize::Zeroizing::new(generate_random_bytes::<32>());

    let secret_dek = SecretBox::new(Box::new(*raw_bytes));

    Ok(secret_dek)
}

pub fn derive_keys(pass: &SecretString, salt: &[u8]) -> Result<VaultKeys, VaultError> {
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e: argon2::password_hash::Error| VaultError::Argon2Error(e.to_string()))?;
    let argon2_params = argon2::Params::new(
        16384, // Memory for testing 16MB prod should be 64MB
        3,     // Iterations TIme cost prod >3
        1,     // parallelization >4
        None,  // output lenght just standard
    )
    .map_err(|e| VaultError::Argon2Error(format!("Argon2 params invalid: {}", e)))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );

    let argon2_output = argon2
        .hash_password(pass.expose_secret().as_bytes(), &salt_string)
        .map_err(|e| VaultError::Argon2Error(e.to_string()))?
        .hash
        .ok_or_else(|| VaultError::CryptoError("No hash output from Argon2".into()))?;

    let master_hash = zeroize::Zeroizing::new(argon2_output.as_bytes().to_vec());

    let hk = Hkdf::<Sha256>::new(None, master_hash.as_ref());

    let mut k_auth_raw = zeroize::Zeroizing::new([0u8; 32]);
    let mut kek_raw = zeroize::Zeroizing::new([0u8; 32]);
    let mut search_raw = zeroize::Zeroizing::new([0u8; 32]);
    let mut owner_id_raw = zeroize::Zeroizing::new([0u8; 32]);

    // Generate independent sub keys to ensure that if one is compromised it wont affect the
    // others.
    hk.expand(b"vault auth key", &mut *k_auth_raw)
        .map_err(|_| VaultError::CryptoError("HKDF k_auth expansion failed".to_string()))?;

    hk.expand(b"vault encryption key", &mut *kek_raw)
        .map_err(|_| VaultError::CryptoError("HKDF kek expansion failed".to_string()))?;

    hk.expand(b"owner_id obfuscation", &mut *owner_id_raw)
        .map_err(|_| VaultError::CryptoError("HKDF owner_id expansion failed".to_string()))?;

    hk.expand(b"vault search key", &mut *search_raw)
        .map_err(|_| VaultError::CryptoError("HKDF search:key expansion failed".to_string()))?;

    let k_auth = SecretBox::new(Box::new(*k_auth_raw));
    let kek = SecretBox::new(Box::new(*kek_raw));
    let search_key = SecretBox::new(Box::new(*search_raw));
    let owner_id = SecretBox::new(Box::new(*owner_id_raw));

    let keys = VaultKeys {
        k_auth: Some(k_auth),
        kek: Some(kek),
        search_key: Some(search_key),
        owner_id: Some(owner_id),
    };

    Ok(keys)
}

pub fn generate_registration_tag(
    k_auth: &SecretBox<[u8; 32]>,
    salt: &[u8],
    username: &str,
) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(k_auth.expose_secret())
        .unwrap_or_else(|_| unreachable!("k_auth is guaranteed 32 bytes"));

    let salt_len_bytes = (salt.len() as u64).to_le_bytes();
    mac.update(&salt_len_bytes);
    mac.update(salt);

    let username_len_bytes = (username.len() as u64).to_le_bytes();
    mac.update(&username_len_bytes);
    mac.update(username.as_bytes());

    mac.update(b"registration_handshake_temp");

    let mut tag = zeroize::Zeroizing::new([0u8; 32]);
    tag.copy_from_slice(mac.finalize().into_bytes().as_slice());
    *tag
}

pub fn calculate_challenge_response(
    k_auth: &SecretBox<[u8; 32]>,
    challenge: &[u8; 32],
) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(k_auth.expose_secret()).unwrap();
    mac.update(challenge);
    mac.update(b"login_challenge_temp");

    let mut response = [0u8; 32];
    response.copy_from_slice(mac.finalize().into_bytes().as_slice());
    response
}

pub fn verify_hmac_challenge(
    k_auth: &SecretBox<[u8; 32]>,
    challenge: &[u8; 32],
    client_response: &[u8; 32],
    stored_verification_tag: &[u8; 32],
    salt: &[u8],
    username: &str,
) -> bool {
    let current_reg_tag = generate_registration_tag(k_auth, salt, username);
    let password_ok = current_reg_tag.ct_eq(stored_verification_tag);

    let expected_response = calculate_challenge_response(k_auth, challenge);
    let challenge_ok = client_response.ct_eq(&expected_response);

    (password_ok & challenge_ok).into()
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

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretBox;

    #[test]
    fn test_keys_lifecycle_and_zeroize() {
        // 1. Create VaultKeys simulating a login
        let vk = VaultKeys {
            k_auth: Some(SecretBox::new(Box::new([2u8; 32]))),
            kek: Some(SecretBox::new(Box::new([3u8; 32]))),
            search_key: Some(SecretBox::new(Box::new([4u8; 32]))),
            owner_id: Some(SecretBox::new(Box::new([5u8; 32]))),
        };

        // 2. Transition to SessionKeys
        let sk = SessionKeys::from(vk);

        // 3. Verify logic: sk should have the keys, vk is dropped
        assert_eq!(sk.owner_id.expose_secret(), "owner");

        // 4. Explicitly drop the session
        drop(sk);
    }
}
