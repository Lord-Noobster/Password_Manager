use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, SaltString, rand_core::OsRng},
};

use secrecy::{ExposeSecret, SecretString};

use hkdf::Hkdf;

use sha2::Sha256;

fn main() {
    let password = SecretString::from("validcomplexpassword".to_string());

    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .expect("KDF failed");

    let master_seed = hash.hash.expect("No hash output");

    println!(
        "Success! Master Seed (Hex) is: {:02x?}",
        master_seed.as_ref()
    );
    println!("Master Seed length {} bytes", master_seed.as_bytes().len());

    let hk = Hkdf::<Sha256>::new(None, master_seed.as_ref());

    let mut k_auth = [0u8; 32];
    let mut kek = [0u8; 32];
    let mut search_key = [0u8; 32];

    hk.expand(b"Authentication-v1", &mut k_auth)
        .expect("HKDF expansion for k_auth failed");

    hk.expand(b"encryption-v1", &mut kek)
        .expect("HKDF expansion for KEK failed");

    hk.expand(b"searching-v1", &mut search_key)
        .expect("HKDF expansion for Search_key failed");

    println!("---Derived Keys---");
    println!("k_auth (first 8 bytes): {:02x?}", &k_auth[..8]);
    println!("KEK (first 8 bytes): {:02x?}", &kek[..8]);
    println!("Search (first 8 bytes): {:02x?}", &search_key[..8]);
    println!("KEK: {:02x?}", &kek)
}
