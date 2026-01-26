use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, AeadMutInPlace, KeyInit, OsRng},
};

use secrecy::{ExposeSecret, SecretString};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Took the KEK Generated in the argon_test.rs file, but worth noting i had to add 0x to each
    // value
    const MOCK_KEK: [u8; 32] = [
        0xeb, 0x99, 0x99, 0xe2, 0xa5, 0x6b, 0x51, 0x4c, 0xfc, 0x0b, 0x0c, 0x55, 0xd9, 0x1a, 0xfd,
        0x52, 0x2d, 0x2e, 0x13, 0x72, 0xe3, 0xdb, 0x15, 0x85, 0xe1, 0xd7, 0x1b, 0xc0, 0xab, 0xfc,
        0x49, 0xec,
    ];
    // defined the pseudo password to be encrypted
    let secret_password = SecretString::from("supersecretpassword".to_string());

    println!("the plain password is: {}", secret_password.expose_secret());

    // translate the MOCK_KEK [u8; 32] into a readable format for the Aes-gcm crate
    let key = Key::<Aes256Gcm>::from_slice(&MOCK_KEK);

    // pass the key to Aes256Gcm
    let cipher = Aes256Gcm::new(key);

    //generate the Nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encryption
    let ciphertext = cipher
        .encrypt(&nonce, secret_password.expose_secret().as_bytes().as_ref())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;

    //Milestone shows the encrypted ciphertext in the terminal
    println!("the ciphertext: {:02x?}", ciphertext);

    //Decyption
    let decrypted_password = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|e| format!("Decyption failed: {:?}", e))?;

    // turns the decrypted password back into human readable text
    let printable_password = String::from_utf8(decrypted_password)?;

    //shows the initial password decrypted again to full encryption -> decryption cycle
    println!("This is the decrypted password: {}", printable_password);

    Ok(())
}
