use std::path::Path;

use crate::backend::VaultError;
use rusqlite::{Connection, params};
use serde::de;

pub struct VaultEntry {
    pub id: i32,
    pub service_name: String, // eveentually search-keyed
    pub username: String,
    pub ciphertext: Vec<u8>,
    pub payload_nonce: [u8; 12],
    pub wrapped_dek: Vec<u8>, // will require further obfusaction
    pub dek_nonce: [u8; 12],  // to 'detach' from the password
}

fn blob_to_nonce(row: &rusqlite::Row, idx: usize) -> rusqlite::Result<[u8; 12]> {
    let bytes: Vec<u8> = row.get(idx)?;
    bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidColumnType(
            idx,
            "Nonce must be 12 bytes".into(),
            rusqlite::types::Type::Blob,
        )
    })
}

pub fn init_auth_db(path: &Path) -> Result<Connection, VaultError> {
    let conn = Connection::open(path)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        salt BLOB NOT NULL,
        auth_key BLOB NOT NULL
    )",
        (),
    )?;

    Ok(conn)
}

pub fn init_vault_db(path: &Path) -> Result<Connection, VaultError> {
    let conn = Connection::open(path)?;
    // NOTE In future iteration the service_name should be stored as BLOB
    conn.execute(
        "CREATE TABLE IF NOT EXISTS vault (
        id INTEGER PRIMARY KEY,
        service_name TEXT NOT NULL,
        username TEXT NOT NULL,
        ciphertext BLOB not NULL,
        payload_nonce BLOB NOT NULL,
        wrapped_dek BLOB NOT NULL,
        dek_nonce BLOB NOT NULL,
        UNIQUE(service_name, username)
        )",
        (),
    )?;
    Ok(conn)
}

pub fn save_new_user(
    conn: &Connection,
    username: &str,
    salt: &[u8],
    auth_key: &[u8; 32],
) -> Result<(), VaultError> {
    conn.execute(
        "INSERT INTO users (username, salt, auth_key) VALUES  (?1, ?2, ?3)",
        (username, salt, auth_key.as_slice()),
    )?;
    Ok(())
}

pub fn get_user_auth_key(
    conn: &Connection,
    username: &str,
) -> Result<(Vec<u8>, Vec<u8>), crate::backend::VaultError> {
    conn.query_row(
        "SELECT salt, auth_key FROM users WHERE username = ?1",
        [username],
        |row| {
            let salt: Vec<u8> = row.get(0)?;
            let auth_key: Vec<u8> = row.get(1)?;
            Ok((salt, auth_key))
        },
    )
    .map_err(|_| crate::backend::VaultError::UserNotFound(username.to_string()))
}

pub fn store_secret(
    conn: &Connection,
    service_name: &str,
    username: &str,
    ciphertext: Vec<u8>,
    payload_nonce: &[u8; 12],
    wrapped_dek: Vec<u8>,
    dek_nonce: &[u8; 12],
) -> Result<(), VaultError> {
    conn.execute(
        "INSERT INTO vault (service_name, username, ciphertext, payload_nonce, wrapped_dek, dek_nonce) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        (service_name, username, ciphertext, payload_nonce, wrapped_dek, dek_nonce),
    )?;

    Ok(())
}

pub fn get_secret(
    conn: &Connection,
    service_name: &str,
    username: &str,
) -> Result<VaultEntry, VaultError> {
    let result = conn.query_row("SELECT id, service_name, username, ciphertext, payload_nonce, wrapped_dek, dek_nonce FROM vault WHERE service_name = ?1 AND username = ?2",
        [service_name, username], |row|{ 
            Ok(VaultEntry {
                id: row.get(0)?,
                service_name: row.get(1)?,
                username: row.get(2)?,
                ciphertext: row.get(3)?,
                payload_nonce: blob_to_nonce(row, 4)?, // nonce stored as Vec<u8> fn to [u8; 12]
                wrapped_dek: row.get(5)?,
                dek_nonce: blob_to_nonce(row, 6)?,
            })
        }
    );
    result.map_err(VaultError::from)
}
