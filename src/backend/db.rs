use std::path::Path;

use crate::backend::VaultError;
use rusqlite::{Connection, params};

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

    conn.execute(
        "CREATE TABLE IF NOT EXISTS vault (
        id INTEGER PRIMARY KEY,
        service_name TEXT NOT NULL,
        noce BLOB not NULL,
        ciphertext BLOB NOT NULL
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
