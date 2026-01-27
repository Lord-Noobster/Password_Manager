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
        auth_key BLOB NOT NULL,
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
        ciphertext BLOB NOT NULL,
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
