use rusqlite::{Connection, Result, params};

pub struct Password {
    pub id: Option<i32>,
    pub service_name: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

fn main() -> Result<()> {
    const MOCK_CHIPERTEXT: [u8; 35] = [
        0x5e, 0x78, 0x8c, 0x07, 0x8e, 0x5c, 0xbc, 0x8f, 0x96, 0x8b, 0xb0, 0x43, 0xb8, 0xb3, 0x5b,
        0x5a, 0xa8, 0x62, 0x30, 0xf0, 0x6b, 0xfd, 0xdf, 0x02, 0xbc, 0xee, 0x42, 0x04, 0xe3, 0x9d,
        0x5a, 0x30, 0x1e, 0x16, 0xdc,
    ];

    const MOCK_NONCE: [u8; 12] = [
        0x67, 0x94, 0xa5, 0x23, 0x96, 0xfa, 0xca, 0x73, 0x8f, 0x94, 0xaa, 0x49,
    ];

    let conn = Connection::open("sqlite_test.db")?;
    conn.execute(
        "CREATE TABLE secrets (
            id INTEGER PRIMARY KEY,
            service_name TEXT NOT NULL,
            nonce BLOB,
            ciphertext  BLOB
        )",
        (), //empty list of params
    )?;

    let new_password = Password {
        id: Some(0),
        service_name: "netflix".to_string(), //planing on blinding the name too in the db
        nonce: MOCK_NONCE.to_vec(),
        ciphertext: MOCK_CHIPERTEXT.to_vec(),
    };

    conn.execute(
        "INSERT INTO secrets (service_name, nonce, ciphertext) VALUES (?1, ?2, ?3)",
        (
            &new_password.service_name,
            &new_password.nonce,
            &new_password.ciphertext,
        ),
    )?;

    let mut stmt = conn.prepare(
        "SELECT id, service_name , nonce, ciphertext FROM secrets WHERE service_name = ?1",
    )?;

    let mut retrieved = stmt.query_map(("netflix",), |row| {
        Ok(Password {
            id: row.get(0)?,
            service_name: row.get(1)?,
            nonce: row.get(2)?,
            ciphertext: row.get(3)?,
        })
    })?;

    if let Some(result) = retrieved.next() {
        let p = result?;
        println!("Retrieved: {} (ID: {:?})", p.service_name, p.id);

        println!(
            "Integrity check: {}",
            p.nonce
                == [
                    0x67, 0x94, 0xa5, 0x23, 0x96, 0xfa, 0xca, 0x73, 0x8f, 0x94, 0xaa, 0x49
                ]
                .to_vec()
        );
    }

    Ok(())
}
