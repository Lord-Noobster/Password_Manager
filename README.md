# A Local Zero-Knowledge Password Manager written in Rust

> **⚠️ DO NOT USE – THIS IS A LEARNING PROJECT**
> This tool is a technical study in memory safety and cryptography. It has not been audited and should not be used for production secrets.


## Project Overview
A CLI-based password manager written in **Rust**. The project started as a way for me to learn Rust, cryptographic principles, and memory safety, and because of that, it focuses on maintaining a zero-knowledge posture.


## Technical Architecture

### Memory Management
I’ve focused on ’defense-in-depth’ when it comes to sensitive data in ram. I use the `secrecy` crate to protect sensitive data while they are sitting in ram, by wrapping them in **SecretBox**, **SecretString**, and **SecretVec** i can prevent the master password and keys from being accidentally logged or exposed while the program is running. I also use `zeroize` to ensure that keys and plain-text buffers are scrubbed from memory as soon as they aren’t needed anymore.


### Cryptographic Stack (KDF & Encryption)
The system avoids single-point-of-failure keys by implementing strict **Key Separation** via **HKDF-SHA256**:
* **Argon2id:** Used for primary password hashing (Memory-hard/GPU resistant).
* **HKDF Derived Sub-keys:**
    * `k_storage`: For database authentication.
    * `k_auth`: For internal handshake integrity.
    * `kek` (Key Encryption Key): To wrap/unwrap Data Encryption Keys (DEK).
    * `search_key`: For HMAC-based **Blind Indexing** of service and account names.
    * `owner_id`: A blinded identifier derived to isolate vault entries in a multi-tenant environment.
* **Encryption:** AES-256-GCM (Authenticated Encryption) with unique, independent nonces for every payload and wrapped DEK.

## Roadmap & Future considerations

"I’m looking into adding a User Configuration file so people can choose where their database files live and even tweak the Argon2id settings themselves instead of just using the defaults. But adding a config file also adds a new way for an attacker to mess with the tool, so I’ll need to build in Config Tamper-Protection. I’m thinking about a check that runs when the tool starts to see if the file has been changed by something else. To handle that, I'll need an Admin User, probably just the first user created who has to confirm any changes to the config with their password before the tool accepts them."

## Known Constraints & Security Leaks

### OS-Level Memory Handling 
Development is currently focused on Linux due to predictable memory control. Porting to Windows introduces specific issues i havent solved yet:
knowing windows to be controlling and obstinate i looked into the way windows manages memory and found that there are security concerns for a tool like this in the way it manages its hibernation memory with swapfiles and an issue with how windows memory manager can choose to ignore zerorize calls.
**Im looking into windows specific solutions.**
  
### Known bugs
* **Stack Exposure:** During `derive_keys`, sub-keys briefly exist in stack-allocated arrays before being moved to `SecretBox`. While transient, this represents a potential leak in the event of a high-speed memory dump.
* **Username Enumeration:** Current authentication failures are being refined to ensure consistent timing and generic messaging to prevent attackers from guessing if a specific user exists in the `users.db`.


## Technical Stack
* **Language:** Rust
* **Persistence:** SQLite (`rusqlite`)
* **Core Crates:** `argon2`, `aes-gcm`, `hkdf`, `zeroize`, `secrecy`, `inquire`.
