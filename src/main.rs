mod backend;
mod frontend;

use std::path::Path;

use backend::VaultError;
use crossterm::cursor::Show;
use frontend::ui_temp;

use backend::VaultManager;

use crate::backend::db::VaultEntry;
// TODO: Move the Inquire loops to frontend/mod.rs
fn main() -> Result<(), VaultError> {
    let mut manager = VaultManager::init(Path::new("user.db"), Path::new("vault.db"))?;
    println!("Vault Engine: Initialized.");

    loop {
        let choice =
            inquire::Select::new("Vault Control", vec!["Login", "Register", "Exit"]).prompt()?;

        match choice {
            "Register" => {
                let (user, pass) = ui_temp::prompt_registration()?;
                match manager.handle_register(&user, &pass) {
                    Ok(msg) => println!("{}", msg),

                    Err(VaultError::UserExists) => {
                        println!("Error: User already exists.");
                    }
                    Err(e) => return Err(e),
                }
            }

            "Login" => {
                let (user, pass) = ui_temp::prompt_login()?;
                match manager.handle_login(&user, &pass) {
                    Ok(_) => {
                        println!("Vault Unlocked!");

                        vault_session(&mut manager)?;
                    }
                    Err(e) => println!("Login Failed: {}", e),
                }
            }
            "Exit" => {
                manager.logout(); // ensures that keys are dropped
                break;
            }

            _ => println!("Unexpected input received"),
        }
    }

    Ok(())
}

pub fn vault_session(manager: &mut VaultManager) -> Result<(), VaultError> {
    //let mut manager = VaultManager::init(Path::new("user.db"), Path::new("vault.db"))?;
    loop {
        let choice =
            inquire::Select::new("Vault Control", vec!["Store", "Retrieve", "Logout"]).prompt()?;

        match choice {
            "Store" => {
                let (service, user, pass) = ui_temp::prompt_store()?;
                match manager.handle_store(&service, &user, &pass) {
                    Ok(msg) => println!("{}", msg),

                    Err(VaultError::EntryAlreadyExists) => {
                        println!(
                            "Error: an entry for '{}' already exists for user '{}'.",
                            service, user
                        );
                        println!("Suggestion: Use a unique service name or a different username.");
                    }

                    Err(e) => return Err(e),
                }
                // should return a confirmation when insert has been done
            }

            "Retrieve" => {
                let (service, user) = ui_temp::prompt_retrieve()?;

                let secret_pass = manager.handle_retrieve(&service, &user)?;
                let show = manager.format_secret_for_print(secret_pass);
                println!("{}", show);
            }

            "Logout" => {
                manager.logout();
                println!("keyes dropped");
                break;
            }
            _ => println!("Unexpected input received"),
        }
    }

    Ok(())
}
