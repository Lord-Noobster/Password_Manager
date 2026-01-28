mod backend;
mod frontend;

use std::path::Path;

use backend::VaultError;
use frontend::ui_temp;

use backend::VaultManager;

fn main() -> Result<(), VaultError> {
    let mut manager = VaultManager::init(Path::new("user.db"), Path::new("vault.db"))?;
    println!("Vault Engine: Initialized.");

    loop {
        let choice =
            inquire::Select::new("Vault Control", vec!["Login", "Register", "Exit"]).prompt()?;

        match choice {
            "Register" => {
                let (user, pass) = ui_temp::prompt_registration()?;
                manager.handle_register(&user, &pass)?; //passes to the VaultManager in backend/mod.rs
            }

            "Login" => {
                let (user, pass) = ui_temp::prompt_login()?;
                match manager.handle_login(&user, &pass) {
                    Ok(_) => println!("Vault Unlocked!"),
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
