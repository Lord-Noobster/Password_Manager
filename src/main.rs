mod backend;
mod frontend;

use backend::VaultError;
use frontend::ui_temp;

fn main() -> Result<(), VaultError> {
    println!("Vault Engine: Initialized.");

    loop {
        let choice =
            inquire::Select::new("Vault Control", vec!["login", "register", "Exit"]).prompt()?;

        match choice {
            "Register" => {
                let (user, pass) = ui_temp::prompt_registration()?;
                //manager.handle_register(&user, &pass)?; passes to the VaultManager in backend/mod.rs
                //backend::db::register_user(&conn, &user, &pass)?; or i handle it in the db.rs
            }

            "Login" => {
                let (user, pass) = ui_temp::prompt_login()?;
                //manager.handle_login(&user, &pass)?;
                //backend::logic::login_flow(&conn, &user, &pass)?;
            }

            "Exit" => break,
            _ => unreachable!(),
        }
    }

    Ok(())
}
