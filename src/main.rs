use anyhow::Result;
use clap::{Arg, Command};

use rustic_key_vault::{get_passwords, AppConfig};

fn main() -> Result<()> {
    // Create a command line where -l will take in login and -p will take in password
    let matches = Command::new("rustic_key_vault")
        .name("Rustic Key Vault")
        .version("0.1.0")
        .about("A secure password vault for storing your passwords locally.")
        .author("Bivav R Satyal")
        .subcommand(
            Command::new("login").about("Login to the vault").arg(
                Arg::new("username")
                    .short('u')
                    .long("username")
                    .help("Your login username")
                    .required(true),
            ),
        )
        .arg_required_else_help(true)
        .get_matches();

    match matches.subcommand() {
        Some(("login", sub_matches)) => {
            let config = AppConfig::from_matches(sub_matches);
            println!("Logging in as: {}", config.username);

            // As for password using rpassword crate
            let password = rpassword::prompt_password("Password: ")?;
            println!("Password: {}", password);

            get_passwords()?;
        }
        _ => {
            println!("No subcommand was used");
        }
    }

    Ok(())
}
