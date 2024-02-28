use anyhow::Result;
use clap::{Arg, Command};

use rustic_key_vault::AppConfig;

fn main() -> Result<()> {
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
        .subcommand(
            Command::new("reset")
                .about("Reset the vault")
                .subcommand(Command::new("master").about("Reset the master password")),
        )
        .arg_required_else_help(true)
        .get_matches();

    match matches.subcommand() {
        Some(("login", sub_matches)) => {
            let config = AppConfig::from_matches(sub_matches);
            println!("Logging in as: {}", config.username);

            let expected_password = rustic_key_vault::create_or_get_master_password()?;
            println!("Expected password: {}", expected_password);

            // Check for password file
            let _password_file = rustic_key_vault::get_passwords()?;
        }
        Some(("reset", reset_matches)) => {
            if reset_matches.subcommand_matches("master").is_some() {
                if AppConfig::am_i_root() {
                    println!("System password verified as root.");
                } else {
                    println!("Failed to verify system password as root. Please run as 'sudo'.");
                }
            } else {
                // Tell user to use 'master' subcommand
                println!("Use 'master' subcommand to reset the master password.")
            }
        }
        _ => {
            println!("No subcommand was used");
        }
    }

    Ok(())
}
