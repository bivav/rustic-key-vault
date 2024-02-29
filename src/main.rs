use std::io::Write;

use anyhow::{Context, Result};
use clap::{Arg, Command};

use rustic_key_vault::*;

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

            let (expected_password, password_file) = AppConfig::create_or_get_master_password()?;

            let mut count = 0;
            let mut matched_password = false;

            // while count < 3, ask for password prompt
            while count < 3 && !matched_password {
                let password = AppConfig::password_prompt()?;

                if password.trim().is_empty() {
                    return Err(anyhow::anyhow!("Password cannot be empty"));
                }
                let val = AppConfig::match_password(&password.as_bytes(), &expected_password)?;
                if val {
                    matched_password = true;
                } else {
                    println!("Password does not match. Please try again.");
                    count += 1;
                }
            }

            if matched_password {
                println!("Login successful");

                // List the options for user to choose from
                println!("Choose an option:");

                println!("Search for a password using domain name");
                write!(std::io::stdout(), "Enter domain name: ")?;
                std::io::stdout().flush()?;
                let mut domain = String::new();
                std::io::stdin()
                    .read_line(&mut domain)
                    .context("Failed to read domain name")?;

                println!("Domain: {}", domain.trim());

                println!("1. Add a new password");
                println!("2. Get a password");
                println!("3. Update a password");
                println!("4. Delete a password");
                println!("5. List all passwords");
                println!("6. Exit");

                // read the password file
                let passwords = AppConfig::read_password_file(&password_file)?;

                // get the user's choice
                let mut choice = String::new();
                std::io::stdin()
                    .read_line(&mut choice)
                    .context("Failed to read user's choice")?;

                // match the choice
                let val = AppConfig::match_choice(&choice)?;
            } else {
                println!("Login failed");
            }
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
