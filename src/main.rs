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

            let (expected_password, _) = AppConfig::create_or_get_master_password()?;

            let mut count = 0;
            let mut matched_password = false;

            // while count < 3, ask for password prompt
            while count < 3 && !matched_password {
                if count == 3 {
                    return Err(anyhow::anyhow!(
                        "You have exceeded the maximum number of attempts"
                    ));
                }

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
                loop {
                    println!("Choose an option:");

                    println!("1. Add a new password");
                    println!("2. Search for a password");
                    println!("3. Update a password");
                    println!("4. Delete a password");
                    println!("5. List all passwords");
                    println!("6. Exit");

                    // Get user's choice
                    let mut choice = String::new();
                    std::io::stdin()
                        .read_line(&mut choice)
                        .context("Failed to read user's choice")?;

                    if choice.trim() == "6" {
                        println!("Exiting the vault");
                        break;
                    }

                    // match the choice
                    AppConfig::match_choice(&choice)?;
                }
            } else {
                println!("Login failed");
            }
        }
        Some(("reset", reset_matches)) => {
            if reset_matches.subcommand_matches("master").is_some() {
                if AppConfig::am_i_root() {
                    println!("System password verified as root.");

                    println!("You are about to reset the master password. Are you sure? (y/n)");

                    let mut choice = String::new();
                    std::io::stdin()
                        .read_line(&mut choice)
                        .context("Failed to read user's choice")?;

                    // check for Y or y
                    if choice.trim().to_lowercase() == "y" {
                        let hash_file = AppConfig::create_or_get_hash_file()?;
                        let new_password = AppConfig::password_prompt()?;
                        let new_password = new_password.trim();

                        if new_password.is_empty() {
                            return Err(anyhow::anyhow!("Password cannot be empty"));
                        }

                        AppConfig::create_password_hash(hash_file, new_password.to_string())?;

                        println!("Master password reset successful");
                    } else {
                        println!("Master password reset aborted");
                    }
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
