use anyhow::{Context, Result};
use clap::{Arg, Command};

use rustic_key_vault::*;
use vault::KeyVaultManager;

use crate::crypto_utils::EncryptDecrypt;
use crate::file_io::FileIoOperation;

mod crypto_utils;
mod file_io;
mod vault;

const APP_NAME: &str = "Rustic Key Vault";
const APP_VERSION: &str = "0.1.0";
const APP_AUTHOR: &str = "Bivav R Satyal";
const APP_ABOUT: &str = "A secure password vault for storing your passwords locally.";

fn main() -> Result<()> {
    let matches = Command::new("rustic_key_vault")
        .name(APP_NAME)
        .version(APP_VERSION)
        .about(APP_ABOUT)
        .author(APP_AUTHOR)
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
            println!("Logging in as: {}", &config.username);

            let (expected_password, _) = FileIoOperation::create_or_get_master_password(config.username.clone())?;

            let mut count = 0;
            let mut matched_password = false;

            while count < 3 && !matched_password {
                let password = KeyVaultManager::password_prompt()?;

                if password.trim().is_empty() {
                    return Err(anyhow::anyhow!("Password cannot be empty"));
                }

                let password_fmt = format!("{}:{}", &config.username, &password);

                if KeyVaultManager::match_password(&password_fmt.as_bytes(), &expected_password)? {
                    matched_password = true;
                } else {
                    println!("Password does not match. Please try again.");
                    count += 1;
                }
            }

            if count == 3 {
                return Err(anyhow::anyhow!(
                    "You have exceeded the maximum number of attempts"
                ));
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
                        let hash_file = FileIoOperation::create_or_get_hash_file()?;
                        let new_password = KeyVaultManager::password_prompt()?;
                        let new_password = new_password.trim();

                        if new_password.is_empty() {
                            return Err(anyhow::anyhow!("Password cannot be empty"));
                        }

                        // TODO: Add a feature to get username from the user
                        // let password_fmt = format!("{}:{}", "root", new_password);

                        EncryptDecrypt::create_password_hash(
                            hash_file,
                            "root".to_string(),
                            new_password.to_string(),
                        )?;

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
