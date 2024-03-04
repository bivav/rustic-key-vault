use std::fs::OpenOptions;
use std::io::Write;

use anyhow::{Context, Result};
use argon2::PasswordHasher;
use nix::unistd;
use prettytable::{row, Table};

use file_io::FileIoOperation;
use vault::KeyVaultManager;

mod crypto_utils;
mod file_io;
mod vault;

pub struct AppConfig {
    pub username: String,
    pub password: Option<String>,
}

impl AppConfig {
    pub fn from_matches(matches: &clap::ArgMatches) -> Self {
        let username = matches.get_one::<String>("username").unwrap().to_string();

        Self {
            username,
            password: None,
        }
    }

    pub fn am_i_root() -> bool {
        unistd::geteuid().is_root()
    }

    // match the choice from user
    pub fn match_choice(choice: &str) -> Result<()> {
        match choice.trim() {
            "1" => {
                println!("Add a new password");

                let user_input = KeyVaultManager::prompt().context("Failed to get user input")?;

                let new_entry = KeyVaultManager::new(
                    user_input.id,
                    user_input.username,
                    user_input.password,
                    user_input.domain,
                );

                // get the password file
                let password_file = FileIoOperation::create_or_get_password_file()?;

                // read the password file
                let mut passwords: Vec<KeyVaultManager> =
                    FileIoOperation::read_password_file(&password_file)?;
                println!("List of passwords: {:?}", passwords);

                // add the new entry to the list of passwords
                passwords.push(new_entry);
                println!("Updated the list of passwords: {:?}", passwords);

                // serialize the passwords vector into a JSON array
                let passwords_json = serde_json::to_string(&passwords).unwrap();

                // insert to password file
                let mut file = OpenOptions::new()
                    .write(true)
                    .open(&password_file)
                    .context("Failed to open password file")?;

                // store the passwords in file as json array
                file.write_all(passwords_json.as_bytes())
                    .context("Failed to write to password file")?;
            }
            "2" => {
                println!("Search for a password using Domain: ");
                println!("Search for a password using domain name");
                write!(std::io::stdout(), "Enter domain name: ")?;
                std::io::stdout().flush()?;
                let mut domain = String::new();
                std::io::stdin()
                    .read_line(&mut domain)
                    .context("Failed to read domain name")?;

                println!("Domain: {}", domain.trim());
            }
            "3" => {
                println!("Update a password");
                unimplemented!("Will be implemented in the next chapter")
            }
            "4" => {
                println!("Delete a password");
                unimplemented!("Will be implemented in the next chapter")
            }
            "5" => {
                println!("List all passwords");
                let password_file = FileIoOperation::create_or_get_password_file()?;
                // read the password file
                let passwords = FileIoOperation::read_password_file(&password_file)?;

                // List all passwords in a table format with auto size
                let mut table = Table::new();
                table.add_row(row!["ID", "Username", "Password", "Domain"]);

                for password in passwords {
                    table.add_row(row![
                        password.id,
                        password.username,
                        password.password,
                        password.domain
                    ]);
                }

                table.printstd();
            }
            "6" => {
                println!("Exit");
            }
            _ => {
                println!("Invalid choice");
            }
        }
        Ok(())
    }
}
