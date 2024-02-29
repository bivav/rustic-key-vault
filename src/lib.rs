use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use nix::unistd;
use prettytable::{row, Table};
use serde::{Deserialize, Serialize};

use crate::password_manager::PasswordEntry;

mod password_manager;

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

    pub fn get_app_dir() -> Result<PathBuf> {
        let home_dir = dirs::home_dir().context("Home directory not found")?;
        let app_dir = home_dir.join(".rustic_key_vault");

        if !app_dir.exists() {
            fs::create_dir_all(&app_dir).context("Failed to create app directory")?;
            let permission = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&app_dir, permission)
                .context("Failed to set permission on app directory")?;
        }

        Ok(app_dir)
    }

    pub fn get_password_file_path() -> Result<PathBuf> {
        let home_dir = dirs::home_dir().context("Home directory not found")?;
        let app_dir = home_dir.join(".rustic_key_vault");
        let password_file = app_dir.join("passwords.json.enc");

        // if !app_dir.exists() {
        //     fs::create_dir_all(&app_dir).context("Failed to create app directory")?;
        //     let permission = fs::Permissions::from_mode(0o700);
        //     fs::set_permissions(&app_dir, permission)
        //         .context("Failed to set permission on app directory")?;
        // }

        Ok(password_file)
    }

    pub fn create_or_get_hash_file() -> Result<PathBuf> {
        let app_dir = Self::get_app_dir()?;
        let hash_file = app_dir.join("master.hash");

        OpenOptions::new()
            .write(true)
            .create(true)
            .read(true)
            .open(&hash_file)
            .context("Failed to create master hash file")?;

        fs::set_permissions(&hash_file, fs::Permissions::from_mode(0o600))
            .context("Failed to set permission on hash file")?;

        println!("Hash file path: {:?}", hash_file);

        Ok(hash_file)
    }

    pub fn create_or_get_password_file() -> Result<PathBuf> {
        let app_dir = Self::get_app_dir()?;
        let password_file = app_dir.join("passwords.json.enc");

        OpenOptions::new()
            .write(true)
            .create(true)
            .read(true)
            .open(&password_file)
            .context("Failed to create password file")?;

        fs::set_permissions(&password_file, fs::Permissions::from_mode(0o600))
            .context("Failed to set permission on password file")?;

        Ok(password_file)
    }

    pub fn create_or_get_master_password() -> Result<(String, PathBuf)> {
        let hash_file = Self::create_or_get_hash_file()?;

        let hash = fs::read_to_string(&hash_file).context("Failed to read hash file")?;

        return if hash.trim().is_empty() {
            println!("Creating a master password");
            let password = Self::password_prompt()?;

            if password.trim().is_empty() {
                return Err(anyhow::anyhow!("Password cannot be empty"));
            }

            let (password_hash, password_file) = Self::create_password_hash(hash_file, password)?;

            // let salt = SaltString::generate(&mut OsRng);
            //
            // // 'Argon2id' with default parameters
            // let argon2 = Argon2::default();
            //
            // // Hash password to PHC string ($argon2id$v=19$...)
            // let password_hash = argon2
            //     .hash_password(password.as_bytes(), &salt)
            //     .unwrap()
            //     .to_string();
            //
            // // create passwords.json.enc file
            // let password_file = Self::create_or_get_password_file()?;
            //
            // // Write the hash to the hash file
            // fs::write(&hash_file, &password_hash).context("Failed to write hash to file")?;

            Ok((password_hash, password_file))
        } else {
            // Get passwords.json.enc file
            let password_file = Self::create_or_get_password_file()?;

            Ok((hash, password_file))
        };
    }

    pub fn password_prompt() -> Result<String> {
        let password = rpassword::prompt_password("Master Password: ")?;
        Ok(password)
    }

    pub fn create_password_hash(hash_file: PathBuf, password: String) -> Result<(String, PathBuf)> {
        let salt = SaltString::generate(&mut OsRng);

        // 'Argon2id' with default parameters
        let argon2 = Argon2::default();

        // Hash password to PHC string ($argon2id$v=19$...)
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        // create passwords.json.enc file
        let password_file = Self::create_or_get_password_file()?;

        // Write the hash to the hash file
        fs::write(&hash_file, &password_hash).context("Failed to write hash to file")?;
        println!("Master password is set. Please enter the master password to continue.");

        Ok((password_hash, password_file))
    }

    pub fn match_password(password: &[u8], password_hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(&password_hash).map_err(|e| anyhow!(e))?;
        Ok(Argon2::default()
            .verify_password(password, &parsed_hash)
            .is_ok())
    }

    pub fn read_password_file(password_file: &PathBuf) -> Result<Vec<PasswordEntry>> {
        // read the content of the password file
        let content = fs::read_to_string(&password_file).context("Failed to read password file")?;

        // check if the content is empty
        if content.trim().is_empty() {
            return Ok(Vec::new());
        }

        // deserialize the JSON array into a Vec<String>
        let passwords: Vec<PasswordEntry> =
            serde_json::from_str(&content).context("Failed to parse JSON")?;

        Ok(passwords)
    }

    // match the choice from user
    pub fn match_choice(choice: &str) -> Result<()> {
        match choice.trim() {
            "1" => {
                println!("Add a new password");

                let user_input = PasswordEntry::prompt().context("Failed to get user input")?;

                let new_entry = PasswordEntry::new(
                    user_input.id,
                    user_input.username,
                    user_input.password,
                    user_input.domain,
                );

                // get the password file
                let password_file = Self::create_or_get_password_file()?;

                // read the password file
                let mut passwords: Vec<PasswordEntry> =
                    AppConfig::read_password_file(&password_file)?;
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
                let password_file = Self::create_or_get_password_file()?;
                // read the password file
                let passwords = AppConfig::read_password_file(&password_file)?;

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
