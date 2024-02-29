use std::fs;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use nix::unistd;

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

    pub fn match_password(password: &[u8], password_hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(&password_hash).map_err(|e| anyhow!(e))?;
        Ok(Argon2::default()
            .verify_password(password, &parsed_hash)
            .is_ok())
    }

    // read_password_file
    pub fn read_password_file(password_file: &PathBuf) -> Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .open(password_file)
            .context("Failed to open password file")?;

        let reader = std::io::BufReader::new(file);
        let passwords: Vec<String> =
            serde_json::from_reader(reader).context("Failed to read password file")?;
        println!("Passwords: {:?}", passwords);
        Ok(())
    }

    // match the choice from user
    pub fn match_choice(choice: &str) -> Result<()> {
        match choice.trim() {
            "1" => {
                println!("Add a new password");
            }
            "2" => {
                println!("Get a password");
            }
            "3" => {
                println!("Update a password");
            }
            "4" => {
                println!("Delete a password");
            }
            "5" => {
                println!("List all passwords");
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

struct Password {
    username: String,
    password: String,
    domain: String,
}
