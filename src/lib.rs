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

fn get_app_dir() -> Result<PathBuf> {
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

pub fn get_passwords() -> Result<PathBuf> {
    let password_file_path = get_password_file_path()?;

    OpenOptions::new()
        .write(true)
        .create(true)
        .open(&password_file_path)
        .context("Failed to create password file")?;

    fs::set_permissions(&password_file_path, fs::Permissions::from_mode(0o600))
        .context("Failed to set permission on password file")?;

    println!("Password file path: {:?}", password_file_path);

    Ok(password_file_path)
}

pub fn create_or_get_hash_file() -> Result<PathBuf> {
    let app_dir = get_app_dir()?;

    let hash_file = app_dir.join("master.hash");

    OpenOptions::new()
        .write(true)
        .create(true)
        .read(true)
        .open(&hash_file)
        .context("Failed to create password file")?;

    fs::set_permissions(&hash_file, fs::Permissions::from_mode(0o600))
        .context("Failed to set permission on hash file")?;

    println!("Hash file path: {:?}", hash_file);

    Ok(hash_file)
}

pub fn create_or_get_master_password() -> Result<String> {
    let hash_file = create_or_get_hash_file()?;

    let hash = fs::read_to_string(&hash_file).context("Failed to read hash file")?;

    return if hash.trim().is_empty() {
        println!("Creating a master password");
        let password = password_prompt()?;

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

        // Write the hash to the hash file
        fs::write(&hash_file, &password_hash).context("Failed to write hash to file")?;
        println!("Master password is set. Please enter the password to continue.");
        Ok(password_hash)
    } else {
        // println!("Master password already exists");
        Ok(hash)
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
