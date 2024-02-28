use std::fs;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{Context, Result};

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
}

pub fn get_password_file_path() -> Result<PathBuf> {
    let home_dir = dirs::home_dir().context("Home directory not found")?;
    let app_dir = home_dir.join(".rustic_key_vault");
    let password_file = app_dir.join("passwords.json.enc");

    if !app_dir.exists() {
        fs::create_dir_all(&app_dir).context("Failed to create app directory")?;
        let permission = fs::Permissions::from_mode(0o700);
        fs::set_permissions(&app_dir, permission)
            .context("Failed to set permission on app directory")?;
    }

    Ok(password_file)
}

pub fn get_passwords() -> Result<()> {
    let password_file_path = get_password_file_path()?;

    let password_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&password_file_path)
        .context("Failed to open password file")?;

    fs::set_permissions(&password_file_path, fs::Permissions::from_mode(0o600))
        .context("Failed to set permission on password file")?;

    println!("Password file path: {:?}", password_file_path);

    Ok(())
}
