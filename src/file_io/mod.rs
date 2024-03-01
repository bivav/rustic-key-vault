use std::fs;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::Context;

use crate::crypto_utils::EncryptDecrypt;
use crate::vault::KeyVaultManager;

pub struct FileIoOperation {}

impl FileIoOperation {
    pub fn get_app_dir() -> anyhow::Result<PathBuf> {
        let home_dir = dirs::home_dir().context("Home directory not found")?;
        let app_dir = home_dir.join(".rustic_key_vault");

        if !app_dir.exists() {
            fs::create_dir_all(&app_dir).context("Failed to create app directory")?;
            let permission = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&app_dir, permission).context("Failed to set permission on app directory")?;
        }

        Ok(app_dir)
    }

    pub fn create_or_get_hash_file() -> anyhow::Result<PathBuf> {
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

    pub fn create_or_get_password_file() -> anyhow::Result<PathBuf> {
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

    pub fn create_or_get_master_password() -> anyhow::Result<(String, PathBuf)> {
        let hash_file = Self::create_or_get_hash_file()?;

        let hash = fs::read_to_string(&hash_file).context("Failed to read hash file")?;

        return if hash.trim().is_empty() {
            println!("Creating a master password");
            let password = KeyVaultManager::password_prompt()?;

            if password.trim().is_empty() {
                return Err(anyhow::anyhow!("Password cannot be empty"));
            }

            let (password_hash, password_file) = EncryptDecrypt::create_password_hash(hash_file, password)?;

            Ok((password_hash, password_file))
        } else {
            // Get passwords.json.enc file
            let password_file = Self::create_or_get_password_file()?;

            Ok((hash, password_file))
        };
    }

    pub fn read_password_file(password_file: &PathBuf) -> anyhow::Result<Vec<KeyVaultManager>> {
        // read the content of the password file
        let content = fs::read_to_string(&password_file).context("Failed to read password file")?;

        // check if the content is empty
        if content.trim().is_empty() {
            return Ok(Vec::new());
        }

        // deserialize the JSON array into a Vec<PasswordManager>
        let passwords: Vec<KeyVaultManager> =
            serde_json::from_str(&content).context("Failed to parse JSON")?;

        Ok(passwords)
    }
}
