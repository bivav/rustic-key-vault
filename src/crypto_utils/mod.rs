use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};

use crate::file_io::FileIoOperation;

pub struct EncryptDecrypt {}

impl EncryptDecrypt {
    pub fn create_password_hash(
        hash_file: PathBuf,
        username: String,
        password: String,
    ) -> Result<(String, PathBuf)> {
        let salt = SaltString::generate(&mut OsRng);

        let password_fmt = format!("{}:{}", username, password);

        // 'Argon2id' with default parameters
        let argon2 = Argon2::default();

        // Hash password to PHC string ($argon2id$v=19$...)
        let password_hash = argon2
            .hash_password(password_fmt.as_bytes(), &salt)
            .unwrap()
            .to_string();

        // create passwords.json.enc file
        let password_file = FileIoOperation::create_or_get_password_file()?;

        // Write the hash to the hash file
        fs::write(&hash_file, &password_hash).context("Failed to write hash to file")?;
        println!("Master password is set. Please enter the master password to continue.");

        Ok((password_hash, password_file))
    }
}
