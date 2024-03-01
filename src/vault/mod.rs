use anyhow::{anyhow, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use dialoguer::{Input, Password as PassPrompt};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyVaultManager {
    pub id: u32,
    pub username: String,
    pub password: String,
    pub domain: String,
}

impl KeyVaultManager {
    pub fn new(id: u32, username: String, password: String, domain: String) -> Self {
        Self {
            id,
            username,
            password,
            domain,
        }
    }

    pub fn prompt() -> Result<Self> {
        let id = uuid::Uuid::new_v4().as_u128() as u32;

        let username = Self::prompt_for_input("Enter the username")?;
        let password = Self::prompt_for_password("Enter the password")?;
        let domain = Self::prompt_for_input("Enter the domain")?;

        Ok(Self {
            id,
            username,
            password,
            domain,
        })
    }

    pub fn password_prompt() -> Result<String> {
        let password = rpassword::prompt_password("Master Password: ")?;
        Ok(password)
    }

    fn prompt_for_input(prompt: &str) -> Result<String> {
        let result = Input::<String>::new().with_prompt(prompt).interact()?;

        if result.is_empty() {
            Err(anyhow::anyhow!("{} cannot be empty", prompt))
        } else {
            Ok(result)
        }
    }

    fn prompt_for_password(prompt: &str) -> Result<String> {
        let result = PassPrompt::new().with_prompt(prompt).interact()?;

        if result.is_empty() {
            Err(anyhow::anyhow!("{} cannot be empty", prompt))
        } else {
            Ok(result)
        }
    }

    pub fn match_password(password: &[u8], password_hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(&password_hash).map_err(|e| anyhow!(e))?;
        Ok(Argon2::default().verify_password(password, &parsed_hash).is_ok())
    }
}
