use serde::{Deserialize, Serialize};
use std::{io, io::{BufWriter, Write, BufReader}, fs ,fs::{File}};
use crate::{hasher::decrypt_blob, structs::{Content, Encryption_data, Profile, Vault}};

const PATH: &str = "data.json";

pub fn save_vaults(vaults: &[Vault]) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(PATH)?;
    serde_json::to_writer_pretty(BufWriter::new(file), vaults)?;
    Ok(())
}

pub fn load_vaults() -> Result<Vec<Vault>, Box<dyn std::error::Error>> {
    let file = match File::open(PATH) {
        Ok(f) => f,
        // No file yet means no vaults yet
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    Ok(serde_json::from_reader(BufReader::new(file))?)
}

pub fn save_login(new_vault: Vault) -> Result<(), Box<dyn std::error::Error>> {
    let mut vaults: Vec<Vault> = load_vaults()?;
    vaults.push(new_vault);
    save_vaults(&vaults)
}


pub fn retrieve_content(){}

pub fn add_content(){}

pub fn validate_login(email: String, master_password: &str) -> Result<Option<Vault>, Box<dyn std::error::Error>> {
    let vaults = load_vaults()?;

    // Find the vault for this email
    let Some(vault) = vaults.into_iter().find(|v| v.vault_profile.email == email) else {
        return Ok(None);
    };


    // Check the password against the vault's stored cipher text
    if decrypt_blob(master_password, &vault)? {
        Ok(Some(vault))
    } else {
        Ok(None)
    }
}