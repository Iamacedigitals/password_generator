use aes_gcm::{
    aead::{consts::U12, generic_array::GenericArray}
};
use crate::{
    generate::{generate_id, generate_password},
    hasher::{encrypt_contents},
    login::{login},
};
use serde::{Deserialize, Serialize};

use std::{io, io::{BufReader}, fs ,fs::{File}, process::ExitCode};
//struct App{}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Vault{
    pub vault_profile: Profile,
    // Encryption details as metadata
    pub metadata: Encryption_data,
    pub content: Vec<Content>,
}

impl Vault{
    pub fn new(
        name: String, 
        email: String, 
        master_password: String
    ) -> 
    Result<Self, Box<dyn std::error::Error>> {

    let metadata = encrypt_contents(master_password, "vault-verifier".to_string())?;

    Ok(Vault {
        vault_profile: Profile {
            name: name.clone(),
            email,              // can serve as recovery email
            vault_id: name.clone() + generate_id(16).as_str(),
        },
        metadata,
        content: Vec::new(),
        })
    }

    pub fn start_vault() -> Result<ExitCode, Box<dyn std::error::Error>>{
        // Login Prompt for the vault in total
        login()?;
        Ok(ExitCode::SUCCESS)
    }

}


#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Profile {
    pub name: String,
    pub email: String,
    pub vault_id: String
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Encryption_data{
    // implement getters and setters later
    pub nonce_bytes:GenericArray<u8, U12>, 
    pub cipher_text:Vec<u8>, 
    pub salt:[u8;16],
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Content{
    pub id: String,
    pub title: String,
    pub metadata: Encryption_data,
    pub secret_question : String,
    pub secret_answer :String,// process these thing later in the modules for authenticating the edits
}

