use aes_gcm::{
    aead::{consts::U12, generic_array::GenericArray}
};
use crate::{generate::{generate_id},hasher::{encrypt_contents}};

//struct App{}

pub struct Vault{
    pub vault_profile: Profile,
    // Encryption details as metadata
    pub metadata: Encryption_data,
    pub content: Vec<Content>,
}

impl Vault{
    pub fn new(name: String, email: String, master_password: String) -> Result<Self, Box<dyn std::error::Error>> {
    let metadata = encrypt_contents(master_password, "vault-verifier".to_string())?;

    Ok(Vault {
        vault_profile: Profile {
            name,
            email,              // can serve as recovery email
            vault_id: generate_id(16),
        },
        metadata,
        content: Vec::new(),
    })
}
    
}

pub struct Profile {
    name: String,
    email: String,
    vault_id: String
}

pub struct Encryption_data{
    // implement getters and setters later
    pub nonce_bytes:GenericArray<u8, U12>, 
    pub cipher_text:Vec<u8>, 
    pub salt:[u8;16],
}

pub struct Content{
    pub id: String,
    pub title: String,
    pub metadata: Encryption_data
}
