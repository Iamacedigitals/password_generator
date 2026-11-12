use aes_gcm::{
    aead::{consts::U12, generic_array::GenericArray}
};
use crate::{generate::{generate_id, generate_password},hasher::{encrypt_contents}};

use std::io;
//struct App{}

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
            name,
            email,              // can serve as recovery email
            vault_id: generate_id(16),
        },
        metadata,
        content: Vec::new(),
        })
    }

    fn start_vault(){
        println!("Hello User. Are You new here? If YES Click (Y) if No Click (N)");
        let mut input = String::new();
        println!("(Y)/(N): ");
        
        io::stdin()
        .read_line(&mut input)
        .expect("Failed to read String");

        let decision = input.trim().to_string();

        input.clear();

        if decision.to_lowercase() == "y" {
            println!("Create new account!");
            println!("Enter your email: ");

            io::stdin()
            .read_line(&mut input)
            .expect("Invalid: Couldnt Parse Entry");

            let email =  input.trim().to_string();

            input.clear();

            // save email using the fle saving logic/ database logic implemetation

            println!("Enter your name: ");

            io::stdin()
            .read_line(&mut input)
            .expect("Invalid: Couldnt Parse Entry");

            let name =  input.trim().to_string();

            input.clear();

            println!("Enter your new password / generate_random strong password: ");
            println!("(N - personal password) / (R - random password): ");

            io::stdin()
            .read_line(&mut input)
            .expect("Invalid: Couldnt Parse Entry");

            let should_random_generate  = input.trim().to_lowercase();

            input.clear();

            if should_random_generate == "n"{

                io::stdin()
                .read_line(&mut input)
                .expect("Invalid: Couldnt Parse Entry");
                
                let password =  input.trim().to_string();

                input.clear();

            } else if should_random_generate == "r"{
                let password = generate_password(16);
            }

            input.clear();
            //validate input

        } else if decision.to_lowercase() == "n"{
            println!("Loading Validation")
        }

        let username = 0;
    }

}

pub struct Profile {
    pub name: String,
    pub email: String,
    pub vault_id: String
}

// #derive[(Debug)]
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
