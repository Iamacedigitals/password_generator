use aes_gcm::{
    aead::{consts::U12, generic_array::GenericArray}
};
use crate::{
    generate::{generate_id, generate_password},
    hasher::{encrypt_contents, encrypt_password},
    json_parser::{save_login},
};
use serde::{Deserialize, Serialize};

use std::{io, io::{BufReader}, fs ,fs::{File}};
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
            name,
            email,              // can serve as recovery email
            vault_id: generate_id(16),
        },
        metadata,
        content: Vec::new(),
        })
    }

    pub fn start_vault() -> Result<(), Box<dyn std::error::Error>>{
        // Login Prompt for the vault in total
        println!("Hello User. Are You new here? If YES Click (Y) if No Click (N)");
        let mut input = String::new();
        println!("(Y)/(N): ");
        
        io::stdin()
        .read_line(&mut input)
        .expect("Failed to read String");

        let decision = input.trim().to_string();

        input.clear();

        // Input validation
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

            println!("Enter your new password / generate_random strong password: \n Best Practice is to use your own password;");
            println!("(N - personal password) / (R - random password): Enter Instruction to continue; ");

            io::stdin()
            .read_line(&mut input)
            .expect("Invalid: Couldnt Parse Entry");

            let should_random_generate  = input.trim().to_lowercase();

            input.clear();

            if should_random_generate == "n"{

                println!("
                Enter Your Personal password. \n 
                Please Ensure that the Length is minimum of 8 characters with at least one Cap, one lower and one special character \n
                ");

                io::stdin()
                .read_line(&mut input)
                .expect("Invalid: Couldnt Parse Entry");
                
                let password =  input.trim().to_string();

                // Encrypting master password. Saving to the json file called data.json
                
                let new_vault =  Vault::new(name, email, password.clone())?;

                save_login(new_vault);

                // profile(name, email, vault-id), 
                // metadata(nonce, salt, cipher_text), 
                // content, already contains the empty vector for contents

                // Start the saving process from main since save login takes in the vault
                input.clear();

            } else if should_random_generate == "r"{
                // randomly generates a password
                let password = generate_password(16);

                let new_vault = Vault::new(name, email, password)?;

                save_login(new_vault);
                // Encrypting master password. Saving to the json file called Passwords.json 
            }

            input.clear();
            // Sign-up validate ends here

        } else if decision.to_lowercase() == "n"{
            // code for validating existing users
            println!("Loading Validation")
        }

        let username = 0;
        Ok(())
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
    pub metadata: Encryption_data
}

