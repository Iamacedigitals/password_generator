use serde::{Deserialize, Serialize};
use std::{fs::{self, File}, io::{self, BufReader, BufWriter, Error, Write}, process::ExitCode};
use crate::{hasher::decrypt_blob, structs::{Content, Encryption_data, Profile, Vault}, generate::generate_password};

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

pub fn login() -> Result<ExitCode, Box<dyn std::error::Error>>{
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
                
                let password =  input.trim().to_string(); // add password validation to it later

                // Encrypting master password. Saving to the json file called data.json
                
                let new_vault =  Vault::new(name, email, password.clone())?;

                input.clear();

                match save_login(new_vault){
                    Ok(_value) => {
                        println!("Vault Created");
                        return Ok(ExitCode::SUCCESS)
                    }
                    Err(e) => {
                        println!("{e}");
                        return Ok(ExitCode::FAILURE)
                    }
                };

            } else if should_random_generate == "r"{
                // randomly generates a password
                let password = generate_password(16);

                let new_vault = Vault::new(name, email, password)?;
                
                match save_login(new_vault){
                    Ok(_value) => {
                        println!("Vault Created");
                        return Ok(ExitCode::SUCCESS)
                    }
                    Err(e) => {
                        println!("{e}");
                        return Ok(ExitCode::FAILURE)
                    }
                };
                // Encrypting master password. Saving to the json file called Passwords.json 
            } else {
                println!("Invalid Entry");
                Ok(ExitCode::FAILURE)
            }

            // Sign-up validate ends here

        } else if decision.to_lowercase() == "n"{
            // code for validating existing users
            println!("Loading Validation__");
            println!("Enter Your Email: ");

            io::stdin()
            .read_line(&mut input)
            .expect("Failed to read String");

            let email = input.trim().to_string();

            input.clear();

            println!("Enter Your Password: ");
            io::stdin()
            .read_line(&mut input)
            .expect("Failed to read String");

            let password = input.trim().to_string();

            input.clear();

            let my_vault = validate_login(email, password.as_str())?.ok_or("Failed to Validate")?;
            
            println!("Accont Login Successful: Welcome Back {}, id {}", my_vault.vault_profile.name, my_vault.vault_profile.vault_id);
            return Ok(ExitCode::SUCCESS)
                
        }else{
            println!("Invalid Entry");
            Ok(ExitCode::SUCCESS)
        }

}

pub fn save_login(mut new_vault: Vault) -> Result<(), Box<dyn std::error::Error>> {
    new_vault.vault_profile.email = normalize_email(&new_vault.vault_profile.email);

    let mut vaults = load_vaults()?;

    if vaults.iter().any(|v| normalize_email(&v.vault_profile.email) == new_vault.vault_profile.email) {
        return Err("A vault already exists for this email. Please log in instead.".into());
    }

    vaults.push(new_vault);

    if let Err(e) = save_vaults(&vaults){
        println!("Failed to save vault: {e}");
        return Ok(())
    };
    Ok(())
}

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}
pub fn validate_login(email: String, master_password: &str) -> Result<Option<Vault>, Box<dyn std::error::Error>> {
    let email = normalize_email(&email);
    let vaults = load_vaults()?;

    let Some(vault) = vaults
        .into_iter()
        .find(|v| normalize_email(&v.vault_profile.email) == email)
    else {
        return Ok(None);
    };

    if decrypt_blob(master_password, &vault)? {
        Ok(Some(vault))
    } else {
        Ok(None)
    }
}