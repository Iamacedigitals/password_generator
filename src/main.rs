mod hasher; mod structs; mod generate; mod login; mod sessions;
use login::{save_login};
use generate::{generate_password};
use structs::{Vault};
use clap::{Parser, Subcommand};
use hasher::encrypt_contents;
use std::process::ExitCode;


// to be continued .. lets first work on the cli

#[derive(Debug, Parser)]
struct PswdGen{
    #[command(subcommand)]
    functions: Commands
}

#[derive(Debug, Subcommand)]
enum Commands{
    CreateVault {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        email:String,
        #[arg(short, long)]
        password: String,
        
    },
    StartVault
}


fn main(){
    
    let cli = PswdGen::parse();
    let result = match cli.functions{
        // implement vault creation, password validations and text_storage
        // text is stored in a json file format where te=
        Commands::CreateVault{
            name, 
            email, 
            password
        } =>{

            let my_vault = Vault::new(name,email,password).unwrap();// fill up this stuff with the data from the encryption
            let id = my_vault.vault_profile.vault_id.clone();
            save_login(my_vault).unwrap();
            println!("Created vault");
            ExitCode::SUCCESS
        },
        Commands::StartVault=>{
            
            if let Err(e) = Vault::start_vault(){
                println!("{e}");
                std::process::exit(1); 
            };
            ExitCode:: SUCCESS
        }
    };
}



            /*creating a new vault gives us a struct with some properties... these properties include   
            vault profile, meta data and content;

            vault profile contains the user data and saves login information for further authentication. 
            It includes: Name, Email, vault id() Unique id not exactly the primary key. the Email is the primary key instead of letting the user guess their own usernames. 
            users can set their own custo user names later

            meta data includes the encryption data. 
            it includes the nonce bytes, cipher text and salt, 
            this is what will be used for the user authenication later on. its type is Encryption_Data

            content.. this containse the content and the information that is actuall being encrypted and its related meta data
            
            */