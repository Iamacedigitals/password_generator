mod hasher; 
mod generate;
use generate::generate_password;
use clap::{Parser, Subcommand};
use hasher::encrypt;

struct Metadata{
    id:String, 
    salt:[u8; 16], 
    nonce_bytes:[u8; 12],
    cipher_text: Vec<u8>
}
struct Blob_data{
    title: String,
    id: String,
    value: String,
    last_update:String
}
// to be continued .. lets first work on the cli

#[derive(Debug, Parser)]
struct PswdGen{
    #[command(subcommand)]
    functions: Commands
}

#[derive(Debug, Subcommand)]
enum Commands{
    Generate{
        #[arg(short, long, default_value_t = 12)]
        length:usize, //at least 12 elements
    }, // useful

    Upload,// useful for the supabase datablob saving
    Decrypt, // useful for testing
    Encrypt{
        #[arg(short, long)]
        password: String, 
        text:String
    },// useful for testing
    Retrieve,
    CreateVault {
        #[arg(short, long)]
        name: String,
        password: String,
    },
    Vault{
        name: String,
        master_password: String,
        add: String,
        remove: String // enter Id/title to remove
    }
}


fn main(){
    
    let cli = PswdGen::parse();
    let result = match cli.functions{
        // implement vault creation, password validations and text_storage
        // text is stored in a json file format where te=
        Commands::CreateVault{ name ,password} =>{
            format!("Created vault")
        },
        Commands::Vault{name, master_password, add, remove}=>{
            format!("Vault updated")
        }
        Commands::Decrypt => format!("Decrypted (Password)"),

        Commands::Encrypt{password, text} => {
            encrypt(password, text).unwrap();
            format!("Hashed: (Password)")
        },
        Commands::Retrieve => format!("Retrieving: (Password name)"),
        Commands::Upload => format!("Uploading to supabase.."),
        Commands::Generate{length}=> format!("You generated: {}", generate_password(length)),
    };
    
    println!("{}", result);
}
