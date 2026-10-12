mod hasher; mod generate;
use hasher::{hash, verify};
use generate::generate_password;
use clap::{Parser, Subcommand};


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
    },
    Upload,
    Decrypt,
    Encrypt,
    Retrieve,
    Vault
}


fn main(){
    
    let cli = PswdGen::parse();
    let result = match cli.functions{
        Commands::Vault => format!("Vault Created"),
        Commands::Decrypt => format!("Decrypted (Password)"),
        Commands::Encrypt => format!("Hashed: (Password)"),
        Commands::Retrieve => format!("Retrieving: (Password name)"),
        Commands::Upload => format!("Uploading to supabase.."),
        Commands::Generate{length}=> format!("You generated: {}", generate_password(length)),
    };
    
    println!("{}", result);
}
