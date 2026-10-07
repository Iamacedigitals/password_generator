use rand::Rng;
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
        length:u8, //at least 12 elements
    },
    Upload,
    Decrypt,
    Hash,
    Retrieve
}


fn main(){
    
    let cli = PswdGen::parse();
    let result = match cli.functions{
        Commands::Decrypt => format!("Decrypted (Password)"),
        Commands::Hash => format!("Hashed: (Password)"),
        Commands::Retrieve => format!("Retrieving: (Password name)"),
        Commands::Upload => format!("Uploading to supabase.."),
        Commands::Generate{length}=> format!("You generated: {}", generate(length)),
    };
    
    println!("{}", result);
}

fn generate(len:u8) -> String {
    let characters = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/`~";
    let mut generator = rand::thread_rng();
    let mut collection: Vec<char> = Vec::new();
    let mut n = 0;
    while n < len{
        let random_index = generator.gen_range(0..characters.len());
        let value = characters[random_index] as char;
        collection.push(value);
        n+=1;
    }
    let password = collection.into_iter().collect();
    return password
}
