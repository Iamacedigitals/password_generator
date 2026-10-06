use clap::parser;
use rand::Rng;

fn main (){
    let random_number = rand::thread_rng().gen_range(0..=15);
    println!("{}", random_number);
}