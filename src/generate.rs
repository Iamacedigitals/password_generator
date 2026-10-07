use rand::Rng;
use rand::seq::SliceRandom;

 fn generate_password(len:usize) -> String {
    let mut rng = rand::thread_rng();

    let all_chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/`~";
    let upper_case = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let lower_case = b"abcdefghijklmnopqrstuvwxyz";
    let numbers = b"0123456789";
    let special_chr = b"!@#$%^&*()_+-=[]{}|;:',.<>?/`~";

    let mut collection: Vec<char> = Vec::new();

    // guaranteed characters
    collection.push(upper_case[rng.gen_range(0..upper_case.len())] as char);
    collection.push(lower_case[rng.gen_range(0..lower_case.len())] as char);
    collection.push(special_chr[rng.gen_range(0..special_chr.len())] as char);
    collection.push(numbers[rng.gen_range(0..numbers.len())] as char);

    // fill the rest
    while collection.len() < len {
        collection.push(all_chars[rng.gen_range(0..all_chars.len())] as char);
    }

    collection.shuffle(&mut rng); // so the upper/lower aren't always first
    collection.into_iter().collect()
 }
