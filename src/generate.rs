use rand::Rng;
 
fn generate_password(len:u8) -> String {
    let characters = b"abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/`~";
    let Upper_case = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
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
