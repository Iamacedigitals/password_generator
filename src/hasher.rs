use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
    Argon2,
};
use rand::{Rng, RngCore, rngs::OsRng};
use aes_gcm::{
    Aes256Gcm, AesGcm, Nonce, aead::{Aead, AeadCore, KeyInit, consts::U12, generic_array::GenericArray}
};
use crate::structs::Encryption_data;

//pub encrypt_vault() -> Result<(), Box<dyn std::error::Error>>{}

pub fn encrypt_contents(
    password: String,
    text: String,
) -> Result<Encryption_data, Box<dyn std::error::Error>> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = generate_key(&password, &salt)?; // unwraps the value of key

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("invalid key length: {e}"))?;

    let mut nonce_bytes = [0u8; 12]; // from consts::U12
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher_text = cipher
        .encrypt(nonce, text.as_bytes())
        .map_err(|e| format!("encryption failed: {e}"))?;

    Ok(Encryption_data {
        nonce_bytes: nonce.clone(),
        cipher_text,
        salt,
    })
}


pub fn generate_key(password: &String, salt:&[u8],) -> Result<[u8; 32], argon2::Error>{
    let mut key = [0u8; 32];

    Argon2::default().hash_password_into(password.as_bytes(), salt, &mut key)
    .expect("Failed to hash Password");
    Ok(key)
}



pub fn decrypt_blob(
    password:String,
    salt: &[u8],
    nonce_bytes: &GenericArray<u8, U12>,
    cipher_text: &[u8],
) -> Result<String, String> {

    // 1. Derive the encryption key using Argon2id
    let key = generate_key(&password, salt)
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    // 2. Initialize AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Cipher initialization failed: {e}"))?;

    // 3. Decrypt and authenticate
    let plaintext = cipher
        .decrypt(nonce_bytes, cipher_text)
        .map_err(|_| "Decryption failed: incorrect key or invalid ciphertext".to_string())?;

    // 4. Convert decrypted bytes into a String
    String::from_utf8(plaintext)
        .map_err(|e| format!("Invalid UTF-8 plaintext: {e}"))
}




/* 
fn decrypt(
    key:&[u8; 32], nonce_bytes:&[u8; 12], cipher_text:Vec<u8>
) -> Result<String, Box<dyn std::error::Error>>{
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, cipher_text.as_ref()).unwrap();

    let message = String::from_utf8(plaintext)?;
    println!("{}", message);

    return Ok(message);
}



fn hash(password: String){
    Argon2::default()
        .hash_password(password.as_bytes())
        .expect("Hash failed");
}

// to verify for argon2 id
pub fn verify(password: String, stored: &str) -> bool {
    let parsed = PasswordHash::new(stored).expect("invalid hash string");
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
  }

*/