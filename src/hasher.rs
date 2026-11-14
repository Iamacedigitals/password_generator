use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
    Argon2,
};
use rand::{Rng, RngCore, rngs::OsRng};
use aes_gcm::{
    Aes256Gcm, AesGcm, Nonce, aead::{Aead, AeadCore, KeyInit, consts::U12, generic_array::GenericArray}
};
use crate::structs::{Encryption_data, Vault};

//pub encrypt_vault() -> Result<(), Box<dyn std::error::Error>>{}

pub fn encrypt_password(password: String) -> Result<Encryption_data, Box<dyn std::error::Error>>{
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = generate_key(&password, &salt)?; // unwraps the value of key

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("invalid key length: {e}"))?;

    let mut nonce_bytes = [0u8; 12]; // from consts::U12
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher_text = cipher
        .encrypt(nonce, password.as_bytes())
        .map_err(|e| format!("encryption failed: {e}"))?;

    Ok(Encryption_data {
        nonce_bytes: nonce.clone(),
        cipher_text,
        salt,
    })
}


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


pub fn generate_key(password: &str, salt:&[u8],) -> Result<[u8; 32], argon2::Error>{
    let mut key = [0u8; 32];

    Argon2::default().hash_password_into(password.as_bytes(), salt, &mut key)
    .expect("Failed to hash Password");
    Ok(key)
}



pub fn decrypt_blob(
    password:&str,
    vault: &Vault
) -> Result<bool, String> {

    // 1. Derive the encryption key using Argon2id
    let key = generate_key(&password, &vault.metadata.salt)
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    // 2. Initialize AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Cipher initialization failed: {e}"))?;

    let nonce = Nonce::from_slice(&vault.metadata.nonce_bytes);
    // 3. Decrypt and authenticate - password is gotten from user, cipher text is retrived from 
    Ok(cipher
        .decrypt(nonce, vault.metadata.cipher_text.as_ref()).is_ok()) 
}