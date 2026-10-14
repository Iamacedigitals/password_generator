use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
    Argon2,
};
use rand::{RngCore, rngs::OsRng};
use aes_gcm::{
    aead::{
        Aead, AeadCore, KeyInit
    },
    Aes256Gcm
};

pub fn encrypt(
    text: String,
) -> Result<Aes256Gcm, Box<dyn std::error::Error>> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = hash_out(&text, &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    Ok(cipher)
}

pub fn hash(password: String){
    Argon2::default()
        .hash_password(password.as_bytes())
        .expect("Hash failed");
}

pub fn hash_out(password: &String, salt:&[u8],) -> Result<[u8; 32], argon2::Error>{
    let mut key = [0u8; 32];

    Argon2::default().hash_password_into(password.as_bytes(), salt, &mut key)
    .expect("Failed to hash Password");

    Ok(key)
}

pub fn verify(password: String, stored: &str) -> bool {
    let parsed = PasswordHash::new(stored).expect("invalid hash string");
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
  }
