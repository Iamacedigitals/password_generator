use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
    Argon2,
};


pub fn hash(password: String) -> String {
    Argon2::default()
        .hash_password(password.as_bytes())
        .expect("Hash failed")
        .to_string()
}

pub fn verify(password: String, stored: &str) -> bool {
    let parsed = PasswordHash::new(stored).expect("invalid hash string");
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
  }
