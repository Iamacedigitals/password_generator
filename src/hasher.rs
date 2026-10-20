use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
    Argon2,
};
use rand::{Rng, RngCore, rngs::OsRng};
use aes_gcm::{
    Aes256Gcm, AesGcm, Nonce, aead::{Aead, AeadCore, KeyInit, consts::U12, generic_array::GenericArray}
};

pub fn encrypt(
    password: String, text:String,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = hash_out(&password, &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let mut nonce_bytes:[u8; 12] = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let nonce:&GenericArray<u8, U12> = Nonce::from_slice(&nonce_bytes);

    let plaintext = text.as_bytes();

    let cipher_text = cipher.encrypt(nonce, plaintext.as_ref()).expect("Encryption Failed");
    Ok(cipher_text)
}

pub fn decrypt(
    key:&[u8; 32], nonce_bytes:&[u8; 12], cipher_text:Vec<u8>
) -> Result<String, Box<dyn std::error::Error>>{
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, cipher_text.as_ref()).unwrap();

    let message = String::from_utf8(plaintext)?;
    println!("{}", message);

    return Ok(message);
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

      // hmm please note that the cipher is not the encryption...
    // what is the cipher cipher_text and the encrypted blob
    
    // the cipher is the encryption tool that is configured by your secret key
    // the cipher text is the ouput produced when you encrypt a plaintext 
    // and the encrypted blob is a container that can hold the ciphertext, nonce and anyother metadata
    // now its best to have a nonce
    // a nonce is like a salt in Argon2ID. the salt helps in the encryotion key derivation process and the nonce helps makes the encryotion unique. 
    // what does s mean the encryption is unique...
    // remember that the salt is used to ensure that 2 master passwords dont/result in the same encryption key
    // the salt is stored in some remote database
    // same is the nonce, it is also stored into the database and is also recomputed upon opening the vault

    // now if multiple users have identical passwords, we must be able to identify which user is making a request
    // so thats why we need a primary key for the identifcation of the user that is requesting which is user's unique id


    // So the struct is going to be...
    // Vault metadata {id, salt, cipher, nonce}, blob {id, title, value, update_history, last_update}.. 

    // this contains the data and information that will be stored on the data base 

    // Process 
    // Encrypt{
    // generate or retreive the key
    // generate a fresh random nonce
    // store the nonce along with the ciphertext
    //}
    // Decrypt{
        // Retrieve the same secret key(where?)
        // extract the nonce and the ciphertext
        // Decrypt ad authentitcate the ciphertext
        // recover if the authentication succeeds
    // }
    // Never reuse a nonce with the same AES-GCM key
    // never store the encryption key along side the cipher text withut appropriate protection
    // you can store the nonce with the cipher text, it doesn't need to be secret
    // If the key is wrong or the cipher text has been modified, decryption should fail
