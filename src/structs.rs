use aes_gcm::{
    aead::{consts::U12, generic_array::GenericArray}
};
pub struct Metadata{
    pub id:String, // create get and set for id
    pub name: String, 
    pub salt:[u8; 16], // create getter and setter for salt 
    pub nonce_bytes:[u8; 12], 
    pub cipher_text: Vec<u8>,
}
pub struct Blob_data{
    pub title: String,
    pub id: String,
    pub value: String,
    pub last_update:String,
}

pub struct Encryption_data{
    pub key: [u8; 32], // implement getters and setters later
    pub nonce_bytes:GenericArray<u8, U12>, 
    pub cipher_text:Vec<u8>, 
    pub salt:[u8;16],
}