pub struct Metadata{
    pub id:String, // create get and set for id
    pub name: String, 
    pub salt:[u8; 16], // create getter and setter for salt 
    pub nonce_bytes:[u8; 12], 
    pub cipher_text: Vec<u8>
}
pub struct Blob_data{
    pub title: String,
    pub id: String,
    pub value: String,
    pub last_update:String
}