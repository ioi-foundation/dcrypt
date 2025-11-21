use dcrypt_algorithms::{
    aead::ChaCha20Poly1305,
    types::Nonce, // Import the generic Nonce type
};

fn main() {
    // Create a key and nonce
    let key_data = [0x42; 32];
    let nonce_data = [0x24; 12];

    // Create ChaCha20Poly1305 instance
    let cipher = ChaCha20Poly1305::new(&key_data);

    // Example plaintext and associated data
    let plaintext = b"Hello, dcrypt!";
    let aad = b"Additional data";

    // Create a Nonce<12> object (12-byte nonce for ChaCha20)
    let nonce = Nonce::<12>::new(nonce_data);

    // Encrypt using the nonce object
    let ciphertext = cipher.encrypt(&nonce, plaintext, Some(aad)).unwrap();
    println!("Ciphertext: {:?}", ciphertext);

    // Decrypt using the nonce object
    let decrypted = cipher.decrypt(&nonce, &ciphertext, Some(aad)).unwrap();
    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
}
