# Symmetric Cryptography (`symmetric`)


The `dcrypt-symmetric` crate provides a high-level, secure, and easy-to-use API for common symmetric encryption algorithms within the dcrypt ecosystem. It is built upon the low-level cryptographic primitives in `dcrypt-algorithms` and integrates with `dcrypt-api` for a unified and robust error-handling system.

This crate is designed for both ease of use in common scenarios and the flexibility required for more complex applications, such as streaming large files.

-----

## \#\# Features

  * **Modern AEAD Ciphers**: Provides implementations for industry-standard Authenticated Encryption with Associated Data (AEAD) ciphers:
      * **ChaCha20-Poly1305**: As specified in RFC 8439.
      * **XChaCha20-Poly1305**: An extended nonce variant, ideal for applications requiring a large number of random nonces.
      * **AES-128-GCM** & **AES-256-GCM**: NIST-approved standard for high-performance, authenticated encryption.
  * **Secure Key Management**:
      * Secure random key generation.
      * Key derivation from passwords using **PBKDF2-HMAC-SHA256**.
      * Keys are wrapped in types that implement `Zeroize` to securely clear them from memory on drop.
      * Safe serialization format for storing and transmitting keys.
  * **Convenient Data Handling**:
      * **Ciphertext Packages**: An easy-to-use format that bundles the nonce and ciphertext together, simplifying storage and transmission.
      * Base64-encoded string representation for packages and keys.
  * **Streaming API**:
      * Memory-efficient streaming encryption and decryption for large files or data streams.
      * Handles nonce management automatically and securely across data chunks.
  * **Unified Error System**:
      * Leverages the `dcrypt-api` error system for consistent and descriptive error handling across the entire dcrypt library stack.
  * **`no_std` Compatibility**: Core features are available in `no_std` environments.

-----

## \#\# Installation

Add the crate to your `Cargo.toml` file:

```toml
[dependencies]
dcrypt-symmetric = "0.12.0-beta.1"
```

Or add it via the command line:

```sh
cargo add dcrypt-symmetric
```

-----

## \#\# Usage Examples

### \#\#\# Basic Encryption & Decryption (AES-256-GCM)

This example shows a simple encrypt/decrypt cycle using `Aes256Gcm`.

```rust
use dcrypt::symmetric::{Aes256Gcm, Aes256Key, Aead, SymmetricCipher, Result};

fn main() -> Result<()> {
    // 1. Generate a new, random key for AES-256-GCM.
    let key = Aes256Key::generate();

    // 2. Create a new cipher instance.
    let cipher = Aes256Gcm::new(&key)?;

    // 3. The data to be encrypted.
    let plaintext = b"this is a very secret message";
    let associated_data = b"metadata"; // Optional associated data

    // 4. Generate a random nonce. It MUST be unique for each encryption with the same key.
    let nonce = Aes256Gcm::generate_nonce();

    // 5. Encrypt the data.
    println!("Encrypting: '{}'", String::from_utf8_lossy(plaintext));
    let ciphertext = cipher.encrypt(&nonce, plaintext, Some(associated_data))?;
    println!("Ciphertext (hex): {}", hex::encode(&ciphertext));


    // 6. Decrypt the data.
    let decrypted_plaintext = cipher.decrypt(&nonce, &ciphertext, Some(associated_data))?;
    println!("Decrypted: '{}'", String::from_utf8_lossy(&decrypted_plaintext));


    // 7. Verify the result.
    assert_eq!(plaintext, &decrypted_plaintext[..]);

    // Decryption will fail if the key, nonce, ciphertext, or AAD is incorrect.
    let wrong_key = Aes256Key::generate();
    let wrong_cipher = Aes256Gcm::new(&wrong_key)?;
    assert!(wrong_cipher.decrypt(&nonce, &ciphertext, Some(associated_data)).is_err());
    println!("Decryption with wrong key failed as expected.");

    Ok(())
}
```

### \#\#\# Packaged Encryption (ChaCha20Poly1305)

The library provides a convenient package format that bundles the nonce with the ciphertext, making it easy to store or transmit.

```rust
use dcrypt::symmetric::{
    ChaCha20Poly1305Cipher,
    ChaCha20Poly1305Key,
    ChaCha20Poly1305CiphertextPackage,
    SymmetricCipher,
    Result
};

fn main() -> Result<()> {
    // 1. Generate a key and create a cipher instance.
    let (cipher, key) = ChaCha20Poly1305Cipher::generate()?;

    let plaintext = b"data packaged for transport";

    // 2. Encrypt the data directly into a package.
    // This generates a random nonce internally and bundles it with the ciphertext.
    let package = cipher.encrypt_to_package(plaintext, None)?;

    // 3. The package can be serialized to a string for easy storage or transmission.
    let serialized_package = package.to_string();
    println!("Serialized Package: {}", serialized_package);

    // ... later, on another machine or after retrieving from storage ...

    // 4. Create a new cipher instance with the same key.
    let receiving_cipher = ChaCha20Poly1305Cipher::new(&key)?;

    // 5. Deserialize the package from the string.
    let parsed_package = ChaCha20Poly1305CiphertextPackage::from_string(&serialized_package)?;

    // 6. Decrypt from the package.
    let decrypted_plaintext = receiving_cipher.decrypt_package(&parsed_package, None)?;

    println!("Decrypted from package: '{}'", String::from_utf8_lossy(&decrypted_plaintext));
    assert_eq!(plaintext, &decrypted_plaintext[..]);

    Ok(())
}
```

### \#\#\# Key Derivation from a Password

Derive a strong cryptographic key from a user-provided password using PBKDF2.

```rust
use dcrypt::symmetric::{aes::derive_aes128_key, aes::generate_salt, Result};

fn main() -> Result<()> {
    let password = b"a-very-secure-password-123";
    
    // Generate a random salt. The salt should be stored alongside the encrypted data.
    let salt = generate_salt(16);

    // Set the number of iterations. Higher is more secure but slower.
    // OWASP recommends at least 100,000.
    let iterations = 250_000;

    // Derive a 128-bit key for AES.
    let derived_key = derive_aes128_key(password, &salt, iterations)?;
    
    println!("Successfully derived AES-128 key from password.");
    // This key can now be used to instantiate an Aes128Gcm cipher.

    Ok(())
}
```

### \#\#\# Streaming File Encryption

For large files, the streaming API encrypts and decrypts data in chunks, keeping memory usage low. This example uses `std::io::Cursor` to simulate file I/O.

```rust
use std::io::Cursor;
use dcrypt::symmetric::{
    streaming::chacha20poly1305::{ChaCha20Poly1305EncryptStream, ChaCha20Poly1305DecryptStream},
    streaming::{StreamingEncrypt, StreamingDecrypt},
    ChaCha20Poly1305Key,
    Result
};

fn main() -> Result<()> {
    // 1. Generate a key. In a real app, this would be loaded or derived.
    let key = ChaCha20Poly1305Key::generate();
    let associated_data = b"streaming-file-example";

    // 2. Simulate a large input file and an output buffer for encrypted data.
    let source_data = b"This is the first part of a very large file. ".repeat(1000);
    let mut source = Cursor::new(source_data);
    let mut encrypted_dest = Vec::new();

    // 3. Create an encryption stream.
    {
        let mut encrypt_stream = ChaCha20Poly1305EncryptStream::new(
            &mut encrypted_dest,
            &key,
            Some(associated_data),
        )?;
        
        // Pipe data from the source to the encryption stream.
        std::io::copy(&mut source, &mut encrypt_stream)?;
    } // The stream is finalized when it goes out of scope.

    println!("Original size: {} bytes", source.get_ref().len());
    println!("Encrypted size: {} bytes", encrypted_dest.len());

    // 4. Now, decrypt the data from the stream.
    let mut encrypted_source = Cursor::new(encrypted_dest);
    let mut decrypt_stream = ChaCha20Poly1305DecryptStream::new(
        &mut encrypted_source,
        &key,
        Some(associated_data),
    )?;

    // 5. Read the decrypted data back.
    let mut decrypted_data = Vec::new();
    decrypt_stream.read_to_end(&mut decrypted_data)?;
    
    println!("Decrypted size: {} bytes", decrypted_data.len());

    // 6. Verify the integrity of the data.
    assert_eq!(source.get_ref(), &decrypted_data);
    println!("Successfully encrypted and decrypted stream!");

    Ok(())
}

```

-----

## \#\# License

This crate is licensed under the [Apache 2.0 License](https://opensource.org/license/apache-2-0).