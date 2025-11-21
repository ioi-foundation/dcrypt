# AES Ciphers - Symmetric (`symmetric/aes`)

This module within the `dcrypt-symmetric` crate focuses on providing high-level interfaces and key management utilities specifically for AES (Advanced Encryption Standard) based ciphers. It primarily re-exports and builds upon AES-GCM functionalities from `symmetric::aead::gcm` and defines AES-specific key types.

## Core Functionality

1.  **AES Key Types (`keys.rs`)**:
    *   **`Aes128Key`**: A type-safe wrapper for 128-bit (16-byte) AES keys.
        *   Implements `Clone`, `Zeroize`, and `ZeroizeOnDrop`.
        *   Provides `new([u8; 16])`, `generate()` (random key), `as_bytes()`.
        *   Includes `to_secure_string()` and `from_secure_string()` for a basic, somewhat protected string serialization (base64 encoded with a prefix).
    *   **`Aes256Key`**: A type-safe wrapper for 256-bit (32-byte) AES keys.
        *   Similar features and security properties as `Aes128Key`.
    *   **Key Derivation**:
        *   `derive_aes128_key(password: &[u8], salt: &[u8], iterations: u32) -> Result<Aes128Key>`
        *   `derive_aes256_key(password: &[u8], salt: &[u8], iterations: u32) -> Result<Aes256Key>`
        *   Both use PBKDF2-HMAC-SHA256 for deriving keys from passwords.
    *   **`generate_salt(size: usize) -> Vec<u8>`**: A utility to generate a random salt for key derivation.

2.  **Re-exported AEAD Ciphers**:
    This module re-exports AES-GCM cipher implementations from `symmetric::aead::gcm`:
    *   **`Aes128Gcm`**: Provides AES-128 in GCM mode.
    *   **`Aes256Gcm`**: Provides AES-256 in GCM mode.
    *   **`GcmNonce`**: The 12-byte nonce type suitable for AES-GCM.
    *   **`AesCiphertextPackage`**: A struct to bundle `GcmNonce` and the ciphertext.
    *   Convenience functions like `aes128_encrypt`, `aes128_decrypt`, `aes256_encrypt_package`, etc., are also re-exported. These functions often combine key generation, cipher instantiation, and encryption/decryption into single calls.

3.  **Re-exported Traits**:
    *   `crate::cipher::SymmetricCipher`
    *   `crate::cipher::Aead`
    These traits are implemented by `Aes128Gcm` and `Aes256Gcm`.

## Purpose

The `symmetric::aes` module aims to:
-   Provide dedicated, type-safe key objects (`Aes128Key`, `Aes256Key`) for AES, enhancing security by ensuring correct key sizes and automatic zeroization.
-   Offer convenient utilities for AES key management, including random generation and password-based derivation.
-   Serve as a clear entry point for users looking to use AES-based authenticated encryption (specifically AES-GCM) within the dcrypt library.
-   Abstract the direct use of `algorithms::block::aes` and `algorithms::aead::gcm` primitives for common AES-GCM use cases.

## Usage Example (Using `Aes128Gcm` re-exported here)

```rust
use dcrypt_symmetric::aes::{Aes128Gcm, Aes128Key, GcmNonce, aes128_encrypt_package, aes128_decrypt_package};
use dcrypt_symmetric::cipher::{SymmetricCipher, Aead}; // Core traits from this crate
use dcrypt_symmetric::error::Result;

fn main_aes_gcm_example() -> Result<()> {
    // Method 1: Explicit key generation and cipher instantiation
    let key1 = Aes128Key::generate();
    let cipher1 = Aes128Gcm::new(&key1)?; // Create cipher with the key

    let plaintext = b"Secret data for AES-128-GCM.";
    let aad = Some(b"Associated data.");

    let nonce1 = Aes128Gcm::generate_nonce(); // Generate a nonce
    let ciphertext1 = cipher1.encrypt(&nonce1, plaintext, aad)?;
    let decrypted1 = cipher1.decrypt(&nonce1, &ciphertext1, aad)?;
    assert_eq!(plaintext, decrypted1.as_slice());
    println!("Method 1: Encryption/Decryption successful!");

    // Method 2: Using convenience package functions
    let (package, key2) = aes128_encrypt_package(plaintext, aad)?;
    let serialized_package = package.to_string();
    println!("Serialized Package: {}", serialized_package);

    // (Store key2 and serialized_package securely)

    let parsed_package = dcrypt_symmetric::aead::gcm::AesCiphertextPackage::from_string(&serialized_package)?;
    let decrypted2 = aes128_decrypt_package(&parsed_package, &key2, aad)?;
    assert_eq!(plaintext, decrypted2.as_slice());
    println!("Method 2: Package Encryption/Decryption successful!");

    Ok(())
}
```

This module simplifies working with AES AEAD ciphers by providing specialized types and higher-level abstractions. For direct block cipher operations (AES-CBC, AES-CTR without GCM's authentication), one would use the primitives in `dcrypt-algorithms::block`.