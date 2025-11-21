# Authenticated Encryption with Associated Data (AEAD) - Symmetric (`symmetric/aead`)

This module within the `dcrypt-symmetric` crate provides high-level implementations and wrappers for Authenticated Encryption with Associated Data (AEAD) ciphers. It builds upon the core AEAD primitives found in `dcrypt-algorithms/src/aead` to offer more ergonomic APIs, including key management, nonce generation, and ciphertext packaging.

## Purpose

AEAD ciphers are essential for modern symmetric encryption as they provide:
1.  **Confidentiality**: Ensuring the plaintext is unreadable without the secret key.
2.  **Integrity**: Ensuring the plaintext has not been tampered with during transit or storage.
3.  **Authenticity**: Verifying that the message originated from a party possessing the secret key (for the message itself and optionally for unencrypted Associated Data).

## Implemented AEAD Schemes

The primary AEAD schemes exposed through this module are:

1.  **ChaCha20Poly1305 (`chacha20poly1305`)**:
    *   Wraps `algorithms::aead::chacha20poly1305::ChaCha20Poly1305`.
    *   Provides `ChaCha20Poly1305Cipher` and `XChaCha20Poly1305Cipher` (for extended nonces).
    *   Defines user-friendly key and nonce types: `ChaCha20Poly1305Key`, `ChaCha20Poly1305Nonce` (12-byte), and `XChaCha20Poly1305Nonce` (24-byte).
    *   Includes `ChaCha20Poly1305CiphertextPackage` for bundling nonce and ciphertext.
    *   Offers key derivation (`derive_chacha20poly1305_key`) and salt generation utilities.

2.  **AES-GCM (`gcm`)**:
    *   Wraps `algorithms::aead::gcm::Gcm` instantiated with AES block ciphers (`algorithms::block::aes::Aes128` or `Aes256`).
    *   Provides `Aes128Gcm` and `Aes256Gcm` cipher structures.
    *   Uses key types `Aes128Key` and `Aes256Key` (defined in `symmetric::aes::keys`).
    *   Defines `GcmNonce` (12-byte) and `AesCiphertextPackage`.

## Core Traits Implemented

The cipher structs in this module (e.g., `ChaCha20Poly1305Cipher`, `Aes128Gcm`) implement:

-   **`crate::cipher::SymmetricCipher`**:
    *   `type Key`: Specifies the dedicated key type (e.g., `ChaCha20Poly1305Key`).
    *   `new(key: &Self::Key) -> Result<Self>`: Constructor.
    *   `name() -> &'static str`: Algorithm name.

-   **`crate::cipher::Aead`**:
    *   `type Nonce`: Specifies the dedicated nonce type (e.g., `GcmNonce`).
    *   `encrypt(&self, nonce: &Self::Nonce, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>`.
    *   `decrypt(&self, nonce: &Self::Nonce, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>`.
    *   `generate_nonce() -> Self::Nonce`: Generates a cryptographically secure random nonce suitable for the algorithm.

## Key and Nonce Management

A key design goal of this module is to provide type-safe and convenient ways to handle keys and nonces:

-   **Key Types** (e.g., `ChaCha20Poly1305Key`, `Aes128Key`):
    *   Fixed-size arrays wrapped in structs that implement `Zeroize` and `ZeroizeOnDrop`.
    *   Provide `generate()` methods for creating random keys.
    *   Offer `to_secure_string()` and `from_secure_string()` for a simple, somewhat protected way to serialize/deserialize keys (primarily for illustrative or specific storage scenarios, not a replacement for robust key management systems).
-   **Nonce Types** (e.g., `ChaCha20Poly1305Nonce`, `GcmNonce`):
    *   Fixed-size arrays ensuring correct nonce length for the algorithm.
    *   Provide `generate()` methods.
    *   Offer `to_string()` (base64) and `from_string()` for serialization.
-   **Ciphertext Packages** (e.g., `ChaCha20Poly1305CiphertextPackage`):
    *   Structs that combine a nonce and its corresponding ciphertext.
    *   Provide `to_string()` and `from_string()` methods for a simple serialized format (e.g., `dcrypt-ALGORITHM:{nonce_b64}:{ciphertext_b64}`). This helps ensure the correct nonce is used during decryption.

## Usage Example (AES-256-GCM)

```rust
use dcrypt_symmetric::aes::{Aes256Gcm, Aes256Key, GcmNonce, AesCiphertextPackage};
use dcrypt_symmetric::cipher::{SymmetricCipher, Aead};
use dcrypt_symmetric::error::Result;

fn aes_gcm_example() -> Result<()> {
    // Generate key and cipher instance
    let (cipher, key) = Aes256Gcm::generate()?; // Helper that generates key and new()
    // Or:
    // let key = Aes256Key::generate();
    // let cipher = Aes256Gcm::new(&key)?;

    let plaintext = b"Sensitive data requiring strong authenticated encryption.";
    let aad = Some(b"Metadata that needs authentication but not encryption.");

    // Encrypt using a randomly generated nonce
    let (ciphertext_bytes, nonce_used) = cipher.encrypt_with_random_nonce(plaintext, aad)?;
    println!("AES-256-GCM Ciphertext (hex): {}", hex::encode(&ciphertext_bytes));
    println!("AES-256-GCM Nonce (base64): {}", nonce_used.to_string());

    // Decrypt
    let decrypted_bytes = cipher.decrypt(&nonce_used, &ciphertext_bytes, aad)?;
    assert_eq!(plaintext, decrypted_bytes.as_slice());
    println!("AES-256-GCM Decryption successful!");

    // Using CiphertextPackage
    let package = cipher.encrypt_to_package(plaintext, aad)?;
    let serialized_package = package.to_string();
    println!("Serialized Package: {}", serialized_package);

    let parsed_package = AesCiphertextPackage::from_string(&serialized_package)?;
    let decrypted_from_package = cipher.decrypt_package(&parsed_package, aad)?;
    assert_eq!(plaintext, decrypted_from_package.as_slice());
    println!("Decryption from package successful!");

    Ok(())
}
```
This module simplifies the use of AEAD ciphers by abstracting away some of the direct interactions with the `algorithms` crate primitives and providing more holistic types for keys, nonces, and packaged ciphertexts.