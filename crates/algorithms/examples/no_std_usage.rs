//! Example demonstrating `no_std` usage of dcrypt primitives
//!
//! This example shows how to use core algorithms in a `no_std` environment,
//! assuming an allocator is available (via the `alloc` feature).

// Standard library features (if available)
#[cfg(feature = "std")]
use std::{println, vec::Vec};

// No-std + alloc features
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{println, vec::Vec};

// Core dcrypt API traits and types
use dcrypt_api::error::{Error as CoreError, Result as CoreResult};
use dcrypt_api::traits::symmetric::{DecryptOperation, EncryptOperation};
use dcrypt_api::traits::SymmetricCipher as ApiSymmetricCipherTrait; // Import the trait
use dcrypt_api::Ciphertext as ApiCiphertext; // Import operation traits

// Algorithms crate components
use dcrypt_algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt_algorithms::hash::sha2::Sha256;
use dcrypt_algorithms::hash::HashFunction; // Import the trait for new, update, finalize
use dcrypt_algorithms::mac::hmac::Hmac;
use dcrypt_algorithms::types::{Digest, Nonce, SecretBytes};

// Randomness (requires a no_std compatible RNG or specific target features)
#[cfg(feature = "std")]
use rand::rngs::OsRng;
#[cfg(feature = "std")]
use rand::RngCore;

fn main() -> CoreResult<()> {
    println!("dcrypt no_std usage example (with alloc):");

    // --- Hashing with SHA-256 ---
    println!("\n--- SHA-256 Hashing ---");
    let data_to_hash = b"Hello, dcrypt no_std!";
    let mut hasher = Sha256::new(); // Now uses HashFunction::new()
    hasher
        .update(data_to_hash) // Now uses HashFunction::update()
        .map_err(CoreError::from)?;
    let digest_result = hasher
        .finalize() // Now uses HashFunction::finalize()
        .map_err(CoreError::from)?;
    let digest_bytes: Digest<32> = digest_result;

    println!(
        "Data: {:?}",
        core::str::from_utf8(data_to_hash).unwrap_or("Invalid UTF-8")
    );
    println!("SHA-256 Digest (hex): {}", digest_bytes.to_hex());

    // --- MAC with HMAC-SHA256 ---
    #[cfg(feature = "std")]
    {
        println!("\n--- HMAC-SHA256 MAC ---");
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let mac_key = SecretBytes::<32>::new(key_bytes);

        let message_to_mac = b"Authenticated message";
        let mut hmac = Hmac::<Sha256>::new(mac_key.as_ref()).map_err(CoreError::from)?;
        hmac.update(message_to_mac).map_err(CoreError::from)?;
        let tag_result = hmac.finalize().map_err(CoreError::from)?;
        let tag_bytes: Vec<u8> = tag_result;

        println!(
            "Message: {:?}",
            core::str::from_utf8(message_to_mac).unwrap_or("Invalid UTF-8")
        );
        println!("HMAC-SHA256 Tag (hex): {}", hex::encode(&tag_bytes));
    }

    // --- AEAD with ChaCha20Poly1305 ---
    #[cfg(feature = "std")]
    {
        println!("\n--- ChaCha20Poly1305 AEAD ---");
        let mut aead_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut aead_key_bytes);

        let aead_cipher = ChaCha20Poly1305::new(&aead_key_bytes);

        let mut aead_nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut aead_nonce_bytes);
        let aead_nonce = Nonce::<12>::new(aead_nonce_bytes);

        let plaintext = b"Secret payload";
        let aad_data_array = b"Associated Data"; // This is &'static [u8; 15]
        let aad: Option<&[u8; 15]> = Some(aad_data_array);

        // Encryption using the SymmetricCipher trait's builder pattern
        // Use UFCS to call the trait method
        let ciphertext_package: ApiCiphertext =
            <ChaCha20Poly1305 as ApiSymmetricCipherTrait>::encrypt(&aead_cipher)
                .with_nonce(&aead_nonce)
                .with_aad(aad.map_or(&[] as &[u8], |a| a as &[u8])) // Convert Option<&[u8;N]> to &[u8]
                .encrypt(plaintext)?;

        println!(
            "Plaintext: {:?}",
            core::str::from_utf8(plaintext).unwrap_or("Invalid UTF-8")
        );
        println!(
            "Ciphertext (hex): {}",
            hex::encode(ciphertext_package.as_ref())
        );

        // Decryption
        let decrypted_payload =
            <ChaCha20Poly1305 as ApiSymmetricCipherTrait>::decrypt(&aead_cipher)
                .with_nonce(&aead_nonce)
                .with_aad(aad.map_or(&[] as &[u8], |a| a as &[u8])) // Convert Option<&[u8;N]> to &[u8]
                .decrypt(&ciphertext_package)?;

        assert_eq!(plaintext, decrypted_payload.as_slice());
        println!("Decryption successful!");
    }

    println!("\nno_std example finished successfully.");
    Ok(())
}
