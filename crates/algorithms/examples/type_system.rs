//! Example demonstrating dcrypt's type system for keys, nonces, etc.

// Standard library features (if available)
#[cfg(feature = "std")]
use std::println;

// No-std + alloc features
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::println;

// Core dcrypt API traits and types
use dcrypt_api::error::{Error as CoreError, Result as CoreResult};

// Algorithms crate components and types
use dcrypt_algorithms::types::{
    // Algorithm marker types
    algorithms::{Aes128, ChaCha20Poly1305, Ed25519},
    key::SymmetricAlgorithm, // For SymmetricKey's A parameter
    // Compatibility traits (examples)
    nonce::ChaCha20Compatible,
    salt::HkdfCompatible,
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    Nonce,
    RandomGeneration, // Added RandomGeneration
    Salt,
    SecretBytes,
    SymmetricKey,
};

// Randomness (requires 'std' or a no_std RNG)
#[cfg(feature = "std")]
use rand::rngs::OsRng;

fn main() -> CoreResult<()> {
    println!("dcrypt Type System Example:");

    // --- SymmetricKey Example ---
    let aes128_key_bytes = [0x42u8; 16];
    let aes_key: SymmetricKey<Aes128, 16> = SymmetricKey::new(aes128_key_bytes);
    println!("Created AES-128 Key: {:?}", aes_key);
    assert_eq!(aes_key.as_ref().len(), Aes128::KEY_SIZE);

    // --- Nonce Example ---
    let chacha_nonce_bytes = [0xABu8; 12];
    let chacha_nonce: Nonce<12> = Nonce::new(chacha_nonce_bytes);
    // We can assert its compatibility (though this is mainly for generic functions)
    fn use_chacha_nonce<N: ChaCha20Compatible + AsRef<[u8]>>(n: &N) {
        // Added AsRef<[u8]>
        println!(
            "Using ChaCha20 compatible nonce of size: {}",
            n.as_ref().len()
        );
    }
    use_chacha_nonce(&chacha_nonce);
    println!("Created ChaCha20 Nonce: {:?}", chacha_nonce);

    // --- Salt Example ---
    let hkdf_salt_bytes = [0xCDu8; 16];
    let hkdf_salt: Salt<16> = Salt::new(hkdf_salt_bytes);
    fn use_hkdf_salt<S: HkdfCompatible + AsRef<[u8]>>(s: &S) {
        // Added AsRef<[u8]>
        println!("Using HKDF compatible salt of size: {}", s.as_ref().len());
    }
    use_hkdf_salt(&hkdf_salt);
    println!("Created HKDF Salt: {:?}", hkdf_salt);

    // --- Asymmetric Keys Example (Ed25519) ---
    let ed_sk_bytes = [0x11u8; 32];
    let ed_secret_key: AsymmetricSecretKey<Ed25519, 32> = AsymmetricSecretKey::new(ed_sk_bytes);
    println!("Created Ed25519 Secret Key: {:?}", ed_secret_key);

    let ed_pk_bytes = [0xEEu8; 32];
    let ed_public_key: AsymmetricPublicKey<Ed25519, 32> = AsymmetricPublicKey::new(ed_pk_bytes);
    println!("Created Ed25519 Public Key: {:?}", ed_public_key);

    // --- SecretBytes Example ---
    let secret_data = [0x01, 0x02, 0x03, 0x04];
    let secret_bytes: SecretBytes<4> = SecretBytes::new(secret_data);
    println!("Created SecretBytes<4>: {:?}", secret_bytes);
    assert_eq!(secret_bytes.as_ref(), &[0x01, 0x02, 0x03, 0x04]);

    // --- Random Generation (if std is enabled) ---
    #[cfg(feature = "std")]
    {
        let mut rng = OsRng;
        // Use RandomGeneration::random explicitly for types that implement it
        let random_key: SymmetricKey<ChaCha20Poly1305, 32> =
            RandomGeneration::random(&mut rng).map_err(CoreError::from)?;
        println!("Generated random ChaCha20Poly1305 Key: {:?}", random_key);

        let random_nonce: Nonce<12> =
            RandomGeneration::random(&mut rng).map_err(CoreError::from)?;
        println!("Generated random Nonce<12>: {:?}", random_nonce);
    }

    println!("\nType system example finished successfully.");
    Ok(())
}
