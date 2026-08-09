# Symmetric Cipher Traits (`symmetric/cipher.rs`)

This file defines the core traits that all symmetric encryption algorithms within the `dcrypt-symmetric` crate should implement. These traits establish a consistent interface for creating and using symmetric ciphers, particularly focusing on Authenticated Encryption with Associated Data (AEAD) schemes.

## Core Traits

1.  **`SymmetricCipher`**:
    *   **Purpose**: This is the base trait for all symmetric encryption algorithms. It defines the minimal contract for a symmetric cipher.
    *   **Associated Types**:
        *   `type Key`: Specifies the concrete key type used by the cipher (e.g., `Aes128Key`, `ChaCha20Poly1305Key`). This key type is expected to handle its own security properties like zeroization.
    *   **Methods**:
        *   `new(key: &Self::Key) -> Result<Self> where Self: Sized`: A constructor that takes a reference to the cipher's specific key type and returns a new cipher instance or an error (e.g., if the key is invalid, though type safety for `Self::Key` should ideally prevent this).
        *   `name() -> &'static str`: Returns a static string slice representing the human-readable name of the cipher (e.g., "AES-128-GCM", "ChaCha20Poly1305").

2.  **`Aead` (Authenticated Encryption with Associated Data)**:
    *   **Purpose**: This trait extends `SymmetricCipher` and is implemented by ciphers that provide authenticated encryption. AEAD ciphers ensure confidentiality, integrity, and authenticity of the data.
    *   **Associated Types**:
        *   `type Nonce`: Specifies the concrete nonce (or IV) type used by the AEAD cipher (e.g., `GcmNonce`, `ChaCha20Poly1305Nonce`). This type should enforce correct nonce sizes.
    *   **Methods**:
        *   `encrypt(&self, nonce: &Self::Nonce, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>`: Encrypts the given `plaintext`.
            *   `nonce`: A nonce unique for each encryption with the same key.
            *   `plaintext`: The data to be encrypted.
            *   `aad`: Optional Associated Data that will be authenticated but not encrypted.
            *   Returns the ciphertext (which typically includes the authentication tag).
        *   `decrypt(&self, nonce: &Self::Nonce, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>>`: Decrypts the given `ciphertext`.
            *   `nonce`: The same nonce used during encryption.
            *   `ciphertext`: The encrypted data, including the authentication tag.
            *   `aad`: Optional Associated Data that was authenticated during encryption.
            *   Returns the original plaintext if decryption and authentication are successful. Otherwise, returns an error (e.g., `Error::Primitive(PrimitiveError::Authentication { .. })` if the tag is invalid).
        *   `generate_nonce(rng: &mut impl CryptoRng) -> Result<Self::Nonce>`: A static method that obtains an appropriate nonce from caller-owned cryptographic randomness.

## How These Traits Are Used

-   Cipher implementations like `Aes128Gcm` or `ChaCha20Poly1305Cipher` in the `symmetric::aead` module implement both `SymmetricCipher` and `Aead`.
-   They associate their specific key types (e.g., `Aes128Key`) and nonce types (e.g., `GcmNonce`).
-   This allows users to write generic code that can work with any AEAD cipher conforming to these traits, while still benefiting from the type safety of specific key/nonce types.

**Example of Trait Usage (Conceptual):**

```rust
use dcrypt_symmetric::cipher::{SymmetricCipher, Aead};
use dcrypt_symmetric::error::Result;
use dcrypt_internal::CryptoRng;
use std::fmt::Debug; // For printing

// A generic function that can encrypt data using any AEAD cipher
fn perform_aead_encryption<C, R>(
    rng: &mut R,
    key: &C::Key,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<()>
where
    C: SymmetricCipher + Aead, // Cipher C must implement both traits
    C::Key: Debug, // For printing (keys usually redact themselves)
    C::Nonce: Debug, // For printing
    R: CryptoRng + ?Sized,
{
    let cipher = C::new(key)?;
    let nonce = C::generate_nonce(rng)?;

    println!("Using cipher: {}", C::name());
    println!("With key: {:?}", key); // Key's Debug impl should redact
    println!("Generated nonce: {:?}", nonce);

    let ciphertext = cipher.encrypt(&nonce, plaintext, aad)?;
    println!("Ciphertext length: {}", ciphertext.len());

    let decrypted = cipher.decrypt(&nonce, &ciphertext, aad)?;
    assert_eq!(plaintext, decrypted.as_slice());
    println!("Generic AEAD encryption and decryption successful for {}!", C::name());

    Ok(())
}

// Example with a concrete cipher would then call this:
// use dcrypt_symmetric::aead::gcm::Aes128Gcm;
// use dcrypt_symmetric::aes::Aes128Key;
// fn concrete_example(rng: &mut impl CryptoRng) -> Result<()> {
//     let my_key = Aes128Key::generate(rng)?;
//     perform_aead_encryption::<Aes128Gcm, _>(rng, &my_key, b"test data", None)
// }
```

These traits form the core API contract for symmetric ciphers within the `dcrypt-symmetric` crate, promoting consistency and safety.
