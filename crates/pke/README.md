# Public Key Encryption

[![Crates.io](https://img.shields.io/crates/v/dcrypt-pke.svg)](https://crates.io/crates/dcrypt-pke)
[![Docs.rs](https://docs.rs/dcrypt-pke/badge.svg)](https://docs.rs/dcrypt-pke)

Part of the dcrypt library, this crate provides Public Key Encryption (PKE) schemes. It specifically contains implementations of the Elliptic Curve Integrated Encryption Scheme (ECIES).

The library is designed with a focus on security, modularity, and `no_std` compatibility (with `alloc`), ensuring it can be used in a wide range of Rust projects, including those in constrained environments like embedded systems or WebAssembly.

## Features

*   **ECIES Implementations**: Provides ECIES using several standard NIST elliptic curves.
*   **Authenticated Encryption**: All schemes use an Authenticated Encryption with Associated Data (AEAD) cipher to ensure both confidentiality and integrity of messages.
*   **Secure Key Derivation**: Utilizes HKDF (HMAC-based Key Derivation Function) with various SHA-2 hash functions to derive strong symmetric keys from the elliptic curve shared secret.
*   **Modern AEAD Ciphers**: Employs `ChaCha20Poly1305` and `AES-256-GCM` for the symmetric encryption part of the ECIES protocol.
*   **`no_std` Support**: Fully compatible with `no_std` environments by using the `alloc` crate for necessary dynamic data structures.
*   **Consistent API**: Adheres to the `Pke` trait from `dcrypt-api`, providing a uniform interface for key generation, encryption, and decryption.

## Supported Schemes

The crate provides the following ECIES configurations, each corresponding to a specific NIST curve and a set of cryptographic primitives:

| Struct | Elliptic Curve | Key Derivation Function | AEAD Cipher |
| :--- | :--- | :--- | :--- |
| `EciesP192` | NIST P-192 | HKDF-SHA256 | ChaCha20Poly1305 |
| `EciesP224` | NIST P-224 | HKDF-SHA256 | ChaCha20Poly1305 |
| `EciesP256` | NIST P-256 | HKDF-SHA256 | ChaCha20Poly1305 |
| `EciesP384` | NIST P-384 | HKDF-SHA384 | AES-256-GCM |
| `EciesP521` | NIST P-521 | HKDF-SHA512 | AES-256-GCM |

## Installation

Add the crate to your `Cargo.toml` file:

```toml
[dependencies]
dcrypt-pke = "0.12.0-beta.1"
# For random number generation, required for keypair generation and encryption
rand = "0.8"
```

## Usage Example

Here is a basic example of how to generate a keypair, encrypt a message, and then decrypt it using `EciesP256`.

```rust
use dcrypt::pke::EciesP256;
use dcrypt::api::traits::Pke;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. A cryptographically secure random number generator is required.
    let mut rng = OsRng;

    // 2. Generate a keypair for the message recipient.
    let (public_key, secret_key) = EciesP256::keypair(&mut rng)?;

    // 3. Define a plaintext message and optional associated data (AAD).
    // AAD is authenticated but not encrypted.
    let plaintext = b"This is a secret message that must be kept confidential.";
    let aad = Some(b"Authenticated metadata".as_slice());

    // 4. Encrypt the message using the recipient's public key.
    // A fresh ephemeral keypair is generated for each encryption.
    println!("Encrypting message...");
    let ciphertext = EciesP256::encrypt(&public_key, plaintext, aad, &mut rng)?;

    // 5. The recipient uses their secret key to decrypt the message.
    println!("Decrypting message...");
    let decrypted_plaintext = EciesP256::decrypt(&secret_key, &ciphertext, aad)?;

    // 6. Verify that the decrypted message matches the original plaintext.
    assert_eq!(plaintext, decrypted_plaintext.as_slice());

    println!("\nSuccess! The original and decrypted messages match.");
    println!("Original:  {}", std::str::from_utf8(plaintext)?);
    println!("Decrypted: {}", std::str::from_utf8(&decrypted_plaintext)?);

    Ok(())
}```

## `no_std` Support

This crate is designed to work in `no_std` environments. To use it this way, you must disable the default features and enable the `alloc` feature in your `Cargo.toml`. This will replace the standard library dependency with the `alloc` crate.

```toml
[dependencies]
dcrypt-pke = { version = "0.12.0-beta.1", default-features = false, features = ["alloc"] }
rand = { version = "0.8", default-features = false }
```

## License

This crate is licensed under the terms of the workspace license. (Please refer to the license file in the root of the `dcrypt` repository).