# dcrypt - Pure Rust Cryptographic Library

dcrypt is a pure Rust cryptographic library implementing both traditional and post-quantum cryptographic algorithms. Built with security, modularity, and usability as core principles, it eliminates foreign function interfaces (FFI) to ensure memory safety and cross-platform compatibility.

This documentation provides an overview of the dcrypt project structure, its core components, and guidance on using its cryptographic functionalities.

## Key Features

-   **Pure Rust Implementation**: All algorithms implemented entirely in Rust without FFI, enhancing memory safety and portability.
-   **Comprehensive Algorithm Support**: Includes a wide range of traditional (AES, SHA, HMAC, RSA, ECDSA, etc.) and post-quantum cryptographic algorithms (Kyber, Dilithium, Falcon, etc.).
-   **Modular Architecture**: Organized as a Rust workspace with specialized crates, promoting maintainability and clear separation of concerns.
-   **Strong Type Safety**: Leverages Rust's type system with const generics and marker traits to prevent misuse of cryptographic primitives and ensure correct API usage.
-   **Memory Protection**: Prioritizes secure memory handling, including automatic zeroization of sensitive data (keys, intermediate values) using the `zeroize` crate and custom secure types.
-   **Constant-Time Operations**: Implements critical cryptographic operations in constant time to mitigate timing side-channel attacks, guided by a formal [Constant-Time Implementation Policy](./CONSTANT_TIME_POLICY.md).
-   **Hybrid Cryptography**: Offers ready-to-use hybrid schemes combining traditional and post-quantum algorithms for robust, forward-looking security.
-   **Cross-Platform**: Designed to work in both `std` (standard library) and `no_std` (embedded) environments, with features for `wasm` and `simd` acceleration.

## Project Structure

dcrypt is organized into the following main crates:

-   **`dcrypt_docs/api/README.md`**: Defines the public API surface, including core traits, error handling infrastructure, and fundamental data types.
-   **`dcrypt_docs/common/README.md`**: Provides shared utilities and security primitives used across the dcrypt ecosystem.
-   **`dcrypt_docs/internal/README.md`**: Contains low-level helper functions not part of the public API, focusing on constant-time operations, endianness, and zeroing.
-   **`dcrypt_docs/params/README.md`**: A `no_std` crate centralizing cryptographic parameters and constants for various algorithms.
-   **`dcrypt_docs/algorithms/README.md`**: The core crate implementing foundational cryptographic primitives like hash functions, block ciphers, MACs, AEADs, KDFs, and XOFs.
-   **`dcrypt_docs/symmetric/README.md`**: Offers high-level APIs for symmetric encryption, building upon the `algorithms` crate.
-   **`dcrypt_docs/kem/README.md`**: Implements Key Encapsulation Mechanisms (KEMs), both traditional and post-quantum.
-   **`dcrypt_docs/sign/README.md`**: Implements Digital Signature schemes, covering traditional and post-quantum algorithms.
-   **`dcrypt_docs/hybrid/README.md`**: Provides hybrid cryptographic schemes by combining algorithms from the `kem` and `sign` crates.
-   **`dcrypt_docs/utils/README.md`**: A development-only crate for utilities (currently a placeholder).
-   **`dcrypt_docs/tests/README.md`**: Contains integration tests, constant-time verification tests, and test vectors.

## Quick Start

To use dcrypt in your project, add it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
# Assuming a future top-level 'dcrypt' crate or direct dependencies:
# dcrypt = "0.1.0"
# For now, you would depend on individual crates like:
# dcrypt-algorithms = { path = "crates/algorithms" }
# dcrypt-symmetric = { path = "crates/symmetric" }
# ...and so on for other required components.
```

### Example: Symmetric Encryption with AES-GCM

```rust
// Note: This example assumes you have the 'dcrypt-symmetric' and 'dcrypt-algorithms'
// (or a future 'dcrypt' facade crate) as dependencies.

use dcrypt_symmetric::aes::{Aes256Key, Aes256Gcm};
use dcrypt_symmetric::cipher::{SymmetricCipher, Aead}; // Core traits
use dcrypt_symmetric::aead::gcm::GcmNonce; // Specific nonce type
use dcrypt_algorithms::types::RandomGeneration; // For key generation if not directly on key type
use rand::rngs::OsRng; // For random generation

fn main() -> dcrypt_symmetric::error::Result<()> {
    // Generate a random key (Actual key generation might be on Aes256Key itself)
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let key = Aes256Key::new(key_bytes);

    let cipher = Aes256Gcm::new(&key)?;

    // Encrypt data with authentication
    let plaintext = b"Confidential message";
    let nonce = Aes256Gcm::generate_nonce(); // Uses the Aead trait method
    let aad = Some(b"additional authenticated data");
    let ciphertext = cipher.encrypt(&nonce, plaintext, aad)?;

    // Decrypt data
    let decrypted = cipher.decrypt(&nonce, &ciphertext, aad)?;
    assert_eq!(decrypted, plaintext);

    println!("AES-256-GCM Encryption/Decryption successful!");
    Ok(())
}
```

### Example: Post-Quantum Key Encapsulation with Kyber

```rust
// Note: This example assumes 'dcrypt-kem' and 'dcrypt-api' crates.

use dcrypt_kem::kyber::{Kyber768, KyberPublicKey, KyberSecretKey, KyberCiphertext, KyberSharedSecret};
use dcrypt_api::Kem; // Core KEM trait
use rand::rngs::OsRng;

fn main() -> dcrypt_api::error::Result<()> {
    // Generate a Kyber768 keypair
    // In a real scenario, Kyber768::keypair would be fully implemented.
    // For this example, we'll assume placeholder keys for structure.
    let mut pk_bytes = vec![0u8; dcrypt_params::pqc::kyber::KYBER768.public_key_size];
    let mut sk_bytes = vec![0u8; dcrypt_params::pqc::kyber::KYBER768.secret_key_size];
    OsRng.fill_bytes(&mut pk_bytes);
    OsRng.fill_bytes(&mut sk_bytes);
    
    let public_key = KyberPublicKey(pk_bytes);
    let secret_key = KyberSecretKey(sk_bytes);

    // Encapsulate a shared secret
    // Real encapsulation would use the public_key.
    let mut rng = OsRng;
    let (ciphertext, shared_secret_sender) = Kyber768::encapsulate(&mut rng, &public_key)?;

    // Decapsulate the shared secret
    // Real decapsulation would use the secret_key and ciphertext.
    let shared_secret_receiver = Kyber768::decapsulate(&secret_key, &ciphertext)?;

    // The shared secrets will be identical (in a real implementation)
    assert_eq!(shared_secret_sender.as_ref(), shared_secret_receiver.as_ref());

    println!("Kyber-768 KEM Encapsulation/Decapsulation successful!");
    Ok(())
}
```

## Security Considerations

dcrypt is designed with security as a primary concern. Key security features include:

-   **Constant-Time Operations**: Many cryptographic primitives are implemented to execute in time independent of secret inputs, helping to prevent timing side-channel attacks. Refer to `CONSTANT_TIME_POLICY.md` for details.
-   **Secure Memory Handling**: Sensitive data like keys and intermediate cryptographic values are handled using types that ensure automatic zeroization on drop (e.g., `SecretBuffer`, `SecretVec` from the `common` crate).
-   **Type Safety**: The library's API uses Rust's strong type system to enforce correct usage of keys, nonces, and other cryptographic parameters, reducing the likelihood of common cryptographic mistakes.
-   **Error Handling**: Errors are designed to provide sufficient information for debugging without leaking sensitive details.
-   **Pure Rust**: The absence of FFI calls reduces the attack surface associated with unsafe code and memory management across language boundaries.

Users should always ensure they are using appropriate key management practices, generating and using nonces correctly (uniquely for each encryption with the same key), and selecting algorithms and parameters suitable for their security requirements.

## Feature Flags

dcrypt utilizes feature flags to tailor the build for different environments and requirements:

-   `std` (default): Enables features requiring the standard library, including heap allocations and OS-level RNG.
-   `alloc`: Enables features requiring heap allocation (like `Vec`) but without the full standard library.
-   `no_std`: For environments without a standard library (e.g., embedded systems). Some functionalities requiring heap allocation might be disabled or require an allocator to be provided.
-   `serde`: Enables serialization and deserialization capabilities for various types using the `serde` framework.
-   `xof`: Includes Extendable Output Functions like SHAKE and BLAKE3.
-   Specific algorithm features (e.g., `aes`, `sha2`, `kyber`) may be available for fine-grained control over compiled code size. (Refer to individual crate `Cargo.toml` files for details).

## Contributing

Contributions to dcrypt are welcome! Please refer to the (forthcoming) `CONTRIBUTING.md` for guidelines on:

-   Code style and formatting.
-   Testing requirements.
-   Documentation standards.
-   The process for submitting pull requests.

Security is paramount; all contributions, especially those touching cryptographic primitives, will undergo careful review.

## License

dcrypt is licensed under the Apache License, Version 2.0. (See `LICENSE` file or `Cargo.toml` for details).