# Digital Signature Schemes

[![Crates.io](https://img.shields.io/crates/v/dcrypt-sign.svg)](https://crates.io/crates/dcrypt-sign)
[![Docs.rs](https://docs.rs/dcrypt-sign/badge.svg)](https://docs.rs/dcrypt-sign)
[![License](https://img.shields.io/crates/l/dcrypt-sign.svg)](https://crates.io/crates/dcrypt-sign)
[![Build Status](https://github.com/your-repo/dcrypt-sign/actions/workflows/rust.yml/badge.svg)](https://github.com/your-repo/dcrypt-sign/actions)

Digital Signature Schemes for the dcrypt library.

## Overview

`dcrypt-sign` is a crate that provides a comprehensive suite of digital signature algorithms. It features a unified API for both traditional, widely-used schemes and next-generation, post-quantum cryptographic standards. The implementations are designed with security, correctness, and performance in mind, conforming to official standards such as FIPS and RFCs.

The primary goal of this crate is to offer robust, production-ready signature algorithms that adhere to the `dcrypt-api` traits, ensuring seamless integration within the dcrypt ecosystem.

## Features

-   **Unified API**: All signature schemes implement the `dcrypt-api::Signature` trait for consistent usage.
-   **Post-Quantum Cryptography**: Includes FIPS 204 compliant implementations of CRYSTALS-Dilithium (ML-DSA). [2, 4, 6]
-   **Traditional Cryptography**: Provides implementations for industry-standard algorithms:
    -   ECDSA over NIST curves P-192, P-224, P-256, P-384, and P-521, compliant with FIPS 186-4. [1, 3]
    -   Ed25519, compliant with RFC 8032. [7, 14]
-   **Security Focused**:
    -   Automatic zeroization of secret key material on drop to mitigate data remanence.
    -   Deterministic signing for Ed25519 and deterministic nonce generation (RFC 6979) for ECDSA to enhance security against fault attacks and weak RNGs.
    -   Constant-time operations where applicable to resist timing-based side-channel attacks.
-   **Selective Compilation**: Use feature flags (`traditional`, `post-quantum`) to include only the necessary algorithm families, reducing binary size.
-   **Future-Proof**: Includes placeholder support for Falcon, Rainbow, and SPHINCS+ to be implemented as standards finalize and mature.

## Implemented Schemes

### Post-Quantum Signatures

| Algorithm | Variants Implemented | Standard |
| :--- | :--- | :--- |
| **CRYSTALS-Dilithium** | `Dilithium2`, `Dilithium3`, `Dilithium5` | FIPS 204 |
| **Falcon** | `Falcon512`, `Falcon1024` | *(Placeholder)* |
| **Rainbow** | `RainbowI`, `RainbowIII`, `RainbowV` | *(Placeholder)* |
| **SPHINCS+** | `SphincsSha2`, `SphincsShake` | *(Placeholder)* |

### Traditional Signatures

| Algorithm | Variants Implemented | Standard |
| :--- | :--- | :--- |
| **ECDSA** | `EcdsaP192`, `EcdsaP224`, `EcdsaP256`, `EcdsaP384`, `EcdsaP521` | FIPS 186-4 |
| **EdDSA** | `Ed25519` | RFC 8032 |

## Installation

Add `dcrypt-sign` to your `Cargo.toml`. To enable specific algorithm suites, use the `features` attribute.

```toml
[dependencies]
# By default, both traditional and post-quantum schemes are available
dcrypt-sign = "0.12.0-beta.1"

# To include only post-quantum schemes:
# dcrypt-sign = { version = "0.12.0-beta.1", default-features = false, features = ["post-quantum"] }

# To include only traditional schemes:
# dcrypt-sign = { version = "0.12.0-beta.1", default-features = false, features = ["traditional"] }
```

You will also need a cryptographically secure random number generator, like `rand`.

```toml
[dependencies]
rand = "0.8"
```

## Usage

All signature schemes in this crate implement the `dcrypt::api::Signature` trait, providing a consistent and easy-to-use interface.

### Example: Dilithium2 (Post-Quantum)

```rust
use dcrypt::api::Signature;
use dcrypt::sign::Dilithium2;
use rand::rngs::OsRng;

fn main() -> dcrypt::api::Result<()> {
    let mut rng = OsRng;
    let message = b"This is a test message for the Dilithium signature algorithm.";

    // 1. Generate a keypair
    let (pk, sk) = Dilithium2::keypair(&mut rng)?;

    // 2. Sign the message with the secret key
    println!("Signing message...");
    let signature = Dilithium2::sign(message, &sk)?;
    println!("Signature generated successfully.");

    // 3. Verify the signature with the public key
    println!("Verifying signature...");
    Dilithium2::verify(message, &signature, &pk)?;
    println!("Signature is valid!");

    // Verification will fail for a tampered message
    let tampered_message = b"This is a tampered message.";
    assert!(Dilithium2::verify(tampered_message, &signature, &pk).is_err());
    println!("Signature verification failed for tampered message, as expected.");

    Ok(())
}
```

### Example: Ed25519 (Traditional)

The API remains the same, just switch the type.

```rust
use dcrypt::api::Signature;
use dcrypt::sign::Ed25519;
use rand::rngs::OsRng;

fn main() -> dcrypt::api::Result<()> {
    let mut rng = OsRng;
    let message = b"A message signed with Ed25519.";

    // 1. Generate a keypair
    let (pk, sk) = Ed25519::keypair(&mut rng)?;

    // 2. Sign the message
    let signature = Ed25519::sign(message, &sk)?;

    // 3. Verify the signature
    assert!(Ed25519::verify(message, &signature, &pk).is_ok());
    println!("Ed25519 signature is valid!");

    Ok(())
}
```

## Feature Flags

This crate uses feature flags to control which code is included, allowing you to optimize binary size by excluding unused algorithm families.

-   `std`: (Enabled by default) Enables functionality that requires the standard library.
-   `serde`: Enables serialization and deserialization of keys and signatures via the `serde` framework.
-   `traditional`: Enables ECDSA and EdDSA signature schemes.
-   `post-quantum`: Enables Dilithium, Falcon, Rainbow, and SPHINCS+ signature schemes.

By default, `std`, `traditional`, and `post-quantum` are enabled.

## Security

This library has been developed with a focus on security. Secret key types implement the `Zeroize` trait, which securely erases their contents from memory when they go out of scope. However, security is a shared responsibility. Users of this crate should follow best practices for handling cryptographic keys, such as:

-   Using a cryptographically secure random number generator (CSPRNG) like `rand::rngs::OsRng`.
-   Protecting secret key material at rest (e.g., via encryption) and in transit.
-   Ensuring the authenticity of public keys before use to prevent impersonation attacks.

## License

This crate is licensed under the terms of the license specified in `Cargo.toml`.

## Contribution

Contributions are welcome! Please feel free to submit pull requests or open issues on the project repository.