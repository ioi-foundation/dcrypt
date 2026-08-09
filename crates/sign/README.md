# Digital Signature Schemes

[![Crates.io](https://img.shields.io/crates/v/dcrypt-sign.svg)](https://crates.io/crates/dcrypt-sign)
[![Docs.rs](https://docs.rs/dcrypt-sign/badge.svg)](https://docs.rs/dcrypt-sign)
[![License](https://img.shields.io/crates/l/dcrypt-sign.svg)](https://crates.io/crates/dcrypt-sign)

Digital Signature Schemes for the dcrypt library.

## Overview

`dcrypt-sign` exposes a unified API for traditional and post-quantum signature schemes. Individual implementations target the encodings and equations in the cited standards; this is not a blanket conformance, side-channel, or certification claim.

The crate offers signature algorithms through the `dcrypt-api` traits. Published
`v1.2.3` is confirmed affected by security defects; earlier release ranges are
still under investigation and unsupported. `v2.0.0` is the first remediated
release, but is not independently audited, FIPS validated, or certified. See the
workspace `SECURITY.md` before use.

## Features

-   **Unified API**: All signature schemes implement the `dcrypt-api::Signature` trait for consistent usage.
-   **Post-Quantum Cryptography**: Includes dcrypt-owned safe-Rust final FIPS 204 ML-DSA for key generation, deterministic or caller-randomized signing, verification, and complete expanded-key validation. Independent implementations are isolated to the non-published verification workspace.
-   **Traditional Cryptography**: Provides implementations for industry-standard algorithms:
    -   ECDSA over NIST curves P-192, P-224, P-256, P-384, and P-521, with strict DER and low-`s` policy.
    -   Ed25519 with RFC 8032 encoding and strict verification behavior.
-   **Security Focused**:
    -   Automatic zeroization of secret key material on drop to mitigate data remanence.
    -   Deterministic signing for Ed25519 and deterministic nonce generation (RFC 6979) for ECDSA to enhance security against fault attacks and weak RNGs.
    -   Secret-dependent ML-DSA signing work uses the fixed public rejection
        window required by the release policy; target-specific compiler and
        timing validation remains necessary.
-   **Selective Compilation**: The historical family feature flags remain, but release builds must verify the actual dependency graph and enabled code paths.
-   **Placeholders**: Falcon, Rainbow, and SPHINCS+ names are placeholders and must not be treated as usable signature schemes.

The crate's historical `no_std` feature combination does not currently compile
and is unsupported until a dedicated build gate passes.

## Implemented Schemes

### Post-Quantum Signatures

| Algorithm | Variants Implemented | Standard |
| :--- | :--- | :--- |
| **ML-DSA** | `MlDsa44`, `MlDsa65`, `MlDsa87` | FIPS 204 |
| **Falcon** | `Falcon512`, `Falcon1024` | *(Placeholder)* |
| **Rainbow** | `RainbowI`, `RainbowIII`, `RainbowV` | *(Placeholder)* |
| **SPHINCS+** | `SphincsSha2`, `SphincsShake` | *(Placeholder)* |

### Traditional Signatures

| Algorithm | Variants Implemented | Standard |
| :--- | :--- | :--- |
| **ECDSA** | `EcdsaP192`, `EcdsaP224`, `EcdsaP256`, `EcdsaP384`, `EcdsaP521` | FIPS 186-4 |
| **EdDSA** | `Ed25519` | RFC 8032 |

## Installation

Do not add `dcrypt-sign` `v1.2.3`; it is confirmed affected, and earlier
releases have not been cleared. Those releases contain the Ed25519 and legacy
Dilithium defects described in the workspace security policy. Use `2.0.0` or
later, pin the exact reviewed version, and select only the required features.

You will also need a cryptographically secure random number generator, like `rand`.

```toml
[dependencies]
rand = "0.8"
```

## Usage

All signature schemes in this crate implement the `dcrypt::api::Signature` trait, providing a consistent and easy-to-use interface.

### Example: ML-DSA-44 (Post-Quantum)

```rust
use dcrypt::api::Signature;
use dcrypt::sign::MlDsa44;
use rand::rngs::OsRng;

fn main() -> dcrypt::api::Result<()> {
    let mut rng = OsRng;
    let message = b"This is a test message for ML-DSA.";

    // 1. Generate a keypair
    let (pk, sk) = MlDsa44::keypair(&mut rng)?;

    // 2. Sign the message with the secret key
    println!("Signing message...");
    let signature = MlDsa44::sign_with_rng(message, &sk, &mut rng)?;
    println!("Signature generated successfully.");

    // 3. Verify the signature with the public key
    println!("Verifying signature...");
    MlDsa44::verify(message, &signature, &pk)?;
    println!("Signature is valid!");

    // Verification will fail for a tampered message
    let tampered_message = b"This is a tampered message.";
    assert!(MlDsa44::verify(tampered_message, &signature, &pk).is_err());
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
