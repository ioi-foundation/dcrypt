# Digital Signature Schemes

[![Crates.io](https://img.shields.io/crates/v/dcrypt-sign.svg)](https://crates.io/crates/dcrypt-sign)
[![Docs.rs](https://docs.rs/dcrypt-sign/badge.svg)](https://docs.rs/dcrypt-sign)
[![License](https://img.shields.io/crates/l/dcrypt-sign.svg)](https://crates.io/crates/dcrypt-sign)

Digital Signature Schemes for the dcrypt library.

## Overview

`dcrypt-sign` exposes protected APIs for traditional and post-quantum signature
schemes. ECDSA, Ed25519, and ML-DSA implement the `dcrypt-api` signature traits.
BLS uses a dedicated API so its secret key can remain deliberately non-`Clone`
and its aggregation and proof-of-possession rules stay visible in the type
surface. Individual implementations target the encodings and equations in the
cited standards; this is not a blanket conformance, side-channel, or
certification claim.
Published versions through `v1.2.3` contain critical defects. `v2.0.0` retains
important remediations but is withdrawn because it violates dcrypt's
zero-unsafe/zero-FFI implementation policy. The next supported line is v3; see
the workspace `SECURITY.md` before use. This crate is not FIPS validated or
certified.

## Features

-   **Unified API**: All signature schemes implement the `dcrypt-api::Signature` trait for consistent usage.
-   **Post-Quantum Cryptography**: Includes dcrypt-owned safe-Rust final FIPS 204 ML-DSA for key generation, deterministic or caller-randomized signing, verification, and complete expanded-key validation. Independent implementations are isolated to the non-published verification workspace.
-   **Traditional Cryptography**: Provides implementations for industry-standard algorithms:
    -   ECDSA over NIST curves P-224, P-256, P-384, and P-521, with strict DER and low-`s` policy.
    -   Ed25519 with RFC 8032 encoding and strict verification behavior.
    -   Minimum-public-key BLS12-381 Basic, Message Augmentation, and Proof of Possession profiles pinned to `draft-irtf-cfrg-bls-signature-07`, plus an explicitly separate Ethereum draft-v4 PoP adapter.
-   **Security Focused**:
    -   Automatic zeroization of secret key material on drop to mitigate data remanence.
    -   Deterministic signing for Ed25519 and deterministic nonce generation (RFC 6979) for ECDSA to enhance security against fault attacks and weak RNGs.
    -   Secret-dependent ML-DSA signing work uses the fixed public rejection
        window required by the release policy; target-specific compiler and
        timing validation remains necessary.
-   **Selective Compilation**: `traditional` enables ECDSA and Ed25519; `post-quantum` enables ML-DSA.
-   **No placeholder algorithms**: Public types are exposed only for implemented signature schemes.

The `alloc` feature supports allocator-backed `no_std` builds. Applications are
responsible for supplying a compatible allocator and a cryptographic RNG.

## Implemented Schemes

### Post-Quantum Signatures

| Algorithm | Variants Implemented | Standard |
| :--- | :--- | :--- |
| **ML-DSA** | `MlDsa44`, `MlDsa65`, `MlDsa87` | FIPS 204 |

### Traditional Signatures

| Algorithm | Variants Implemented | Standard |
| :--- | :--- | :--- |
| **ECDSA** | `EcdsaP224`, `EcdsaP256`, `EcdsaP384`, `EcdsaP521` | FIPS 186-5 |
| **EdDSA** | `Ed25519` | RFC 8032 |
| **BLS12-381 (minimum public key)** | `Bls12381G2Basic`, `Bls12381G2MessageAugmentation`, `Bls12381G2ProofOfPossession`; separate `Eth2Bls12381G2PopV4` adapter | CFRG BLS draft-07; Ethereum draft-v4 profile |

## Installation

Do not use v1 or v2. Pin the exact reviewed v3 release and select only the
required features.

```toml
[dependencies]
dcrypt = { version = "=3.0.0", default-features = false, features = ["std", "sign", "traditional", "post-quantum"] }
```

dcrypt never obtains operating-system entropy. Key generation and randomized
ML-DSA signing require an application-owned type implementing
`dcrypt::internal::{RngCore, CryptoRng}`. `ChaCha20Rng::from_seed` is provided
for callers that already have a fresh 32-byte seed from their own trusted
entropy boundary; reusing or hard-coding that seed is insecure.

## Usage

ECDSA, Ed25519, and ML-DSA implement `dcrypt::api::Signature`. BLS uses the
dedicated protected API shown below.

### Example: BLS12-381 Basic (minimum public key)

```rust
use dcrypt::sign::bls::{Bls12381G2Basic, Bls12381SecretKey};

fn sign(ikm: &[u8]) -> dcrypt::api::Result<()> {
    // Draft-07 requires at least 32 unpredictable IKM bytes and an explicit
    // caller-chosen salt. An application may instead call `generate` with its
    // own CryptoRng.
    let secret = Bls12381SecretKey::key_gen(ikm, b"example application salt")?;
    let public = secret.public_key()?;
    let message = b"standard BLS signature";
    let signature = Bls12381G2Basic::sign(&secret, message)?;
    Bls12381G2Basic::verify(&public, message, &signature)?;
    Ok(())
}
```

Use `Bls12381G2ProofOfPossession` when same-message aggregation is required;
its aggregate verification methods take and validate a proof for every public
key. Ethereum consensus callers must deliberately select
`Eth2Bls12381G2PopV4`, whose verification contract relies on Ethereum's
registration-time proof validation and whose empty fast-aggregate case matches
the consensus specification.

### Example: ML-DSA-44 (Post-Quantum)

```rust
use dcrypt::api::Signature;
use dcrypt::internal::ChaCha20Rng;
use dcrypt::sign::MlDsa44;

fn sign_with_application_entropy(seed: [u8; 32]) -> dcrypt::api::Result<()> {
    let mut rng = ChaCha20Rng::from_seed(seed);
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
use dcrypt::internal::ChaCha20Rng;
use dcrypt::sign::Ed25519;

fn sign_with_application_entropy(seed: [u8; 32]) -> dcrypt::api::Result<()> {
    let mut rng = ChaCha20Rng::from_seed(seed);
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
-   `traditional`: Enables ECDSA, Ed25519, and BLS12-381 signature schemes.
-   `post-quantum`: Enables ML-DSA signature schemes.

The selected dcrypt facade features determine which families are exposed.

## Security

Secret key types overwrite their initialized storage on drop using dcrypt's
safe-Rust zeroing trait. Safe Rust cannot promise that an optimizing compiler
or every platform will preserve every wipe without target-specific inspection.
Users should also:

-   Supply fresh cryptographic entropy through the caller-owned RNG boundary.
-   Protect secret key material at rest (e.g., via encryption) and in transit.
-   Ensure the authenticity of public keys before use to prevent impersonation attacks.

## License

This crate is licensed under the terms of the license specified in `Cargo.toml`.

## Contribution

Contributions are welcome! Please feel free to submit pull requests or open issues on the project repository.
