# dcrypt: A Modern, High-Assurance Cryptographic Library in Rust

[![Crates.io](https://img.shields.io/crates/v/dcrypt.svg?style=flat-square)](https://crates.io/crates/dcrypt)
[![Docs.rs](https://img.shields.io/docsrs/dcrypt?style=flat-square)](https://docs.rs/dcrypt)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/ioi-foundation/dcrypt/rust.yml?branch=main&style=flat-square)](https://github.com/ioi-foundation/dcrypt/actions)

**dcrypt** (Decentralized Cryptography) is a comprehensive cryptographic library implemented entirely in safe Rust. It bridges the gap between traditional security and the post-quantum future by providing NIST-standardized Post-Quantum Cryptography (PQC) algorithms alongside novel, production-ready hybrid constructions.

Spearheaded by the **IOI Foundation** (Internet of Intelligence) as the security cornerstone for next-generation decentralized infrastructure ("Web4"), dcrypt eliminates foreign function interfaces (FFI) and `unsafe` code blocks in cryptographic logic, ensuring memory safety and cross-platform compatibility from embedded devices to enterprise servers.

## Novel Capabilities

dcrypt introduces two first-of-its-kind capabilities to the Rust ecosystem:

1.  **First Pure-Rust Dilithium/ML-DSA**: The first publicly released, production-ready implementation of the complete CRYSTALS-Dilithium signature scheme with zero `unsafe` code, zero FFI, and full constant-time execution.
2.  **Native Hybrid Cryptography**: The first pure-Rust library to provide hybrid Key Encapsulation Mechanisms (ECDH + Kyber) and hybrid Digital Signatures (ECDSA + Dilithium) as composable, general-purpose primitives.

## Key Design Principles

*   **Pure Rust & Memory Safety**: Implemented with **zero FFI dependencies** and **no `unsafe` code** in cryptographic kernels. This eliminates entire classes of memory vulnerabilities (buffer overflows, use-after-free) common in C/C++ wrapped libraries.
*   **Post-Quantum Ready**: Full support for NIST-selected algorithms **CRYSTALS-Kyber (ML-KEM)** and **CRYSTALS-Dilithium (ML-DSA)**.
*   **Defense-in-Depth (Hybrid Schemes)**: Native support for hybrid constructions. A shared secret or signature is compromised only if *both* the classical and post-quantum assumptions are broken.
*   **Constant-Time Execution**: All primitives handling secret data are engineered to be branch-free and memory-access-pattern-free. This is enforced by a built-in **Constant-Time Verification Suite** that statistically detects timing leaks during CI.
*   **Modular & Ergonomic**: High-level APIs prevent misuse (e.g., strong typing for keys and nonces), while a workspace architecture allows users to include only necessary algorithm families.
*   **`no_std` & Cross-Platform**: Fully functional in `no_std` environments (requiring `alloc`), making it suitable for IoT, embedded systems, and WASM targets.

## Quick Start

Add `dcrypt` to your project's `Cargo.toml`. You can select specific features to reduce binary size.

```toml
[dependencies]
dcrypt = { version = "0.1.0", features = ["hybrid", "aes-gcm"] }
rand = "0.8"
```

### Example 1: Hybrid Post-Quantum Key Encapsulation

Securely exchange keys using a hybrid scheme (ECDH P-256 + Kyber768). This ensures security even if quantum computers break elliptic curve cryptography.

```rust
use dcrypt::hybrid::{HybridKem, HybridP256Kyber768};
use dcrypt::rng::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Alice generates a Hybrid Keypair (Classical ECC + Post-Quantum Kyber)
    let (alice_pk, alice_sk) = HybridP256Kyber768::generate_keypair(&mut rng);

    // 2. Bob encapsulates a shared secret against Alice's public key
    let (shared_secret_bob, ciphertext) = alice_pk.encapsulate(&mut rng)?;

    // 3. Alice decapsulates the ciphertext to recover the shared secret
    let shared_secret_alice = alice_sk.decapsulate(&ciphertext)?;

    // 4. Verify secrets match
    assert_eq!(shared_secret_bob, shared_secret_alice);
    println!("Hybrid Quantum-Safe Key Exchange successful!");
    
    Ok(())
}
```

### Example 2: Authenticated Encryption (AES-256-GCM)

Standard symmetric encryption remains a core part of the library.

```rust
use dcrypt::symmetric::{Aes256Gcm, Key, Nonce, Aead};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = Key::<Aes256Gcm>::generate();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::generate(); // Unique per encryption

    let plaintext = b"Quantum resistance is futile... actually it's necessary.";
    
    // Encrypt
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;
    
    // Decrypt
    let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref())?;
    
    assert_eq!(plaintext.to_vec(), decrypted);
    Ok(())
}
```

## Supported Algorithms

dcrypt provides a unified API for classical, post-quantum, and hybrid operations:

| Category | Algorithms |
| :--- | :--- |
| **Symmetric Encryption (AEAD)** | `AES-256-GCM`, `ChaCha20-Poly1305`, `XChaCha20-Poly1305` |
| **Hash Functions** | `SHA-2`, `SHA-3`, `BLAKE2` |
| **XOFs** | `SHAKE-128/256`, `BLAKE3` |
| **Password Hashing** | `Argon2id` (default), `Argon2i`, `Argon2d` |
| **Key Derivation** | `HKDF`, `PBKDF2` |
| **Digital Signatures** | `ECDSA` (P-256, P-384), `Ed25519` |
| **Post-Quantum Signatures** | `CRYSTALS-Dilithium` / `ML-DSA` (Levels 2, 3, 5) |
| **Key Exchange / KEM** | `ECDH` (P-256, P-384, P-521) |
| **Post-Quantum KEMs**| `CRYSTALS-Kyber` / `ML-KEM` (Levels 512, 768, 1024) |
| **Hybrid Schemes** | `HybridECDH` (ECDH + Kyber), `HybridSign` (ECDSA + Dilithium) |

## Architecture & Crates

The library is organized as a workspace of specialized crates to align type-safety boundaries with security boundaries:

*   **`dcrypt-api`**: Core public traits, error types, and fundamental data structures.
*   **`dcrypt-algorithms`**: Low-level, constant-time implementations of cryptographic kernels.
*   **`dcrypt-common`**: Shared utilities, including secure memory zeroization (`SecretBytes`).
*   **`dcrypt-symmetric`**: AEADs and stream ciphers.
*   **`dcrypt-kem`**: Key Encapsulation Mechanisms (Kyber, ECDH).
*   **`dcrypt-sign`**: Digital Signatures (Dilithium, ECDSA, Ed25519).
*   **`dcrypt-hybrid`**: Ready-to-use hybrid combiners for KEMs and Signatures.
*   **`dcrypt-tests`**: Integration tests, Known-Answer Tests (KATs), and the Constant-Time Verification Suite.

## Security & Verification

Security is the primary driver for dcrypt. The library employs a rigorous **Constant-Time Verification Suite** that integrates directly into the CI pipeline to ensure side-channel resistance.

*   **Microbenchmark Timing Acquisition**: Captures timing data at microsecond resolution across thousands of iterations.
*   **Multi-Signal Leakage Analysis**: Uses Welch’s t-test, Median Absolute Deviation (MAD), and Kolmogorov–Smirnov tests to distinguish genuine timing leaks from environmental noise.
*   **Automated Regression Protection**: Builds fail automatically if secret-dependent timing correlations are detected in Kyber, Dilithium, or hybrid primitives.

## Performance

Benchmarks (executed on AMD Ryzen 9 7950X) demonstrate that `dcrypt` achieves production-grade speeds without compromising safety:
*   **Kyber Keygen**: ~180–230 µs.
*   **Hybrid Overhead**: Hybrid constructions introduce less than **10% overhead** compared to post-quantum-only implementations.
*   **Scaling**: Linear scaling for Dilithium verification across message sizes.

## Roadmap

*   **Audit**: Third-party security audit by an expert cryptography firm.
*   **Expanded Suite**: Implementation of FALCON and SPHINCS+ upon final NIST standardization.
*   **Web4 Integration**: Native integration into IOI's DePIN and decentralized identity frameworks.

## License

This project is licensed under the **Apache License, Version 2.0**.