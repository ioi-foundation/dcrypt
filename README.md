# dcrypt: A Modern, High-Assurance Cryptographic Library in Rust

[![Crates.io](https://img.shields.io/crates/v/dcrypt.svg?style=flat-square)](https://crates.io/crates/dcrypt)
[![Docs.rs](https://img.shields.io/docsrs/dcrypt?style=flat-square)](https://docs.rs/dcrypt)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/ioi-foundation/dcrypt/rust.yml?branch=main&style=flat-square)](https://github.com/ioi-foundation/dcrypt/actions)

**dcrypt** (Decentralized Cryptography) is a comprehensive cryptographic library implemented entirely in safe Rust. It bridges the gap between traditional security and the post-quantum future by providing NIST-standardized Post-Quantum Cryptography (PQC) algorithms alongside novel, production-ready hybrid constructions.

Spearheaded by the **IOI Foundation** as the security cornerstone for next-generation decentralized infrastructure, dcrypt eliminates foreign function interfaces (FFI) and `unsafe` code blocks in cryptographic logic, ensuring memory safety and cross-platform compatibility from embedded devices to enterprise servers.

## 🚀 Novel Capabilities

dcrypt introduces capabilities critical for the transition to quantum-safe computing:

1.  **Pure-Rust FIPS 204 (ML-DSA)**: A production-ready implementation of the complete **CRYSTALS-Dilithium** signature scheme with zero `unsafe` code and full constant-time execution.
2.  **Pure-Rust FIPS 203 (ML-KEM)**: A complete implementation of **CRYSTALS-Kyber** with protections against timing side-channels.
3.  **Native Hybrid Cryptography**: First-class support for hybrid Key Encapsulation Mechanisms (e.g., `ECDH P-256 + Kyber-768`) and hybrid Digital Signatures, ensuring security even if one underlying primitive is compromised.

## 🛡️ Key Design Principles

*   **Pure Rust & Memory Safety**: Implemented with **zero FFI dependencies** to eliminate memory vulnerabilities like buffer overflows and use-after-free errors common in C/C++ wrapped libraries.
*   **Post-Quantum Ready**: Full support for NIST-selected algorithms, protecting data against "Harvest Now, Decrypt Later" attacks.
*   **Defense-in-Depth**: Hybrid schemes combine battle-tested classical algorithms (ECDH/ECDSA) with modern PQC primitives.
*   **Constant-Time Execution**: All primitives handling secret data are engineered to be branch-free and memory-access-pattern-free. This is enforced by a built-in **Constant-Time Verification Suite** that statistically detects timing leaks during CI.
*   **Type Safety**: High-level APIs prevent misuse through strong typing (e.g., distinct types for `Nonce`, `Key`, and `Tag` prevents byte-array confusion).
*   **`no_std` & Cross-Platform**: Fully functional in `no_std` environments (requiring `alloc`), making it suitable for IoT, embedded systems, and WASM targets.

## 📦 Quick Start

Add `dcrypt` to your project's `Cargo.toml`.

```toml
[dependencies]
dcrypt = { version = "1.0" }
```

### Example 1: Hybrid Post-Quantum Key Exchange

Securely exchange keys using a hybrid scheme (`EcdhP256` + `Kyber768`). This ensures security remains intact even if quantum computers break elliptic curve cryptography.

```rust
use dcrypt::hybrid::kem::EcdhP256Kyber768;
use dcrypt::api::Kem;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // 1. Alice generates a Hybrid Keypair
    // (Contains both a P-256 keypair and a Kyber-768 keypair)
    let (alice_pk, alice_sk) = EcdhP256Kyber768::keypair(&mut rng)?;

    // 2. Bob encapsulates a shared secret against Alice's public key
    let (ciphertext, shared_secret_bob) = EcdhP256Kyber768::encapsulate(&mut rng, &alice_pk)?;

    // 3. Alice decapsulates the ciphertext to recover the shared secret
    let shared_secret_alice = EcdhP256Kyber768::decapsulate(&alice_sk, &ciphertext)?;

    // 4. Verify secrets match
    assert_eq!(shared_secret_bob.as_ref(), shared_secret_alice.as_ref());
    println!("Hybrid Quantum-Safe Key Exchange successful!");
    
    Ok(())
}
```

### Example 2: Authenticated Encryption (AES-256-GCM)

Standard symmetric encryption remains a core part of the library, featuring ergonomic key management.

```rust
use dcrypt::symmetric::aes::{Aes256Gcm, Aes256Key};
use dcrypt::symmetric::cipher::{SymmetricCipher, Aead};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a secure random key
    let key = Aes256Key::generate();
    let cipher = Aes256Gcm::new(&key)?;
    
    let nonce = Aes256Gcm::generate_nonce();
    let plaintext = b"Quantum resistance is futile... actually it's necessary.";
    let aad = Some(b"metadata".as_slice());
    
    // Encrypt
    let ciphertext = cipher.encrypt(&nonce, plaintext, aad)?;
    
    // Decrypt
    let decrypted = cipher.decrypt(&nonce, &ciphertext, aad)?;
    
    assert_eq!(plaintext.to_vec(), decrypted);
    Ok(())
}
```

## 📚 Supported Algorithms

dcrypt provides a unified API for classical, post-quantum, and hybrid operations:

| Category | Algorithms |
| :--- | :--- |
| **Symmetric Encryption (AEAD)** | `AES-128/256-GCM`, `ChaCha20-Poly1305`, `XChaCha20-Poly1305` |
| **Hash Functions** | `SHA-2` (224, 256, 384, 512), `SHA-3`, `BLAKE2b/s` |
| **XOFs** | `SHAKE-128/256`, `BLAKE3` |
| **Password Hashing** | `Argon2id` (default), `Argon2i`, `Argon2d`, `PBKDF2` |
| **Key Derivation** | `HKDF`, `PBKDF2` |
| **Digital Signatures** | `ECDSA` (P-192 to P-521), `Ed25519` |
| **Post-Quantum Signatures** | `Dilithium` / `ML-DSA` (Levels 2, 3, 5) |
| **Key Exchange / KEM** | `ECDH` (P-Curves, K-256, B-283) |
| **Post-Quantum KEMs**| `Kyber` / `ML-KEM` (Levels 512, 768, 1024) |
| **Hybrid Schemes** | `EcdhP256Kyber768`, `EcdhP384Kyber1024`, `EcdsaDilithiumHybrid` |

## 🏗️ Architecture

The library is organized as a workspace of specialized crates to align type-safety boundaries with security boundaries:

*   **`dcrypt-api`**: Defines core traits (`SymmetricCipher`, `Kem`, `Signature`), error types, and fundamental data structures.
*   **`dcrypt-algorithms`**: Low-level, constant-time implementations of cryptographic kernels (hashing, curve arithmetic, lattice math).
*   **`dcrypt-common`**: Shared security primitives, including `SecretBuffer` (automatic zeroization) and `SecureCompare`.
*   **`dcrypt-symmetric`**: High-level AEADs, stream ciphers, and secure key management wrappers.
*   **`dcrypt-kem`**: implementations of Key Encapsulation Mechanisms (Kyber, ECDH, McEliece placeholders).
*   **`dcrypt-sign`**: Implementations of Digital Signatures (Dilithium, ECDSA, Ed25519, SPHINCS+ placeholders).
*   **`dcrypt-hybrid`**: Ready-to-use combiners for KEMs and Signatures ensuring crypto-agility.
*   **`dcrypt-tests`**: Contains the ACVP test harness and Constant-Time Verification Suite.

## 🔒 Security & Verification

Security is the primary driver for dcrypt. The library employs a rigorous testing methodology:

### Constant-Time Verification
We utilize a custom statistical analysis engine (`dcrypt-tests/src/suites/constant_time`) that integrates into our CI.
*   **Methodology**: Uses Welch’s t-test, Kolmogorov–Smirnov tests, and Bootstrap resampling on high-resolution timing measurements.
*   **Dynamic Threshold Scaling**: Adapts to environmental noise (OS jitter) to prevent false positives in CI environments.
*   **Coverage**: Verifies critical paths in Kyber, Dilithium, ECDH, and AES-GCM against timing side-channels.

### FIPS/NIST Compliance
*   **ACVP Test Harness**: Includes a full test harness compatible with NIST's Automated Cryptographic Validation Program (ACVP) JSON vectors to ensure implementation correctness against official standards.
*   **Parameters**: All PQC parameters strictly adhere to FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).

## 📄 License

This project is licensed under the **Apache License, Version 2.0**.