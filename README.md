# dcrypt: A Cryptographic Library in Rust

[![Crates.io](https://img.shields.io/crates/v/dcrypt.svg?style=flat-square)](https://crates.io/crates/dcrypt)
[![Docs.rs](https://img.shields.io/docsrs/dcrypt?style=flat-square)](https://docs.rs/dcrypt)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![Security validation](https://img.shields.io/github/actions/workflow/status/ioi-foundation/dcrypt/security-validation.yml?branch=master&style=flat-square)](https://github.com/ioi-foundation/dcrypt/actions/workflows/security-validation.yml)

> [!WARNING]
> No dcrypt release is currently supported. `v2.0.0` contains important
> security remediations, but is withdrawn because its implementation and
> normal/build dependency closure violate the project's zero-unsafe,
> zero-native-code, and zero-FFI policy. `v1.2.3` contains critical defects and
> is not a safe fallback; earlier releases remain unsupported and uncleared.
> See the [v2.0.0 withdrawal notice](docs/security/V2.0.0-WITHDRAWAL.md) and
> [SECURITY.md](SECURITY.md).

**dcrypt** (Decentralized Cryptography) is a Rust workspace for classical,
post-quantum, and hybrid cryptographic APIs. The corrective release is being
developed under a strict contract: published dcrypt code and its normal/build
dependency closure must contain no unsafe Rust, native code, or FFI. External
implementations may be used only as isolated test oracles. These constraints
reduce implementation risk but do not by themselves prove cryptographic
correctness, side-channel resistance, or suitability for production.

## 🚀 Novel Capabilities

dcrypt introduces capabilities critical for the transition to quantum-safe and decentralized computing:

1.  **Pure-Rust FIPS 204 (ML-DSA)**: Final-standard `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87` use dcrypt-owned safe-Rust key generation, signing, verification, sampling, arithmetic, and exact encodings. Public APIs support deterministic signing and hedged signing with caller-provided randomness and contexts. All 615 official ACVP cases pass exactly; independent implementations are confined to the excluded verification workspace. This is not a claim that dcrypt is formally verified, audited, or FIPS validated.
2.  **Pure-Rust FIPS 203 (ML-KEM)**: Final-standard ML-KEM-512, ML-KEM-768, and ML-KEM-1024 use owned safe-Rust arithmetic, encoding, and SHA3/SHAKE primitives. All 240 official ACVP cases pass exactly; this project is not a FIPS-validated cryptographic module.
3.  **Native Hybrid Cryptography**: First-class support for hybrid Key Encapsulation Mechanisms (e.g., `ECDH P-256 + ML-KEM-768`) and hybrid Digital Signatures, designed to combine independent primitive families.
4.  **BLS12-381 Signatures and Pairings**: Safe-Rust group arithmetic, optimal Ate pairings, strict point decoding, and RFC 9380 hash-to-curve support high-level minimum-public-key Basic, Message Augmentation, and Proof of Possession schemes pinned to CFRG BLS draft-07. A separately named adapter preserves Ethereum's draft-v4 PoP and empty fast-aggregate semantics. No external runtime hash-to-curve library is required.

## 🛡️ Key Design Principles

*   **Safe-Rust implementation boundary**: The next supported release must contain no unsafe Rust, native code, or FFI in published dcrypt crates or their normal/build dependency closure. This is an enforceable implementation policy, not by itself a security proof.
*   **Post-Quantum APIs**: Exposes ML-DSA and ML-KEM parameter sets for interoperability testing and evaluation.
*   **Defense-in-Depth**: Hybrid schemes combine battle-tested classical algorithms (ECDH/ECDSA) with modern PQC primitives.
*   **Timing Analysis**: Security-sensitive paths are tested with a built-in statistical **Constant-Time Verification Suite** where applicable; passing statistical tests is not presented as a proof of constant-time execution.
*   **Type Safety**: High-level APIs prevent misuse through strong typing (e.g., distinct types for `Nonce`, `Key`, and `Tag` prevents byte-array confusion).
*   **`no_std` & Cross-Platform**: Selected crates and feature combinations support `no_std` with `alloc`; validate the exact algorithm and target combination before deployment.

## 📦 Quick Start

Do not select `v1.2.3`; it contains critical defects. Do not select `v2.0.0` as
a replacement; it has been withdrawn for violating the project's implementation
policy. Earlier releases are unsupported and have not been cleared. The examples
below describe the reviewed v3 API under development. They are not a
recommendation to deploy any currently published release.

### Example 1: Hybrid Post-Quantum Key Exchange

Securely exchange keys using the `EcdhP256MlKem768` hybrid scheme.

```rust
use dcrypt::api::Kem;
use dcrypt::hybrid::kem::EcdhP256MlKem768;
use dcrypt::internal::{CryptoRng, RngCore};

fn exchange<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::api::Result<()> {
    let (alice_pk, alice_sk) = EcdhP256MlKem768::keypair(rng)?;

    // 2. Bob encapsulates a shared secret against Alice's public key
    let (ciphertext, shared_secret_bob) = EcdhP256MlKem768::encapsulate(rng, &alice_pk)?;

    // 3. Alice decapsulates the ciphertext to recover the shared secret
    let shared_secret_alice = EcdhP256MlKem768::decapsulate(&alice_sk, &ciphertext)?;

    // 4. Verify secrets match
    assert_eq!(
        &shared_secret_bob.to_bytes_zeroizing()[..],
        &shared_secret_alice.to_bytes_zeroizing()[..],
    );
    println!("Hybrid Quantum-Safe Key Exchange successful!");
    
    Ok(())
}
```

### Example 2: Authenticated Encryption (AES-256-GCM)

Standard symmetric encryption remains a core part of the library, featuring ergonomic key management.

```rust
use dcrypt::internal::{CryptoRng, RngCore};
use dcrypt::symmetric::{Aead, Aes256Gcm, Aes256Key, SymmetricCipher};

fn encrypt<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::api::Result<()> {
    // dcrypt never chooses an operating-system RNG. The application supplies
    // the CSPRNG used for both key and nonce generation.
    let key = Aes256Key::generate(rng)?;
    let cipher = Aes256Gcm::new(&key)?;

    let nonce = Aes256Gcm::generate_nonce(rng)?;
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

### Example 3: Standard BLS12-381 Signatures

Create a minimum-public-key Basic signature through the protected high-level
API. Use `Bls12381G2ProofOfPossession` for same-message aggregation, or select
`Eth2Bls12381G2PopV4` explicitly when implementing Ethereum consensus rules.

```rust
use dcrypt::internal::{CryptoRng, RngCore};
use dcrypt::sign::bls::{Bls12381G2Basic, Bls12381SecretKey};

fn sign<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::api::Result<()> {
    // dcrypt obtains no OS entropy. Generate 32 bytes of IKM through the
    // caller-owned CSPRNG, then run draft-07 KeyGen with an explicit salt.
    let secret = Bls12381SecretKey::generate(rng, b"example application salt")?;
    let public = secret.public_key()?;
    let message = b"standard BLS signature";
    let signature = Bls12381G2Basic::sign(&secret, message)?;
    Bls12381G2Basic::verify(&public, message, &signature)?;
    Ok(())
}
```

## 📚 Supported Algorithms

dcrypt provides a unified API for classical, post-quantum, and hybrid operations:

| Category | Algorithms |
| :--- | :--- |
| **Symmetric Encryption (AEAD)** | `AES-128/256-GCM`, `ChaCha20-Poly1305`, `XChaCha20-Poly1305` |
| **Public Key Encryption (PKE)** | `ECIES` (P-224, P-256, P-384, P-521) |
| **Hash Functions** | `SHA-2` (224, 256, 384, 512), `SHA-3`, `BLAKE2b/s` |
| **XOFs** | `SHAKE-128/256`, `BLAKE3` |
| **Password Hashing** | `Argon2id` (default), `Argon2i`, `Argon2d`, `PBKDF2` |
| **Key Derivation** | `HKDF`, `PBKDF2` |
| **Digital Signatures** | `ECDSA` (P-224, P-256, P-384, P-521), `Ed25519`, BLS12-381 minimum-public-key Basic/Aug/PoP and separate Eth2 PoP-v4 |
| **Post-Quantum Signatures** | `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` (final FIPS 204) |
| **Key Exchange / KEM** | `ECDH` (P-224, P-256, P-384, P-521, K-256) |
| **Pairing-Friendly Curves** | `BLS12-381` (G1, G2, Gt, Pairings, Hash-to-Curve) |
| **Post-Quantum KEMs**| `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` (final FIPS 203) |
| **Hybrid Schemes** | `EcdhP256MlKem768`, `EcdhP384MlKem1024`, `EcdsaMlDsa65Hybrid` |

## 🏗️ Architecture

The library is organized as a workspace of specialized crates to align type-safety boundaries with security boundaries:

*   **`dcrypt-api`**: Defines core traits (`SymmetricCipher`, `Kem`, `Signature`), error types, and fundamental data structures.
*   **`dcrypt-algorithms`**: Low-level cryptographic kernels. Constant-time behavior is primitive- and backend-specific; no blanket guarantee is made for this crate.
*   **`dcrypt-common`**: Shared security primitives, including `SecretBuffer` (automatic zeroization) and `SecureCompare`.
*   **`dcrypt-symmetric`**: High-level AEADs, stream ciphers, and secure key management wrappers.
*   **`dcrypt-pke`**: Public Key Encryption schemes, specifically **ECIES** (Elliptic Curve Integrated Encryption Scheme) over standard NIST curves.
*   **`dcrypt-kem`**: Owned implementations of final FIPS 203 ML-KEM and ECDH-based KEMs.
*   **`dcrypt-sign`**: Implementations of final FIPS 204 ML-DSA, ECDSA, Ed25519, and high-level BLS12-381 signature profiles.
*   **`dcrypt-hybrid`**: Ready-to-use combiners for KEMs and Signatures ensuring crypto-agility.
*   **`dcrypt-tests`**: Contains the ACVP test harness and Constant-Time Verification Suite.

## 🔒 Security & Verification

Security is the primary driver for dcrypt. The library employs a rigorous testing methodology:

### Constant-Time Verification
The repository contains a custom statistical regression engine (`dcrypt-tests/src/suites/constant_time`). The security-validation workflow runs it serially as a regression gate and labels its scope explicitly. It is not dudect or ctgrind, and those stronger target-specific checks remain required before any production constant-time claim.
*   **Methodology**: Uses interleaved A/B timing measurements, bootstrap confidence intervals, Kolmogorov-Smirnov tests, Welch-style mean-shift checks, and Holm-Bonferroni correction across the combined signals.
*   **Noise Gating**: Maintains a persistent noise profile and aborts inconclusive runs when the host environment is materially noisier than the historical baseline.
*   **Coverage**: Exercises critical paths in ML-KEM, ML-DSA verification, BLS secret scalar multiplication, hybrid constructions, ECDH, and AEAD implementations for timing regressions.

### Standards testing
*   **ACVP Test Harness**: Includes an ACVP JSON test harness for supported parameter sets. Passing vectors is a correctness gate, not NIST validation or certification.
*   **ML-DSA Interoperability**: Runtime key generation, signing, verification, and complete expanded-key validation use only the dcrypt-owned implementation. The official key-generation, signature-generation, and signature-verification ACVP results are checked exactly. A separate non-published workspace performs bidirectional and byte-for-byte tests against `fips204`, libcrux, and RustCrypto. Bare expanded keys are validated coherently and retain their derived public key; paired import additionally rejects a mismatched public key.
*   **BLS Interoperability**: Ethereum-compatible KeyGen is checked against the four published ERC-2333 master-key vectors. Draft-07 KeyGen and all four minimum-public-key domains (Basic, Augmentation, PoP signatures, and PoP proofs) are checked byte-for-byte against an independent implementation confined to the excluded verification workspace. Draft-07 Appendix B still marks G2/minimum-public-key vectors as TBA, so no nonexistent official signature-vector claim is made.
*   **No certification claim**: dcrypt is not a FIPS-validated cryptographic module. Each algorithm and encoding must be assessed independently.

## 📄 License

This project is licensed under the **Apache License, Version 2.0**.
