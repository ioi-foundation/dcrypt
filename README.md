# dcrypt

## Built to be attacked before it is trusted.

**dcrypt is evidence-native cryptography.** Every release is exercised through
an openly reproducible security laboratory that injects faults, calibrates
leakage detection, replays historical vulnerabilities, probes timing-sensitive
operations, rebuilds packages, and verifies the artifacts users install.

[![Crates.io](https://img.shields.io/crates/v/dcrypt.svg?style=flat-square)](https://crates.io/crates/dcrypt)
[![Docs.rs](https://img.shields.io/docsrs/dcrypt?style=flat-square)](https://docs.rs/dcrypt)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![Security validation](https://img.shields.io/github/actions/workflow/status/ioi-foundation/dcrypt/security-validation.yml?branch=master&style=flat-square)](https://github.com/ioi-foundation/dcrypt/actions/workflows/security-validation.yml)

> [!IMPORTANT]
> [`v4.0.1`](https://github.com/ioi-foundation/dcrypt/releases/tag/v4.0.1) is
> the current supported portable-software release. `v3.0.0` remains the prior
> corrective line. `v2.0.0` contains important
> security remediations, but remains withdrawn because its implementation and
> normal/build dependency closure violate the project's zero-unsafe,
> zero-native-code, and zero-FFI policy. `v1.2.3` contains critical defects and
> is not a safe fallback; every pre-v3 release is unsupported.
> See the [v2.0.0 withdrawal notice](docs/security/V2.0.0-WITHDRAWAL.md) and
> [SECURITY.md](SECURITY.md).

The result is not another “security tested” badge. It is a machine-readable
**Assurance Profile** bound to an exact source tree, dependency closure,
toolchain, target set, and release artifact collection. Security claims have an
address: a release, a subject commit, a metric, an evidence class, and a public
path to the result.

[Download the v4.0.1 visual report](https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.1/assurance-report.html) ·
[Inspect every v4.0.1 metric](https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.1/V4-SUMMARY.md) ·
[Download the v4.0.1 machine profile](https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.1/assurance-profile.json) ·
[Reproduce the open laboratory](docs/assurance/REPRODUCE.md) ·
[Understand the evidence model](docs/assurance/README.md)

<a href="https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.1/assurance-report.html">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.1/v4-assurance-overview-dark.svg">
    <img src="https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.1/v4-assurance-overview-light.svg" alt="dcrypt 4.0.1 Assurance Profile overview — four separate evidence panels">
  </picture>
</a>

### The v4 Assurance Profile

The released v4 profile and self-contained report were generated from the same
laboratory evidence that gated publication. The tracked
[v4.0.1 evidence index](https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.1/V4-SUMMARY.md) links every headline result to
its machine field, interpretation, and source model.

| Security signal | Released v4 result | Inspect |
| :--- | :--- | :--- |
| Detection calibration | **432 / 432** injected artifact faults detected; **20,000 samples/class** in leakage controls | [Simulation model](docs/assurance/OPEN-SECURITY-LAB.md) · [v4.0.1 profile fields](https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.1/V4-SUMMARY.md) |
| Product execution | **29 cases × 2** timing passes; **11 / 11** historical vulnerability classes replayed | [Timing policy](docs/assurance/METRICS.md#timing-visualization) · [advisories](docs/security/README.md) |
| Correctness corpus | **855** exact post-quantum vector cases | [Terminology and boundary](docs/assurance/METRICS.md#standards-vector-terminology) |
| Supply and build surface | **12 / 12** byte-equal packages; **5** deterministic SBOMs; **4** target profiles | [Full v4.0.1 evidence ledger](https://github.com/ioi-foundation/dcrypt/releases/download/v4.0.1/V4-SUMMARY.md) |

These are separate, inspectable signals—not inputs to an opaque security score.
The simulation metrics demonstrate the declared simulation models and calibrate
the analysis pipeline. Statistical timing results remain scoped evidence rather
than a universal constant-time proof, and passing the repository's byte-bound
ACVP-format corpus is not NIST validation or authenticated upstream provenance.

**dcrypt** (Decentralized Cryptography) is a Rust workspace for classical,
post-quantum, and hybrid cryptographic APIs. Published dcrypt code and its
normal/build dependency closure are required to contain no unsafe Rust, native
code, or FFI. External implementations may be used only as isolated test
oracles. This boundary is mechanically enforced; it is not treated as a
substitute for cryptographic evidence.

## Why dcrypt exists

**The release is the unit of trust.** Algorithms, audits, project reputation,
and signatures each answer useful questions, but none describes the complete
software subject a user deploys. dcrypt makes its security posture observable
at release time:

*   **Minimize and expose the trusted computing base.** No unsafe Rust, native
    code, or FFI in the published code or its normal/build dependency closure
    — mechanically enforced by a fail-closed boundary gate
    ([`implementation-boundary.toml`](implementation-boundary.toml)), not
    asserted. External implementations exist only as isolated test oracles.
*   **Diversify assumptions.** First-class classical/post-quantum hybrid KEMs
    and signatures, so no system makes one irreversible bet on one algorithm
    family or one era of cryptanalysis. Separate implementations are still
    required when implementation diversity is part of the threat model.
*   **Measure the implementation.** Controlled fault and leakage signals
    calibrate the laboratory; product executions replay known failures and
    probe timing-sensitive paths.
*   **Scope every claim.** Release evidence records the applicable release,
    configuration, toolchain, target, property, and threat model. Replay of the
    repository's byte-bound ACVP-format corpus is a correctness gate, not FIPS
    validation or authenticated upstream provenance; statistical timing results
    are evidence, not a constant-time proof. A claim without enough scope to
    evaluate it is treated as a defect.
*   **Preserve assurance continuity.** Evidence is regenerated when the release
    subject changes. When a release violates the contract, it is withdrawn
    rather than weakening the contract—as practiced in the
    [v2.0.0 withdrawal](docs/security/V2.0.0-WITHDRAWAL.md) and the
    [eleven advisories](docs/security/README.md) documented for this
    corrective-release campaign.
*   **Decentralize verification.** The boundary manifest, ACVP harness, timing
    suite, fuzz targets, and release gates live in this repository and are
    runnable by anyone. No maintainer, auditor, or institution — including
    this project — should become an unquestioned root of trust.

dcrypt does not ask users to inherit a conclusion. It publishes the profile,
the evidence behind it, and the command that reproduces both.

## 🚀 Capabilities

dcrypt provides capabilities for the transition to quantum-safe and decentralized computing:

1.  **Pure-Rust FIPS 204 (ML-DSA)**: Final-standard `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87` use dcrypt-owned safe-Rust key generation, signing, verification, sampling, arithmetic, and exact encodings. Public APIs support deterministic signing and hedged signing with caller-provided randomness and contexts. All expected fields for 615 cases in the repository's byte-bound ACVP-format corpus pass exactly; the upstream URL, revision, acquisition record, and original download digest of those fixtures remain unverified. Candidate comparator implementations are confined to the excluded verification workspace, and none is currently accepted as an independent assurance oracle. This is not a claim that dcrypt is formally verified, audited, FIPS validated, or that the local fixtures have authenticated upstream provenance.
2.  **Pure-Rust FIPS 203 (ML-KEM)**: Final-standard ML-KEM-512, ML-KEM-768, and ML-KEM-1024 use owned safe-Rust arithmetic, encoding, and SHA3/SHAKE primitives. All expected fields for 240 cases in the repository's byte-bound ACVP-format corpus pass exactly; their upstream acquisition provenance remains unverified. This project is not a FIPS-validated cryptographic module.
3.  **Native Hybrid Cryptography**: First-class support for hybrid Key Encapsulation Mechanisms (e.g., `ECDH P-256 + ML-KEM-768`) and hybrid Digital Signatures, designed to combine independent primitive families.
4.  **BLS12-381 Signatures and Pairings**: Safe-Rust group arithmetic, optimal Ate pairings, strict point decoding, and RFC 9380 hash-to-curve support high-level minimum-public-key Basic, Message Augmentation, and Proof of Possession schemes pinned to CFRG BLS draft-07. A separately named adapter preserves Ethereum's draft-v4 PoP and empty fast-aggregate semantics. No external runtime hash-to-curve library is required.

## 🛡️ Key Design Principles

*   **Safe-Rust implementation boundary**: The published v4 implementation and its normal/build dependency closure contain no unsafe Rust, native code, or FFI. This is an enforceable implementation policy, not by itself a security proof.
*   **Post-Quantum APIs**: Exposes ML-DSA and ML-KEM parameter sets for interoperability testing and evaluation.
*   **Defense-in-Depth**: Hybrid schemes combine battle-tested classical algorithms (ECDH/ECDSA) with modern PQC primitives.
*   **Timing Analysis**: Security-sensitive paths are tested with a built-in statistical **Constant-Time Verification Suite** where applicable; passing statistical tests is not presented as a proof of constant-time execution.
*   **Type Safety**: High-level APIs prevent misuse through strong typing (e.g., distinct types for `Nonce`, `Key`, and `Tag` prevents byte-array confusion).
*   **`no_std` & Cross-Platform**: Selected crates and feature combinations support `no_std` with `alloc`; validate the exact algorithm and target combination before deployment.

## 📦 Quick Start

Use `dcrypt = { version = "4.0.1", features = ["hybrid"] }` for the examples
below. Do not select `v1.2.3`; it contains critical defects.
Do not select `v2.0.0` as a replacement; it has been withdrawn for violating
the project's implementation policy. Every earlier release is unsupported.
The examples below describe the v4 API. Review [SECURITY.md](SECURITY.md) and
the [v4 migration notes](docs/migration/V4-ERROR-API.md) before deployment; the release has not received an
independent post-remediation security audit or FIPS validation.

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
| **Hybrid Schemes** | `EcdhK256MlKem512`, `EcdhP256MlKem512`, `EcdhP256MlKem768`, `EcdhP384MlKem1024`, `EcdhP521MlKem1024`, `EcdsaMlDsa65Hybrid` |

## 🏗️ Architecture

The library is organized as a workspace of specialized crates to align type-safety boundaries with security boundaries:

*   **`dcrypt-api`**: Defines core traits (`SymmetricCipher`, `Kem`, `Signature`), error types, and fundamental data structures.
*   **`dcrypt-algorithms`**: Low-level cryptographic kernels. Constant-time behavior is primitive- and backend-specific; no blanket guarantee is made for this crate.
*   **`dcrypt-common`**: Shared security primitives, including `SecretBuffer` (best-effort drop-time clearing of owned initialized storage) and `SecureCompare`.
*   **`dcrypt-symmetric`**: High-level AEADs, stream ciphers, and secure key management wrappers.
*   **`dcrypt-pke`**: Public Key Encryption schemes, specifically **ECIES** (Elliptic Curve Integrated Encryption Scheme) over standard NIST curves.
*   **`dcrypt-kem`**: Owned implementations of final FIPS 203 ML-KEM and ECDH-based KEMs.
*   **`dcrypt-sign`**: Implementations of final FIPS 204 ML-DSA, ECDSA, Ed25519, and high-level BLS12-381 signature profiles.
*   **`dcrypt-hybrid`**: Ready-to-use combiners for KEMs and Signatures ensuring crypto-agility.
*   **`dcrypt-tests`**: Contains the ACVP test harness and Constant-Time Verification Suite.

## 🔒 Security & Verification

Security is the primary driver for dcrypt, and assurance is continuously
re-earned rather than inherited. The evidence below states the applicable
release, configuration, toolchain, target, property, and threat-model scope and
is reproducible from this repository.

### Constant-Time Verification
The repository contains a custom statistical regression engine (`dcrypt-tests/src/suites/constant_time`). The security-validation workflow runs it serially as a regression gate and labels its scope explicitly. A constant-time claim additionally requires operation-specific source review and optimized-assembly/target evidence, supplemented by external dynamic tools where applicable. Passing that scoped evidence is not a universal compiler, target, microarchitectural, or caller-level proof.
*   **Methodology**: Each of the 29 blocking cases uses one reusable same-address state, prepares its equal-public-metadata A/B input outside the clock with read-both mask selection, and follows an exactly balanced paired schedule. One fixed-seed paired-randomization p-value per case enters a single suite-wide Holm correction at family alpha 0.01. A case blocks the suite only when Holm rejects and the absolute paired mean difference exceeds the unchanged case-specific practical threshold. Paired-bootstrap confidence intervals, Welch-style mean-shift checks, and Kolmogorov-Smirnov tests are descriptive diagnostics only.
*   **Noise Gating**: Records the current environment in the versioned `paired-v1` noise-profile namespace. A legacy-harness profile is never consumed. When a comparable prior `paired-v1` baseline exists, the gate aborts an inconclusive run if the host is materially noisier than that baseline.
*   **Coverage**: Exercises critical paths in ML-KEM, ML-DSA verification, BLS secret scalar multiplication, hybrid constructions, ECDH, and AEAD implementations for timing regressions.

### Standards testing
*   **ACVP Test Harness**: Includes an ACVP JSON test harness for supported parameter sets. Passing vectors is a correctness gate, not NIST validation or certification.
*   **ML-DSA Interoperability**: Runtime key generation, signing, verification, and complete expanded-key validation use only the dcrypt-owned implementation. The expected key-generation, signature-generation, and signature-verification fields in the repository's byte-bound ACVP-format corpus are checked exactly; upstream acquisition provenance for those fixtures remains unverified. A separate non-published workspace performs bidirectional and byte-for-byte corroborative tests against `fips204`, libcrux, and RustCrypto. Lineage review rejects libcrux and RustCrypto as independent assurance oracles and leaves `fips204` unresolved, so none of these comparisons is passing assurance evidence. Bare expanded keys are validated coherently and retain their derived public key; paired import additionally rejects a mismatched public key.
*   **BLS Interoperability**: Ethereum-compatible KeyGen is checked against four recorded EIP-2333 vectors, while the repository Ethereum corpus retains unverified upstream acquisition provenance. Draft-07 KeyGen and all four minimum-public-key domains (Basic, Augmentation, PoP signatures, and PoP proofs) are checked byte-for-byte against a comparator confined to the excluded verification workspace. Source-overlap review classifies that comparator as shared-lineage, not an independent assurance oracle. Draft-07 Appendix B still marks G2/minimum-public-key vectors as TBA, so no nonexistent official signature-vector claim is made.
*   **No certification claim**: dcrypt is not a FIPS-validated cryptographic module. Each algorithm and encoding must be assessed independently.

## 📄 License

This project is licensed under the **Apache License, Version 2.0**.
