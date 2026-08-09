# docs/algorithms/README.md

[![Crates.io](https://img.shields.io/crates/v/dcrypt-algorithms.svg)](https://crates.io/crates/dcrypt-algorithms)
[![Docs.rs](https://docs.rs/dcrypt-algorithms/badge.svg)](https://docs.rs/dcrypt-algorithms)
[![License](https://img.shields.io/crates/l/dcrypt-algorithms.svg)](https://opensource.org/licenses/MIT)

`dcrypt-algorithms` is a Rust crate providing a range of cryptographic
primitives and type-oriented adapters. `v1.2.3` is confirmed
not production-safe; known-answer tests and Rust implementation alone do not
constitute high assurance or an independent audit.

This crate is the low-level engine for the dcrypt ecosystem. Side-channel and
memory-erasure properties are primitive-, backend-, compiler-, and
target-specific; this document makes no blanket guarantee.

## Overview

This library provides low-level cryptographic implementations intended to be used through the higher-level APIs of the `dcrypt` suite. It is built with the following principles:

*   **Security review:** Secret-bearing paths are expected to follow the workspace constant-time and zeroization policies, but not every current implementation has completed the required dynamic review.
*   **Correctness:** Selected algorithms have NIST/RFC known-answer coverage. Self-roundtrips and vector tests are evidence of interoperability, not certification or a security audit.
*   **Type Safety:** A strong type system is used to prevent common cryptographic mistakes at compile time. Keys, nonces, and other cryptographic types are bound to the algorithms they are intended for.
*   **Feature-oriented builds:** The crate exposes `std` and `alloc` feature
    boundaries. A complete standalone `no_std` algorithms build is not currently
    a validated configuration; check the exact primitive and target.
*   **Modern Cryptography:** Includes a selection of modern, post-quantum and pairing-friendly primitives alongside traditional, widely-adopted standards.

## Features

The crate provides a broad range of cryptographic primitives, categorized as follows:

### Hashing
*   **SHA-2 Family:** SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
*   **SHA-3 Family:** SHA3-224, SHA3-256, SHA3-384, SHA3-512
*   **BLAKE2:** BLAKE2b (64-bit optimized) and BLAKE2s (32-bit optimized)
*   **Keccak:** Keccak-256 (Ethereum compatible)
*   **SHA-1:** Included for legacy compatibility, but its use is strongly discouraged.

### Extendable-Output Functions (XOFs)
*   **SHAKE:** SHAKE128 and SHAKE256
*   **BLAKE3:** A high-performance XOF with built-in parallelism.

### Authenticated Encryption with Associated Data (AEAD)
*   **AES-GCM:** AES in Galois/Counter Mode with 128, 192, and 256-bit keys.
*   **ChaCha20-Poly1305:** As specified in RFC 8439.
*   **XChaCha20-Poly1305:** ChaCha20-Poly1305 with an extended 24-byte nonce.

### Key Derivation Functions (KDFs)
*   **Argon2:** The password-hashing competition winner, with `Argon2id`, `Argon2i`, and `Argon2d` variants.
*   **PBKDF2:** Password-Based Key Derivation Function 2.
*   **HKDF:** HMAC-based Key Derivation Function.

### Message Authentication Codes (MACs)
*   **HMAC:** Hash-based MAC.
*   **Poly1305:** A high-speed, one-time authenticator.

### Block Ciphers & Modes
*   **AES:** AES-128, AES-192, and AES-256.
*   **Modes of Operation:** Cipher Block Chaining (CBC) and Counter (CTR) mode.

### Elliptic Curve Cryptography
*   **NIST Prime Curves:** P-256, P-384, P-521, P-224, and P-192.
*   **Koblitz Curve:** `secp256k1`.
*   **Binary Curve:** `sect283k1`.
*   **Pairing-Friendly Curve:** BLS12-381, including G1/G2 operations and optimal Ate pairing.

### Post-Quantum Primitives
*   **Lattice-Based Math:** Includes a generic polynomial engine with Number-Theoretic Transform (NTT) implementations for Dilithium (FIPS-204) and Kyber parameters.

## Security

This library is written with a security-first mindset.

*   **Timing boundary:** Some operations use branchless code or maintained backends designed for constant-time execution. Refer to `CONSTANT_TIME_POLICY.md`; source shape and statistical tests are not proof for every build.
*   **Memory hygiene:** Owned key and intermediate buffers use `SecretBuffer` or `Zeroizing` where implemented. This cannot guarantee erasure of caller copies, registers, compiler temporaries, freed allocator storage, or every backend-internal copy.
*   **Type System:** We leverage Rust's type system to enforce cryptographic properties at compile time. For example, a `SymmetricKey<Aes128, 16>` cannot be accidentally used with a ChaCha20 cipher, preventing API misuse.

## Usage

Here are a few examples of how to use the primitives in this crate.

### AEAD: ChaCha20-Poly1305

```rust
use dcrypt::algorithms::aead::ChaCha20Poly1305;
use dcrypt::algorithms::types::Nonce;

// Create a key and nonce
let key = [0x42; 32];
let nonce_data = [0x24; 12];
let nonce = Nonce::<12>::new(nonce_data);

// Create a cipher instance
let cipher = ChaCha20Poly1305::new(&key);

// Encrypt plaintext with associated data
let plaintext = b"Hello, secure world!";
let aad = b"metadata";
let ciphertext = cipher.encrypt(&nonce, plaintext, Some(aad)).unwrap();

// Decrypt
let decrypted = cipher.decrypt(&nonce, &ciphertext, Some(aad)).unwrap();

assert_eq!(decrypted, plaintext);
```

### Hashing: SHA-256

```rust
use dcrypt::algorithms::hash::{Sha256, HashFunction};

// One-shot hashing
let digest = Sha256::digest(b"some data").unwrap();
println!("SHA-256 Digest: {}", digest.to_hex());

// Incremental hashing
let mut hasher = Sha256::new();
hasher.update(b"some ").unwrap();
hasher.update(b"data").unwrap();
let digest2 = hasher.finalize().unwrap();

assert_eq!(digest, digest2);
```

### Elliptic Curves: P-256 ECDH

```rust
use dcrypt::algorithms::ec::p256;
use rand::rngs::OsRng;

// 1. Alice generates a keypair.
let (alice_sk, alice_pk) = p256::generate_keypair(&mut OsRng).unwrap();

// 2. Bob generates a keypair.
let (bob_sk, bob_pk) = p256::generate_keypair(&mut OsRng).unwrap();

// 3. Alice and Bob compute their shared secrets.
let alice_shared_secret = p256::scalar_mult(&alice_sk, &bob_pk).unwrap();
let bob_shared_secret = p256::scalar_mult(&bob_sk, &alice_pk).unwrap();

// Both secrets will be the same elliptic curve point.
assert_eq!(alice_shared_secret, bob_shared_secret);

// They can then use a KDF on the x-coordinate to derive a symmetric key.
let key_material = alice_shared_secret.x_coordinate_bytes();
let derived_key = p256::kdf_hkdf_sha256_for_ecdh_kem(&key_material, Some(b"ecdh-example")).unwrap();
```

## `no_std` Support

The manifest retains granular `alloc` and algorithm feature flags for ongoing
portability work. A complete standalone `no_std` configuration is not currently
a release-gated or supported build. Do not infer support from the presence of a
feature name; validate the exact primitive, dependency graph, target, and panic
strategy before use.

## Benchmarks

This crate includes a comprehensive benchmark suite using `criterion`. To run the benchmarks:

```sh
cargo bench
```

HTML reports will be generated in the `target/criterion/report` directory.

## Feature Flags

This crate uses feature flags to control which algorithm modules are compiled.

*   `std`: Enables functionality that requires the standard library. Enables `alloc` automatically.
*   `alloc`: Enables functionality that requires a memory allocator (like `Vec` and `Box`).
*   `hash`: Enables all hash function modules (SHA-2, SHA-3, BLAKE2, etc.).
*   `xof`: Enables extendable-output functions (SHAKE, BLAKE3). Requires `alloc`.
*   `aead`: Enables authenticated encryption ciphers (AES-GCM, ChaCha20-Poly1305). Requires `alloc`.
*   `block`: Enables block ciphers (AES) and modes (CBC, CTR).
*   `kdf`: Enables key derivation functions (Argon2, PBKDF2, HKDF). Requires `alloc`.
*   `mac`: Enables message authentication codes (HMAC, Poly1305).
*   `stream`: Enables stream ciphers (ChaCha20).
*   `ec`: Enables all elliptic curve cryptography. Requires `alloc`.

By default, `std`, `xof`, and `ec` are enabled.

## License

This project is licensed under the [APACHE 2.0 License](LICENSE).
