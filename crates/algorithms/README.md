# docs/algorithms/README.md

[![Crates.io](https://img.shields.io/crates/v/dcrypt-algorithms.svg)](https://crates.io/crates/dcrypt-algorithms)
[![Docs.rs](https://docs.rs/dcrypt-algorithms/badge.svg)](https://docs.rs/dcrypt-algorithms)
[![License](https://img.shields.io/crates/l/dcrypt-algorithms.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/your-repo/rust.yml?branch=main)](https://github.com/your-repo/actions)

`dcrypt-algorithms` is a comprehensive, high-assurance cryptographic library for Rust, providing a wide array of primitives with a strong focus on security, correctness, and type-safety.

This crate serves as the core cryptographic engine for the `dcrypt` ecosystem, implementing algorithms designed to be resistant to side-channel attacks through constant-time execution and secure memory handling.

## Overview

This library provides low-level cryptographic implementations intended to be used through the higher-level APIs of the `dcrypt` suite. It is built with the following principles:

*   **Security-First:** Implementations prioritize resistance to side-channel attacks. Operations on secret data are designed to be constant-time, and sensitive memory is securely zeroed on drop.
*   **Correctness:** Algorithms are rigorously tested against official test vectors from sources like NIST (CAVP) and RFCs to ensure interoperability and correctness.
*   **Type Safety:** A strong type system is used to prevent common cryptographic mistakes at compile time. Keys, nonces, and other cryptographic types are bound to the algorithms they are intended for.
*   **Flexibility:** The crate is designed to work in both `std` and `no_std` environments (with `alloc`), making it suitable for a wide range of applications from servers to embedded systems.
*   **Modern Cryptography:** Includes a selection of modern, post-quantum and pairing-friendly primitives alongside traditional, widely-adopted standards.

## Features

The crate provides a broad range of cryptographic primitives, categorized as follows:

### Hashing
*   **SHA-2 Family:** SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
*   **SHA-3 Family:** SHA3-224, SHA3-256, SHA3-384, SHA3-512
*   **BLAKE2:** BLAKE2b (64-bit optimized) and BLAKE2s (32-bit optimized)
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

*   **Constant-Time Execution:** Primitives that handle secret data, particularly elliptic curve and block cipher operations, are implemented to be "constant-time." This means their execution time does not depend on the values of the secret inputs, mitigating a broad class of timing side-channel attacks.
*   **Secure Memory Handling:** Sensitive data like keys, intermediate cryptographic state, and nonces are handled using secure memory buffers (`SecretBuffer`, `Zeroizing`) that automatically zero their contents when they go out of scope, preventing accidental leakage.
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

This crate supports `no_std` environments by disabling the default `std` feature. Many algorithms require an allocator, which can be enabled with the `alloc` feature.

```toml
[dependencies.dcrypt-algorithms]
version = "0.12.0-beta.1"
default-features = false
features = ["alloc", "hash", "mac", "aead"] # Enable desired algorithm modules
```

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