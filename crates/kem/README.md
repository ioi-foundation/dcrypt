# Key Encapsulation Mechanisms

[![Crates.io](https://img.shields.io/crates/v/dcrypt-kem.svg)](https://crates.io/crates/dcrypt-kem)
[![Docs.rs](https://docs.rs/dcrypt-kem/badge.svg)](https://docs.rs/dcrypt-kem)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/your-repo/your-workflow.yml?branch=main)](https://github.com/your-repo/action)

The `dcrypt-kem` crate provides a unified interface for various Key Encapsulation Mechanisms (KEMs), including both traditional and post-quantum cryptographic algorithms. It is designed with a strong focus on security, type safety, and ease of use, leveraging the `dcrypt::api` trait system.

This crate is part of the `dcrypt` cryptographic library.

## Features

-   **Broad Algorithm Support:** Includes classic ECDH-based KEMs and final FIPS 203 ML-KEM.
-   **Security-First Design:**
    -   **Strongly-Typed Keys:** Uses distinct, validated types for public keys, secret keys, and ciphertexts.
    -   **Zeroization:** Secret key and shared secret materials are automatically zeroized on drop to minimize their lifetime in memory.
    -   **Controlled Byte Access:** Deliberately avoids generic `AsRef<[u8]>` implementations on sensitive types, requiring explicit serialization calls.
    -   **Validation:** Incoming keys and ciphertexts are validated to prevent common attacks, such as those involving invalid curve points.
-   **`no_std` Compatibility:** Fully operational in `no_std` environments with the `alloc` feature for heap-allocated types.
-   **Extensive Testing:** Comes with a comprehensive test suite and performance benchmarks for all implemented algorithms.
-   **Optional Serde Support:** Provides `serde` integration for key serialization and deserialization when the `serde` feature is enabled.

## Implemented Algorithms

The crate provides implementations for the following KEMs, accessible via the `dcrypt::api::Kem` trait.

| Category | Algorithm | Struct Name | Security Level | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Elliptic Curve** | ECDH over NIST P-192 | `EcdhP192` | ~80-bit | **Implemented** |
| **Elliptic Curve** | ECDH over NIST P-224 | `EcdhP224` | ~112-bit | **Implemented** |
| **Elliptic Curve** | ECDH over NIST P-256 | `EcdhP256` | ~128-bit | **Implemented** |
| **Elliptic Curve** | ECDH over NIST P-384 | `EcdhP384` | ~192-bit | **Implemented** |
| **Elliptic Curve** | ECDH over NIST P-521 | `EcdhP521` | ~256-bit | **Implemented** |
| **Elliptic Curve** | ECDH over secp256k1 | `EcdhK256` | ~128-bit | **Implemented** |
| **Elliptic Curve**| ECDH over sect283k1 | `EcdhB283k` | ~142-bit | **Implemented** |
| **Post-Quantum** | FIPS 203 ML-KEM-512 | `MlKem512` | NIST Level 1 | **Implemented** |
| **Post-Quantum** | FIPS 203 ML-KEM-768 | `MlKem768` | NIST Level 3 | **Implemented** |
| **Post-Quantum** | FIPS 203 ML-KEM-1024 | `MlKem1024` | NIST Level 5 | **Implemented** |

## Installation

Add the main `dcrypt` crate to your `Cargo.toml`:

```toml
[dependencies]
dcrypt = "0.12.0-beta.1"
```

## Usage Example

All KEMs in this crate implement the `dcrypt::api::Kem` trait, providing a consistent workflow.

Here is an example using `EcdhP256`:

```rust
use dcrypt::api::Kem;
use dcrypt::kem::ecdh::EcdhP256;
use dcrypt::internal::{CryptoRng, RngCore};

fn establish<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::api::Result<()> {
    let (public_key, secret_key) = EcdhP256::keypair(rng)?;

    // The recipient can now share `public_key` with senders.
    // For example, by serializing it:
    let pk_bytes = public_key.to_bytes();


    // 2. A sender uses the recipient's public key to generate a
    //    shared secret and a ciphertext for transport.
    let (ciphertext, shared_secret_sender) = EcdhP256::encapsulate(rng, &public_key)?;

    // The sender sends `ciphertext` to the recipient.
    let ct_bytes = ciphertext.to_bytes();


    // 3. The recipient uses their secret key to decapsulate the
    //    ciphertext and derive the same shared secret.
    let shared_secret_recipient = EcdhP256::decapsulate(&secret_key, &ciphertext)?;

    // 4. Both parties now possess the same shared secret.
    assert_eq!(shared_secret_sender.to_bytes(), shared_secret_recipient.to_bytes());

    println!("Successfully derived a shared secret!");
    println!("Shared Secret Length: {} bytes", shared_secret_sender.to_bytes().len());
    println!("Ciphertext Length: {} bytes", ct_bytes.len());

    Ok(())
}
```

The same pattern applies to final FIPS 203 ML-KEM:

```rust
use dcrypt::api::Kem;
use dcrypt::kem::ml_kem::MlKem768;
use dcrypt::internal::{CryptoRng, RngCore};

fn establish<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::api::Result<()> {
    let keypair = MlKem768::keypair(rng)?;
    let pk = MlKem768::public_key(&keypair);
    let sk = MlKem768::secret_key(&keypair);
    let (ct, ss1) = MlKem768::encapsulate(rng, &pk)?;
    let ss2 = MlKem768::decapsulate(&sk, &ct)?;
    assert_eq!(&ss1.to_bytes_zeroizing()[..], &ss2.to_bytes_zeroizing()[..]);
    Ok(())
}
```

## Cargo Features

The `dcrypt-kem` crate provides the following features:

-   `std` (default): Enables functionality that depends on the Rust standard library.
-   `alloc`: Enables usage of heap-allocated types. This is required for `no_std` environments that have a heap allocator.
-   `no_std`: Disables `std` support for use in bare-metal and embedded environments.
-   `post-quantum`: Enables the final FIPS 203 ML-KEM surface and forwards `alloc`.

## Benchmarks

The crate includes a comprehensive benchmark suite using `criterion`. To run the benchmarks and view the results:

```bash
cargo bench
```

The results will be available in the `target/criterion/` directory. The benchmarks cover key generation, encapsulation, and decapsulation for all implemented algorithms, providing a clear view of their relative performance.

An `ecdh_comparison` suite is also included to directly compare the performance of the different elliptic curves.

## License

This crate is licensed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).
