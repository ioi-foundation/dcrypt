# BLAKE3: Extendable-Output Functions

[![Crates.io](https://img.shields.io/crates/v/dcrypt-algorithms.svg)](https://crates.io/crates/dcrypt-algorithms)
[![Docs.rs](https://docs.rs/dcrypt-algorithms/badge.svg)](https://docs.rs/dcrypt-algorithms)

This document provides detailed documentation for the BLAKE3 Extendable-Output Function (XOF) implementation within the `dcrypt-algorithms` crate.

## Overview

BLAKE3 is a state-of-the-art cryptographic hash function designed for exceptional performance, high security, and versatility. It is built upon the well-analyzed ChaCha stream cipher permutation and a Merkle tree structure, allowing for massive parallelism.

This module provides a safe-Rust implementation of BLAKE3 in its native
Extendable-Output Function (XOF) mode. Keyed and derive-key state uses explicit
clearing wrappers; source-level mask/flow properties remain subject to
compiler- and target-specific validation.

## Modes of Operation

This module exposes the full versatility of BLAKE3 through three distinct modes of operation, accessible via different traits:

1.  **Standard Hashing (XOF)**: The default mode for generating a hash of arbitrary length from input data. Implemented via the `ExtendableOutputFunction` trait.
2.  **Keyed Hashing (MAC)**: A secure mode for message authentication, analogous to HMAC. It uses a 32-byte secret key to produce an authentication tag. Implemented via the `KeyedXof` trait.
3.  **Key Derivation (KDF)**: A mode for deriving cryptographic keys from a combination of a context string and input keying material. Implemented via the `DeriveKeyXof` trait.

## Usage

The primary entry point is the `Blake3Xof` struct, which implements the traits for all three modes.

### 1. Standard Hashing (XOF)

Use the `ExtendableOutputFunction` trait for standard hashing. You can use the one-shot `generate` function for convenience or the incremental API for streaming data.

```rust
use dcrypt::algorithms::xof::{Blake3Xof, ExtendableOutputFunction};

// --- One-Shot Hashing ---
// Generate 64 bytes of output from the input data.
let input = b"some data to hash";
let output = Blake3Xof::generate(input, 64).unwrap();
assert_eq!(output.len(), 64);
println!("BLAKE3 Hash: {}", hex::encode(&output));

// --- Incremental (Streaming) Hashing ---
let mut xof = Blake3Xof::new();
xof.update(b"some data").unwrap();
xof.update(b" to hash").unwrap();

// Finalize the absorption phase (no more updates allowed after this).
xof.finalize().unwrap();

// Squeeze 64 bytes of output.
let mut output_buf = [0u8; 64];
xof.squeeze(&mut output_buf).unwrap();

// You can continue squeezing more data from the same state.
let mut more_output = [0u8; 32];
xof.squeeze(&mut more_output).unwrap();
```

### 2. Keyed Hashing (MAC Mode)

Use the `KeyedXof` trait to create a MAC. The key **must** be 32 bytes long.

```rust
use dcrypt::algorithms::xof::{Blake3Xof, KeyedXof};

let key = b"this is a 32-byte key for BLAKE3"; // Must be exactly 32 bytes.
let data = b"authenticated message";

// Create a keyed instance.
let mut xof = Blake3Xof::with_key(key).unwrap();
xof.update(data).unwrap();

// Generate a 32-byte authentication tag.
let tag = xof.squeeze_into_vec(32).unwrap();

println!("BLAKE3 MAC Tag: {}", hex::encode(&tag));
```

### 3. Key Derivation (KDF Mode)

Use the `DeriveKeyXof` trait for key derivation. A `context` string is used for domain separation, ensuring that keys derived for different purposes are unique.

```rust
use dcrypt::algorithms::xof::{Blake3Xof, DeriveKeyXof};

let context = "My Application v2 Session Keys";
let input_key_material = b"user_id:12345,nonce:abcdef";

// Create a key-derivation instance with the context string.
let mut kdf = Blake3Xof::for_derive_key(context.as_bytes()).unwrap();

// Absorb the input keying material.
kdf.update(input_key_material).unwrap();

// Derive a 64-byte key for symmetric encryption.
let derived_key = kdf.squeeze_into_vec(64).unwrap();

assert_eq!(derived_key.len(), 64);
```

## Security & Implementation Notes

*   **Correctness First**: This implementation is checked against the published
    BLAKE3 test vectors. That is not formal validation or a blanket
    side-channel claim.
*   **No SIMD Optimizations**: This is a pure Rust implementation and does not include platform-specific SIMD optimizations found in some other BLAKE3 libraries. It is intended for environments where security and portability are the primary concerns.
*   **Owned Memory Hygiene**: Keys, chaining values, and secret-derived scratch
    use exact-size zeroizing wrappers and explicitly clear owned initialized
    bytes on drop. This cannot guarantee physical erasure of compiler/register
    copies, caller copies, freed storage, swap, or crash dumps.
*   **State Management**: The API is designed to prevent misuse. For example, calling `update()` after `finalize()` or `squeeze()` will result in an error, ensuring the integrity of the hash computation.

## API Reference

The primary entry point is the `Blake3Xof` struct, which implements the following core traits from the `dcrypt::algorithms::xof` module:

*   `ExtendableOutputFunction`
*   `KeyedXof`
*   `DeriveKeyXof`

For a full API reference, please see the [official documentation on docs.rs](https://docs.rs/dcrypt-algorithms).
