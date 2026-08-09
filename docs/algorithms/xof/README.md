# Extendable-Output Functions

This document provides detailed documentation for the `xof` (Extendable-Output Function) module within the `dcrypt-algorithms` crate.

## Overview

Extendable-Output Functions (XOFs) are a class of cryptographic hash functions that can produce an output of any desired length. They are useful in a variety of protocols, including key derivation, stream encryption, and building other cryptographic primitives.

This module provides type-safe dcrypt implementations of popular XOFs. Keyed
and secret-bearing paths use explicit clearing wrappers where documented; the
release does not make a blanket compiler/target constant-time claim.

### Core Traits

The functionality of this module is exposed through a set of traits:

*   **`ExtendableOutputFunction`**: The primary trait for all XOFs. It provides a standard interface for hashing data and generating, or "squeezing," an arbitrary-length output.
    *   `new()`: Creates a new XOF instance.
    *   `update()`: Absorbs input data into the XOF's state.
    *   `finalize()`: Finalizes the absorption phase. No more data can be added after this.
    *   `squeeze()`: Fills a provided buffer with output from the XOF. Can be called multiple times to generate more output.
    *   `reset()`: Resets the XOF to its initial state for reuse.

*   **`KeyedXof`**: A trait for XOFs that support a keyed mode, functioning similarly to a MAC. Implemented by `Blake3Xof`.
    *   `with_key(key: &[u8])`: Creates a new instance keyed with the provided secret key.

*   **`DeriveKeyXof`**: A trait for XOFs that support a dedicated key derivation mode. Implemented by `Blake3Xof`.
    *   `for_derive_key(context: &[u8])`: Creates an instance using a context string for domain separation, ready to derive a key from input material.

## Implemented Algorithms

### SHAKE (Secure Hash Algorithm and KECCAK)

The SHAKE functions are part of the FIPS 202 (SHA-3) standard. They are based on the Keccak sponge construction.

*   **`ShakeXof128`**: Provides a 128-bit security level.
*   **`ShakeXof256`**: Provides a 256-bit security level.

#### Usage: Standard SHAKE Hashing

```rust
use dcrypt::algorithms::xof::{ShakeXof128, ExtendableOutputFunction};

// 1. Create a new SHAKE instance.
let mut xof = ShakeXof128::new();

// 2. Absorb the input data. This can be done in one or more calls.
xof.update(b"The quick brown fox").unwrap();
xof.update(b" jumps over the lazy dog").unwrap();

// 3. Finalize the input phase.
xof.finalize().unwrap();

// 4. Squeeze the desired amount of output.
let mut output = [0u8; 64];
xof.squeeze(&mut output).unwrap();

println!("SHAKE-128 Output: {}", hex::encode(output));

// 5. You can continue squeezing more data from the same state.
let mut more_output = [0u8; 32];
xof.squeeze(&mut more_output).unwrap();
```

### BLAKE3

BLAKE3 is a state-of-the-art cryptographic hash function designed for high performance and parallelism, based on the ChaCha permutation. It natively supports standard hashing, keyed hashing, and key derivation modes.

*   **`Blake3Xof`**: Provides a 256-bit security level.

#### Usage: Standard BLAKE3 Hashing

The `ExtendableOutputFunction` trait is used for standard hashing.

```rust
use dcrypt::algorithms::xof::{Blake3Xof, ExtendableOutputFunction};

// One-shot hashing is available for convenience.
let output = Blake3Xof::generate(b"some data to hash", 64).unwrap();
assert_eq!(output.len(), 64);

// Incremental hashing follows the update -> squeeze pattern.
let mut xof = Blake3Xof::new();
xof.update(b"some data").unwrap();
xof.update(b" to hash").unwrap();
let mut output_buf = [0u8; 64];
xof.squeeze(&mut output_buf).unwrap();
```

#### Usage: Keyed Hashing (MAC)

The `KeyedXof` trait provides a secure way to use BLAKE3 for message authentication.

```rust
use dcrypt::algorithms::xof::{Blake3Xof, KeyedXof};

let key = &[0x42; 32]; // Key must be 32 bytes.
let data = b"authenticated message";

// Create a keyed instance.
let mut xof = Blake3Xof::with_key(key).unwrap();
xof.update(data).unwrap();

// Generate a 32-byte authentication tag.
let tag = xof.squeeze_into_vec(32).unwrap();
```

#### Usage: Key Derivation

The `DeriveKeyXof` trait uses a context string for domain separation, making it ideal for deriving application-specific keys.

```rust
use dcrypt::algorithms::xof::{Blake3Xof, DeriveKeyXof};

let context = "My Application v2 Session Keys";
let input_key_material = b"user_id:12345,nonce:abcdef";

// Create a key-derivation instance with the context string.
let mut kdf = Blake3Xof::for_derive_key(context.as_bytes()).unwrap();

// Absorb the input material.
kdf.update(input_key_material).unwrap();

// Derive a 64-byte key.
let derived_key = kdf.squeeze_into_vec(64).unwrap();
```

## Security and Implementation Details

*   **Timing-sensitive paths:** The Keccak and BLAKE3 permutations avoid
    intentional secret-dependent control flow where applicable. Target code is
    inspected by release gates, but this is not a blanket proof.
*   **Owned memory hygiene:** Secret-bearing states, buffers, and keys use
    clearing wrappers. These wrappers cannot erase caller, compiler/register,
    allocator, swap, or crash-dump copies.
*   **State Management:** The XOF implementations robustly manage their internal state. Attempting to `update` the state after `finalize` or `squeeze` has been called will return an error, preventing accidental misuse. The `reset` method provides a secure way to reuse an instance for a new, independent computation.
