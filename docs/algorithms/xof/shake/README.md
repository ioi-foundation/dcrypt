# SHAKE: Extendable-Output Functions

This document provides detailed documentation for the `dcrypt::algorithms::xof::shake` module.

## Overview

This module provides implementations of the **SHAKE** (Secure Hash Algorithm and KECCAK) family of **eXtendable-Output Functions (XOFs)** as specified in FIPS PUB 202.

Unlike traditional hash functions that produce a fixed-size digest, XOFs can generate an output of any desired length. They are based on the Keccak sponge construction, the same foundation as the SHA-3 family. This makes them highly versatile for a range of cryptographic tasks, including:

*   Creating unique identifiers of any length.
*   Seeding pseudorandom number generators.
*   Serving as a basis for building stream ciphers.
*   Key derivation.

The implementations use clearing wrappers for owned secret-bearing state. That
is best-effort software memory hygiene, subject to the limits described below.

## Implemented Algorithms

This module provides two primary SHAKE variants:

*   **`ShakeXof128`**: An XOF providing a **128-bit security level**. It uses the Keccak permutation with a rate of 168 bytes.
*   **`ShakeXof256`**: An XOF providing a **256-bit security level**. It uses the Keccak permutation with a rate of 136 bytes.

## Core Interface: `ExtendableOutputFunction`

The functionality for both `ShakeXof128` and `ShakeXof256` is exposed through the `ExtendableOutputFunction` trait. This provides a consistent and safe API for all XOFs in the `dcrypt` ecosystem.

The core methods are:

| Method                 | Description                                                                                             |
| ---------------------- | ------------------------------------------------------------------------------------------------------- |
| `new()`                | Creates a new, empty XOF instance.                                                                      |
| `update(data: &[u8])`  | Absorbs input data into the XOF's internal state. Can be called multiple times.                         |
| `finalize()`           | Finalizes the absorption phase. No more data can be absorbed after this call.                           |
| `squeeze(out: &mut [u8])` | Squeezes (generates) output bytes into the provided buffer. Can be called multiple times to get more output. |
| `squeeze_into_vec(len)`| A convenient wrapper that allocates a `Vec<u8>` of the specified length and fills it with output.       |
| `reset()`              | Resets the XOF instance to its initial state, allowing for reuse.                                       |
| `generate(data, len)`  | A static convenience method for one-shot hashing and output generation.                                 |

## Usage Examples

### Standard Hashing (One-Shot)

For simple use cases where the entire input is available at once, the `generate` convenience function is recommended.

```rust
use dcrypt::algorithms::xof::{ShakeXof128, ExtendableOutputFunction};

let input = b"The quick brown fox jumps over the lazy dog";
let output_len = 64; // Generate a 64-byte output

let output = ShakeXof128::generate(input, output_len).unwrap();

assert_eq!(output.len(), output_len);
println!("SHAKE-128 Output: {}", hex::encode(output));
```

### Incremental Hashing (Streaming Input)

For streaming data or large files, the incremental API allows you to absorb data in chunks.

```rust
use dcrypt::algorithms::xof::{ShakeXof256, ExtendableOutputFunction};

// 1. Create a new instance.
let mut xof = ShakeXof256::new();

// 2. Absorb data in multiple calls.
xof.update(b"some data").unwrap();
xof.update(b" followed by some more data").unwrap();

// 3. Finalize the input phase. After this, no more `update` calls are allowed.
xof.finalize().unwrap();

// 4. Squeeze the desired amount of output.
let mut output = [0u8; 100];
xof.squeeze(&mut output).unwrap();

println!("SHAKE-256 Output: {}", hex::encode(output));
```

### Incremental Output (Squeezing)

A key feature of XOFs is the ability to continue generating output after finalization. The `squeeze` method can be called multiple times.

```rust
use dcrypt::algorithms::xof::{ShakeXof128, ExtendableOutputFunction};

let mut xof = ShakeXof128::new();
xof.update(b"generating a long stream of data").unwrap();

// After finalizing, you can squeeze output in chunks.
let mut output1 = [0u8; 32];
xof.squeeze(&mut output1).unwrap();

let mut output2 = [0u8; 64];
xof.squeeze(&mut output2).unwrap();

// The second output chunk will be different from the first.
assert_ne!(&output1[..], &output2[..32]);

println!("First 32 bytes:  {}", hex::encode(output1));
println!("Next 64 bytes: {}", hex::encode(output2));
```

## Security and Implementation Details

*   **Owned Memory Hygiene:** The internal Keccak state and buffered data use
    exact-size zeroizing wrappers. They explicitly clear owned initialized
    bytes on drop, but cannot guarantee erasure of compiler/register copies,
    caller copies, freed storage, swap, crash dumps, or cold-boot remnants.

*   **State Management:** The implementation enforces a strict state machine to prevent misuse.
    *   Calling `update()` after the state has been finalized (either by an explicit call to `finalize()` or implicitly by the first call to `squeeze()`) will result in an error.
    *   This prevents accidental data injection after the absorption phase is complete.
    *   The `reset()` method must be called to reuse the instance for a new, independent computation.

*   **Timing-Aware Operations:** The underlying `keccak-f[1600]` permutation
    avoids secret-indexed tables and secret-dependent control flow in source.
    This is not a blanket compiler- or target-level constant-time proof.

## Relationship to `dcrypt::algorithms::hash::shake`

The `dcrypt-algorithms` crate contains two modules for SHAKE:

1.  **`xof::shake` (this module):** Implements the true **eXtendable-Output Function** interface, allowing for variable-length, streamable output. This is the canonical and most flexible way to use SHAKE.
2.  **`hash::shake`:** Provides a wrapper around the XOF functionality to expose a standard, **fixed-output** `HashFunction` interface. For example, `hash::Shake128` will always produce a 32-byte output, behaving like `SHA-256`. This is provided for API consistency where a fixed-size digest is expected.

For applications that require arbitrary-length output, **this `xof::shake` module is the correct choice.**
