# SHA-2 Hash Functions

This module provides a comprehensive suite of SHA-2 (Secure Hash Algorithm 2) hash functions as specified in **FIPS PUB 180-4**. The implementations prioritize security, correctness, and a consistent, ergonomic API, with a strong focus on resistance to side-channel attacks.

## Overview

The SHA-2 family consists of six hash functions with varying digest sizes. They are a fundamental component of modern cryptography, used in digital signatures, message authentication codes, and a wide range of other security protocols.

This implementation provides the documented SHA-2 variants and known-answer
tests. That coverage is a correctness check, not a high-assurance certification.

## Features

-   **Complete SHA-2 Family:** All standard variants are available.
-   **Unified API:** All variants implement the `HashFunction` trait, providing a consistent interface for hashing and verification.
-   **Security-First Design:**
    -   **Owned Memory Handling:** Secret-bearing schedules and working state use
        clearing wrappers whose initialized storage is explicitly cleared on
        drop. This does not erase compiler/register or external copies.
    -   **Timing-sensitive implementation:** The compression path avoids
        intentional secret-indexed lookup tables. Memory fences support the
        clearing implementation; they do not prove side-channel resistance.
-   **Type Safety:** The use of a generic `Digest<N>` type for hash outputs ensures that digests of different sizes (e.g., from SHA-256 and SHA-384) cannot be accidentally interchanged at compile time.
-   **`no_std` Compatibility:** Fully usable in embedded and resource-constrained environments (requires `alloc`).

## Supported Variants

This module provides the following FIPS-compliant SHA-2 hash functions:

| Struct        | Output Size (bits) | Output Size (bytes) | Block Size (bytes) |
| :------------ | :----------------- | :------------------ | :----------------- |
| `Sha224`      | 224                | 28                  | 64                 |
| `Sha256`      | 256                | 32                  | 64                 |
| `Sha384`      | 384                | 48                  | 128                |
| `Sha512`      | 512                | 64                  | 128                |
| `Sha512_224`  | 224                | 28                  | 128                |
| `Sha512_256`  | 256                | 32                  | 128                |

## Core API: The `HashFunction` Trait

All SHA-2 structs implement the `HashFunction` trait from the parent `dcrypt::algorithms::hash` module, providing a consistent and ergonomic API for all hashing operations.

```rust
pub trait HashFunction {
    // Creates a new hasher instance.
    fn new() -> Self;

    // Updates the hash state with more data. Can be called multiple times.
    fn update(&mut self, data: &[u8]) -> Result<&mut Self>;

    // Finalizes the hash computation and returns the digest.
    fn finalize(&mut self) -> Result<Self::Output>;

    // Convenience method for one-shot hashing.
    fn digest(data: &[u8]) -> Result<Self::Output>;

    // Equal-length digest comparison avoids data-dependent early exit.
    fn verify(data: &[u8], expected: &Self::Output) -> Result<bool>;
}
```

## Usage Examples

### One-Shot Hashing (SHA-256)

For simple, single inputs, the `digest` method is the most straightforward.

```rust
use dcrypt::algorithms::hash::{Sha256, HashFunction};

let data = b"some important data";
let digest = Sha256::digest(data).unwrap();

println!("SHA-256: {}", digest.to_hex());
// Output: SHA-256: 1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee
```

### Incremental (Streaming) Hashing (SHA-512)

For large files or network streams, the incremental API allows you to process data in chunks.

```rust
use dcrypt::algorithms::hash::{Sha512, HashFunction};

let mut hasher = Sha512::new();
hasher.update(b"this is the first part of a very long message, ")
      .unwrap()
      .update(b"and this is the second and final part.")
      .unwrap();

let digest = hasher.finalize().unwrap();

println!("SHA-512: {}", digest.to_hex());
```

### Hash Verification

For equal-length digests, `verify` compares bytes without a data-dependent early
exit. Public lengths and errors may branch, and this is not a whole-operation
compiler/target timing proof.

```rust
use dcrypt::algorithms::hash::{Sha256, HashFunction};

let data = b"verify me";
let correct_digest = Sha256::digest(data).unwrap();
let incorrect_digest = Sha256::digest(b"wrong data").unwrap();

// Verification should succeed
assert!(Sha256::verify(data, &correct_digest).unwrap());

// Verification should fail for a different message
assert!(!Sha256::verify(b"wrong data", &correct_digest).unwrap());

// Verification should fail for a different digest
assert!(!Sha256::verify(data, &incorrect_digest).unwrap());
```

### Using a Different Variant (SHA-384)

The API remains the same across all SHA-2 variants, with the only difference being the struct name and the size of the output `Digest`.

```rust
use dcrypt::algorithms::hash::{Sha384, HashFunction};

let data = b"some other data";
let digest = Sha384::digest(data).unwrap();

// The Digest<N> type provides the correct size at compile time.
assert_eq!(digest.len(), 48); // SHA-384 produces a 48-byte digest

println!("SHA-384: {}", digest.to_hex());
```
