# Cryptographic Hash Functions

This module provides a suite of cryptographic hash functions with a consistent,
type-safe API. Keyed and secret-bearing paths use exact-size clearing wrappers
where documented; those wrappers do not prove physical erasure or
whole-operation side-channel resistance.

## Overview

The core of this module is the `HashFunction` trait, which provides a unified interface for both one-shot and incremental (streaming) hashing. All hash functions produce a type-safe `Digest<N>` object, where `N` is the output size in bytes, ensuring that digests of different sizes cannot be accidentally interchanged at compile time.

## Features

- **Unified API:** A consistent `HashFunction` trait for all supported algorithms.
- **One-Shot & Incremental Hashing:** Support for both simple, single-call hashing and streaming operations for large data.
- **Type Safety:** Compile-time guarantees on digest sizes using the `Digest<N>` type.
- **Security-First Design:**
    - **Timing-sensitive paths:** Implementations avoid intentional
      secret-indexed lookup tables or secret-dependent early exits where
      documented. Release checks are not a compiler/target-wide proof.
    - **Owned memory hygiene:** Secret-bearing intermediate values use clearing
      wrappers where documented, subject to the limits of software zeroization.
- **Keyed Hashing:** Native support for keyed hashing with BLAKE2.
- **`no_std` Compatibility:** Usable in embedded and resource-constrained environments (requires `alloc`).

## Supported Algorithms

The module includes the following standard hash functions:

-   **SHA-2 Family**
    -   `Sha224`
    -   `Sha256`
    -   `Sha384`
    -   `Sha512`
    -   `Sha512_224`
    -   `Sha512_256`

-   **SHA-3 (Keccak) Family**
    -   `Sha3_224`
    -   `Sha3_256`
    -   `Sha3_384`
    -   `Sha3_512`

-   **Keccak Family (Ethereum Compatible)**
    -   `Keccak256` (Uses `0x01` padding, distinct from NIST SHA3-256)

-   **SHAKE (as fixed-output hashes)**
    -   `Shake128` (fixed 32-byte output)
    -   `Shake256` (fixed 64-byte output)
    > **Note:** For variable-length output (XOF), use the implementations in `dcrypt::algorithms::xof`.

-   **BLAKE2 Family**
    -   `Blake2b` (64-bit optimized, variable output up to 64 bytes)
    -   `Blake2s` (32-bit optimized, variable output up to 32 bytes)

-   **Legacy**
    > ⚠️ **Warning: SHA-1 Deprecation**
    > `Sha1` is included for interoperability with legacy systems only. It is considered cryptographically broken and should not be used in new protocols or applications.

## Core Abstraction: The `HashFunction` Trait

All hash functions implement the `HashFunction` trait, providing a consistent interface:

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

    // Convenience method for verifying a hash against input data.
    fn verify(data: &[u8], expected: &Self::Output) -> Result<bool>;
}
```

## Usage Examples

### One-Shot Hashing

The simplest way to compute a hash is with the `digest` static method.

```rust
use dcrypt::algorithms::hash::{Sha256, HashFunction};

let data = b"hello world";
let digest = Sha256::digest(data).unwrap();

println!("Data: {}", String::from_utf8_lossy(data));
println!("SHA-256 Digest: {}", digest.to_hex());
// Output: SHA-256 Digest: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
```

### Incremental (Streaming) Hashing

For large inputs (e.g., files or network streams), you can use the incremental API.

```rust
use dcrypt::algorithms::hash::{Sha512, HashFunction};

let mut hasher = Sha512::new();
hasher.update(b"this is the first part of the message, ")
      .unwrap()
      .update(b"and this is the second part.")
      .unwrap();

let digest = hasher.finalize().unwrap();

println!("SHA-512 Digest: {}", digest.to_hex());
```

### Hash Verification

For equal-length digests, `verify` computes the candidate digest and compares
its bytes without a data-dependent early exit. Public lengths and errors may
branch; this is not a whole-operation timing guarantee.

```rust
use dcrypt::algorithms::hash::{Sha256, HashFunction};

let data = b"my secret data";
let correct_digest = Sha256::digest(data).unwrap();
let incorrect_digest = Sha256::digest(b"wrong data").unwrap();

// Verification should succeed
assert!(Sha256::verify(data, &correct_digest).unwrap());

// Verification should fail
assert!(!Sha256::verify(data, &incorrect_digest).unwrap());
```

### Keyed Hashing with BLAKE2b

The BLAKE2 family of hashes natively supports a keyed mode, which is more efficient than the generic HMAC construction.

```rust
use dcrypt::algorithms::hash::Blake2b;

let key = b"my-secret-key-for-blake2b-auth"; // Can be up to 64 bytes
let data = b"authenticated message";
let output_size = 32; // Desired tag size in bytes

// Create a keyed Blake2b instance
let mut hasher = Blake2b::with_key(key, output_size).unwrap();
hasher.update(data).unwrap();
let tag = hasher.finalize().unwrap();

println!("BLAKE2b Tag: {}", tag.to_hex());
```

### Fixed-Output SHAKE

This module provides an interface to use SHAKE functions as if they were standard hash functions with a fixed default output size.

```rust
use dcrypt::algorithms::hash::{Shake128, HashFunction};

// SHAKE128 will produce a 32-byte (256-bit) digest by default
let data = b"some data";
let digest = Shake128::digest(data).unwrap();

assert_eq!(digest.len(), 32);
println!("SHAKE-128 (32-byte) Digest: {}", digest.to_hex());
```
> For variable-length output from SHAKE, please see the `dcrypt::algorithms::xof` module.

### Ethereum-Compatible Hashing (Keccak-256)

For compatibility with Ethereum addresses and signatures, use `Keccak256`. Note that this produces different output than NIST `Sha3_256` due to different padding.

```rust
use dcrypt::algorithms::hash::{Keccak256, HashFunction};

let data = b"transfer(address,uint256)";
let digest = Keccak256::digest(data).unwrap();

// This matches Ethereum's function selector hash
println!("Keccak-256 Digest: {}", digest.to_hex());
```
