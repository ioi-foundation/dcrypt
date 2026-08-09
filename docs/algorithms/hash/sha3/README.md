# SHA-3 Hash Functions

This module provides dcrypt's implementation of the **SHA-3 family of hash
functions** specified in **FIPS PUB 202**, built on Keccak-f[1600].

## Overview

The SHA-3 functions are based on the "sponge construction," which allows them to process input messages of arbitrary length and produce a fixed-size digest. This module provides the standard fixed-output hash functions defined in the SHA-3 standard. For variable-length output functions (XOFs) like SHAKE, see the `dcrypt::algorithms::xof` module.

## Features

-   **FIPS 202 interoperability:** The algorithms are checked against the
    complete repository ACVP corpus, including partial-bit, Monte Carlo, and
    large-data cases. This is not FIPS validation or certification.
-   **Security-First Design:**
    -   **Timing-sensitive source design:** The Keccak permutation avoids
        intentional data-dependent branches and table lookups. This is not a
        compiler- or target-wide side-channel proof.
    -   **Owned memory hygiene:** Secret-bearing intermediate state and buffers
        use clearing wrappers, subject to the limits of software zeroization.
-   **Unified API:** All SHA-3 variants implement the `HashFunction` trait, providing a consistent and ergonomic interface that is shared with all other hash functions in the `dcrypt` library.
-   **`no_std` Compatibility:** The implementation is fully compatible with `no_std` environments that have an allocator (`alloc` feature).

## Supported Algorithms

This module provides the following four standard SHA-3 hash functions:

| Struct        | Output Size (bits) | Output Size (bytes) | Security Strength (bits) |
|---------------|--------------------|---------------------|--------------------------|
| `Sha3_224`    | 224                | 28                  | 112                      |
| `Sha3_256`    | 256                | 32                  | 128                      |
| `Sha3_384`    | 384                | 48                  | 192                      |
| `Sha3_512`    | 512                | 64                  | 256                      |

## Usage Examples

All SHA-3 functions share the same API provided by the `HashFunction` trait.

### One-Shot Hashing

For simple use cases, the `digest` method is the most convenient way to hash a message.

```rust
use dcrypt::algorithms::hash::{Sha3_256, HashFunction};

let data = b"The quick brown fox jumps over the lazy dog";
let digest = Sha3_256::digest(data).unwrap();

println!("SHA3-256 Digest: {}", digest.to_hex());
// Expected Output: 69070dda01975c8c120c3aada1b282394e03217c183390a7860f0b7556f0ae8f
```

### Incremental (Streaming) Hashing

For large inputs, such as files or network streams, the incremental API allows you to process data in chunks.

```rust
use dcrypt::algorithms::hash::{Sha3_512, HashFunction};

let part1 = b"This is a long message that will be processed ";
let part2 = b"incrementally in multiple parts.";

let mut hasher = Sha3_512::new();
hasher.update(part1).unwrap();
hasher.update(part2).unwrap();
let digest = hasher.finalize().unwrap();

println!("SHA3-512 Digest: {}", digest.to_hex());
```

### Hash Verification

For equal-length digests, `verify` compares bytes without a data-dependent early
exit. Public lengths and errors may branch.

```rust
use dcrypt::algorithms::hash::{Sha3_384, HashFunction};

let data = b"message to be verified";
let correct_digest = Sha3_384::digest(data).unwrap();

// Verification with the correct data should succeed.
assert!(Sha3_384::verify(data, &correct_digest).unwrap());

// Verification with different data should fail.
assert!(!Sha3_384::verify(b"different message", &correct_digest).unwrap());
```

## Implementation Details

The security of this module relies on a carefully implemented `keccak_f1600` permutation. Key aspects include:

-   **Theta (`θ`) step:** Uses bitwise operations to mix data across columns.
-   **Rho (`ρ`) and Pi (`π`) steps:** Perform bit rotations and permutations to diffuse data across the state.
-   **Chi (`χ`) step:** A non-linear operation that provides confusion.
-   **Iota (`ι`) step:** Adds round constants to break symmetry between rounds.

Each step uses fixed arithmetic and bitwise operations rather than
secret-indexed tables. Release gates inspect representative target code; they
do not constitute a formal timing proof.
