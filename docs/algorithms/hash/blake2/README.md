# BLAKE2 Hash Functions

This module provides a pure Rust, security-focused implementation of the BLAKE2 family of cryptographic hash functions as specified in [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html). BLAKE2 is a high-performance hash function optimized for modern 64-bit and 32-bit platforms while providing a high level of security.

## Overview

The BLAKE2 family offers significant speed improvements over the SHA-2 family while maintaining or exceeding its security level. This implementation provides two main variants:

-   **`Blake2b`**: Optimized for 64-bit platforms. It can produce digests of any size between 1 and 64 bytes.
-   **`Blake2s`**: Optimized for 32-bit platforms. It can produce digests of any size between 1 and 32 bytes.

Both variants are exposed through the standard `HashFunction` trait, providing a consistent and ergonomic API for both one-shot and incremental (streaming) hashing.

## Features

-   **Portable implementation**: Provides both 64-bit and 32-bit BLAKE2
    variants without native code or FFI.
-   **Versatile Variants**:
    -   `Blake2b` for servers and desktops (64-bit architecture).
    -   `Blake2s` for embedded systems and older hardware (32-bit architecture).
-   **Variable Output Length**: Unlike SHA-2, BLAKE2 can produce digests of any length up to its maximum (64 bytes for BLAKE2b, 32 for BLAKE2s), making it suitable as a KDF or for applications requiring specific output sizes.
-   **Built-in Keyed Hashing**: Provides a highly efficient MAC (Message Authentication Code) capability out-of-the-box, which is faster than the traditional HMAC construction.
-   **Security-First Design**:
    -   **Owned memory hygiene**: Secret-bearing keyed state and working
        buffers use clearing wrappers, subject to software-zeroization limits.
    -   **Timing-sensitive source design**: The implementation avoids
        intentional secret-dependent branches where applicable; this is not a
        blanket compiler/target proof.
-   **Advanced Customization**: Exposes the low-level parameter block for advanced use cases like tree hashing or for building other cryptographic primitives like Argon2.

## Usage

### Standard Hashing (One-Shot)

The simplest way to compute a hash is with the `digest` static method. By default, `Blake2b::new()` and `Blake2s::new()` produce the maximum possible output length (64 and 32 bytes, respectively).

```rust
use dcrypt::algorithms::hash::{blake2::Blake2b, HashFunction};

let data = b"The quick brown fox jumps over the lazy dog";
let digest = Blake2b::digest(data).unwrap();

println!("BLAKE2b Digest (64 bytes): {}", digest.to_hex());
// Expected: a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918
```

### Incremental (Streaming) Hashing

For large inputs, such as files or network streams, you can use the incremental API provided by the `HashFunction` trait.

```rust
use dcrypt::algorithms::hash::{blake2::Blake2s, HashFunction};

let mut hasher = Blake2s::new();
hasher.update(b"The quick brown fox ")
      .unwrap()
      .update(b"jumps over the lazy dog")
      .unwrap();

let digest = hasher.finalize().unwrap();

println!("BLAKE2s Digest (32 bytes): {}", digest.to_hex());
// Expected: 606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812
```

### Variable Output Length

BLAKE2's standout feature is its ability to produce digests of arbitrary length. This is achieved using the `with_output_size` constructor.

```rust
use dcrypt::algorithms::hash::blake2::Blake2b;

let data = b"BLAKE2 can produce variable-length output";
let output_size = 20; // Request a 20-byte digest

let mut hasher = Blake2b::with_output_size(output_size);
hasher.update(data).unwrap();
let digest = hasher.finalize().unwrap();

assert_eq!(digest.len(), output_size);
println!("BLAKE2b Digest ({} bytes): {}", output_size, digest.to_hex());
```

### Keyed Hashing (MAC Mode)

BLAKE2 provides a built-in mechanism for keyed hashing, which functions as a highly efficient Message Authentication Code (MAC).

```rust
use dcrypt::algorithms::hash::blake2::Blake2b;

let key = b"my-top-secret-authentication-key"; // Key can be up to 64 bytes
let data = b"this message needs to be authenticated";
let output_size = 32;

// Create a keyed Blake2b instance
let mut hasher = Blake2b::with_key(key, output_size).unwrap();
hasher.update(data).unwrap();
let tag = hasher.finalize().unwrap();

println!("BLAKE2b MAC Tag ({} bytes): {}", output_size, tag.to_hex());
```

## Advanced Usage: Parameter Block

For advanced cryptographic constructions like tree hashing or Argon2, BLAKE2 allows for full customization of its initial state via a 64-byte parameter block. This can be configured using the `with_parameter_block` constructor.

```rust
use dcrypt::algorithms::hash::blake2::Blake2b;

// Example: Manually configuring parameters for Argon2's H₀ function
let mut param_block = [0u8; 64];
param_block[0] = 64; // digest_length = 64
param_block[2] = 1;  // fanout = 1
param_block[3] = 1;  // depth = 1
// ... other parameters like node_offset, inner_length, etc.

let output_size = 64;
let mut hasher = Blake2b::with_parameter_block(param_block, output_size);

// Use the hasher as usual
hasher.update(b"some data").unwrap();
let digest = hasher.finalize().unwrap();
```

## Compliance

The `Blake2b` and `Blake2s` implementations follow **RFC 7693** and are
checked against its published vectors. This is not formal validation or
certification.
