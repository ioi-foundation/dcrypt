# NIST P-224 ('secp224r1') Elliptic Curve

This module implements the legacy NIST P-224 curve, also known as
`secp224r1`. It has not received a complete side-channel audit and makes no
blanket constant-time or production-suitability claim.

The implementation conforms to standards specified by NIST, including SP 800-186, "Recommendations for Discrete Logarithm-based Cryptography".

## Module Overview

The `p224` module is structured to provide a comprehensive and secure set of tools for working with the NIST P-224 curve. It includes:

*   **`field.rs`**: A constant-time implementation of arithmetic over the curve's prime field, defined by the modulus `p = 2^224 - 2^96 + 1`. This includes addition, subtraction, multiplication, and inversion.
*   **`scalar.rs`**: A constant-time implementation of arithmetic for scalars modulo the curve's group order `n`. This is crucial for handling private keys securely.
*   **`point.rs`**: An implementation of point arithmetic (addition, doubling) using efficient and secure Jacobian projective coordinates, with conversion to and from affine coordinates. It also handles point serialization.
*   **`constants.rs`**: Defines key size constants for scalars, field elements, and serialized points.
*   **`mod.rs`**: The main module file, which integrates the components and exposes the public API for key generation, scalar multiplication, and key derivation.
*   **`tests.rs`**: A comprehensive suite of unit, integration, and property-based tests to ensure correctness and security.

## Core Features

*   **Timing-aware implementation**: Secret-bearing paths attempt to avoid obvious value-dependent control flow; this is not a compiler- or target-level guarantee.
*   **Key Generation**: The `generate_keypair` function securely creates a new P-224 key pair using a cryptographically secure random number generator.
*   **Scalar Multiplication**: Efficient and secure scalar multiplication is provided through two functions:
    *   `scalar_mult_base_g`: For fixed-base multiplication with the curve's standard generator, used in public key generation.
    *   `scalar_mult`: For variable-base multiplication, essential for ECDH key agreement.
*   **Point Serialization**: Supports both compressed (29 bytes) and uncompressed (57 bytes) point formats as defined in the SEC 1 standard. This allows developers to choose between smaller data sizes and faster processing.
*   **ECDH with KDF**: The module includes `kdf_hkdf_sha256_for_ecdh_kem` for deriving a secure shared symmetric key from the point computed during an Elliptic Curve Diffie-Hellman (ECDH) exchange.

## Security Considerations

NIST P-224 provides approximately 112 bits of security, which is generally considered the minimum for modern applications. While secure against classical computers today, some vulnerability scanners may flag it as weak for long-term security. For new applications requiring at least 128-bit security, **P-256 is often recommended over P-224**.

Point decoders perform curve validation, but callers must independently assess
subgroup, protocol, side-channel, and legacy-algorithm requirements.

## Usage Example: ECDH Key Exchange

The following example shows how to use the `p224` module to perform a secure key exchange.

```rust
use dcrypt::algorithms::ec::p224::{self, Point, Scalar};
use rand::rngs::OsRng;

fn main() -> Result<(), dcrypt_algorithms::error::Error> {
    // 1. Alice generates her keypair.
    let (alice_private_key, alice_public_key) = p224::generate_keypair(&mut OsRng)?;

    // 2. Bob generates his keypair.
    let (bob_private_key, bob_public_key) = p224::generate_keypair(&mut OsRng)?;

    // 3. Alice computes the shared secret point using her private key and Bob's public key.
    let alice_shared_point = p224::scalar_mult(&alice_private_key, &bob_public_key)?;

    // 4. Bob computes the shared secret point using his private key and Alice's public key.
    let bob_shared_point = p224::scalar_mult(&bob_private_key, &alice_public_key)?;

    // Both parties arrive at the same point.
    assert_eq!(alice_shared_point, bob_shared_point);

    // 5. Derive a symmetric key from the shared point's x-coordinate using HKDF-SHA256.
    let ikm = alice_shared_point.x_coordinate_bytes();
    let info = Some(b"p224-ecdh-example".as_slice());

    let alice_derived_key = p224::kdf_hkdf_sha256_for_ecdh_kem(&ikm, info)?;
    let bob_derived_key = p224::kdf_hkdf_sha256_for_ecdh_kem(&ikm, info)?;

    assert_eq!(alice_derived_key, bob_derived_key);

    println!("P-224 ECDH key exchange successful!");
    println!("Derived Symmetric Key: {}", hex::encode(alice_derived_key));

    Ok(())
}

```

## Public API

The `p224` module exports the following key types and functions for public use:

*   **Types**:
    *   `Point`: Represents a point on the P-224 curve.
    *   `Scalar`: Represents a scalar value (private key).
    *   `FieldElement`: Represents an element in the curve's prime field.
    *   `PointFormat`: An enum for distinguishing serialization formats.
*   **Functions**:
    *   `base_point_g()`: Returns the standard generator point for the curve.
    *   `generate_keypair()`: Creates a new random `(Scalar, Point)` key pair.
    *   `scalar_mult_base_g()`: Computes `scalar * G`.
    *   `scalar_mult()`: Computes `scalar * P` for an arbitrary point `P`.
    *   `kdf_hkdf_sha256_for_ecdh_kem()`: Derives a shared key from an ECDH secret.
