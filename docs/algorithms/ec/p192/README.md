# NIST P-192 (`secp192r1`) Elliptic Curve 

This module implements the legacy NIST P-192 curve, also known as `secp192r1`
and `prime192v1`. It is a prime-field Weierstrass curve. No blanket
constant-time or production-suitability claim is made.

**⚠️ Security Warning:** The P-192 curve provides an effective security strength of only 96 bits, which is below the minimum of 112 bits recommended for modern cryptographic applications. This implementation is intended for interoperability with legacy systems and should not be used for new protocols.

## Core Features

*   **Timing-aware implementation**: Secret-bearing paths attempt to avoid obvious value-dependent control flow; compiler- and target-level behavior is not guaranteed.
*   **Key Generation**: Securely generate public/private key pairs using `generate_keypair`. This function uses a cryptographically secure random number generator to create a private key (a 192-bit scalar) and computes the corresponding public key (a point on the curve).
*   **Scalar Multiplication**: Provides efficient and secure scalar multiplication:
    *   `scalar_mult_base_g`: Fixed-base multiplication with the curve's standard generator point, ideal for public key derivation.
    *   `scalar_mult`: Variable-base multiplication for operations like ECDH.
*   **Point Arithmetic**: Includes fundamental point operations such as addition and doubling. These are implemented using efficient Jacobian coordinates to minimize costly field inversions.
*   **Point Serialization**: Supports both compressed and uncompressed point serialization formats according to SEC 1 standards, offering a trade-off between storage size and computational overhead during deserialization.
*   **Elliptic Curve Diffie-Hellman (ECDH)**: The primitives in this module can be used to perform ECDH key exchange. A Key Derivation Function (KDF), `kdf_hkdf_sha256_for_ecdh_kem`, is provided to securely derive a shared symmetric key from the computed ECDH point.

## Usage Example: ECDH Key Exchange

The following example demonstrates how to generate a key pair and compute a shared secret using the P-192 curve.

```rust
use dcrypt::algorithms::ec::p192::{self, Point, Scalar};
use rand::rngs::OsRng;

fn main() -> Result<(), dcrypt_algorithms::error::Error> {
    // 1. Alice generates her keypair.
    let (alice_private_key, alice_public_key) = p192::generate_keypair(&mut OsRng)?;

    // 2. Bob generates his keypair.
    let (bob_private_key, bob_public_key) = p192::generate_keypair(&mut OsRng)?;

    // 3. Alice computes the shared secret using her private key and Bob's public key.
    let alice_shared_secret_point = p192::scalar_mult(&alice_private_key, &bob_public_key)?;

    // 4. Bob computes the shared secret using his private key and Alice's public key.
    let bob_shared_secret_point = p192::scalar_mult(&bob_private_key, &alice_public_key)?;

    // Both parties should arrive at the same point on the curve.
    assert_eq!(alice_shared_secret_point, bob_shared_secret_point);

    // 5. Derive a symmetric key from the shared secret's x-coordinate using a KDF.
    //    Both parties must use the same context string ("info") to derive the same key.
    let ikm = alice_shared_secret_point.x_coordinate_bytes();
    let info = Some(b"ecdh-p192-example".as_slice());

    let alice_derived_key = p192::kdf_hkdf_sha256_for_ecdh_kem(&ikm, info)?;
    let bob_derived_key = p192::kdf_hkdf_sha256_for_ecdh_kem(&ikm, info)?;

    assert_eq!(alice_derived_key, bob_derived_key);

    println!("P-192 ECDH key exchange successful!");
    println!("Derived Symmetric Key: {}", hex::encode(alice_derived_key));

    Ok(())
}
```

## Module Structure

The `p192` module is organized into the following main components:

*   **`Point`**: Represents a point on the elliptic curve in affine coordinates. It provides methods for point arithmetic, serialization (compressed and uncompressed), and validation.
*   **`Scalar`**: Represents an integer in the scalar field of the curve's group order. It is used for private keys and in scalar multiplication operations.
*   **`FieldElement`**: Represents an element in the prime field Fₚ and implements the necessary arithmetic for point operations.

## Benchmarks

Comprehensive benchmarks for all core P-192 elliptic curve operations are included in the `benches/p192.rs` file. These can be executed to measure the performance of field arithmetic, point operations, key generation, and ECDH on a given target machine.
