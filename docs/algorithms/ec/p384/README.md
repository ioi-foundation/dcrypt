# NIST P-384 (`secp384r1`) Elliptic Curve

This module implements the NIST P-384 curve, also known as `secp384r1`.
Conformance of the curve parameters does not make this implementation FIPS
validated or suitable for a particular classified-data profile. No blanket
constant-time claim is made.

The P-384 curve is a Weierstrass curve defined by the equation `y² = x³ - 3x + b` over the 384-bit prime field `p = 2³⁸⁴ − 2¹²⁸ − 2⁹⁶ + 2³² − 1`.

## Key Features

*   **192-bit Security Level**: Offers a higher security margin than 256-bit curves, suitable for protecting highly sensitive data.
*   **Timing-aware implementation**: Secret-bearing paths attempt to avoid obvious value-dependent control flow; this is not a compiler- or target-level guarantee.
*   **Secure Key Generation**: `generate_keypair` securely creates new public/private key pairs using a cryptographically secure random number generator and rejection sampling to ensure private keys are uniformly distributed.
*   **Efficient Point Arithmetic**: Utilizes Jacobian projective coordinates for point addition and doubling, minimizing the number of costly modular inversions required during computations.
*   **Standard parameters**: Uses the NIST/SECG P-384 parameters. Interoperability must be established with external vectors for the operation and encoding in use.
*   **Point Serialization**: Supports both uncompressed (`0x04 || x || y`) and compressed (`0x02/0x03 || x`) point formats as defined in SEC 1, allowing developers to balance storage size and computational overhead.
*   **ECDH Key Exchange**: Provides all necessary primitives for Elliptic Curve Diffie-Hellman, including a dedicated Key Derivation Function (`kdf_hkdf_sha384_for_ecdh_kem`) to derive a shared symmetric key.

## Usage Example: ECDH Key Exchange

The primary use case for this module is performing an Elliptic Curve Diffie-Hellman (ECDH) key exchange. Below is an example of how two parties, Alice and Bob, can establish a shared secret.

```rust
use dcrypt::algorithms::ec::p384::{self, Point, Scalar};
use rand::rngs::OsRng;

fn main() -> Result<(), dcrypt_algorithms::error::Error> {
    // 1. Alice and Bob generate their own P-384 keypairs.
    let (alice_private_key, alice_public_key) = p384::generate_keypair(&mut OsRng)?;
    let (bob_private_key, bob_public_key) = p384::generate_keypair(&mut OsRng)?;

    // 2. Alice computes a shared secret using her private key and Bob's public key.
    let alice_shared_point = p384::scalar_mult(&alice_private_key, &bob_public_key)?;

    // 3. Bob computes the same shared secret using his private key and Alice's public key.
    let bob_shared_point = p384::scalar_mult(&bob_private_key, &alice_public_key)?;

    // Both computations result in the same point on the curve.
    assert_eq!(alice_shared_point, bob_shared_point);

    // 4. A symmetric key is derived from the x-coordinate of the shared point using HKDF-SHA384.
    //    Using a KDF is a critical step to ensure the final key is cryptographically strong.
    let ikm = alice_shared_point.x_coordinate_bytes();
    let info = Some(b"p384-ecdh-example".as_slice()); // Optional context string

    let alice_derived_key = p384::kdf_hkdf_sha384_for_ecdh_kem(&ikm, info)?;
    let bob_derived_key = p384::kdf_hkdf_sha384_for_ecdh_kem(&ikm, info)?;

    assert_eq!(alice_derived_key, bob_derived_key);

    println!("P-384 ECDH key exchange successful!");
    println!("Derived Symmetric Key (first 16 bytes): {}", hex::encode(&alice_derived_key[..16]));

    Ok(())
}```

## API Overview

The `p384` module exposes a concise and powerful API for elliptic curve operations:

*   **`Point`**: Represents a point on the P-384 curve in affine coordinates. It provides methods for point arithmetic (`add`, `double`), serialization (`serialize_compressed`, `serialize_uncompressed`), and validation.
*   **`Scalar`**: Represents an integer modulo the curve's group order `n`. It is used for private keys and scalar multiplication. The implementation ensures that all scalar values are valid and within the correct range.
*   **`generate_keypair`**: Creates a new `(Scalar, Point)` key pair.
*   **`scalar_mult`**: Performs variable-base scalar multiplication (`k * P`), essential for ECDH.
*   **`scalar_mult_base_g`**: Performs fixed-base scalar multiplication (`k * G`), used for deriving a public key from a private key.
*   **`kdf_hkdf_sha384_for_ecdh_kem`**: A key derivation function that uses HKDF with SHA-384 to transform the raw ECDH shared secret into a uniform symmetric key suitable for use with AEAD ciphers.

## Security and Performance

This implementation is written with a security-first mindset. All operations on secret values (i.e., `Scalar` objects) are performed in constant time to protect against timing-based side-channel attacks. Field arithmetic uses specialized reduction techniques for the P-384 prime to ensure both correctness and efficiency.

While P-384 may be less performant than smaller curves like P-256 or Curve25519, its 192-bit security level makes it a suitable choice for applications requiring a higher degree of long-term security. Performance benchmarks for all critical operations can be found in `benches/p384.rs` and executed to evaluate performance on a specific platform.
