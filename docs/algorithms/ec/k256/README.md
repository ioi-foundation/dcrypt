# K256 ('secp256k1') Elliptic Curve

This module implements the `secp256k1` elliptic curve. It has not received a
complete compiler- and target-level side-channel audit and makes no blanket
constant-time or protocol-suitability claim.

The module operates on the curve defined by the equation `y² = x³ + 7` over the prime field `F_p`, where `p = 2^256 - 2^32 - 977`.

## Core Features

*   **Timing-aware implementation**: Secret-bearing paths attempt to avoid obvious value-dependent control flow; this is not a whole-operation guarantee.
*   **Key Generation**: Provides a `generate_keypair` function for creating cryptographically secure private keys (Scalars) and their corresponding public keys (Points).
*   **Point Arithmetic**: Implements fundamental elliptic curve operations, including point addition, doubling, and negation. These operations are performed efficiently using projective coordinates internally to avoid costly modular inversions.
*   **Scalar Multiplication**: Offers robust and secure scalar multiplication functions:
    *   `scalar_mult_base_g`: A fixed-base multiplication with the standard curve generator `G`, optimized for deriving a public key from a private key.
    *   `scalar_mult`: A variable-base multiplication for operations involving an arbitrary point on the curve, essential for ECDH.
*   **Point Serialization**: Supports both compressed (33 bytes) and uncompressed (65 bytes) point serialization formats as defined in the SEC 1 standard. This allows for flexibility in choosing between smaller data sizes and faster processing.
*   **ECDH Support**: Facilitates Elliptic Curve Diffie-Hellman key exchange by providing all the necessary primitives. A dedicated Key Derivation Function, `kdf_hkdf_sha256_for_ecdh_kem`, is included to securely derive a shared symmetric key from the computed ECDH shared secret.

## Usage Example: ECDH Key Exchange

Here is a complete example of how to perform an ECDH key exchange between two parties, Alice and Bob, to establish a shared secret key.

```rust
use dcrypt::algorithms::ec::k256::{self, Point, Scalar};
use rand::rngs::OsRng;

fn main() -> Result<(), dcrypt_algorithms::error::Error> {
    // 1. Alice generates her key pair.
    let (alice_private_key, alice_public_key) = k256::generate_keypair(&mut OsRng)?;
    println!("Alice's private key generated.");

    // 2. Bob generates his key pair.
    let (bob_private_key, bob_public_key) = k256::generate_keypair(&mut OsRng)?;
    println!("Bob's private key generated.");

    // 3. Alice computes the shared secret using her private key and Bob's public key.
    let alice_shared_point = k256::scalar_mult(&alice_private_key, &bob_public_key)?;
    println!("Alice computed the shared secret point.");

    // 4. Bob computes the shared secret using his private key and Alice's public key.
    let bob_shared_point = k256::scalar_mult(&bob_private_key, &alice_public_key)?;
    println!("Bob computed the shared secret point.");

    // 5. Both parties now have the same shared secret point.
    assert_eq!(alice_shared_point, bob_shared_point);
    println!("Shared secret points match!");

    // 6. To create a symmetric key, they derive it from the x-coordinate of the shared point.
    //    Using a KDF is crucial for the security of the final key.
    let shared_x_coordinate = alice_shared_point.x_coordinate_bytes();
    let info = Some(b"k256-ecdh-example".as_slice());

    let alice_derived_key = k256::kdf_hkdf_sha256_for_ecdh_kem(&shared_x_coordinate, info)?;
    let bob_derived_key = k256::kdf_hkdf_sha256_for_ecdh_kem(&shared_x_coordinate, info)?;

    assert_eq!(alice_derived_key, bob_derived_key);

    println!("Successfully derived a shared symmetric key: {}", hex::encode(alice_derived_key));

    Ok(())
}
```

## API Overview

The `k256` module exposes a clean and secure API centered around two main types:

*   **`Point`**: Represents a point on the `secp256k1` curve in affine coordinates `(x, y)`. It provides methods for point arithmetic (`add`, `double`), scalar multiplication (`mul`), serialization (`serialize_compressed`, `serialize_uncompressed`), and validation (`is_on_curve`). The identity point (point at infinity) is also supported.
*   **`Scalar`**: Represents an element in the scalar field, i.e., an integer modulo the curve's group order `n`. This type is used for private keys. Its constructor ensures that the value is valid (non-zero and less than `n`).

High-level functions abstract away the underlying complexity:
*   `generate_keypair`: Creates a new `(Scalar, Point)` key pair.
*   `scalar_mult`: Computes `scalar * point`.
*   `scalar_mult_base_g`: Computes `scalar * G`, where `G` is the curve generator.
*   `kdf_hkdf_sha256_for_ecdh_kem`: Derives a symmetric key from an ECDH shared secret.

## Benchmarks

A comprehensive benchmark suite is provided in `benches/k256.rs` to measure the performance of all critical operations, including field arithmetic, point operations, scalar multiplication, key generation, and the full ECDH workflow. You can run these benchmarks using `cargo bench --bench k256`.
