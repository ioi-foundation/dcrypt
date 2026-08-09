# B283K ('sect283k1') Elliptic Curve

This module implements the legacy `sect283k1` binary Koblitz curve. It has not
received a complete side-channel audit and makes no blanket constant-time or
protocol-suitability claim.

The `sect283k1` curve is specified by SECG (Standards for Efficient Cryptography Group) and offers a security level of approximately 141 bits.

### Curve Parameters

*   **Curve Equation**: `y² + xy = x³ + 1`
*   **Base Field**: `GF(2^283)` (a binary field with 2^283 elements)
*   **Irreducible Polynomial**: `x^283 + x^12 + x^7 + x^5 + 1`

## Core Features

*   **Timing-aware implementation**: Scalar multiplication uses branch-free selection in relevant paths, but compiler- and target-level behavior is not guaranteed.
*   **Key Generation**: Provides the `generate_keypair` function to securely create `(private_key, public_key)` pairs suitable for ECDH.
*   **Scalar Multiplication**: Offers efficient and secure scalar multiplication functions:
    *   `scalar_mult_base_g`: Fixed-base multiplication with the curve's standard generator point (G), used for deriving a public key from a private key.
    *   `scalar_mult`: Variable-base multiplication, which is the core operation for computing the shared secret in an ECDH exchange.
*   **Point Arithmetic**: Implements fundamental point operations, including addition and doubling, using efficient algorithms.
*   **Point Serialization**: Supports both compressed and uncompressed point serialization formats.
    *   **Uncompressed**: `0x04 || x || y` (73 bytes)
    *   **Compressed**: `0x02/0x03 || x` (37 bytes), where the prefix disambiguates the y-coordinate.
*   **ECDH Key Exchange Support**: Includes a dedicated Key Derivation Function (KDF), `kdf_hkdf_sha384_for_ecdh_kem`, to securely derive a shared symmetric key from the raw ECDH shared secret point.

## Primary Use Case: ECDH Key Exchange

The main application of the `b283k` primitives is to establish a shared secret between two parties. The following example demonstrates how Alice and Bob can perform an ECDH key exchange.

```rust
use dcrypt::algorithms::ec::b283k::{self, Point, Scalar};
use rand::rngs::OsRng;

fn main() -> Result<(), dcrypt_algorithms::error::Error> {
    // 1. Alice generates her keypair.
    let (alice_private_key, alice_public_key) = b283k::generate_keypair(&mut OsRng)?;

    // 2. Bob generates his keypair.
    let (bob_private_key, bob_public_key) = b283k::generate_keypair(&mut OsRng)?;

    // 3. Alice computes the shared secret point using her private key and Bob's public key.
    let alice_shared_secret_point = b283k::scalar_mult(&alice_private_key, &bob_public_key)?;

    // 4. Bob computes the shared secret point using his private key and Alice's public key.
    let bob_shared_secret_point = b283k::scalar_mult(&bob_private_key, &alice_public_key)?;

    // Both parties will arrive at the same point on the curve.
    assert_eq!(alice_shared_secret_point, bob_shared_secret_point);

    // 5. To create a symmetric key, both parties use the x-coordinate of the shared point
    //    as input to a Key Derivation Function (KDF).
    let ikm = alice_shared_secret_point.x_coordinate_bytes();
    let info = Some(b"ecdh-with-b283k-context".as_slice());

    let alice_derived_key = b283k::kdf_hkdf_sha384_for_ecdh_kem(&ikm, info)?;
    let bob_derived_key = b283k::kdf_hkdf_sha384_for_ecdh_kem(&ikm, info)?;

    assert_eq!(alice_derived_key, bob_derived_key);

    println!("ECDH key exchange successful!");
    println!("Derived Symmetric Key (first 16 bytes): {}", hex::encode(&alice_derived_key[..16]));

    Ok(())
}
```

## API Overview

The `b283k` module exposes a concise and secure API for developers:

*   **`Point`**: Represents a point on the `sect283k1` curve. It handles all point-related arithmetic, validation, and serialization.
*   **`Scalar`**: Represents a value in the scalar field (an integer modulo the curve's order `n`). This type is used for private keys. It ensures that all values are valid and handles modular arithmetic securely.
*   **`generate_keypair`**: The recommended way to create a new key pair.
*   **`scalar_mult`**: Computes `k * P`, where `k` is a `Scalar` and `P` is a `Point`. This is the core function for ECDH.
*   **`kdf_hkdf_sha384_for_ecdh_kem`**: Derives a secure 48-byte symmetric key from a shared secret point using HKDF-SHA384.

## Benchmarks

Performance benchmarks for all core `sect283k1` operations are available in `benches/b283k.rs`. These benchmarks measure the performance of:

*   Field arithmetic (`add`, `mul`, `square`, `invert`)
*   Point operations (`add`, `double`, `scalar_mul`)
*   Point compression and decompression
*   Keypair generation
*   Full ECDH shared secret computation
