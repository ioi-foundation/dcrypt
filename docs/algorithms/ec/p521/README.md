# NIST P-521 (`secp521r1`) Elliptic Curve

This module implements the NIST P-521 curve, also known as `secp521r1`. It is a
low-level primitive, not by itself a complete ECDH or ECDSA protocol. No blanket
constant-time or production-suitability claim is made.

P-521 is a prime-order curve that operates over a 521-bit prime field defined by the Mersenne prime `p = 2^521 - 1`. It offers a very high security level (approximately 256 bits) and is part of the NSA's Suite B (now CNSA) cryptography standards for protecting classified information.

## Timing scope

Secret-bearing paths attempt to avoid obvious value-dependent control flow.
That source-level property is not proof of constant-time execution after
compilation on every target; deployment requires independent side-channel
validation.

## Core Primitives

The `p521` module provides the essential building blocks for Elliptic Curve Cryptography:

*   **`Point`**: Represents a point on the curve in affine `(x, y)` coordinates. It supports:
    *   Point addition and doubling.
    *   Serialization to both **uncompressed** (`0x04 || x || y`) and **compressed** (`0x02/0x03 || x`) formats as per SEC 1 standards.
    *   Deserialization with validation to ensure the point is on the curve.

*   **`Scalar`**: Represents an integer modulo the curve's group order `n`. This type is used for private keys and supports:
    *   Secure generation and modular arithmetic.
    *   Constant-time operations.

*   **`generate_keypair()`**: Securely generates a new P-521 key pair, consisting of a private key (`Scalar`) and a corresponding public key (`Point`).

*   **`scalar_mult()` and `scalar_mult_base_g()`**: Scalar multiplication with timing-aware source structure. `scalar_mult_base_g` multiplies the standard generator; `scalar_mult` handles an arbitrary point.

*   **`kdf_hkdf_sha512_for_ecdh_kem()`**: A Key Derivation Function based on HKDF-SHA512. This function is essential for ECDH, transforming the raw shared secret (an elliptic curve point) into a cryptographically secure symmetric key suitable for encryption or authentication. SHA-512 is used as the underlying hash function to match the high security level of the P-521 curve.

## Usage Example: ECDH Key Exchange

Here is an example of how to perform a key exchange using the P-521 primitives. Alice and Bob generate their respective key pairs and use them to derive a shared symmetric key.

```rust
use dcrypt::algorithms::ec::p521;
use rand::rngs::OsRng;

fn main() -> Result<(), dcrypt_algorithms::error::Error> {
    // 1. Alice generates her P-521 key pair.
    let (alice_private_key, alice_public_key) = p521::generate_keypair(&mut OsRng)?;

    // 2. Bob generates his P-521 key pair.
    let (bob_private_key, bob_public_key) = p521::generate_keypair(&mut OsRng)?;

    // 3. Alice computes the shared secret using her private key and Bob's public key.
    let alice_shared_point = p521::scalar_mult(&alice_private_key, &bob_public_key)?;

    // 4. Bob computes the shared secret using his private key and Alice's public key.
    let bob_shared_point = p521::scalar_mult(&bob_private_key, &alice_public_key)?;

    // Both parties will arrive at the same point on the curve.
    assert_eq!(alice_shared_point, bob_shared_point);

    // 5. To get a symmetric key, they use the KDF on the x-coordinate of the shared point.
    // Both must use the same "info" string for domain separation.
    let ikm = alice_shared_point.x_coordinate_bytes();
    let info = Some(b"p521-ecdh-example".as_slice());

    let alice_derived_key = p521::kdf_hkdf_sha512_for_ecdh_kem(&ikm, info)?;
    let bob_derived_key = p521::kdf_hkdf_sha512_for_ecdh_kem(&ikm, info)?;

    // The final derived keys will be identical.
    assert_eq!(alice_derived_key, bob_derived_key);

    println!("P-521 ECDH key exchange successful!");
    println!("Derived Symmetric Key (first 16 bytes): {}", hex::encode(&alice_derived_key[..16]));

    Ok(())
}
```

## API Overview

### Key Functions

| Function                       | Description                                                                 |
| ------------------------------ | --------------------------------------------------------------------------- |
| `base_point_g()`               | Returns the standard generator point `G` for the P-521 curve.               |
| `generate_keypair()`           | Generates a new `(Scalar, Point)` key pair.                                 |
| `scalar_mult_base_g(&scalar)`  | Computes `scalar * G`. Used for deriving a public key.                      |
| `scalar_mult(&scalar, &point)` | Computes `scalar * point`. Used for ECDH shared secret calculation.         |
| `kdf_hkdf_sha512_for_ecdh_kem()`| Derives a symmetric key from a raw shared secret using HKDF-SHA512.         |

### Core Types

| Type      | Description                                                                                    |
| --------- | ---------------------------------------------------------------------------------------------- |
| `Point`   | Represents a point on the P-521 curve. Provides methods for point arithmetic and serialization. |
| `Scalar`  | Represents a scalar value modulo the curve order. Used for private keys.                       |

## Benchmarks

A full suite of benchmarks is available in `benches/p521.rs` to evaluate the performance of all core operations, including:
*   Field and scalar arithmetic (`add`, `mul`, `invert`).
*   Point operations (`add`, `double`, `scalar_mult`).
*   Serialization and deserialization (compressed and uncompressed).
*   Key generation and the full ECDH workflow.
