# P-256 ('secp256r1') Elliptic Curve

This module implements the NIST P-256 curve, also known as `secp256r1` and
`prime256v1`. Conformance of curve parameters does not make this module a
FIPS-validated implementation. It has not received a complete compiler- and
target-level side-channel audit.

## Core Features

*   **Timing-aware implementation**: Secret-bearing paths attempt to avoid obvious value-dependent control flow; this is not a whole-operation guarantee.
*   **Key Generation**: Securely generate P-256 key pairs using `p256::generate_keypair`.
*   **Scalar Multiplication**: Provides efficient and secure scalar multiplication for core ECC operations:
    *   `scalar_mult_base_g`: Fixed-base multiplication with the standard generator point, used for deriving a public key from a private key.
    *   `scalar_mult`: Variable-base multiplication for operations like Elliptic Curve Diffie-Hellman (ECDH).
*   **Point Arithmetic**: Includes fundamental point operations such as addition and doubling. The implementation uses Jacobian projective coordinates internally to minimize costly field inversions.
*   **Point Serialization**: Supports both compressed (33 bytes) and uncompressed (65 bytes) point serialization formats as defined in the SEC 1 standard.
*   **ECDH Key Exchange**: The primitives are designed to facilitate ECDH. A dedicated Key Derivation Function, `kdf_hkdf_sha256_for_ecdh_kem`, is provided to securely derive a shared symmetric key from the raw ECDH shared secret (the x-coordinate of the computed point).

## Core Components

The module exposes three main data structures:

*   **`FieldElement`**: Represents a number in the prime field F_p, where `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`. It handles all the underlying modular arithmetic.
*   **`Scalar`**: Represents an integer modulo the curve's group order *n*. This type is used for private keys.
*   **`Point`**: Represents a point on the elliptic curve in affine coordinates `(x, y)`. It provides the group operations (addition, doubling, multiplication).

## Usage Examples

### 1. Key Pair Generation

Generate a new P-256 private key (`Scalar`) and its corresponding public key (`Point`).

```rust
use dcrypt::algorithms::ec::p256;
use rand::rngs::OsRng;

// Generate a new random key pair using the operating system's RNG.
let (private_key, public_key) = p256::generate_keypair(&mut OsRng).unwrap();

println!("Private Key (Scalar): [REDACTED]"); // Scalars are redacted for security
println!("Public Key (Point) X: {}", hex::encode(public_key.x_coordinate_bytes()));
println!("Public Key (Point) Y: {}", hex::encode(public_key.y_coordinate_bytes()));

// You can re-derive the public key from the private key
let derived_public_key = p256::scalar_mult_base_g(&private_key).unwrap();
assert_eq!(public_key, derived_public_key);
```

### 2. ECDH Key Exchange

Two parties, Alice and Bob, can establish a shared secret key without ever transmitting it directly.

```rust
use dcrypt::algorithms::ec::p256;
use rand::rngs::OsRng;

// 1. Alice and Bob generate their own key pairs.
let (alice_private, alice_public) = p256::generate_keypair(&mut OsRng).unwrap();
let (bob_private, bob_public) = p256::generate_keypair(&mut OsRng).unwrap();

// 2. They exchange public keys.

// 3. Alice computes the shared secret using her private key and Bob's public key.
let alice_shared_point = p256::scalar_mult(&alice_private, &bob_public).unwrap();

// 4. Bob computes the shared secret using his private key and Alice's public key.
let bob_shared_point = p256::scalar_mult(&bob_private, &alice_public).unwrap();

// Both will arrive at the same point on the curve.
assert_eq!(alice_shared_point, bob_shared_point);

// 5. They use the x-coordinate of the shared point as input to a KDF
//    to derive a strong symmetric key for encryption.
let shared_ikm = alice_shared_point.x_coordinate_bytes();
let context_info = Some(b"session-encryption-key".as_slice());

let symmetric_key = p256::kdf_hkdf_sha256_for_ecdh_kem(&shared_ikm, context_info).unwrap();

println!("ECDH successful!");
println!("Derived 32-byte symmetric key: {}", hex::encode(symmetric_key));
```

### 3. Point Serialization and Deserialization

Public keys (`Point` objects) often need to be stored or sent over a network. This is done by serializing them into bytes.

```rust
use dcrypt::algorithms::ec::p256::Point;

let (_, public_key) = p256::generate_keypair(&mut rand::rngs::OsRng).unwrap();

// Serialize to the uncompressed format (65 bytes)
let uncompressed_bytes = public_key.serialize_uncompressed();
assert_eq!(uncompressed_bytes.len(), 65);
assert_eq!(uncompressed_bytes[0], 0x04); // Uncompressed tag

// Deserialize back to a Point
let restored_from_uncompressed = Point::deserialize_uncompressed(&uncompressed_bytes).unwrap();
assert_eq!(public_key, restored_from_uncompressed);

// Serialize to the compressed format (33 bytes) for space savings
let compressed_bytes = public_key.serialize_compressed();
assert_eq!(compressed_bytes.len(), 33);
assert!(compressed_bytes[0] == 0x02 || compressed_bytes[0] == 0x03); // Compressed tags

// Deserialize back to a Point
let restored_from_compressed = Point::deserialize_compressed(&compressed_bytes).unwrap();
assert_eq!(public_key, restored_from_compressed);
```

## Benchmarks

This module includes a comprehensive benchmark suite to measure the performance of its cryptographic operations. You can run the benchmarks using the following command from the `crates/algorithms` directory:

```sh
cargo bench --bench p256
```

The benchmarks cover:
*   Field and scalar arithmetic (addition, multiplication, inversion).
*   Point operations (addition, doubling).
*   Scalar multiplication (both fixed-base and variable-base).
*   Serialization and deserialization.
*   Key pair generation and the full ECDH workflow.
