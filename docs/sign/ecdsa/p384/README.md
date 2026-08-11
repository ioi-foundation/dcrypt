# ECDSA with NIST P-384 (`dcrypt_sign::ecdsa::p384`)

This module implements the Elliptic Curve Digital Signature Algorithm (ECDSA) using the NIST P-384 curve (also known as secp384r1). The signature scheme adheres to FIPS 186-4 for the core algorithm and incorporates deterministic nonce generation as per RFC 6979, hedged with additional entropy (inspired by FIPS 186-5 recommendations) for enhanced security. SHA-384 is used as the hash function, as specified for P-384 in FIPS 186-4/5.

## Algorithm Details (`EcdsaP384`)

The `EcdsaP384` struct implements the `api::Signature` trait.

### Key Types

-   **`EcdsaP384PublicKey`**:
    *   Wraps a `[u8; algorithms::ec::p384::P384_POINT_UNCOMPRESSED_SIZE]`.
    *   Stores the P-384 public key point in uncompressed format (97 bytes: `0x04 || X-coordinate || Y-coordinate`).
-   **`EcdsaP384SecretKey`**:
    *   Contains `raw: algorithms::ec::p384::Scalar` and `bytes: [u8; algorithms::ec::p384::P384_SCALAR_SIZE]`.
    *   Stores the P-384 private key scalar (48 bytes) and its direct byte representation.
    *   Implements `Zeroize` and `Drop` for secure memory handling of the byte array component.

### Signature Format

-   **`EcdsaP384Signature`**:
    *   Wraps a `Vec<u8>`.
    *   Stores the ECDSA signature `(r, s)` encoded in ASN.1 DER format: `SEQUENCE { r INTEGER, s INTEGER }`.
    *   The integers `r` and `s` are derived from P-384 scalar values.

### Operations

1.  **`keypair(rng)`**:
    *   Generates a P-384 key pair using `algorithms::ec::p384::generate_keypair`.
    *   The private key scalar `d` is ensured to be in the range `[1, n-1]`, where `n` is the order of the curve's base point.
    *   The public key point `Q = d*G` is serialized in uncompressed format.

2.  **`sign(message, secret_key)`**:
    *   Hashes the input `message` using SHA-384.
    *   Converts the hash output to an integer `z` (specifically, the leftmost `min(N, bitlen(hash))` bits, where `N` for P-384 is 384 bits).
    *   Generates a per-message secret number `k` using deterministic nonce generation as per RFC 6979, hedged with additional entropy. HMAC-SHA384 is used as the PRF.
    *   Computes the elliptic curve point `(x_1, y_1) = k*G`.
    *   Calculates `r = x_1 mod n`. If `r = 0`, a new `k` is generated.
    *   Calculates `s = k^(-1) * (z + r*d) mod n`. If `s = 0`, a new `k` is generated.
    *   The signature `(r, s)` is DER-encoded.

3.  **`verify(message, signature, public_key)`**:
    *   Parses the DER-encoded `signature` to retrieve `r` and `s`. Validates they are in `[1, n-1]`.
    *   Hashes the `message` using SHA-384 to get `z`.
    *   Computes `w = s^(-1) mod n`.
    *   Computes `u1 = z*w mod n` and `u2 = r*w mod n`.
    *   Deserializes the `public_key` to point `Q`.
    *   Computes point `(x_1, y_1) = u1*G + u2*Q`.
    *   If `(x_1, y_1)` is the point at infinity, the signature is invalid.
    *   Calculates `v = x_1 mod n`.
    *   The signature is valid if `v == r` (constant-time comparison).

This implementation provides a high-security digital signature scheme based on the P-384 curve.
