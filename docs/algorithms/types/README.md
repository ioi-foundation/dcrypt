# Cryptographic Types (`algorithms/types`)

This module defines various type-safe wrappers for common cryptographic data structures like keys, nonces, salts, digests, and tags. The primary goal is to leverage Rust's type system, particularly const generics, to enforce size constraints and algorithm compatibility at compile time, thereby reducing common cryptographic misuse errors.

These types also integrate with secure memory handling practices, such as zeroization on drop for sensitive data.

## Core Type Wrappers

1.  **`Nonce<const N: usize>` (`nonce.rs`)**
    *   Represents a cryptographic nonce (Number used ONCE) or Initialization Vector (IV).
    *   `N` specifies the size in bytes.
    *   Provides methods for creation from arrays/slices, random generation, and zeroing.
    *   Implements `AsRef<[u8]>`, `AsMut<[u8]>`, `Deref`, `DerefMut`, `PartialEq`, `Eq`, `Debug`, `Zeroize`.
    *   Includes algorithm compatibility marker traits:
        *   `ChaCha20Compatible` (for `Nonce<12>`)
        *   `XChaCha20Compatible` (for `Nonce<24>`)
        *   `AesGcmCompatible` (for `Nonce<12>`, `Nonce<16>`)
        *   `AesCtrCompatible` (for `Nonce<N>`, allowing various sizes for CTR mode)

2.  **`Salt<const N: usize>` (`salt.rs`)**
    *   Represents a cryptographic salt, used primarily in KDFs and password hashing.
    *   `N` specifies the size in bytes.
    *   Provides methods for creation, random generation (including `random_with_size`), and zeroing.
    *   Implements standard traits similar to `Nonce`.
    *   Includes algorithm compatibility marker traits:
        *   `Pbkdf2Compatible` (for `Salt<16>`, `Salt<24>`, `Salt<32>`, `Salt<64>`)
        *   `Argon2Compatible` (for `Salt<16>`, `Salt<24>`, `Salt<32>`, `Salt<64>`)
        *   `HkdfCompatible` (for `Salt<16>`, `Salt<24>`, `Salt<32>`, `Salt<64>`)

3.  **`Digest<const N: usize>` (`digest.rs`)**
    *   Represents the output of a cryptographic hash function.
    *   `N` specifies the maximum size in bytes; an internal `len` field tracks the actual digest length for variable-output hashes (though primarily used for fixed-size here).
    *   Methods for creation, hex conversion (`to_hex`, `from_hex`).
    *   Implements standard traits, including `ConstantTimeEq` for secure comparisons.
    *   Includes algorithm compatibility marker traits:
        *   `Sha256Compatible` (for `Digest<32>`)
        *   `Sha512Compatible` (for `Digest<64>`)
        *   `Blake2bCompatible` (for `Digest<32>`, `Digest<64>`)

4.  **`Tag<const N: usize>` (`tag.rs`)**
    *   Represents a Message Authentication Code (MAC) tag or an AEAD authentication tag.
    *   `N` specifies the size in bytes.
    *   Methods for creation, hex conversion.
    *   Implements standard traits. `PartialEq` is *not* constant-time by default (for performance in non-security-critical contexts), but `ConstantTimeEq` is provided for secure verification.
    *   Includes algorithm compatibility marker traits:
        *   `Poly1305Compatible` (for `Tag<16>`)
        *   `HmacCompatible` (for `Tag<32>` (e.g., HMAC-SHA256), `Tag<64>` (e.g., HMAC-SHA512))
        *   `GcmCompatible` (for `Tag<16>`)
        *   `ChaCha20Poly1305Compatible` (for `Tag<16>`)

5.  **Key Types (`key.rs`)**
    *   **`SymmetricKey<A: SymmetricAlgorithm, const N: usize>`**:
        *   Represents a symmetric key.
        *   `A` is a marker trait (e.g., `Aes128Algorithm`) defining algorithm properties.
        *   `N` is the key size in bytes.
        *   Uses `SecretBuffer<N>` internally for secure zeroization.
        *   Requires `ValidKeySize<A, N>` trait bound for construction to ensure `N` matches `A::KEY_SIZE`.
    *   **`AsymmetricSecretKey<A: AsymmetricAlgorithm, const N: usize>`**:
        *   Represents an asymmetric secret key.
        *   Uses `SecretBuffer<N>` internally.
        *   Requires `ValidSecretKeySize<A, N>` trait bound.
    *   **`AsymmetricPublicKey<A: AsymmetricAlgorithm, const N: usize>`**:
        *   Represents an asymmetric public key.
        *   Uses a plain `[u8; N]` internally as public keys are not secret.
        *   Requires `ValidPublicKeySize<A, N>` trait bound.
    *   **Marker Traits**:
        *   `SymmetricAlgorithm`: Defines `KEY_SIZE`, `BLOCK_SIZE`, `ALGORITHM_ID`.
        *   `AsymmetricAlgorithm`: Defines `PUBLIC_KEY_SIZE`, `SECRET_KEY_SIZE`, `ALGORITHM_ID`.
        *   `ValidKeySize`, `ValidSecretKeySize`, `ValidPublicKeySize`: Sealed traits implemented for valid algorithm/size combinations to enable type-safe key construction.

6.  **Algorithm Markers (`algorithms.rs`)**
    *   Defines empty enums that act as type-level markers for specific algorithms (e.g., `Aes128`, `Ed25519`). These markers implement `SymmetricAlgorithm` or `AsymmetricAlgorithm`.
    *   Provides type aliases for common key types (e.g., `Aes128Key = SymmetricKey<Aes128, 16>`).

## Common Traits Implemented by Types

-   `AsRef<[u8]>`, `AsMut<[u8]>`
-   `Deref`, `DerefMut` (to the inner byte array or slice)
-   `Clone`, `Debug` (debug output redacts sensitive data for secret types)
-   `PartialEq`, `Eq` (often constant-time for secret types)
-   `Zeroize`, `ZeroizeOnDrop` (for secret types)
-   `ConstantTimeEq` (local trait for secure comparison)
-   `RandomGeneration`: For types that can be securely randomly generated.
-   `FixedSize`: Provides `size()` method.
-   `ByteSerializable`: For `to_bytes()` and `from_bytes()` conversions.
-   `SecureZeroingType` (from `dcrypt-common`, re-exported): For types that can be zeroed and securely cloned.

## Sealed Traits (`sealed.rs`)

The `Sealed` trait is used internally to prevent external crates from implementing certain dcrypt traits (like `ValidKeySize` or algorithm compatibility traits). This ensures that only combinations vetted within the `algorithms` crate are considered valid, maintaining control over type safety.

## Purpose

The primary goal of this type system is to:
-   Prevent errors like using a key of incorrect size for an algorithm.
-   Ensure nonces and salts are distinct types, preventing accidental misuse.
-   Provide strong guarantees about the size of cryptographic outputs (digests, tags).
-   Integrate security best practices (zeroization, constant-time comparison) directly into the types.
-   Improve API clarity and ergonomics by making algorithm requirements explicit at the type level.