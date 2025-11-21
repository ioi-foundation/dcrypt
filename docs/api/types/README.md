# API Core Types (`api/types.rs`)

This module in the `api` crate defines fundamental data types used throughout the dcrypt library. These types are designed with security and type safety in mind, often providing compile-time guarantees and integrating secure memory handling practices like zeroization on drop.

While the `algorithms` crate (`dcrypt_docs/algorithms/types/README.md`) defines more specialized, const-generic types like `Nonce<N>`, `Tag<N>`, etc., this `api/types.rs` file provides foundational wrappers primarily for variable-length secret data and basic cryptographic object representation.

## Core Types

1.  **`SecretBytes<const N: usize>`**:
    *   **Purpose**: A fixed-size array of `N` bytes designed for storing sensitive data.
    *   **Security**:
        *   Implements `Zeroize` and `ZeroizeOnDrop` to ensure the memory is cleared when the `SecretBytes` instance goes out of scope or is explicitly zeroized.
        *   `PartialEq` is implemented using constant-time comparison (`internal::constant_time::ct_eq`) to prevent timing side-channel attacks.
        *   `Debug` formatting redacts the content (`SecretBytes<N>[REDACTED]`).
    *   **Functionality**:
        *   Constructors: `new(data: [u8; N])`, `from_slice(slice: &[u8]) -> Result<Self>`, `zeroed()`, `random<R: RngCore + CryptoRng>(rng: &mut R)`.
        *   Accessors: `as_ref() -> &[u8]`, `as_mut() -> &mut [u8]`, `Deref` to `[u8; N]`.
        *   Length: `len() -> usize`, `is_empty() -> bool`.
    *   **Serialization**: Implements `crate::Serialize`.

2.  **`SecretVec`**:
    *   **Purpose**: A variable-length vector (`Vec<u8>`) for sensitive data.
    *   **Security**:
        *   Implements `Zeroize` and `ZeroizeOnDrop`.
        *   `PartialEq` uses constant-time comparison.
        *   `Debug` formatting redacts content.
    *   **Functionality**:
        *   Constructors: `new(data: Vec<u8>)`, `from_slice(slice: &[u8])`, `zeroed(len: usize)`, `random<R: RngCore + CryptoRng>(rng: &mut R, len: usize)`.
        *   Standard `Vec`-like methods: `len()`, `is_empty()`, `as_ref()`, `as_mut()`, `Deref` to `Vec<u8>`.
    *   **Serialization**: Implements `crate::Serialize`.
    *   **Feature Dependency**: Available when the `alloc` feature is enabled.

3.  **`Key`**:
    *   **Purpose**: A generic wrapper for cryptographic key data (variable length).
    *   **Security**: Implements `Zeroize` and `ZeroizeOnDrop`.
    *   **Functionality**: `new(bytes: &[u8])`, `new_zeros(len: usize)`, `len()`, `is_empty()`, `as_ref()`, `as_mut()`.
    *   **Serialization**: Implements `crate::Serialize`.

4.  **`PublicKey`**:
    *   **Purpose**: A wrapper for public key data (variable length).
    *   **Security**: Implements `Zeroize` (public keys are not typically secret but zeroing can be good practice for consistency, though `ZeroizeOnDrop` is not used here).
    *   **Functionality**: Similar to `Key`.
    *   **Serialization**: Implements `crate::Serialize`.

5.  **`Ciphertext`**:
    *   **Purpose**: A wrapper for ciphertext data (variable length).
    *   **Security**: Does not inherently implement `Zeroize` as ciphertexts are generally not considered secret in the same way keys are.
    *   **Functionality**: `new(bytes: &[u8])`, `len()`, `is_empty()`, `as_ref()`, `as_mut()`.
    *   **Serialization**: Implements `crate::Serialize`.

## Relationship with `algorithms::types`

-   The types in `api::types` (like `SecretBytes<N>`, `SecretVec`) are foundational and are *re-exported* by `algorithms::types` for direct use within the `algorithms` crate.
-   `algorithms::types` then builds upon these by defining more specialized, algorithm-aware types like `Nonce<N>`, `Salt<N>`, `Digest<N>`, `Tag<N>`, `SymmetricKey<A, N>`, etc., which often use `SecretBytes<N>` or `SecretBuffer<N>` (from `common`) internally.
-   The `Key` type from `api` is used by some of the KEM/Signature trait implementations as the `Self::Key` associated type for simplicity where fixed-size, algorithm-bound keys (like `SymmetricKey<A,N>`) are not yet fully integrated into those placeholder implementations.

These core types are crucial for writing secure cryptographic code in dcrypt, providing a safe foundation for handling sensitive materials and cryptographic objects.