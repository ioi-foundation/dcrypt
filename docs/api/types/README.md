# API Core Types (`api/types.rs`)

This module in the `api` crate defines fundamental data types used throughout
the dcrypt library. Secret wrappers use exact-size ownership and explicitly
clear their initialized bytes on drop. This is best-effort safe-Rust memory
hygiene, not a guarantee that compiler/register copies, caller copies, freed
storage, swap, or crash dumps are erased.

While the [`algorithms` types](../../algorithms/types/README.md) define more
specialized const-generic types such as `Nonce<N>` and `Tag<N>`, this module
provides foundational wrappers for secret data and basic public cryptographic
objects.

## Core Types

1.  **`SecretBytes<const N: usize>`**:
    *   **Purpose**: A fixed-size array of `N` bytes designed for storing sensitive data.
    *   **Security**:
        *   Implements `Zeroize` and `ZeroizeOnDrop` to explicitly clear its
            owned initialized bytes on drop or manual zeroization.
        *   Equal-length `PartialEq` uses dcrypt's mask-based comparison. This
            narrow source-level property is not a whole-operation
            compiler/target timing proof.
        *   `Debug` formatting redacts the content (`SecretBytes<N>[REDACTED]`).
    *   **Functionality**:
        *   Constructors: `new(data: [u8; N])`, `from_slice(slice: &[u8]) -> Result<Self>`, `zeroed()`, `random<R: RngCore + CryptoRng>(rng: &mut R)`.
        *   Accessors: `as_ref() -> &[u8]`, `as_mut() -> &mut [u8]`, `Deref` to `[u8; N]`.
        *   Length: `len() -> usize`, `is_empty() -> bool`.
    *   **Serialization**: Implements `crate::SerializeSecret` with an
        exact-size zeroizing output.

2.  **`SecretVec`**:
    *   **Purpose**: Variable-length exact-size boxed storage (`Box<[u8]>`) for sensitive data.
    *   **Security**:
        *   Implements `Zeroize` and `ZeroizeOnDrop`.
        *   Never retains inaccessible spare capacity. It wipes the complete old allocation before any operation replaces it.
        *   Mutable dereferencing exposes only `[u8]`, preventing callers from invoking `Vec` operations that can reallocate without first wiping the old allocation.
        *   Equal-length `PartialEq` uses dcrypt's mask-based comparison; this
            is not a whole-operation compiler/target timing proof.
        *   `Debug` formatting redacts content.
    *   **Functionality**:
        *   Constructors: `new(data: Box<[u8]>)`, `from_slice(slice: &[u8])`, `zeroed(len: usize)`, and `random<R: CryptoRng>(rng: &mut R, len: usize)`.
        *   Controlled methods: `len()`, `is_empty()`, `capacity()`, `extend_from_slice()`, `resize()`, `truncate()`, `clear()`, `push()`, and `pop()`; plus slice access through `as_ref()`, `as_mut()`, and `Deref<Target = [u8]>`.
        *   `to_bytes_zeroizing_boxed()` and `into_bytes_zeroizing_boxed()` return exact-size zeroizing storage.
    *   **Serialization**: Implements `crate::SerializeSecret` with an
        exact-size zeroizing output.
3.  **`Key`**:
    *   **Purpose**: A generic wrapper for cryptographic key data (variable length).
    *   **Security**: Uses exact-size boxed storage and implements `Zeroize` and `ZeroizeOnDrop`.
    *   **Functionality**: `new(bytes: &[u8])`, `from_boxed_slice(bytes: Box<[u8]>)`, `new_zeros(len: usize)`, `len()`, `is_empty()`, `as_ref()`, `as_mut()`.
    *   **Serialization**: Implements `crate::SerializeSecret` and returns an
        exact-size clearing owner for secret export.

4.  **`PublicKey`**:
    *   **Purpose**: A wrapper for public key data (variable length).
    *   **Security**: Public-key bytes are public protocol data and use an
        ordinary `Vec<u8>` representation.
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
-   Algorithm traits select distinct associated public-key, secret-key,
    ciphertext, signature, and shared-secret types; the generic `Key` wrapper
    remains an exact-size secret owner for APIs that explicitly choose it.

These core types are crucial for writing secure cryptographic code in dcrypt, providing a safe foundation for handling sensitive materials and cryptographic objects.
