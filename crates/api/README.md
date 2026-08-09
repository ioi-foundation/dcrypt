# dcrypt API (`api`)

The `api` crate defines the public Application Programming Interface for the dcrypt cryptographic ecosystem. It establishes the core traits, error handling mechanisms, and fundamental types that are used consistently across all dcrypt libraries.

The primary goal of this crate is to provide a stable and ergonomic interface for users of dcrypt, abstracting away the specific implementation details of the underlying cryptographic algorithms.

## Core Components

1.  **[Traits](../../docs/api/traits/README.md)**:
    Defines the essential traits that cryptographic primitives must implement. These traits ensure a consistent interface for various operations:
    *   `Kem`: For Key Encapsulation Mechanisms.
    *   `Signature`: For Digital Signature schemes.
    *   `SymmetricCipher`: For symmetric encryption algorithms, including builder patterns for `EncryptOperation` and `DecryptOperation`.
    *   `Serialize` and `SerializeSecret`: Separate public-data serialization
        from exact-size, clearing secret exports.
    *   Marker Traits: `BlockCipher`, `StreamCipher`, `AuthenticatedCipher`, `KeyDerivationFunction`, `HashAlgorithm` to categorize algorithms and define their core properties (like block size, tag size, etc.).

2.  **[Error Handling](../../docs/api/error/README.md)**:
    Provides a unified error handling system:
    *   `Error` (enum): The primary error type for all dcrypt operations, with variants for common cryptographic failures (e.g., `InvalidKey`, `InvalidSignature`, `DecryptionFailed`, `InvalidLength`).
    *   `Result<T>`: A type alias for `core::result::Result<T, api::Error>`.
    *   `ResultExt` (trait): Extension methods for `Result` types to easily add context or wrap errors.
    *   `ErrorRegistryExt` (trait): For explicitly recording an error before returning a fallback value. This is ordinary, branching control flow and is not constant-time.
    *   `SecureErrorHandling` (trait): A compatibility name whose deprecated `secure_unwrap` method is not constant-time.
    *   `ErrorRegistry`: A synchronized, type-checked global last-error slot retained for compatibility. Returning errors normally is preferred.
    *   `validate` (module): Utility functions for common input validations (e.g., length checks, parameter conditions).

3.  **[Types](../../docs/api/types/README.md)**:
    Defines fundamental, security-conscious data types:
    *   `SecretBytes<const N: usize>`: A fixed-size array for sensitive data that explicitly clears its owned initialized bytes on drop and provides constant-time equality. Clearing uses best-effort safe-Rust optimization barriers rather than a compiler-guaranteed physical-erasure primitive.
    *   `SecretVec`: Exact-size boxed storage for variable-length sensitive data. It never retains spare capacity, wipes old allocations before replacement, and zeroizes its current allocation on drop.
    *   `Key`: A wrapper for cryptographic key data that explicitly clears its owned initialized bytes on drop.
    *   `PublicKey`: A wrapper for public key data.
    *   `Ciphertext`: A wrapper for ciphertext data.
    *   Implementations expose only the access and serialization traits
        appropriate for each public or secret data type; see the linked type
        reference for the current contracts.

## Design Philosophy

-   **Consistency**: Provides a uniform way to interact with different cryptographic algorithms.
-   **Type Safety**: Leverages Rust's type system to prevent common errors, such as using a key with an incompatible algorithm or providing data of incorrect length.
-   **Ergonomics**: Aims for an API that is easy to use correctly and hard to misuse. Builder patterns for operations like encryption and decryption enhance this.
-   **Explicit Security Boundaries**: Secret types own exact-size initialized
    storage and invoke best-effort clearing. Equal-length secret comparison uses
    owned mask-based primitives; neither property is a blanket compiler,
    target, or physical-erasure guarantee.
-   **`no_std` Compatibility**: Supports `no_std` with an allocator;
    variable-length public and secret types require allocation.

## How It Fits in dcrypt

The `api` crate serves as the contract between the users of the dcrypt library and the underlying algorithm implementations (primarily found in `dcrypt-algorithms`). Higher-level crates like `dcrypt-symmetric`, `dcrypt-kem`, and `dcrypt-sign` implement the traits defined in `api` to expose their functionalities.

For executable examples of the current caller-supplied-randomness and
explicit-nonce APIs, see the repository [README](../../README.md) and the
[trait reference](../../docs/api/traits/README.md).
