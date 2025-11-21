# Cryptographic Operations (`algorithms/operation`)

This module defines a set of traits for building and executing cryptographic operations in a fluent, step-by-step manner. This "operation pattern" aims to enhance API ergonomics and ensure that necessary parameters are provided before an operation is executed, backed by both compile-time and runtime validation.

These traits are primarily used internally by higher-level API wrappers (e.g., in `dcrypt-symmetric` or `dcrypt-algorithms` itself when implementing `SymmetricCipher` traits) but illustrate the design philosophy for constructing cryptographic calls.

## Core Operation Traits

1.  **`Operation<T>`**:
    *   The base trait for all operations.
    *   `execute(self) -> Result<T>`: Consumes the builder and executes the operation, returning a result `T` or an error.
    *   `reset(&mut self)`: Resets the builder to its initial state, allowing reuse for a similar operation with potentially different parameters.

2.  **`WithAssociatedData<'a, T>`**:
    *   For operations (typically AEAD) that can include Associated Data (AAD).
    *   `with_associated_data(self, aad: &'a [u8]) -> T`: Sets the AAD for the operation.

3.  **`WithNonce<'a, N, T>`**:
    *   For operations that require a nonce or Initialization Vector (IV).
    *   `with_nonce(self, nonce: &'a N) -> T`: Sets the nonce for the operation. `N` is the nonce type.

4.  **`WithOutputLength<T>`**:
    *   For operations (like KDFs or XOFs) where the output length is configurable.
    *   `with_output_length(self, length: usize) -> T`: Sets the desired output length.

5.  **`WithData<'a, T>`**:
    *   A generic trait for operations that process input data (e.g., plaintext for encryption, IKM for KDFs).
    *   `with_data(self, data: &'a [u8]) -> T`: Sets the primary input data.

## Specific Operation Builders

The module provides concrete builder implementations for common cryptographic tasks:

1.  **AEAD Operations (`aead.rs`)**:
    *   **`AeadOperation` (trait)**: A marker trait for AEAD operations specifying `Key`, `Nonce` types, `TAG_SIZE`, and `algorithm_name`.
    *   **`AeadEncryptOperation<'a, T: AeadOperation>`**:
        *   Builds an AEAD encryption operation.
        *   Methods: `new(key)`, `with_nonce`, `with_associated_data`, `with_data` (for plaintext), `encrypt` (or `execute`).
    *   **`AeadDecryptOperation<'a, T: AeadOperation>`**:
        *   Builds an AEAD decryption operation.
        *   Methods: `new(key)`, `with_nonce`, `with_associated_data`, `with_data` (for ciphertext), `decrypt` (or `execute`).
    *   **Note**: The implementations in `algorithms/operation/aead.rs` are placeholder structures demonstrating the pattern. Actual AEAD logic resides in `algorithms::aead` and its submodules, often invoked via `api::traits::SymmetricCipher`.

2.  **KDF Operations (`kdf.rs`)**:
    *   **`KdfOperation` (trait)**: A marker trait for KDF operations specifying `Salt`, `Info` types, `DEFAULT_OUTPUT_SIZE`, `MIN_SALT_SIZE`, and `algorithm_name`.
    *   **`KdfBuilder<'a, T: KdfOperation>`**:
        *   Builds a key derivation operation.
        *   Methods: `new`, `with_salt`, `with_info`, `with_data` (for IKM), `with_output_length`, `derive` (or `execute`), `derive_array`.
    *   **Note**: Similar to AEAD, the `KdfBuilder` here is a structural example. Concrete KDFs in `algorithms::kdf` implement `algorithms::kdf::KdfOperation` (a different trait with a similar name but defined within the `kdf` module itself) for their specific builders.

## Design Philosophy

-   **Fluent API**: Enables chaining method calls to configure an operation, e.g., `cipher.encrypt().with_nonce(...).with_aad(...).encrypt(...)`.
-   **Parameter Validation**: Operations typically validate required parameters (e.g., nonce presence, data length) upon calling `execute()` or the final action method (e.g., `encrypt()`, `derive()`).
-   **Type Safety**: Generic parameters (like `T::Nonce` or `T::Salt`) encourage the use of specific, type-safe wrappers for cryptographic parameters.
-   **Extensibility**: The trait-based design allows new operations or variants to be added by implementing these common builder patterns.

## Relationship to `api` Crate Traits

The operation traits defined here are often used to *implement* the higher-level operation patterns defined in `dcrypt-api/src/traits/symmetric.rs` (like `api::traits::symmetric::EncryptOperation` and `DecryptOperation`). For example, an AEAD cipher struct might implement `api::traits::SymmetricCipher` where its `encrypt()` method returns an instance of `algorithms::operation::aead::AeadEncryptOperation` (or a similar struct specific to that cipher).

This module provides the building blocks for creating ergonomic and safe cryptographic APIs within the dcrypt ecosystem.