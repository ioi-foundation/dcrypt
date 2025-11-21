# PKE Error Handling (`pke::error`)

This module defines the error handling system for the Public Key Encryption (PKE) crate (`dcrypt-pke`). It provides a specific `Error` enum for PKE operations, a `Result` type alias, and mechanisms for converting between PKE errors and the core API errors or underlying primitive errors.

## Core Components

1.  **`Error` Enum**:
    The primary error type for operations within the `dcrypt-pke` crate. Its variants cover failures specific to PKE schemes like ECIES:
    *   **`Primitive(PrimitiveError)`**: Wraps an error originating from the `dcrypt-algorithms` crate (e.g., an error during an elliptic curve point operation, hash computation, or AEAD processing *before* it's identified as an ECIES-level decryption failure). `PrimitiveError` is `algorithms::error::Error`.
    *   **`Api(CoreError)`**: Wraps an error originating from the `dcrypt-api` crate (e.g., a validation error from `api::error::validate`). `CoreError` is `api::error::Error`.
    *   **`InvalidCiphertextFormat(&'static str)`**: Indicates that the provided ciphertext bytes do not conform to the expected structure for the PKE scheme (e.g., ECIES component lengths are incorrect). The `&'static str` provides a brief reason.
    *   **`EncryptionFailed(&'static str)`**: A general failure during the encryption process. This could be due to issues like the recipient's public key being invalid (e.g., point at infinity) or the ECDH key agreement resulting in an invalid shared point.
    *   **`DecryptionFailed(&'static str)`**: A general failure during the decryption process. For AEAD-based schemes like ECIES, this is the primary error returned if the AEAD tag verification fails (due to tampered ciphertext, wrong key, or incorrect AAD). It also covers failures like an invalid ephemeral public key in the ciphertext or an invalid ECDH shared point.
    *   **`KeyDerivationFailed(&'static str)`**: An error occurred during the Key Derivation Function (KDF) step used within the PKE scheme (e.g., HKDF in ECIES).
    *   **`UnsupportedOperation(&'static str)`**: The requested PKE operation or variant is not supported.
    *   **`SerializationError(&'static str)`**: An error occurred during internal serialization or deserialization steps, not related to the primary ciphertext format (which would be `InvalidCiphertextFormat`).

    The `Error` enum implements `Debug`, `Display`, and `std::error::Error` (if the `std` feature is enabled).

2.  **`Result<T>` Type Alias**:
    A shorthand for `core::result::Result<T, pke::error::Error>`, serving as the standard return type for fallible operations within the `dcrypt-pke` crate.

3.  **Error Conversions**:
    *   `From<PrimitiveError> for Error`: Converts errors from `dcrypt-algorithms` into `PkeError::Primitive`.
    *   `From<CoreError> for Error`: Converts errors from `dcrypt-api` into `PkeError::Api`.
    *   `From<Error> for CoreError`: This is a crucial conversion. It maps specific `pke::Error` variants to appropriate `api::error::Error` variants. For example:
        *   `PkeError::DecryptionFailed` maps to `CoreError::DecryptionFailed { context: "ECIES Decryption", ... }`.
        *   `PkeError::InvalidCiphertextFormat` maps to `CoreError::InvalidCiphertext { context: "ECIES", ... }`.
        *   `PkeError::EncryptionFailed` often maps to `CoreError::Other { context: "ECIES Encryption", ... }`.
        This ensures that users of the `dcrypt-api::Pke` trait receive errors consistent with the API's error taxonomy.

## Error Philosophy

-   **Abstraction**: PKE errors often abstract away the finer details of underlying primitive failures. For instance, if an AEAD tag fails to verify during ECIES decryption (whether due to tampering, wrong key, or wrong AAD), the `pke` crate reports it as a `PkeError::DecryptionFailed`. This is then converted to an `api::error::Error::DecryptionFailed`, simplifying error handling for the end-user.
-   **Clarity**: Provides context for where the error occurred (e.g., "ECIES Encryption", "ECIES Decryption").
-   **Integration**: Seamlessly converts to and from errors in the `api` and `algorithms` crates.

This error system allows the `pke` crate to manage its specific operational failures while fitting neatly into the overall dcrypt error handling strategy.