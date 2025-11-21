# Symmetric Cryptography Error Handling (`symmetric/error`)

This module defines the error handling mechanisms for the `dcrypt-symmetric` crate, which provides high-level symmetric encryption functionalities. It establishes a custom `Error` enum, a `Result` type alias, and validation helpers tailored for symmetric cipher operations, including AEAD and streaming.

## Core Components

1.  **`Error` Enum**:
    The primary error type for operations within the `dcrypt-symmetric` crate. It encompasses various error conditions:
    *   `Primitive(PrimitiveError)`: Wraps errors originating from the lower-level `dcrypt-algorithms` crate (where `PrimitiveError` is `algorithms::error::Error`). This is used for errors like authentication failures, invalid primitive parameters, etc.
    *   `Stream { operation: &'static str, details: &'static str }`: For errors specific to streaming encryption or decryption operations (e.g., trying to write to a finalized stream).
    *   `Format { context: &'static str, details: &'static str }`: For errors related to data formatting, such as invalid base64 encoding when parsing serialized keys or ciphertext packages, or incorrect serialized structure.
    *   `KeyDerivation { algorithm: &'static str, details: &'static str }`: For errors occurring during password-based key derivation (e.g., invalid iteration count for PBKDF2).
    *   `Io(String)` (std-only): Wraps standard I/O errors, storing the error message as a `String`. This is used by streaming operations that interact with `std::io::Read` or `std::io::Write`.

    The `Error` enum implements `Debug`, `Clone` (with `Io` error converted to string for `Clone`), and `Display`. When the `std` feature is enabled, it also implements `std::error::Error`.

2.  **`Result<T>` Type Alias**:
    A shorthand for `core::result::Result<T, symmetric::error::Error>`, used as the return type for fallible operations within this crate.

3.  **Error Conversions**:
    *   `From<PrimitiveError> for Error`: Allows errors from `dcrypt-algorithms` to be converted into `symmetric::error::Error`.
    *   `From<CoreError> for Error`: Allows errors from `dcrypt-api` (like `api::error::Error::InvalidLength`) to be converted, typically into a `Format` error.
    *   `From<std::io::Error> for Error` (std-only): Converts I/O errors into `Error::Io(String)`.
    *   `From<Error> for CoreError`: Enables `symmetric::error::Error` to be converted into the dcrypt API's core error type (`api::error::Error`), facilitating consistent error handling if `dcrypt-symmetric` is used as part of a larger dcrypt application.

4.  **`validate` Module (`symmetric::error::validate`)**:
    This sub-module provides validation utility functions specific to the needs of the `symmetric` crate:
    *   `stream(condition: bool, operation: &'static str, details: &'static str) -> Result<()>`: Validates conditions related to stream operations.
    *   `format(condition: bool, context: &'static str, details: &'static str) -> Result<()>`: Validates data formats or serialization structures.
    *   `key_derivation(condition: bool, algorithm: &'static str, details: &'static str) -> Result<()>`: Validates parameters for key derivation.
    It also re-exports common validation functions (like `length`, `parameter`, `authentication`) from `api::error::validate` for convenience.

## Error Handling Strategy

-   **Layered Errors**: Errors from underlying crates (`algorithms`, `api`) are wrapped or converted, allowing higher-level code to handle them as `symmetric::error::Error` or further convert them to `api::error::Error`.
-   **Contextual Information**: Errors aim to provide context about where and why the error occurred.
-   **No Sensitive Leakage**: Error messages are designed to avoid revealing secret information.
-   **`std::io::Error` Handling**: For streaming operations, `std::io::Error`s are wrapped. The `Io(String)` variant ensures that the `Error` enum can still be `Clone` even if `std::io::Error` is not, by storing the error message.

## Usage

Operations within `dcrypt-symmetric` return `symmetric::error::Result<T>`.

```rust
use dcrypt_symmetric::error::{Error, Result, validate};
use dcrypt_algorithms::error::Error as AlgoError;

fn example_operation(data: &[u8]) -> Result<Vec<u8>> {
    validate::format(!data.is_empty(), "input data", "cannot be empty")?;

    if data.len() > 100 {
        // Example of an error originating from a primitive operation
        return Err(Error::Primitive(AlgoError::Length {
            context: "data processing",
            expected: 100,
            actual: data.len(),
        }));
    }
    // ...
    Ok(data.to_vec())
}

// fn main() {
//     match example_operation(&[1,2,3]) {
//         Ok(d) => println!("Success: {:?}", d),
//         Err(e) => {
//             println!("Symmetric Error: {}", e);
//             if let Error::Primitive(algo_err) = e {
//                 println!("  Caused by Algorithms Error: {}", algo_err);
//             }
//         }
//     }
// }
```
This error system provides a structured way to manage and report errors specific to the domain of high-level symmetric cryptography operations.