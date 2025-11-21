//! Operation pattern traits for constructing cryptographic operations
//!
//! This module provides the core operation traits used throughout the dcrypt library
//! for a fluent API with compile-time and runtime validation guarantees.

use crate::error::Result;

/// Base trait for all operations in the dcrypt library
///
/// This trait defines the core functionality for constructing objects
/// in a step-by-step manner with proper validation.
pub trait Operation<T> {
    /// Validate and execute the final object
    ///
    /// # Returns
    /// - `Ok(T)` if the construction was successful
    /// - `Err(Error)` if validation failed or construction was not possible
    fn execute(self) -> Result<T>;

    /// Reset the builder to its initial state
    ///
    /// This method is useful for reusing a builder configuration
    /// with only minor changes.
    fn reset(&mut self);
}

/// Trait for operations that can be reused with different parameters
pub trait Reusable<T, P> {
    /// Execute the operation with the given parameters
    fn execute(&self, params: P) -> Result<T>;
}

/// Trait for operations that can be performed with associated data
pub trait WithAssociatedData<'a, T> {
    /// Set the associated data for this operation
    fn with_associated_data(self, aad: &'a [u8]) -> T;
}

/// Trait for operations that require a nonce
pub trait WithNonce<'a, N, T> {
    /// Set the nonce for this operation
    fn with_nonce(self, nonce: &'a N) -> T;
}

/// Trait for operations with a configurable output length
pub trait WithOutputLength<T> {
    /// Set the desired output length
    fn with_output_length(self, length: usize) -> T;
}

/// Trait for operations that can operate on arbitrary input data
pub trait WithData<'a, T> {
    /// Set the input data for this operation
    fn with_data(self, data: &'a [u8]) -> T;
}

/// Mode of operation for cryptographic operations
pub enum OperationMode {
    /// Standard encryption/decryption
    Standard,
    /// Streaming mode for large data
    Streaming,
    /// In-place operation that modifies data in place
    InPlace,
}

/// Export public modules
pub mod aead;
pub mod kdf;

// Re-export commonly used items for convenience
pub use aead::{AeadEncryptOperation, AeadDecryptOperation};
pub use kdf::KdfOperation;