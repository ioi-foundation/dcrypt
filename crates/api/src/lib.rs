//! Public API traits and types for the dcrypt library
//!
//! This crate provides the public API surface for the dcrypt ecosystem, including
//! trait definitions, error types, and common types used throughout the library.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

pub mod error;
pub mod traits;
pub mod types;

// Re-export commonly used items at the crate level for convenience
pub use error::{Error, Result};
pub use types::*;

// Re-export all traits from the traits module
pub use traits::{
    AuthenticatedCipher, BlockCipher, HashAlgorithm, Kem, KeyDerivationFunction, Serialize,
    Signature, StreamCipher, SymmetricCipher,
};

// Re-export trait modules for direct access
pub use traits::{kem, serialize, signature, symmetric};
