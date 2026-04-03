//! Cryptographic hash function implementations with enhanced type safety
//!
//! This module provides implementations of various cryptographic hash functions
//! with improved type-level guarantees and method chaining for ergonomic usage.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::error::Result;
use crate::types::Digest;

pub mod blake2;
pub mod keccak; // Added module
pub mod sha1;
pub mod sha2;
pub mod sha3;
pub mod shake;

// Re-exports
pub use blake2::{Blake2b, Blake2s};
pub use keccak::Keccak256; // Export Keccak256
pub use sha1::Sha1;
pub use sha2::{Sha224, Sha256, Sha384, Sha512};
pub use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
pub use shake::{Shake128, Shake256};

/// A byte-vector hash result for backward compatibility.
pub type Hash = Vec<u8>;

/// Marker trait for hash algorithms with compile-time guarantees
pub trait HashAlgorithm {
    /// Output size in bytes
    const OUTPUT_SIZE: usize;

    /// Block size in bytes
    const BLOCK_SIZE: usize;

    /// Static algorithm identifier for compile-time checking
    const ALGORITHM_ID: &'static str;

    /// Algorithm name for display purposes
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// Trait for cryptographic hash functions with improved type safety.
///
/// Example usage of the enhanced hash functions:
///
/// ```
/// use dcrypt_algorithms::hash::{EnhancedSha256, HashFunction};
///
/// // One-shot API
/// let digest = EnhancedSha256::digest(b"hello world").unwrap();
///
/// // Incremental API with method chaining
/// let digest = EnhancedSha256::new()
///     .update(b"hello ").unwrap()
///     .update(b"world").unwrap()
///     .finalize().unwrap();
///
/// // Verification
/// assert!(EnhancedSha256::verify(b"hello world", &digest).unwrap());
/// ```
pub trait HashFunction: Sized {
    /// The algorithm type that defines constants and properties
    type Algorithm: HashAlgorithm;

    /// The output digest type with size guarantees
    type Output: AsRef<[u8]> + AsMut<[u8]> + Clone;

    /// Creates a new instance of the hash function.
    fn new() -> Self;

    /// Updates the hash state with `data`, returning self for chaining.
    fn update(&mut self, data: &[u8]) -> Result<&mut Self>;

    /// Finalizes and returns the digest.
    fn finalize(&mut self) -> Result<Self::Output>;

    /// Finalizes, returns the digest, and resets state.
    fn finalize_reset(&mut self) -> Result<Self::Output> {
        let h = self.finalize()?;
        *self = Self::new();
        Ok(h)
    }

    /// The output size in bytes.
    fn output_size() -> usize {
        Self::Algorithm::OUTPUT_SIZE
    }

    /// The internal block size in bytes.
    fn block_size() -> usize {
        Self::Algorithm::BLOCK_SIZE
    }

    /// Convenience: one-shot digest computation with fluent interface.
    fn digest(data: &[u8]) -> Result<Self::Output> {
        let mut hasher = Self::new();
        hasher.update(data)?;
        hasher.finalize()
    }

    /// Human-readable name.
    fn name() -> String {
        Self::Algorithm::name()
    }

    /// Convenience method to verify a hash against input data
    fn verify(data: &[u8], expected: &Self::Output) -> Result<bool>
    where
        Self::Output: PartialEq,
    {
        let computed = Self::digest(data)?;
        Ok(computed == *expected)
    }
}

/// Implementation of enhanced Sha256 using the new trait structure
#[derive(Clone)]
pub struct EnhancedSha256 {
    inner: sha2::Sha256,
}

/// Marker type for SHA-256 algorithm
pub enum Sha256Algorithm {}

impl HashAlgorithm for Sha256Algorithm {
    const OUTPUT_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 64;
    const ALGORITHM_ID: &'static str = "SHA-256";
}

impl HashFunction for EnhancedSha256 {
    type Algorithm = Sha256Algorithm;
    type Output = Digest<32>;

    fn new() -> Self {
        Self {
            inner: sha2::Sha256::new(),
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        self.inner.update(data)?;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        self.inner.finalize()
    }
}
