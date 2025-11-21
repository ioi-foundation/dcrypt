//! Trait definitions for cryptographic operations in dcrypt
//!
//! This module provides core traits that define the interfaces for various
//! cryptographic operations, along with marker traits that define algorithm
//! properties.

// Original trait modules
pub mod kem;
pub mod pke;
pub mod serialize;
pub mod signature;
pub mod symmetric;

// Original trait re-exports
pub use kem::Kem;
pub use pke::Pke;
pub use serialize::{Serialize, SerializeSecret};
pub use signature::Signature;
pub use symmetric::SymmetricCipher;

/// Marker trait for block cipher algorithms
pub trait BlockCipher {
    /// Block size in bytes
    const BLOCK_SIZE: usize;

    /// Static algorithm identifier for compile-time checking
    const ALGORITHM_ID: &'static str;

    /// Returns the block cipher algorithm name
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// Marker trait for stream cipher algorithms
pub trait StreamCipher {
    /// State size in bytes
    const STATE_SIZE: usize;

    /// Static algorithm identifier for compile-time checking
    const ALGORITHM_ID: &'static str;

    /// Returns the stream cipher algorithm name
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// Marker trait for authenticated encryption algorithms
pub trait AuthenticatedCipher {
    /// Authentication tag size in bytes
    const TAG_SIZE: usize;

    /// Static algorithm identifier for compile-time checking
    const ALGORITHM_ID: &'static str;

    /// Returns the authenticated cipher algorithm name
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// Marker trait for key derivation functions
pub trait KeyDerivationFunction {
    /// Minimum recommended salt size in bytes
    const MIN_SALT_SIZE: usize;

    /// Default output size in bytes
    const DEFAULT_OUTPUT_SIZE: usize;

    /// Static algorithm identifier for compile-time checking
    const ALGORITHM_ID: &'static str;

    /// Returns the KDF algorithm name
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// Marker trait for hash function algorithms
pub trait HashAlgorithm {
    /// Output digest size in bytes
    const OUTPUT_SIZE: usize;

    /// Block size used by the algorithm in bytes
    const BLOCK_SIZE: usize;

    /// Static algorithm identifier for compile-time checking
    const ALGORITHM_ID: &'static str;

    /// Returns the hash algorithm name
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}
