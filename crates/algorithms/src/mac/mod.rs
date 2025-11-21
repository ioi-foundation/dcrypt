//! Message Authentication Code (MAC) implementations with type-safe interfaces
//!
//! This module contains implementations of various Message Authentication Codes (MACs)
//! used throughout the dcrypt library, with improved type safety and ergonomic APIs.

use crate::error::Result;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub mod hmac;
pub mod poly1305;

// Re-exports
pub use hmac::Hmac;
pub use poly1305::{Poly1305, POLY1305_KEY_SIZE, POLY1305_TAG_SIZE};

/// Marker trait for MAC algorithms with algorithm-specific constants
pub trait MacAlgorithm {
    /// Key size in bytes
    const KEY_SIZE: usize;

    /// Tag size in bytes
    const TAG_SIZE: usize;

    /// Block size in bytes (if applicable)
    const BLOCK_SIZE: usize;

    /// Algorithm name
    fn name() -> &'static str;
}

/// Trait for Message Authentication Code (MAC) algorithms
pub trait Mac: Sized {
    /// Key type with appropriate algorithm binding
    type Key: AsRef<[u8]> + AsMut<[u8]> + Clone + Zeroize;

    /// Tag output type with appropriate size constraint
    type Tag: AsRef<[u8]> + AsMut<[u8]> + Clone;

    /// Creates a new MAC instance with the given key
    fn new(key: &[u8]) -> Result<Self>;

    /// Updates the MAC state with data, returning self for method chaining
    fn update(&mut self, data: &[u8]) -> Result<&mut Self>;

    /// Finalizes and returns the MAC tag
    fn finalize(&mut self) -> Result<Self::Tag>;

    /// Reset the MAC state for reuse
    fn reset(&mut self) -> Result<()>;

    /// One-shot MAC computation
    fn compute_tag(key: &[u8], data: &[u8]) -> Result<Self::Tag> {
        let mut mac = Self::new(key)?;
        mac.update(data)?;
        mac.finalize()
    }

    /// Verify a MAC tag in constant time
    fn verify_tag(key: &[u8], data: &[u8], tag: &[u8]) -> Result<bool> {
        let computed = Self::compute_tag(key, data)?;

        if computed.as_ref().len() != tag.len() {
            return Ok(false);
        }

        Ok(computed.as_ref().ct_eq(tag).into())
    }
}

/// Operation for MAC operations
pub trait MacBuilder<'a, M: Mac>: Sized {
    /// Add data to the MAC computation
    fn update(self, data: &'a [u8]) -> Result<Self>;

    /// Process multiple data chunks
    fn update_multi(self, data: &[&'a [u8]]) -> Result<Self>;

    /// Finalize and return the MAC tag
    fn finalize(self) -> Result<M::Tag>;

    /// Verify against an expected tag
    fn verify(self, expected: &'a [u8]) -> Result<bool>;
}

/// Generic MAC builder implementation
pub struct GenericMacBuilder<'a, M: Mac> {
    /// Reference to the MAC instance
    mac: &'a mut M,
}

impl<'a, M: Mac> MacBuilder<'a, M> for GenericMacBuilder<'a, M> {
    fn update(self, data: &'a [u8]) -> Result<Self> {
        self.mac.update(data)?;
        Ok(self)
    }

    fn update_multi(self, data: &[&'a [u8]]) -> Result<Self> {
        for chunk in data {
            self.mac.update(chunk)?;
        }
        Ok(self)
    }

    fn finalize(self) -> Result<M::Tag> {
        self.mac.finalize()
    }

    fn verify(self, expected: &'a [u8]) -> Result<bool> {
        let tag = self.mac.finalize()?;

        if tag.as_ref().len() != expected.len() {
            return Ok(false);
        }

        Ok(tag.as_ref().ct_eq(expected).into())
    }
}

/// Extension trait for MAC implementations to provide builder methods
pub trait MacExt: Mac {
    /// Creates a builder for this MAC instance
    fn builder(&mut self) -> GenericMacBuilder<'_, Self>;
}

impl<T: Mac> MacExt for T {
    fn builder(&mut self) -> GenericMacBuilder<'_, Self> {
        GenericMacBuilder { mac: self }
    }
}
