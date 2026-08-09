//! Extendable Output Functions (XOF)
//!
//! This module contains implementations of Extendable Output Functions (XOFs)
//! which can produce outputs of arbitrary length.

#[cfg(feature = "alloc")]
extern crate alloc;

use crate::error::{validate, Error, Result};
#[cfg(feature = "alloc")]
use dcrypt_internal::zeroing::ZeroizingBytes;

#[cfg(feature = "alloc")]
pub mod shake;

#[cfg(feature = "alloc")]
pub mod blake3;

// Re-exports
#[cfg(feature = "alloc")]
pub use shake::{ShakeXof128, ShakeXof256};

#[cfg(feature = "alloc")]
pub use blake3::Blake3Xof;

/// An Extendable Output Function (XOF) produces output of arbitrary length
#[cfg(feature = "alloc")]
pub type Xof = ZeroizingBytes;

/// Trait for extendable output functions
pub trait ExtendableOutputFunction {
    /// Creates a new instance of the XOF
    fn new() -> Self;

    /// Updates the XOF state with new data
    fn update(&mut self, data: &[u8]) -> Result<()>;

    /// Finalizes the XOF state for output
    fn finalize(&mut self) -> Result<()>;

    /// Squeezes output bytes into the provided buffer
    fn squeeze(&mut self, output: &mut [u8]) -> Result<()>;

    /// Squeezes the specified number of output bytes into exact-size storage
    /// that clears itself on drop.
    #[cfg(feature = "alloc")]
    fn squeeze_into_vec(&mut self, len: usize) -> Result<ZeroizingBytes>;

    /// Resets the XOF state
    fn reset(&mut self) -> Result<()>;

    /// Returns the security level in bits
    fn security_level() -> usize;

    /// Convenience method to generate output in a single call
    #[cfg(feature = "alloc")]
    fn generate(data: &[u8], len: usize) -> Result<ZeroizingBytes>
    where
        Self: Sized,
    {
        validate::parameter(
            len > 0,
            "output_length",
            "XOF output length must be greater than 0",
        )?;

        let mut xof = Self::new();
        xof.update(data)?;
        xof.squeeze_into_vec(len)
    }
}

/// Trait for XOF algorithms with compile-time guarantees
pub trait XofAlgorithm {
    /// Security level in bits
    const SECURITY_LEVEL: usize;

    /// Minimum recommended output size in bytes
    const MIN_OUTPUT_SIZE: usize;

    /// Maximum output size in bytes (None for unlimited)
    const MAX_OUTPUT_SIZE: Option<usize>;

    /// Algorithm identifier
    const ALGORITHM_ID: &'static str;

    /// Algorithm name
    fn name() -> &'static str {
        Self::ALGORITHM_ID
    }

    /// Validate output length
    fn validate_output_length(len: usize) -> Result<()> {
        validate::parameter(
            len >= Self::MIN_OUTPUT_SIZE,
            "output_length",
            "Output length below minimum recommended size",
        )?;

        if let Some(max) = Self::MAX_OUTPUT_SIZE {
            validate::max_length("XOF output", len, max)?;
        }

        Ok(())
    }
}

/// Type-level constants for SHAKE-128
pub enum Shake128Algorithm {}

impl XofAlgorithm for Shake128Algorithm {
    const SECURITY_LEVEL: usize = 128;
    const MIN_OUTPUT_SIZE: usize = 16; // 128 bits
    const MAX_OUTPUT_SIZE: Option<usize> = None; // Unlimited
    const ALGORITHM_ID: &'static str = "SHAKE-128";
}

/// Type-level constants for SHAKE-256
pub enum Shake256Algorithm {}

impl XofAlgorithm for Shake256Algorithm {
    const SECURITY_LEVEL: usize = 256;
    const MIN_OUTPUT_SIZE: usize = 32; // 256 bits
    const MAX_OUTPUT_SIZE: Option<usize> = None; // Unlimited
    const ALGORITHM_ID: &'static str = "SHAKE-256";
}

/// Type-level constants for BLAKE3
pub enum Blake3Algorithm {}

impl XofAlgorithm for Blake3Algorithm {
    const SECURITY_LEVEL: usize = 256;
    const MIN_OUTPUT_SIZE: usize = 32; // 256 bits
    const MAX_OUTPUT_SIZE: Option<usize> = None; // Unlimited
    const ALGORITHM_ID: &'static str = "BLAKE3-XOF";
}

/// Helper trait for XOFs that need keyed variants
pub trait KeyedXof: ExtendableOutputFunction {
    /// Creates a new keyed XOF instance
    fn with_key(key: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Generates keyed output in a single call
    #[cfg(feature = "alloc")]
    fn keyed_generate(key: &[u8], data: &[u8], len: usize) -> Result<ZeroizingBytes>
    where
        Self: Sized,
    {
        validate::parameter(
            len > 0,
            "output_length",
            "XOF output length must be greater than 0",
        )?;

        let mut xof = Self::with_key(key)?;
        xof.update(data)?;
        xof.squeeze_into_vec(len)
    }
}

/// Helper trait for XOFs that support key derivation mode
pub trait DeriveKeyXof: ExtendableOutputFunction {
    /// Creates a new XOF instance for key derivation
    fn for_derive_key(context: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Derives key material in a single call
    #[cfg(feature = "alloc")]
    fn derive_key(context: &[u8], data: &[u8], len: usize) -> Result<ZeroizingBytes>
    where
        Self: Sized,
    {
        validate::parameter(
            len > 0,
            "output_length",
            "Key derivation output length must be greater than 0",
        )?;

        let mut xof = Self::for_derive_key(context)?;
        xof.update(data)?;
        xof.squeeze_into_vec(len)
    }
}

// Error conversion helpers for XOF-specific errors
impl Error {
    /// Create an XOF finalization error
    pub(crate) fn xof_finalized() -> Self {
        Error::Processing {
            operation: "XOF",
            details: "Cannot update after finalization",
        }
    }

    /// Create an XOF squeezing error
    pub(crate) fn xof_squeezing() -> Self {
        Error::Processing {
            operation: "XOF",
            details: "Cannot update after squeezing has begun",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xof_algorithm_validation() {
        // Test SHAKE-128 validation
        assert!(Shake128Algorithm::validate_output_length(16).is_ok());
        assert!(Shake128Algorithm::validate_output_length(15).is_err());

        // Test SHAKE-256 validation
        assert!(Shake256Algorithm::validate_output_length(32).is_ok());
        assert!(Shake256Algorithm::validate_output_length(31).is_err());

        // Test BLAKE3 validation
        assert!(Blake3Algorithm::validate_output_length(32).is_ok());
        assert!(Blake3Algorithm::validate_output_length(31).is_err());
    }
}
