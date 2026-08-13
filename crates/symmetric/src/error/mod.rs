//! Error handling for symmetric cryptographic operations
//!
//! This module provides a simplified error handling layer that uses the API error system
//! and adds conversions for symmetric-specific error types.

// Re-export the primary API error system
pub use dcrypt_api::error::{validate, Error, Result};

// Import for conversions
use dcrypt_algorithms::error::Error as PrimitiveError;
use dcrypt_internal::random::{try_fill_bytes_zeroing_on_error, CryptoRng};

/// Fill a buffer from caller-owned cryptographic randomness.
///
/// A failed source is reported to the caller and any partially written bytes
/// are erased before returning.
pub(crate) fn fill_random<R: CryptoRng + ?Sized>(
    rng: &mut R,
    destination: &mut [u8],
    context: &'static str,
) -> Result<()> {
    if try_fill_bytes_zeroing_on_error(rng, destination).is_err() {
        return Err(Error::RandomGenerationError {
            context,
            #[cfg(feature = "std")]
            message: "caller-provided randomness source failed".into(),
        });
    }
    Ok(())
}

// Helper functions to convert errors (instead of From impls which violate orphan rules)

/// Convert a PrimitiveError to an API Error
pub fn from_primitive_error(err: PrimitiveError) -> Error {
    match err {
        PrimitiveError::Authentication { algorithm } => Error::AuthenticationFailed {
            context: algorithm,
            #[cfg(feature = "std")]
            message: "authentication tag verification failed".to_string(),
        },
        PrimitiveError::Other(message) => {
            #[cfg(not(feature = "std"))]
            let _ = message;
            Error::Other {
                context: "primitive operation",
                #[cfg(feature = "std")]
                message: message.to_string(),
            }
        }
        _ => Error::Other {
            context: "primitive operation",
            #[cfg(feature = "std")]
            message: format!("Primitive error: {}", err),
        },
    }
}

/// Convert an IO error to an API Error
#[cfg(feature = "std")]
pub fn from_io_error(err: std::io::Error) -> Error {
    Error::Other {
        context: "I/O operation",
        message: err.to_string(),
    }
}

// Specialized result types for different operations
pub type CipherResult<T> = Result<T>;
pub type AeadResult<T> = Result<T>;
pub type StreamResult<T> = Result<T>;

// Helper functions for common validation patterns in symmetric crypto

/// Validate stream state
pub fn validate_stream_state(
    condition: bool,
    operation: &'static str,
    details: &'static str,
) -> Result<()> {
    validate::parameter(condition, operation, details)
}

/// Validate format/serialization with consistent context
pub fn validate_format(
    condition: bool,
    context: &'static str,
    details: &'static str,
) -> Result<()> {
    validate::parameter(condition, context, details)
}

/// Validate key derivation parameters
pub fn validate_key_derivation(
    condition: bool,
    algorithm: &'static str,
    details: &'static str,
) -> Result<()> {
    validate::parameter(condition, algorithm, details)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcrypt_internal::{random::Error as RandomError, RngCore};

    struct PartialFailure;

    impl RngCore for PartialFailure {
        fn try_fill_bytes(
            &mut self,
            destination: &mut [u8],
        ) -> core::result::Result<(), RandomError> {
            if let Some(first) = destination.first_mut() {
                *first = 0xaa;
            }
            Err(RandomError)
        }
    }

    impl CryptoRng for PartialFailure {}

    #[test]
    fn random_failures_are_propagated_and_partial_output_is_erased() {
        let mut rng = PartialFailure;
        let mut output = [0x55; 16];
        let error = fill_random(&mut rng, &mut output, "test RNG").unwrap_err();
        assert!(matches!(error, Error::RandomGenerationError { .. }));
        assert_eq!(output, [0; 16]);
    }
}
