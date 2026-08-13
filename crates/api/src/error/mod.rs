//! Error handling for cryptographic ecosystem

pub mod registry;
pub mod traits;
pub mod types;
pub mod validate;

// Re-export the primary error type and result
pub use types::{Error, Result};

// Re-export validation utilities module (not as a nested function)
pub use validate as validation;

// Standard library error conversions
#[cfg(feature = "std")]
impl From<std::array::TryFromSliceError> for Error {
    fn from(_: std::array::TryFromSliceError) -> Self {
        Self::InvalidLength {
            context: "array conversion",
            expected: 0, // Unknown expected size
            actual: 0,   // Unknown actual size
        }
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Other {
            context: "I/O operation",
            message: e.to_string(),
        }
    }
}

#[cfg(feature = "std")]
use std::error::Error as StdError;

// Implement standard Error trait when std is available
#[cfg(feature = "std")]
impl StdError for Error {}

// Specialized result types for different operations
pub type CipherResult<T> = Result<T>;
pub type HashResult<T> = Result<T>;
pub type KeyResult<T> = Result<T>;
pub type SignatureResult<T> = Result<T>;
