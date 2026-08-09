//! Error handling for cryptographic primitives

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;

#[cfg(feature = "alloc")]
use alloc::borrow::Cow;

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use core::fmt;

use dcrypt_api::{Error as CoreError, Result as CoreResult};

/// The error type for cryptographic primitives
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Parameter validation error
    Parameter {
        /// Name of the invalid parameter
        name: Cow<'static, str>, // Changed from &'static str
        /// Reason why the parameter is invalid
        reason: Cow<'static, str>, // Changed from &'static str
    },

    /// Length validation error
    Length {
        /// Context where the length error occurred
        context: &'static str,
        /// Expected length in bytes
        expected: usize,
        /// Actual length in bytes
        actual: usize,
    },

    /// Authentication failure (e.g., AEAD tag verification)
    Authentication {
        /// Algorithm that failed authentication
        algorithm: &'static str,
    },

    /// A caller-provided cryptographic randomness source failed.
    Randomness,

    /// Feature not implemented
    NotImplemented {
        /// Name of the unimplemented feature
        feature: &'static str,
    },

    /// Processing error during cryptographic operation
    Processing {
        /// Operation that failed
        operation: &'static str,
        /// Additional details about the failure
        details: &'static str,
    },

    /// MAC error
    MacError {
        /// MAC algorithm that encountered the error
        algorithm: &'static str,
        /// Additional details about the MAC error
        details: &'static str,
    },

    /// External errors with String details (only available with alloc/std)
    #[cfg(feature = "std")]
    External {
        /// Source of the external error
        source: &'static str,
        /// Detailed error message
        details: String,
    },

    #[cfg(not(feature = "std"))]
    /// External error context without heap-allocated details.
    External {
        /// Source of the external error
        source: &'static str,
    },

    /// Fallback for other errors
    Other(&'static str),
}

// Add convenience helper
impl Error {
    /// Shorthand to create a Parameter error
    pub fn param<N: Into<Cow<'static, str>>, R: Into<Cow<'static, str>>>(
        name: N,
        reason: R,
    ) -> Self {
        Error::Parameter {
            name: name.into(),
            reason: reason.into(),
        }
    }
}

/// Result type for cryptographic primitives operations
pub type Result<T> = core::result::Result<T, Error>;

// Specialized result types for different cryptographic operations
/// Result type for cipher operations
pub type CipherResult<T> = Result<T>;
/// Result type for hash operations
pub type HashResult<T> = Result<T>;
/// Result type for MAC operations
pub type MacResult<T> = Result<T>;

// Display implementation for error formatting
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Parameter { name, reason } => {
                write!(f, "Invalid parameter '{}': {}", name, reason)
            }
            Error::Length {
                context,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Invalid length for {}: expected {}, got {}",
                    context, expected, actual
                )
            }
            Error::Authentication { algorithm } => {
                write!(f, "Authentication failed for {}", algorithm)
            }
            Error::Randomness => f.write_str("Caller-provided randomness source failed"),
            Error::NotImplemented { feature } => {
                write!(f, "Feature not implemented: {}", feature)
            }
            Error::Processing { operation, details } => {
                write!(f, "Processing error in {}: {}", operation, details)
            }
            Error::MacError { algorithm, details } => {
                write!(f, "MAC error in {}: {}", algorithm, details)
            }
            #[cfg(feature = "std")]
            Error::External { source, details } => {
                write!(f, "External error from {}: {}", source, details)
            }
            #[cfg(not(feature = "std"))]
            Error::External { source } => {
                write!(f, "External error from {}", source)
            }
            Error::Other(msg) => write!(f, "{}", msg),
        }
    }
}

// Implement std::error::Error when std is available
#[cfg(feature = "std")]
impl std::error::Error for Error {}

// Implement conversion to CoreError
impl From<Error> for CoreError {
    fn from(err: Error) -> Self {
        match err {
            Error::Parameter { name, reason } => CoreError::InvalidParameter {
                context: match name {
                    Cow::Borrowed(s) => s,
                    Cow::Owned(s) => Box::leak(s.into_boxed_str()),
                },
                #[cfg(feature = "std")]
                message: reason.into_owned(),
            },
            Error::Length {
                context,
                expected,
                actual,
            } => CoreError::InvalidLength {
                context,
                expected,
                actual,
            },
            Error::Authentication { algorithm } => CoreError::AuthenticationFailed {
                context: algorithm,
                #[cfg(feature = "std")]
                message: "authentication failed".to_string(),
            },
            Error::Randomness => CoreError::Other {
                context: "randomness",
                #[cfg(feature = "std")]
                message: "caller-provided randomness source failed".to_string(),
            },
            Error::NotImplemented { feature } => CoreError::NotImplemented { feature },
            Error::Processing { operation, details } => CoreError::Other {
                context: operation,
                #[cfg(feature = "std")]
                message: details.to_string(),
            },
            Error::MacError { algorithm, details } => CoreError::Other {
                context: algorithm,
                #[cfg(feature = "std")]
                message: details.to_string(),
            },
            #[cfg(feature = "std")]
            Error::External { source, details } => CoreError::Other {
                context: source,
                message: details,
            },
            #[cfg(not(feature = "std"))]
            Error::External { source } => CoreError::Other {
                context: source,
                #[cfg(feature = "std")]
                message: "external error".to_string(),
            },
            Error::Other(msg) => CoreError::Other {
                context: "primitives",
                #[cfg(feature = "std")]
                message: msg.to_string(),
            },
        }
    }
}

impl From<dcrypt_internal::random::Error> for Error {
    fn from(_: dcrypt_internal::random::Error) -> Self {
        Self::Randomness
    }
}

/// Convert a primitives result to a core result with additional context
#[inline]
pub fn to_core_result<T>(r: Result<T>, ctx: &'static str) -> CoreResult<T> {
    r.map_err(|e| {
        let mut core = CoreError::from(e);
        core = core.with_context(ctx);
        core
    })
}

// Re-export core error handling traits for convenience
pub use dcrypt_api::error::{ResultExt, SecureErrorHandling};

// Include the validation submodule
pub mod validate;
