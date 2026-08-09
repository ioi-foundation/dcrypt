//! Error handling for KEM operations

use core::fmt;
use dcrypt_algorithms::error::Error as PrimitiveError;
use dcrypt_api::error::Error as CoreError;

/// Error type for KEM operations
#[derive(Debug)]
pub enum Error {
    /// Primitive error
    Primitive(PrimitiveError),

    /// KEM-specific errors
    KeyGeneration {
        algorithm: &'static str,
        details: &'static str,
    },

    Encapsulation {
        algorithm: &'static str,
        details: &'static str,
    },

    Decapsulation {
        algorithm: &'static str,
        details: &'static str,
    },

    /// Invalid key format
    InvalidKey {
        key_type: &'static str,
        reason: &'static str,
    },

    /// Invalid ciphertext format
    InvalidCiphertext {
        algorithm: &'static str,
        reason: &'static str,
    },

    /// Serialization/deserialization errors
    Serialization {
        context: &'static str,
        details: &'static str,
    },

    /// I/O error (only when std is available)
    #[cfg(feature = "std")]
    Io(std::io::Error),
}

// Implement Clone manually since std::io::Error doesn't implement Clone
impl Clone for Error {
    fn clone(&self) -> Self {
        match self {
            Error::Primitive(e) => Error::Primitive(e.clone()),
            Error::KeyGeneration { algorithm, details } => {
                Error::KeyGeneration { algorithm, details }
            }
            Error::Encapsulation { algorithm, details } => {
                Error::Encapsulation { algorithm, details }
            }
            Error::Decapsulation { algorithm, details } => {
                Error::Decapsulation { algorithm, details }
            }
            Error::InvalidKey { key_type, reason } => Error::InvalidKey { key_type, reason },
            Error::InvalidCiphertext { algorithm, reason } => {
                Error::InvalidCiphertext { algorithm, reason }
            }
            Error::Serialization { context, details } => Error::Serialization { context, details },
            #[cfg(feature = "std")]
            Error::Io(e) => Error::Io(std::io::Error::new(e.kind(), e.to_string())),
        }
    }
}

/// Result type for KEM operations
pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Primitive(e) => write!(f, "Primitive error: {}", e),
            Error::KeyGeneration { algorithm, details } => {
                write!(f, "Key generation error for {}: {}", algorithm, details)
            }
            Error::Encapsulation { algorithm, details } => {
                write!(f, "Encapsulation error for {}: {}", algorithm, details)
            }
            Error::Decapsulation { algorithm, details } => {
                write!(f, "Decapsulation error for {}: {}", algorithm, details)
            }
            Error::InvalidKey { key_type, reason } => {
                write!(f, "Invalid {} key: {}", key_type, reason)
            }
            Error::InvalidCiphertext { algorithm, reason } => {
                write!(f, "Invalid {} ciphertext: {}", algorithm, reason)
            }
            Error::Serialization { context, details } => {
                write!(f, "Serialization error in {}: {}", context, details)
            }
            #[cfg(feature = "std")]
            Error::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

// Standard error trait
#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Primitive(e) => Some(e),
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

// From PrimitiveError to Error
impl From<PrimitiveError> for Error {
    fn from(err: PrimitiveError) -> Self {
        Error::Primitive(err)
    }
}

// From std::io::Error to Error (when std is available)
#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

// FIXED: From Error to CoreError - removed incorrect generic parameter
impl From<Error> for CoreError {
    fn from(err: Error) -> Self {
        match err {
            Error::Primitive(e) => e.into(),
            Error::KeyGeneration { algorithm, details } => {
                #[cfg(not(feature = "std"))]
                let _ = details;
                CoreError::Other {
                    context: algorithm,
                    #[cfg(feature = "std")]
                    message: format!("key generation failed: {}", details),
                }
            }
            Error::Encapsulation { algorithm, details } => {
                #[cfg(not(feature = "std"))]
                let _ = details;
                CoreError::Other {
                    context: algorithm,
                    #[cfg(feature = "std")]
                    message: format!("encapsulation failed: {}", details),
                }
            }
            Error::Decapsulation { algorithm, details } => {
                #[cfg(not(feature = "std"))]
                let _ = details;
                CoreError::DecryptionFailed {
                    context: algorithm,
                    #[cfg(feature = "std")]
                    message: format!("decapsulation failed: {}", details),
                }
            }
            Error::InvalidKey { key_type, reason } => {
                #[cfg(not(feature = "std"))]
                let _ = reason;
                CoreError::InvalidKey {
                    context: key_type,
                    #[cfg(feature = "std")]
                    message: reason.to_string(),
                }
            }
            Error::InvalidCiphertext { algorithm, reason } => {
                #[cfg(not(feature = "std"))]
                let _ = reason;
                CoreError::InvalidCiphertext {
                    context: algorithm,
                    #[cfg(feature = "std")]
                    message: reason.to_string(),
                }
            }
            Error::Serialization { context, details } => {
                #[cfg(not(feature = "std"))]
                let _ = details;
                CoreError::SerializationError {
                    context,
                    #[cfg(feature = "std")]
                    message: details.to_string(),
                }
            }
            #[cfg(feature = "std")]
            Error::Io(e) => CoreError::Other {
                context: "I/O operation",
                message: e.to_string(),
            },
        }
    }
}

// Include validation submodule
pub mod validate;

// Re-export core error handling traits
pub use dcrypt_api::error::{ResultExt, SecureErrorHandling};
