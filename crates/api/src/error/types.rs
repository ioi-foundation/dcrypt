//! Error type definitions for cryptographic operations

#[cfg(feature = "std")]
use std::string::String;

/// Primary error type for cryptographic operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid key error
    InvalidKey {
        context: &'static str,
        #[cfg(feature = "std")]
        message: String,
    },

    /// Invalid signature error
    InvalidSignature {
        context: &'static str,
        #[cfg(feature = "std")]
        message: String,
    },

    /// Decryption error
    DecryptionFailed {
        context: &'static str,
        #[cfg(feature = "std")]
        message: String,
    },

    /// Invalid ciphertext error
    InvalidCiphertext {
        context: &'static str,
        #[cfg(feature = "std")]
        message: String,
    },

    /// Invalid length error with context
    InvalidLength {
        context: &'static str,
        expected: usize,
        actual: usize,
    },

    /// Invalid parameter error
    InvalidParameter {
        context: &'static str,
        #[cfg(feature = "std")]
        message: String,
    },

    /// Serialization error
    SerializationError {
        context: &'static str,
        #[cfg(feature = "std")]
        message: String,
    },

    /// Random generation error
    RandomGenerationError {
        context: &'static str,
        #[cfg(feature = "std")]
        message: String,
    },

    /// Not implemented error
    NotImplemented { feature: &'static str },

    /// Authentication failed error
    AuthenticationFailed {
        context: &'static str,
        #[cfg(feature = "std")]
        message: String,
    },

    /// Other error
    Other {
        context: &'static str,
        #[cfg(feature = "std")]
        message: String,
    },
}

/// Result type for cryptographic operations
pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    /// Add context to an existing error
    pub fn with_context(self, context: &'static str) -> Self {
        match self {
            Self::InvalidKey { .. } => Self::InvalidKey {
                context,
                #[cfg(feature = "std")]
                message: String::new(),
            },
            Self::InvalidSignature { .. } => Self::InvalidSignature {
                context,
                #[cfg(feature = "std")]
                message: String::new(),
            },
            Self::DecryptionFailed { .. } => Self::DecryptionFailed {
                context,
                #[cfg(feature = "std")]
                message: String::new(),
            },
            Self::InvalidCiphertext { .. } => Self::InvalidCiphertext {
                context,
                #[cfg(feature = "std")]
                message: String::new(),
            },
            Self::InvalidLength {
                expected, actual, ..
            } => Self::InvalidLength {
                context,
                expected,
                actual,
            },
            Self::InvalidParameter { .. } => Self::InvalidParameter {
                context,
                #[cfg(feature = "std")]
                message: String::new(),
            },
            Self::SerializationError { .. } => Self::SerializationError {
                context,
                #[cfg(feature = "std")]
                message: String::new(),
            },
            Self::RandomGenerationError { .. } => Self::RandomGenerationError {
                context,
                #[cfg(feature = "std")]
                message: String::new(),
            },
            Self::NotImplemented { feature } => Self::NotImplemented { feature },
            Self::AuthenticationFailed { .. } => Self::AuthenticationFailed {
                context,
                #[cfg(feature = "std")]
                message: String::new(),
            },
            Self::Other { .. } => Self::Other {
                context,
                #[cfg(feature = "std")]
                message: String::new(),
            },
        }
    }

    /// Add a message to an existing error (when std is available)
    #[cfg(feature = "std")]
    pub fn with_message(self, message: impl Into<String>) -> Self {
        let message = message.into();
        match self {
            Self::InvalidKey { context, .. } => Self::InvalidKey { context, message },
            Self::InvalidSignature { context, .. } => Self::InvalidSignature { context, message },
            Self::DecryptionFailed { context, .. } => Self::DecryptionFailed { context, message },
            Self::InvalidCiphertext { context, .. } => Self::InvalidCiphertext { context, message },
            Self::InvalidLength {
                context,
                expected,
                actual,
            } => Self::InvalidLength {
                context,
                expected,
                actual,
            },
            Self::InvalidParameter { context, .. } => Self::InvalidParameter { context, message },
            Self::SerializationError { context, .. } => {
                Self::SerializationError { context, message }
            }
            Self::RandomGenerationError { context, .. } => {
                Self::RandomGenerationError { context, message }
            }
            Self::NotImplemented { feature } => Self::NotImplemented { feature },
            Self::AuthenticationFailed { context, .. } => {
                Self::AuthenticationFailed { context, message }
            }
            Self::Other { context, .. } => Self::Other { context, message },
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKey { context, .. } => {
                write!(f, "Invalid key: {}", context)
            }
            Self::InvalidSignature { context, .. } => {
                write!(f, "Invalid signature: {}", context)
            }
            Self::DecryptionFailed { context, .. } => {
                write!(f, "Decryption failed: {}", context)
            }
            Self::InvalidCiphertext { context, .. } => {
                write!(f, "Invalid ciphertext: {}", context)
            }
            Self::InvalidLength {
                context,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{}: invalid length (expected {}, got {})",
                    context, expected, actual
                )
            }
            #[cfg(feature = "std")]
            Self::InvalidParameter { context, message } => {
                write!(f, "{}: {}", context, message)
            }
            #[cfg(not(feature = "std"))]
            Self::InvalidParameter { context } => {
                write!(f, "Invalid parameter: {}", context)
            }
            #[cfg(feature = "std")]
            Self::SerializationError { context, message } => {
                write!(f, "Serialization error: {}: {}", context, message)
            }
            #[cfg(not(feature = "std"))]
            Self::SerializationError { context } => {
                write!(f, "Serialization error: {}", context)
            }
            #[cfg(feature = "std")]
            Self::RandomGenerationError { context, message } => {
                write!(f, "Random generation error: {}: {}", context, message)
            }
            #[cfg(not(feature = "std"))]
            Self::RandomGenerationError { context } => {
                write!(f, "Random generation error: {}", context)
            }
            Self::NotImplemented { feature } => {
                write!(f, "{} is not implemented", feature)
            }
            #[cfg(feature = "std")]
            Self::AuthenticationFailed { context, message } => {
                write!(f, "Authentication failed: {}: {}", context, message)
            }
            #[cfg(not(feature = "std"))]
            Self::AuthenticationFailed { context } => {
                write!(f, "Authentication failed: {}", context)
            }
            #[cfg(feature = "std")]
            Self::Other { context, message } => {
                write!(f, "{}: {}", context, message)
            }
            #[cfg(not(feature = "std"))]
            Self::Other { context } => {
                write!(f, "Error: {}", context)
            }
        }
    }
}
