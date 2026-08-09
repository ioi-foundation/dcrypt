//! Validation utilities for cryptographic operations

use super::types::{Error, Result};

/// Validate a parameter condition
pub fn parameter<T>(condition: bool, context: &'static str, reason: &'static str) -> Result<T>
where
    T: Default,
{
    #[cfg(not(feature = "std"))]
    let _ = reason;

    if !condition {
        return Err(Error::InvalidParameter {
            context,
            #[cfg(feature = "std")]
            message: reason.to_string(),
        });
    }
    Ok(T::default())
}

/// Just check a parameter condition
pub fn check_parameter(condition: bool, context: &'static str, reason: &'static str) -> Result<()> {
    #[cfg(not(feature = "std"))]
    let _ = reason;

    if !condition {
        return Err(Error::InvalidParameter {
            context,
            #[cfg(feature = "std")]
            message: reason.to_string(),
        });
    }
    Ok(())
}

/// Validate an exact length
pub fn length(context: &'static str, actual: usize, expected: usize) -> Result<()> {
    if actual != expected {
        return Err(Error::InvalidLength {
            context,
            expected,
            actual,
        });
    }
    Ok(())
}

/// Validate a minimum length
pub fn min_length(context: &'static str, actual: usize, min: usize) -> Result<()> {
    if actual < min {
        return Err(Error::InvalidLength {
            context,
            expected: min,
            actual,
        });
    }
    Ok(())
}

/// Validate a maximum length
pub fn max_length(context: &'static str, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        return Err(Error::InvalidLength {
            context,
            expected: max,
            actual,
        });
    }
    Ok(())
}

/// Validate length is within range (inclusive)
pub fn range_length(context: &'static str, actual: usize, min: usize, max: usize) -> Result<()> {
    if actual < min || actual > max {
        return Err(Error::InvalidParameter {
            context,
            #[cfg(feature = "std")]
            message: format!("length must be between {} and {}", min, max),
        });
    }
    Ok(())
}

/// Validate authentication result
pub fn authentication(is_valid: bool, context: &'static str) -> Result<()> {
    if !is_valid {
        return Err(Error::AuthenticationFailed {
            context,
            #[cfg(feature = "std")]
            message: "authentication failed".to_string(),
        });
    }
    Ok(())
}

/// Validate key format or content
pub fn key(is_valid: bool, context: &'static str, reason: &'static str) -> Result<()> {
    #[cfg(not(feature = "std"))]
    let _ = reason;

    if !is_valid {
        return Err(Error::InvalidKey {
            context,
            #[cfg(feature = "std")]
            message: reason.to_string(),
        });
    }
    Ok(())
}

/// Validate signature format or content
pub fn signature(is_valid: bool, context: &'static str, reason: &'static str) -> Result<()> {
    #[cfg(not(feature = "std"))]
    let _ = reason;

    if !is_valid {
        return Err(Error::InvalidSignature {
            context,
            #[cfg(feature = "std")]
            message: reason.to_string(),
        });
    }
    Ok(())
}

/// Validate ciphertext format or content
pub fn ciphertext(is_valid: bool, context: &'static str, reason: &'static str) -> Result<()> {
    #[cfg(not(feature = "std"))]
    let _ = reason;

    if !is_valid {
        return Err(Error::InvalidCiphertext {
            context,
            #[cfg(feature = "std")]
            message: reason.to_string(),
        });
    }
    Ok(())
}

/// Create a not implemented error
pub fn not_implemented(feature: &'static str) -> Error {
    Error::NotImplemented { feature }
}
