//! data_conversion.rs
//!
//! Utility functions for converting data between common formats like
//! hexadecimal, Base64, and byte arrays.

// Ensure Vec is available for no_std + alloc
#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{format, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{format, string::String, vec::Vec};

/// Converts a hexadecimal string to a byte vector.
///
/// # Arguments
/// * `s`: A string slice representing the hexadecimal data.
///
/// # Returns
/// A `Result` containing the byte vector on success, or an error message string on failure.
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("Hex decoding failed for input string '{}': {}", s, e))
}

/// Converts a byte slice to a hexadecimal string.
///
/// # Arguments
/// * `b`: A byte slice.
///
/// # Returns
/// The hexadecimal string representation of the byte slice.
pub fn bytes_to_hex(b: &[u8]) -> String {
    hex::encode(b)
}

/// Converts a Base64 encoded string to a byte vector.
/// Uses the standard Base64 alphabet and padding.
///
/// # Arguments
/// * `s`: A string slice representing the Base64 encoded data.
///
/// # Returns
/// A `Result` containing the byte vector on success, or an error message string on failure.
pub fn base64_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD
        .decode(s)
        .map_err(|e| format!("Base64 decoding failed for input string '{}': {}", s, e))
}

/// Converts a byte slice to a Base64 encoded string.
/// Uses the standard Base64 alphabet and padding.
///
/// # Arguments
/// * `b`: A byte slice.
///
/// # Returns
/// The Base64 encoded string representation of the byte slice.
pub fn bytes_to_base64(b: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(b)
}

/// Converts a Base64 encoded string (URL-safe, no padding) to a byte vector.
///
/// # Arguments
/// * `s`: A string slice representing the URL-safe Base64 encoded data without padding.
///
/// # Returns
/// A `Result` containing the byte vector on success, or an error message string on failure.
pub fn base64url_nopad_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.decode(s).map_err(|e| {
        format!(
            "Base64 (URL-safe, no pad) decoding failed for '{}': {}",
            s, e
        )
    })
}

/// Converts a byte slice to a Base64 encoded string (URL-safe, no padding).
///
/// # Arguments
/// * `b`: A byte slice.
///
/// # Returns
/// The URL-safe Base64 encoded string representation (no padding) of the byte slice.
pub fn bytes_to_base64url_nopad(b: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_conversions() {
        let bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex_string = "0123456789abcdef";

        assert_eq!(bytes_to_hex(&bytes), hex_string);
        assert_eq!(hex_to_bytes(hex_string).unwrap(), bytes);

        assert_eq!(bytes_to_hex(&[]), "");
        assert_eq!(hex_to_bytes("").unwrap(), Vec::<u8>::new());

        assert!(hex_to_bytes("invalid hex").is_err());
        assert!(hex_to_bytes("0g").is_err()); // invalid char
        assert!(hex_to_bytes("012").is_err()); // odd length
    }

    #[test]
    fn test_base64_standard_conversions() {
        let original_str = "Hello, dcrypt! This is a test string.";
        let bytes = original_str.as_bytes();
        let base64_string = "SGVsbG8sIERDUllQVCEgVGhpcyBpcyBhIHRlc3Qgc3RyaW5nLg==";

        assert_eq!(bytes_to_base64(bytes), base64_string);
        assert_eq!(base64_to_bytes(base64_string).unwrap(), bytes);

        assert_eq!(bytes_to_base64(&[]), "");
        assert_eq!(base64_to_bytes("").unwrap(), Vec::<u8>::new());

        assert!(base64_to_bytes("invalid base64 char !@#").is_err());
        assert!(
            base64_to_bytes("SGVsbG8sIERCWVBUISEgVGhpcyBpcyBhIHRlc3Qgc3RyaW5nLg").is_err(),
            "Missing padding should fail strict decode"
        );
        // A slightly more lenient decoder might accept it, but `base64` crate's standard engine is strict.
    }

    #[test]
    fn test_base64url_nopad_conversions() {
        // Example from RFC 4648 for base64url
        let bytes1 = vec![0xfb, 0xfb, 0xff]; // \xfb\xfb\xff
        let base64url_string1 = "-_v_";
        assert_eq!(bytes_to_base64url_nopad(&bytes1), base64url_string1);
        assert_eq!(base64url_nopad_to_bytes(base64url_string1).unwrap(), bytes1);

        let original_str = "Many hands make light work.";
        let bytes = original_str.as_bytes();
        let base64url_nopad_string = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"; // Standard would be "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu" (same here)

        assert_eq!(bytes_to_base64url_nopad(bytes), base64url_nopad_string);
        assert_eq!(
            base64url_nopad_to_bytes(base64url_nopad_string).unwrap(),
            bytes
        );

        assert_eq!(bytes_to_base64url_nopad(&[]), "");
        assert_eq!(base64url_nopad_to_bytes("").unwrap(), Vec::<u8>::new());

        assert!(
            base64url_nopad_to_bytes("invalid base64 char +/=").is_err(),
            "Standard chars should fail URL-safe"
        );
    }
}
