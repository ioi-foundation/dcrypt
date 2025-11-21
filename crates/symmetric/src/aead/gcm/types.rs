//! Types specific to GCM mode of operation

use crate::error::{validate, validate_format, Result};
use base64;
use rand::{rngs::OsRng, RngCore};
use std::fmt;

/// GCM nonce type (96 bits/12 bytes is the recommended size for GCM)
#[derive(Clone, Debug)]
pub struct GcmNonce([u8; 12]);

impl GcmNonce {
    /// Creates a new nonce from raw bytes
    pub fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Creates a new random nonce
    pub fn generate() -> Self {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        Self(nonce)
    }

    /// Returns a reference to the raw nonce bytes
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    /// Creates a nonce from a base64 string
    pub fn from_string(s: &str) -> Result<Self> {
        let bytes =
            base64::decode(s).map_err(|_| dcrypt_api::error::Error::SerializationError {
                context: "nonce base64",
                #[cfg(feature = "std")]
                message: "invalid base64 encoding".to_string(),
            })?;

        validate::length("GCM nonce", bytes.len(), 12)?;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes);

        Ok(Self(nonce))
    }
}

impl fmt::Display for GcmNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base64::encode(self.0))
    }
}

/// Format for storing both ciphertext and nonce together
#[derive(Clone, Debug)]
pub struct AesCiphertextPackage {
    /// The nonce used for encryption
    pub nonce: GcmNonce,
    /// The encrypted data
    pub ciphertext: Vec<u8>,
}

impl AesCiphertextPackage {
    /// Creates a new package containing nonce and ciphertext
    pub fn new(nonce: GcmNonce, ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// Parses a serialized package
    pub fn from_string(s: &str) -> Result<Self> {
        validate_format(
            s.starts_with("dcrypt-AES-GCM:"),
            "package deserialization",
            "invalid package format",
        )?;

        let parts: Vec<&str> = s["dcrypt-AES-GCM:".len()..].split(':').collect();
        validate_format(
            parts.len() == 2,
            "package deserialization",
            "expected format: dcrypt-AES-GCM:<nonce>:<ciphertext>",
        )?;

        let nonce_bytes =
            base64::decode(parts[0]).map_err(|_| dcrypt_api::error::Error::SerializationError {
                context: "nonce base64",
                #[cfg(feature = "std")]
                message: "invalid base64 encoding".to_string(),
            })?;

        validate::length("GCM nonce", nonce_bytes.len(), 12)?;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);

        let ciphertext =
            base64::decode(parts[1]).map_err(|_| dcrypt_api::error::Error::SerializationError {
                context: "ciphertext base64",
                #[cfg(feature = "std")]
                message: "invalid base64 encoding".to_string(),
            })?;

        Ok(Self {
            nonce: GcmNonce(nonce),
            ciphertext,
        })
    }
}

impl fmt::Display for AesCiphertextPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let nonce_b64 = base64::encode(self.nonce.as_bytes());
        let ciphertext_b64 = base64::encode(&self.ciphertext);
        write!(f, "dcrypt-AES-GCM:{}:{}", nonce_b64, ciphertext_b64)
    }
}
