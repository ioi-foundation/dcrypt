//! Types specific to GCM mode of operation.

use alloc::vec::Vec;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use core::fmt;
use dcrypt_internal::CryptoRng;

use crate::error::{fill_random, validate, validate_format, Result};

/// GCM nonce type (the recommended 96-bit size).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcmNonce([u8; 12]);

impl GcmNonce {
    /// Creates a nonce from raw bytes.
    pub const fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Creates a nonce using caller-owned cryptographic randomness.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut nonce = [0u8; 12];
        fill_random(rng, &mut nonce, "AES-GCM nonce generation")?;
        Ok(Self(nonce))
    }

    /// Returns the raw nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    /// Parses a base64 nonce.
    pub fn from_string(encoded: &str) -> Result<Self> {
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| serialization_error("nonce base64"))?;
        validate::length("GCM nonce", bytes.len(), 12)?;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes);
        Ok(Self(nonce))
    }
}

impl fmt::Display for GcmNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&STANDARD.encode(self.0))
    }
}

/// Serialized nonce and AES-GCM ciphertext package.
#[derive(Clone, Debug)]
pub struct AesCiphertextPackage {
    /// The nonce used for encryption.
    pub nonce: GcmNonce,
    /// The encrypted data, including its authentication tag.
    pub ciphertext: Vec<u8>,
}

impl AesCiphertextPackage {
    /// Creates a package containing a nonce and ciphertext.
    pub fn new(nonce: GcmNonce, ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// Parses a serialized package.
    pub fn from_string(serialized: &str) -> Result<Self> {
        const PREFIX: &str = "dcrypt-AES-GCM:";
        validate_format(
            serialized.starts_with(PREFIX),
            "package deserialization",
            "invalid package format",
        )?;

        let mut parts = serialized[PREFIX.len()..].split(':');
        let nonce_part = parts.next();
        let ciphertext_part = parts.next();
        validate_format(
            nonce_part.is_some() && ciphertext_part.is_some() && parts.next().is_none(),
            "package deserialization",
            "expected format: dcrypt-AES-GCM:<nonce>:<ciphertext>",
        )?;

        let nonce = GcmNonce::from_string(nonce_part.unwrap_or_default())?;
        let ciphertext = STANDARD
            .decode(ciphertext_part.unwrap_or_default())
            .map_err(|_| serialization_error("ciphertext base64"))?;
        Ok(Self { nonce, ciphertext })
    }
}

impl fmt::Display for AesCiphertextPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "dcrypt-AES-GCM:{}:{}",
            STANDARD.encode(self.nonce.as_bytes()),
            STANDARD.encode(&self.ciphertext)
        )
    }
}

fn serialization_error(context: &'static str) -> dcrypt_api::error::Error {
    dcrypt_api::error::Error::SerializationError {
        context,
        #[cfg(feature = "std")]
        message: "invalid base64 encoding".into(),
    }
}
