//! Common functionality for ChaCha20-Poly1305 ciphers.

use alloc::{format, string::String, vec, vec::Vec};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use core::fmt;
use dcrypt_algorithms::{
    aead::chacha20poly1305::{CHACHA20POLY1305_KEY_SIZE, CHACHA20POLY1305_NONCE_SIZE},
    hash::Sha256,
    kdf::Pbkdf2,
};
use dcrypt_internal::{CryptoRng, Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{
    fill_random, from_primitive_error, validate, validate_format, validate_key_derivation, Result,
};

/// ChaCha20-Poly1305 key type.
#[derive(Clone)]
pub struct ChaCha20Poly1305Key([u8; CHACHA20POLY1305_KEY_SIZE]);

impl ChaCha20Poly1305Key {
    /// Creates a key from raw bytes.
    pub const fn new(bytes: [u8; CHACHA20POLY1305_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Creates a key using caller-owned cryptographic randomness.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
        fill_random(rng, &mut key, "ChaCha20-Poly1305 key generation")?;
        Ok(Self(key))
    }

    /// Returns the raw key bytes.
    pub const fn as_bytes(&self) -> &[u8; CHACHA20POLY1305_KEY_SIZE] {
        &self.0
    }

    /// Serializes the key for storage.
    pub fn to_secure_string(&self) -> String {
        format!(
            "dcrypt-CHACHA20POLY1305-KEY:{}",
            STANDARD.encode(self.as_bytes())
        )
    }

    /// Loads a key from its serialized format.
    pub fn from_secure_string(serialized: &str) -> Result<Self> {
        validate_format(
            serialized.starts_with("dcrypt-CHACHA20POLY1305-KEY:"),
            "key deserialization",
            "invalid key format",
        )?;

        let encoded = &serialized["dcrypt-CHACHA20POLY1305-KEY:".len()..];
        let key_bytes = Zeroizing::new(
            STANDARD
                .decode(encoded)
                .map_err(|_| serialization_error("base64 decode"))?,
        );
        validate::length(
            "ChaCha20Poly1305 key",
            key_bytes.len(),
            CHACHA20POLY1305_KEY_SIZE,
        )?;

        let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
        key.copy_from_slice(&key_bytes);
        Ok(Self(key))
    }
}

impl Zeroize for ChaCha20Poly1305Key {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for ChaCha20Poly1305Key {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ChaCha20Poly1305Key {}

impl fmt::Debug for ChaCha20Poly1305Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChaCha20Poly1305Key([REDACTED])")
    }
}

/// ChaCha20-Poly1305 nonce type (96 bits/12 bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChaCha20Poly1305Nonce([u8; CHACHA20POLY1305_NONCE_SIZE]);

impl ChaCha20Poly1305Nonce {
    /// Creates a nonce from raw bytes.
    pub const fn new(bytes: [u8; CHACHA20POLY1305_NONCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Creates a nonce using caller-owned cryptographic randomness.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut nonce = [0u8; CHACHA20POLY1305_NONCE_SIZE];
        fill_random(rng, &mut nonce, "ChaCha20-Poly1305 nonce generation")?;
        Ok(Self(nonce))
    }

    /// Returns the raw nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; CHACHA20POLY1305_NONCE_SIZE] {
        &self.0
    }

    /// Parses a base64 nonce.
    pub fn from_string(encoded: &str) -> Result<Self> {
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| serialization_error("nonce base64 decode"))?;
        validate::length(
            "ChaCha20Poly1305 nonce",
            bytes.len(),
            CHACHA20POLY1305_NONCE_SIZE,
        )?;

        let mut nonce = [0u8; CHACHA20POLY1305_NONCE_SIZE];
        nonce.copy_from_slice(&bytes);
        Ok(Self(nonce))
    }
}

impl fmt::Display for ChaCha20Poly1305Nonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&STANDARD.encode(self.0))
    }
}

/// Serialized nonce and ciphertext package.
#[derive(Clone, Debug)]
pub struct ChaCha20Poly1305CiphertextPackage {
    /// The nonce used for encryption.
    pub nonce: ChaCha20Poly1305Nonce,
    /// The encrypted data, including its authentication tag.
    pub ciphertext: Vec<u8>,
}

impl ChaCha20Poly1305CiphertextPackage {
    /// Creates a package containing a nonce and ciphertext.
    pub fn new(nonce: ChaCha20Poly1305Nonce, ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// Parses a serialized package.
    pub fn from_string(serialized: &str) -> Result<Self> {
        const PREFIX: &str = "dcrypt-CHACHA20POLY1305:";
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
            "expected format: dcrypt-CHACHA20POLY1305:<nonce>:<ciphertext>",
        )?;

        let nonce = ChaCha20Poly1305Nonce::from_string(nonce_part.unwrap_or_default())?;
        let ciphertext = STANDARD
            .decode(ciphertext_part.unwrap_or_default())
            .map_err(|_| serialization_error("ciphertext base64 decode"))?;
        Ok(Self { nonce, ciphertext })
    }
}

impl fmt::Display for ChaCha20Poly1305CiphertextPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "dcrypt-CHACHA20POLY1305:{}:{}",
            STANDARD.encode(self.nonce.as_bytes()),
            STANDARD.encode(&self.ciphertext)
        )
    }
}

/// Derives a ChaCha20-Poly1305 key with PBKDF2-HMAC-SHA-256.
pub fn derive_chacha20poly1305_key(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<ChaCha20Poly1305Key> {
    validate::check_parameter(!password.is_empty(), "password", "cannot be empty")?;
    validate::check_parameter(!salt.is_empty(), "salt", "cannot be empty")?;
    validate_key_derivation(
        iterations > 0,
        "PBKDF2",
        "iterations must be greater than 0",
    )?;

    let derived = Pbkdf2::<Sha256>::pbkdf2(password, salt, iterations, CHACHA20POLY1305_KEY_SIZE)
        .map_err(from_primitive_error)?;
    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
    key.copy_from_slice(&derived);
    Ok(ChaCha20Poly1305Key(key))
}

/// Generates a salt using caller-owned cryptographic randomness.
pub fn generate_salt<R: CryptoRng + ?Sized>(rng: &mut R, size: usize) -> Result<Vec<u8>> {
    let mut salt = vec![0u8; size];
    fill_random(rng, &mut salt, "ChaCha20-Poly1305 salt generation")?;
    Ok(salt)
}

fn serialization_error(context: &'static str) -> dcrypt_api::error::Error {
    dcrypt_api::error::Error::SerializationError {
        context,
        #[cfg(feature = "std")]
        message: "invalid base64 encoding".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcrypt_internal::ChaCha20Rng;

    #[test]
    fn caller_seeded_nonce_generation_is_deterministic() {
        let mut left_rng = ChaCha20Rng::from_seed([0x7a; 32]);
        let mut right_rng = ChaCha20Rng::from_seed([0x7a; 32]);
        let left = ChaCha20Poly1305Nonce::generate(&mut left_rng).unwrap();
        let right = ChaCha20Poly1305Nonce::generate(&mut right_rng).unwrap();
        assert_eq!(left, right);
    }
}
