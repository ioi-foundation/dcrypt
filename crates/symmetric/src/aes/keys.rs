//! Key types for AES-based ciphers.

use alloc::{format, string::String, vec, vec::Vec};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use core::fmt;
use dcrypt_algorithms::{hash::Sha256, kdf::Pbkdf2};
use dcrypt_internal::{CryptoRng, Zeroize, ZeroizeOnDrop, Zeroizing};
use dcrypt_params::utils::symmetric::{AES128_KEY_SIZE, AES256_KEY_SIZE};

use crate::error::{
    fill_random, from_primitive_error, validate, validate_format, validate_key_derivation, Result,
};

/// AES-128 key type.
#[derive(Clone)]
pub struct Aes128Key([u8; AES128_KEY_SIZE]);

impl Aes128Key {
    /// Creates a key from raw bytes.
    pub const fn new(bytes: [u8; AES128_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Creates a key using caller-owned cryptographic randomness.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut key = [0u8; AES128_KEY_SIZE];
        fill_random(rng, &mut key, "AES-128 key generation")?;
        Ok(Self(key))
    }

    /// Returns the raw key bytes.
    pub const fn as_bytes(&self) -> &[u8; AES128_KEY_SIZE] {
        &self.0
    }

    /// Serializes the key for storage.
    pub fn to_secure_string(&self) -> String {
        format!("dcrypt-AES128-KEY:{}", STANDARD.encode(self.as_bytes()))
    }

    /// Loads a key from its serialized format.
    pub fn from_secure_string(serialized: &str) -> Result<Self> {
        validate_format(
            serialized.starts_with("dcrypt-AES128-KEY:"),
            "key deserialization",
            "invalid key format",
        )?;

        let encoded = &serialized["dcrypt-AES128-KEY:".len()..];
        let key_bytes = Zeroizing::new(
            STANDARD
                .decode(encoded)
                .map_err(|_| serialization_error("base64 decode"))?,
        );
        validate::length("AES-128 key", key_bytes.len(), AES128_KEY_SIZE)?;

        let mut key = [0u8; AES128_KEY_SIZE];
        key.copy_from_slice(&key_bytes);
        Ok(Self(key))
    }
}

impl Zeroize for Aes128Key {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Aes128Key {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Aes128Key {}

impl fmt::Debug for Aes128Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Aes128Key([REDACTED])")
    }
}

/// AES-256 key type.
#[derive(Clone)]
pub struct Aes256Key([u8; AES256_KEY_SIZE]);

impl Aes256Key {
    /// Creates a key from raw bytes.
    pub const fn new(bytes: [u8; AES256_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Creates a key using caller-owned cryptographic randomness.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut key = [0u8; AES256_KEY_SIZE];
        fill_random(rng, &mut key, "AES-256 key generation")?;
        Ok(Self(key))
    }

    /// Returns the raw key bytes.
    pub const fn as_bytes(&self) -> &[u8; AES256_KEY_SIZE] {
        &self.0
    }

    /// Serializes the key for storage.
    pub fn to_secure_string(&self) -> String {
        format!("dcrypt-AES256-KEY:{}", STANDARD.encode(self.as_bytes()))
    }

    /// Loads a key from its serialized format.
    pub fn from_secure_string(serialized: &str) -> Result<Self> {
        validate_format(
            serialized.starts_with("dcrypt-AES256-KEY:"),
            "key deserialization",
            "invalid key format",
        )?;

        let encoded = &serialized["dcrypt-AES256-KEY:".len()..];
        let key_bytes = Zeroizing::new(
            STANDARD
                .decode(encoded)
                .map_err(|_| serialization_error("base64 decode"))?,
        );
        validate::length("AES-256 key", key_bytes.len(), AES256_KEY_SIZE)?;

        let mut key = [0u8; AES256_KEY_SIZE];
        key.copy_from_slice(&key_bytes);
        Ok(Self(key))
    }
}

impl Zeroize for Aes256Key {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Aes256Key {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Aes256Key {}

impl fmt::Debug for Aes256Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Aes256Key([REDACTED])")
    }
}

/// Derives an AES-128 key with PBKDF2-HMAC-SHA-256.
pub fn derive_aes128_key(password: &[u8], salt: &[u8], iterations: u32) -> Result<Aes128Key> {
    validate_derivation_inputs(password, salt, iterations)?;
    let derived = Pbkdf2::<Sha256>::pbkdf2(password, salt, iterations, AES128_KEY_SIZE)
        .map_err(from_primitive_error)?;
    let mut key = [0u8; AES128_KEY_SIZE];
    key.copy_from_slice(&derived);
    Ok(Aes128Key(key))
}

/// Derives an AES-256 key with PBKDF2-HMAC-SHA-256.
pub fn derive_aes256_key(password: &[u8], salt: &[u8], iterations: u32) -> Result<Aes256Key> {
    validate_derivation_inputs(password, salt, iterations)?;
    let derived = Pbkdf2::<Sha256>::pbkdf2(password, salt, iterations, AES256_KEY_SIZE)
        .map_err(from_primitive_error)?;
    let mut key = [0u8; AES256_KEY_SIZE];
    key.copy_from_slice(&derived);
    Ok(Aes256Key(key))
}

/// Generates a salt using caller-owned cryptographic randomness.
pub fn generate_salt<R: CryptoRng + ?Sized>(rng: &mut R, size: usize) -> Result<Vec<u8>> {
    let mut salt = vec![0u8; size];
    fill_random(rng, &mut salt, "AES key-derivation salt generation")?;
    Ok(salt)
}

fn validate_derivation_inputs(password: &[u8], salt: &[u8], iterations: u32) -> Result<()> {
    validate::check_parameter(!password.is_empty(), "password", "cannot be empty")?;
    validate::check_parameter(!salt.is_empty(), "salt", "cannot be empty")?;
    validate_key_derivation(
        iterations > 0,
        "PBKDF2",
        "iterations must be greater than 0",
    )
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
    fn caller_seeded_generation_is_deterministic() {
        let mut left_rng = ChaCha20Rng::from_seed([0x11; 32]);
        let mut right_rng = ChaCha20Rng::from_seed([0x11; 32]);
        let left = Aes256Key::generate(&mut left_rng).unwrap();
        let right = Aes256Key::generate(&mut right_rng).unwrap();
        assert_eq!(left.as_bytes(), right.as_bytes());
    }

    #[test]
    fn secure_string_round_trip() {
        let key = Aes128Key::new([0x42; AES128_KEY_SIZE]);
        assert_eq!(
            Aes128Key::from_secure_string(&key.to_secure_string())
                .unwrap()
                .as_bytes(),
            key.as_bytes()
        );
    }
}
