//! Key types for AES-based ciphers

use crate::error::{validate, validate_format, validate_key_derivation, Result};
use base64;
use dcrypt_params::utils::symmetric::{AES128_KEY_SIZE, AES256_KEY_SIZE};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroize;

/// AES-128 key type
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Aes128Key([u8; AES128_KEY_SIZE]);

impl Aes128Key {
    /// Creates a new key from raw bytes
    pub fn new(bytes: [u8; AES128_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Creates a new random key
    pub fn generate() -> Self {
        let mut key = [0u8; AES128_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Returns a reference to the raw key bytes
    pub fn as_bytes(&self) -> &[u8; AES128_KEY_SIZE] {
        &self.0
    }

    /// Securely serializes the key for storage
    pub fn to_secure_string(&self) -> String {
        let key_b64 = base64::encode(self.0);
        format!("dcrypt-AES128-KEY:{}", key_b64)
    }

    /// Loads a key from a secure serialized format
    pub fn from_secure_string(serialized: &str) -> Result<Self> {
        validate_format(
            serialized.starts_with("dcrypt-AES128-KEY:"),
            "key deserialization",
            "invalid key format",
        )?;

        let b64_part = &serialized["dcrypt-AES128-KEY:".len()..];
        let key_bytes =
            base64::decode(b64_part).map_err(|_| dcrypt_api::error::Error::SerializationError {
                context: "base64 decode",
                #[cfg(feature = "std")]
                message: "invalid base64 encoding".to_string(),
            })?;

        validate::length("AES-128 key", key_bytes.len(), AES128_KEY_SIZE)?;

        let mut key = [0u8; AES128_KEY_SIZE];
        key.copy_from_slice(&key_bytes);

        Ok(Self(key))
    }
}

impl fmt::Debug for Aes128Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Aes128Key([REDACTED])")
    }
}

/// AES-256 key type
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Aes256Key([u8; AES256_KEY_SIZE]);

impl Aes256Key {
    /// Creates a new key from raw bytes
    pub fn new(bytes: [u8; AES256_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Creates a new random key
    pub fn generate() -> Self {
        let mut key = [0u8; AES256_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Returns a reference to the raw key bytes
    pub fn as_bytes(&self) -> &[u8; AES256_KEY_SIZE] {
        &self.0
    }

    /// Securely serializes the key for storage
    pub fn to_secure_string(&self) -> String {
        let key_b64 = base64::encode(self.0);
        format!("dcrypt-AES256-KEY:{}", key_b64)
    }

    /// Loads a key from a secure serialized format
    pub fn from_secure_string(serialized: &str) -> Result<Self> {
        validate_format(
            serialized.starts_with("dcrypt-AES256-KEY:"),
            "key deserialization",
            "invalid key format",
        )?;

        let b64_part = &serialized["dcrypt-AES256-KEY:".len()..];
        let key_bytes =
            base64::decode(b64_part).map_err(|_| dcrypt_api::error::Error::SerializationError {
                context: "base64 decode",
                #[cfg(feature = "std")]
                message: "invalid base64 encoding".to_string(),
            })?;

        validate::length("AES-256 key", key_bytes.len(), AES256_KEY_SIZE)?;

        let mut key = [0u8; AES256_KEY_SIZE];
        key.copy_from_slice(&key_bytes);

        Ok(Self(key))
    }
}

impl fmt::Debug for Aes256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Aes256Key([REDACTED])")
    }
}

/// Derives an AES-128 key from a password and salt using PBKDF2-HMAC-SHA256
pub fn derive_aes128_key(password: &[u8], salt: &[u8], iterations: u32) -> Result<Aes128Key> {
    validate::check_parameter(!password.is_empty(), "password", "cannot be empty")?;
    validate::check_parameter(!salt.is_empty(), "salt", "cannot be empty")?;
    validate_key_derivation(
        iterations > 0,
        "PBKDF2",
        "iterations must be greater than 0",
    )?;

    let mut key = [0u8; AES128_KEY_SIZE];

    // pbkdf2 returns () when successful, so we'll use a dummy result
    let _: () = pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut key);

    Ok(Aes128Key(key))
}

/// Derives an AES-256 key from a password and salt using PBKDF2-HMAC-SHA256
pub fn derive_aes256_key(password: &[u8], salt: &[u8], iterations: u32) -> Result<Aes256Key> {
    validate::check_parameter(!password.is_empty(), "password", "cannot be empty")?;
    validate::check_parameter(!salt.is_empty(), "salt", "cannot be empty")?;
    validate_key_derivation(
        iterations > 0,
        "PBKDF2",
        "iterations must be greater than 0",
    )?;

    let mut key = [0u8; AES256_KEY_SIZE];

    // pbkdf2 returns () when successful, so we'll use a dummy result
    let _: () = pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut key);

    Ok(Aes256Key(key))
}

/// Generates a random salt for key derivation
pub fn generate_salt(size: usize) -> Vec<u8> {
    let mut salt = vec![0u8; size];
    OsRng.fill_bytes(&mut salt);
    salt
}
