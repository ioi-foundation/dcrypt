//! Common functionality for ChaCha20Poly1305-based ciphers

use crate::error::{validate, validate_format, validate_key_derivation, Result};
use dcrypt_algorithms::aead::chacha20poly1305::{
    CHACHA20POLY1305_KEY_SIZE, CHACHA20POLY1305_NONCE_SIZE,
};
use std::fmt;
use zeroize::Zeroize;
// Fix base64 usage
use base64;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

/// ChaCha20Poly1305 key type
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct ChaCha20Poly1305Key([u8; CHACHA20POLY1305_KEY_SIZE]);

impl ChaCha20Poly1305Key {
    /// Creates a new key from raw bytes
    pub fn new(bytes: [u8; CHACHA20POLY1305_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Creates a new random key
    pub fn generate() -> Self {
        let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Returns a reference to the raw key bytes
    pub fn as_bytes(&self) -> &[u8; CHACHA20POLY1305_KEY_SIZE] {
        &self.0
    }

    /// Securely serializes the key for storage
    pub fn to_secure_string(&self) -> String {
        let key_b64 = base64::encode(self.0);
        format!("dcrypt-CHACHA20POLY1305-KEY:{}", key_b64)
    }

    /// Loads a key from a secure serialized format
    pub fn from_secure_string(serialized: &str) -> Result<Self> {
        validate_format(
            serialized.starts_with("dcrypt-CHACHA20POLY1305-KEY:"),
            "key deserialization",
            "invalid key format",
        )?;

        let b64_part = &serialized["dcrypt-CHACHA20POLY1305-KEY:".len()..];
        let key_bytes =
            base64::decode(b64_part).map_err(|_| dcrypt_api::error::Error::SerializationError {
                context: "base64 decode",
                #[cfg(feature = "std")]
                message: "invalid base64 encoding".to_string(),
            })?;

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

impl fmt::Debug for ChaCha20Poly1305Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChaCha20Poly1305Key([REDACTED])")
    }
}

/// ChaCha20Poly1305 nonce type (96 bits/12 bytes)
#[derive(Clone, Debug)]
pub struct ChaCha20Poly1305Nonce([u8; CHACHA20POLY1305_NONCE_SIZE]);

impl ChaCha20Poly1305Nonce {
    /// Creates a new nonce from raw bytes
    pub fn new(bytes: [u8; CHACHA20POLY1305_NONCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Creates a new random nonce
    pub fn generate() -> Self {
        let mut nonce = [0u8; CHACHA20POLY1305_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        Self(nonce)
    }

    /// Returns a reference to the raw nonce bytes
    pub fn as_bytes(&self) -> &[u8; CHACHA20POLY1305_NONCE_SIZE] {
        &self.0
    }

    /// Creates a nonce from a base64 string
    pub fn from_string(s: &str) -> Result<Self> {
        let bytes =
            base64::decode(s).map_err(|_| dcrypt_api::error::Error::SerializationError {
                context: "nonce base64 decode",
                #[cfg(feature = "std")]
                message: "invalid base64 encoding".to_string(),
            })?;

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base64::encode(self.0))
    }
}

/// Format for storing both ciphertext and nonce together
#[derive(Clone, Debug)]
pub struct ChaCha20Poly1305CiphertextPackage {
    /// The nonce used for encryption
    pub nonce: ChaCha20Poly1305Nonce,
    /// The encrypted data
    pub ciphertext: Vec<u8>,
}

impl ChaCha20Poly1305CiphertextPackage {
    /// Creates a new package containing nonce and ciphertext
    pub fn new(nonce: ChaCha20Poly1305Nonce, ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// Parses a serialized package
    pub fn from_string(s: &str) -> Result<Self> {
        validate_format(
            s.starts_with("dcrypt-CHACHA20POLY1305:"),
            "package deserialization",
            "invalid package format",
        )?;

        let parts: Vec<&str> = s["dcrypt-CHACHA20POLY1305:".len()..].split(':').collect();
        validate_format(
            parts.len() == 2,
            "package deserialization",
            "expected format: dcrypt-CHACHA20POLY1305:<nonce>:<ciphertext>",
        )?;

        let nonce_bytes =
            base64::decode(parts[0]).map_err(|_| dcrypt_api::error::Error::SerializationError {
                context: "nonce base64 decode",
                #[cfg(feature = "std")]
                message: "invalid base64 encoding".to_string(),
            })?;

        validate::length(
            "package nonce",
            nonce_bytes.len(),
            CHACHA20POLY1305_NONCE_SIZE,
        )?;

        let mut nonce = [0u8; CHACHA20POLY1305_NONCE_SIZE];
        nonce.copy_from_slice(&nonce_bytes);

        let ciphertext =
            base64::decode(parts[1]).map_err(|_| dcrypt_api::error::Error::SerializationError {
                context: "ciphertext base64 decode",
                #[cfg(feature = "std")]
                message: "invalid base64 encoding".to_string(),
            })?;

        Ok(Self {
            nonce: ChaCha20Poly1305Nonce(nonce),
            ciphertext,
        })
    }
}

impl fmt::Display for ChaCha20Poly1305CiphertextPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let nonce_b64 = base64::encode(self.nonce.as_bytes());
        let ciphertext_b64 = base64::encode(&self.ciphertext);
        write!(
            f,
            "dcrypt-CHACHA20POLY1305:{}:{}",
            nonce_b64, ciphertext_b64
        )
    }
}

/// Derives a ChaCha20Poly1305 key from a password and salt using PBKDF2-HMAC-SHA256
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

    let mut key = [0u8; CHACHA20POLY1305_KEY_SIZE];

    // pbkdf2 returns () when successful, so we'll use a dummy result
    let _: () = pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut key);

    Ok(ChaCha20Poly1305Key(key))
}

/// Generates a random salt for key derivation
pub fn generate_salt(size: usize) -> Vec<u8> {
    let mut salt = vec![0u8; size];
    OsRng.fill_bytes(&mut salt);
    salt
}
