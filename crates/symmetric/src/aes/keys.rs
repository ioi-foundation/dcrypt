//! Key types for AES-based ciphers.

use alloc::{vec, vec::Vec};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use core::fmt;
use dcrypt_algorithms::{hash::Sha256, kdf::Pbkdf2};
use dcrypt_api::ZeroizingBytes;
use dcrypt_internal::{boxed_bytes_zeroed, CryptoRng, Zeroize, ZeroizeOnDrop, Zeroizing};
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
        let mut key = Zeroizing::new([0u8; AES128_KEY_SIZE]);
        fill_random(rng, &mut key[..], "AES-128 key generation")?;
        Ok(Self(key.into_inner()))
    }

    /// Returns the raw key bytes.
    pub const fn as_bytes(&self) -> &[u8; AES128_KEY_SIZE] {
        &self.0
    }

    /// Serializes the key into exact-size ASCII storage whose initialized
    /// bytes are explicitly cleared on drop.
    pub fn to_secure_bytes(&self) -> ZeroizingBytes {
        encode_secure_key(b"dcrypt-AES128-KEY:", self.as_bytes())
    }

    /// Loads a key from its serialized byte format.
    pub fn from_secure_bytes(serialized: &[u8]) -> Result<Self> {
        const PREFIX: &[u8] = b"dcrypt-AES128-KEY:";
        validate_format(
            serialized.starts_with(PREFIX),
            "key deserialization",
            "invalid key format",
        )?;

        let encoded = &serialized[PREFIX.len()..];
        let mut key = Zeroizing::new([0u8; AES128_KEY_SIZE]);
        let decoded_len = STANDARD
            .decode_slice(encoded, &mut key[..])
            .map_err(|_| serialization_error("base64 decode"))?;
        validate::length("AES-128 key", decoded_len, AES128_KEY_SIZE)?;
        Ok(Self(key.into_inner()))
    }

    /// Loads a key from the legacy caller-owned string representation.
    pub fn from_secure_string(serialized: &str) -> Result<Self> {
        Self::from_secure_bytes(serialized.as_bytes())
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
        let mut key = Zeroizing::new([0u8; AES256_KEY_SIZE]);
        fill_random(rng, &mut key[..], "AES-256 key generation")?;
        Ok(Self(key.into_inner()))
    }

    /// Returns the raw key bytes.
    pub const fn as_bytes(&self) -> &[u8; AES256_KEY_SIZE] {
        &self.0
    }

    /// Serializes the key into exact-size ASCII storage whose initialized
    /// bytes are explicitly cleared on drop.
    pub fn to_secure_bytes(&self) -> ZeroizingBytes {
        encode_secure_key(b"dcrypt-AES256-KEY:", self.as_bytes())
    }

    /// Loads a key from its serialized byte format.
    pub fn from_secure_bytes(serialized: &[u8]) -> Result<Self> {
        const PREFIX: &[u8] = b"dcrypt-AES256-KEY:";
        validate_format(
            serialized.starts_with(PREFIX),
            "key deserialization",
            "invalid key format",
        )?;

        let encoded = &serialized[PREFIX.len()..];
        let mut key = Zeroizing::new([0u8; AES256_KEY_SIZE]);
        let decoded_len = STANDARD
            .decode_slice(encoded, &mut key[..])
            .map_err(|_| serialization_error("base64 decode"))?;
        validate::length("AES-256 key", decoded_len, AES256_KEY_SIZE)?;
        Ok(Self(key.into_inner()))
    }

    /// Loads a key from the legacy caller-owned string representation.
    pub fn from_secure_string(serialized: &str) -> Result<Self> {
        Self::from_secure_bytes(serialized.as_bytes())
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

fn encode_secure_key(prefix: &[u8], key: &[u8]) -> ZeroizingBytes {
    let encoded_len = base64::encoded_len(key.len(), true)
        .expect("fixed-size AES key encoding length cannot overflow");
    let mut serialized = Zeroizing::new(boxed_bytes_zeroed(prefix.len() + encoded_len));
    serialized[..prefix.len()].copy_from_slice(prefix);
    let written = STANDARD
        .encode_slice(key, &mut serialized[prefix.len()..])
        .expect("exact base64 output allocation must be sufficient");
    debug_assert_eq!(written, encoded_len);
    serialized
}

/// Derives an AES-128 key with PBKDF2-HMAC-SHA-256.
pub fn derive_aes128_key(password: &[u8], salt: &[u8], iterations: u32) -> Result<Aes128Key> {
    validate_derivation_inputs(password, salt, iterations)?;
    let derived = Pbkdf2::<Sha256>::pbkdf2(password, salt, iterations, AES128_KEY_SIZE)
        .map_err(from_primitive_error)?;
    let mut key = Zeroizing::new([0u8; AES128_KEY_SIZE]);
    key.copy_from_slice(&derived);
    Ok(Aes128Key(key.into_inner()))
}

/// Derives an AES-256 key with PBKDF2-HMAC-SHA-256.
pub fn derive_aes256_key(password: &[u8], salt: &[u8], iterations: u32) -> Result<Aes256Key> {
    validate_derivation_inputs(password, salt, iterations)?;
    let derived = Pbkdf2::<Sha256>::pbkdf2(password, salt, iterations, AES256_KEY_SIZE)
        .map_err(from_primitive_error)?;
    let mut key = Zeroizing::new([0u8; AES256_KEY_SIZE]);
    key.copy_from_slice(&derived);
    Ok(Aes256Key(key.into_inner()))
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
    fn secure_bytes_round_trip_uses_exact_storage() {
        let key128 = Aes128Key::new([0x42; AES128_KEY_SIZE]);
        let serialized128 = key128.to_secure_bytes();
        assert_eq!(serialized128.capacity(), serialized128.len());
        assert_eq!(
            &serialized128[..],
            b"dcrypt-AES128-KEY:QkJCQkJCQkJCQkJCQkJCQg=="
        );
        assert_eq!(
            Aes128Key::from_secure_bytes(&serialized128)
                .unwrap()
                .as_bytes(),
            key128.as_bytes()
        );

        let key256 = Aes256Key::new([0x24; AES256_KEY_SIZE]);
        let serialized256 = key256.to_secure_bytes();
        assert_eq!(serialized256.capacity(), serialized256.len());
        assert_eq!(
            &serialized256[..],
            b"dcrypt-AES256-KEY:JCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQ="
        );
        assert_eq!(
            Aes256Key::from_secure_bytes(&serialized256)
                .unwrap()
                .as_bytes(),
            key256.as_bytes()
        );
    }
}
