//! Authenticated Encryption with Associated Data (AEAD) with operation pattern
//!
//! This module provides implementations of authenticated encryption algorithms
//! with an ergonomic operation pattern for operations.
//!
//! ## Example usage
//!
//! ```
//! use dcrypt_algorithms::aead::{ChaCha20Poly1305Cipher, AeadCipher, AeadEncryptOperation, AeadDecryptOperation};
//! use dcrypt_internal::random::ChaCha20Rng;
//!
//! // Generate key and nonce
//! let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
//! let key = ChaCha20Poly1305Cipher::generate_key(&mut rng).unwrap();
//! let nonce = ChaCha20Poly1305Cipher::generate_nonce(&mut rng).unwrap();
//!
//! // Create cipher instance
//! let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
//!
//! // Encrypt with operation pattern
//! let ciphertext = cipher.encrypt()
//!     .with_nonce(&nonce)
//!     .with_aad(b"additional data")
//!     .encrypt(b"secret message").unwrap();
//!
//! // Decrypt with operation pattern
//! let plaintext = cipher.decrypt()
//!     .with_nonce(&nonce)
//!     .with_aad(b"additional data")
//!     .decrypt(&ciphertext).unwrap();
//!
//! assert_eq!(plaintext, b"secret message");
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

// Core modules
#[cfg(feature = "alloc")]
pub mod gcm;

#[cfg(feature = "alloc")]
pub mod chacha20poly1305;

#[cfg(feature = "alloc")]
pub mod xchacha20poly1305;

// Re-export for convenience when alloc is available
#[cfg(feature = "alloc")]
pub use self::gcm::Gcm;

#[cfg(feature = "alloc")]
pub use self::chacha20poly1305::ChaCha20Poly1305;

#[cfg(feature = "alloc")]
pub use self::xchacha20poly1305::XChaCha20Poly1305;

use crate::error::{Error, Result};
use crate::types::{Nonce, SecretBytes};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::Zeroize;

/// Marker trait for AEAD algorithms
pub trait AeadAlgorithm {
    /// Key size in bytes
    const KEY_SIZE: usize;

    /// Tag size in bytes
    const TAG_SIZE: usize;

    /// Algorithm name
    fn name() -> &'static str;
}

/// Type-level constants for ChaCha20-Poly1305
pub enum ChaCha20Poly1305Algorithm {}

impl AeadAlgorithm for ChaCha20Poly1305Algorithm {
    const KEY_SIZE: usize = 32;
    const TAG_SIZE: usize = 16;

    fn name() -> &'static str {
        "ChaCha20-Poly1305"
    }
}

/// Base trait for operations
pub trait Operation<T> {
    /// Execute the operation and produce a result
    fn execute(self) -> Result<T>;

    /// Reset the operation to its initial state
    fn reset(&mut self);
}

/// Trait for encryption operations with AEAD algorithms
pub trait AeadEncryptOperation<'a, A: AeadAlgorithm>: Operation<Vec<u8>> {
    /// Set the nonce for encryption
    fn with_nonce(self, nonce: &'a Nonce<12>) -> Self;

    /// Set associated data for authenticated encryption
    fn with_aad(self, aad: &'a [u8]) -> Self;

    /// Set plaintext and execute encryption
    fn encrypt(self, plaintext: &'a [u8]) -> Result<Vec<u8>>;
}

/// Trait for decryption operations with AEAD algorithms
pub trait AeadDecryptOperation<'a, A: AeadAlgorithm>: Operation<Vec<u8>> {
    /// Set the nonce for decryption
    fn with_nonce(self, nonce: &'a Nonce<12>) -> Self;

    /// Set associated data for authenticated decryption
    fn with_aad(self, aad: &'a [u8]) -> Self;

    /// Set ciphertext and execute decryption
    fn decrypt(self, ciphertext: &'a [u8]) -> Result<Vec<u8>>;
}

/// Trait for AEAD ciphers with improved type safety
pub trait AeadCipher {
    /// The algorithm this cipher implements
    type Algorithm: AeadAlgorithm;

    /// Key type with appropriate size guarantee
    type Key: AsRef<[u8]> + AsMut<[u8]> + Clone + Zeroize;

    /// Creates a new AEAD cipher instance
    fn new(key: &Self::Key) -> Result<Self>
    where
        Self: Sized;

    /// Begin encryption operation with operation pattern
    fn encrypt(&self) -> impl AeadEncryptOperation<'_, Self::Algorithm>;

    /// Begin decryption operation with operation pattern
    fn decrypt(&self) -> impl AeadDecryptOperation<'_, Self::Algorithm>;

    /// Generate a random key
    fn generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Key>;

    /// Generate a random nonce for ChaCha20Poly1305
    fn generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Nonce<12>>;

    /// Returns the cipher name
    fn name() -> &'static str {
        Self::Algorithm::name()
    }

    /// Returns the key size in bytes
    fn key_size() -> usize {
        Self::Algorithm::KEY_SIZE
    }

    /// Returns the tag size in bytes
    fn tag_size() -> usize {
        Self::Algorithm::TAG_SIZE
    }
}

/// Implementation of ChaCha20-Poly1305 with enhanced type safety
#[cfg(feature = "alloc")]
pub struct ChaCha20Poly1305Cipher {
    inner: chacha20poly1305::ChaCha20Poly1305,
}

#[cfg(feature = "alloc")]
impl AeadCipher for ChaCha20Poly1305Cipher {
    type Algorithm = ChaCha20Poly1305Algorithm;
    type Key = SecretBytes<32>;

    fn new(key: &Self::Key) -> Result<Self> {
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key.as_ref());

        let inner = chacha20poly1305::ChaCha20Poly1305::new(&key_array);

        Ok(Self { inner })
    }

    fn encrypt(&self) -> impl AeadEncryptOperation<'_, Self::Algorithm> {
        ChaCha20Poly1305EncryptOperation {
            cipher: self,
            nonce: None,
            aad: None,
        }
    }

    fn decrypt(&self) -> impl AeadDecryptOperation<'_, Self::Algorithm> {
        ChaCha20Poly1305DecryptOperation {
            cipher: self,
            nonce: None,
            aad: None,
        }
    }

    fn generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Key> {
        let mut key = [0u8; 32];
        rng.try_fill_bytes(&mut key)?;
        Ok(SecretBytes::new(key))
    }

    fn generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Nonce<12>> {
        let mut nonce = [0u8; 12];
        rng.try_fill_bytes(&mut nonce)?;
        Ok(Nonce::<12>::new(nonce))
    }
}

/// ChaCha20-Poly1305 encryption operation
#[cfg(feature = "alloc")]
pub struct ChaCha20Poly1305EncryptOperation<'a> {
    cipher: &'a ChaCha20Poly1305Cipher,
    nonce: Option<&'a Nonce<12>>,
    aad: Option<&'a [u8]>,
}

#[cfg(feature = "alloc")]
impl Operation<Vec<u8>> for ChaCha20Poly1305EncryptOperation<'_> {
    fn execute(self) -> Result<Vec<u8>> {
        Err(Error::param("operation", "use encrypt method instead"))
    }

    fn reset(&mut self) {
        self.nonce = None;
        self.aad = None;
    }
}

#[cfg(feature = "alloc")]
impl<'a> AeadEncryptOperation<'a, ChaCha20Poly1305Algorithm>
    for ChaCha20Poly1305EncryptOperation<'a>
{
    fn with_nonce(mut self, nonce: &'a Nonce<12>) -> Self {
        self.nonce = Some(nonce);
        self
    }

    fn with_aad(mut self, aad: &'a [u8]) -> Self {
        self.aad = Some(aad);
        self
    }

    fn encrypt(self, plaintext: &'a [u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce.ok_or_else(|| {
            Error::param("nonce", "nonce is required for ChaCha20Poly1305 encryption")
        })?;

        self.cipher.inner.encrypt(nonce, plaintext, self.aad)
    }
}

/// ChaCha20-Poly1305 decryption operation
#[cfg(feature = "alloc")]
pub struct ChaCha20Poly1305DecryptOperation<'a> {
    cipher: &'a ChaCha20Poly1305Cipher,
    nonce: Option<&'a Nonce<12>>,
    aad: Option<&'a [u8]>,
}

#[cfg(feature = "alloc")]
impl Operation<Vec<u8>> for ChaCha20Poly1305DecryptOperation<'_> {
    fn execute(self) -> Result<Vec<u8>> {
        Err(Error::param("operation", "use decrypt method instead"))
    }

    fn reset(&mut self) {
        self.nonce = None;
        self.aad = None;
    }
}

#[cfg(feature = "alloc")]
impl<'a> AeadDecryptOperation<'a, ChaCha20Poly1305Algorithm>
    for ChaCha20Poly1305DecryptOperation<'a>
{
    fn with_nonce(mut self, nonce: &'a Nonce<12>) -> Self {
        self.nonce = Some(nonce);
        self
    }

    fn with_aad(mut self, aad: &'a [u8]) -> Self {
        self.aad = Some(aad);
        self
    }

    fn decrypt(self, ciphertext: &'a [u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce.ok_or_else(|| {
            Error::param("nonce", "nonce is required for ChaCha20Poly1305 decryption")
        })?;

        self.cipher.inner.decrypt(nonce, ciphertext, self.aad)
    }
}
