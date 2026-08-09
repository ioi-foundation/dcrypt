//! Block cipher implementations with advanced type-level guarantees
//!
//! This module contains implementations of various block ciphers and related
//! algorithms with improved type-safety through compile-time constraints.
//!
//! ## Example usage
//!
//! ```
//! use dcrypt_algorithms::block::{TypedAes128, TypedCbc, BlockCipher, BlockCipherMode, CipherAlgorithm};
//! use dcrypt_internal::random::ChaCha20Rng;
//!
//! // Generate a random key and nonce
//! let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
//! let key = TypedAes128::generate_key(&mut rng).unwrap();
//! let nonce = TypedCbc::<TypedAes128>::generate_nonce(&mut rng).unwrap();
//!
//! // Create cipher and mode instances
//! let cipher = TypedAes128::new(&key);
//! let mode = TypedCbc::new(cipher, &nonce).unwrap();
//!
//! // Encrypt and decrypt
//! let plaintext = b"secret message with padding...!!"; // Exactly 32 bytes (multiple of 16)
//! let ciphertext = mode.encrypt(plaintext).unwrap();
//! let decrypted = mode.decrypt(&ciphertext).unwrap();
//!
//! assert_eq!(plaintext, &decrypted[..]);
//! ```

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop};

use crate::error::{validate, Error, Result};
use crate::types::{Nonce, SecretBytes};
use dcrypt_internal::random::{CryptoRng, RngCore};

pub mod aes;
pub mod modes;

// Re-exports
pub use aes::{Aes128, Aes192, Aes256};
pub use modes::{cbc::Cbc, ctr::Ctr};

/// Marker trait for cipher algorithms with compile-time properties
pub trait CipherAlgorithm {
    /// Key size in bytes
    const KEY_SIZE: usize;

    /// Block size in bytes
    const BLOCK_SIZE: usize;

    /// Algorithm name
    fn name() -> &'static str;
}

/// Marker trait for specific AES key sizes
pub trait AesVariant: CipherAlgorithm {
    /// Number of rounds
    const ROUNDS: usize;
}

/// Marker trait for block cipher operating modes
pub trait CipherMode {
    /// Mode name
    fn name() -> &'static str;

    /// Whether the mode requires initialization vector/nonce
    const REQUIRES_IV: bool;

    /// Whether this is an authenticated mode
    const IS_AUTHENTICATED: bool;

    /// Size of the nonce/IV in bytes (if applicable)
    const IV_SIZE: usize;

    /// Size of the tag in bytes (if applicable and authenticated)
    const TAG_SIZE: Option<usize>;
}

/// Trait for block ciphers with type-level constraints
pub trait BlockCipher {
    /// The algorithm this cipher implements
    type Algorithm: CipherAlgorithm;

    /// Key type with appropriate size guarantee
    type Key: AsRef<[u8]> + AsMut<[u8]> + Clone + Zeroize;

    /// Creates a new block cipher instance with the given key
    fn new(key: &Self::Key) -> Self;

    /// Encrypts a single block in place
    fn encrypt_block(&self, block: &mut [u8]) -> Result<()>;

    /// Decrypts a single block in place
    fn decrypt_block(&self, block: &mut [u8]) -> Result<()>;

    /// Returns the key size in bytes
    fn key_size() -> usize {
        Self::Algorithm::KEY_SIZE
    }

    /// Returns the block size in bytes
    fn block_size() -> usize {
        Self::Algorithm::BLOCK_SIZE
    }

    /// Returns the name of the block cipher
    fn name() -> &'static str {
        Self::Algorithm::name()
    }

    /// Generate a random key
    fn generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Key>;
}

/// Trait for block cipher modes with type parameters
pub trait BlockCipherMode<C: BlockCipher> {
    /// The mode this implementation uses
    type Mode: CipherMode;

    /// Nonce/IV type with appropriate size constraint
    type Nonce: AsRef<[u8]> + AsMut<[u8]> + Clone;

    /// Creates a new block cipher mode instance
    fn new(cipher: C, nonce: &Self::Nonce) -> Result<Self>
    where
        Self: Sized;

    /// Encrypts plaintext data
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypts ciphertext data
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Generate a random nonce
    fn generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Nonce>;

    /// Returns the mode name
    fn mode_name() -> &'static str {
        Self::Mode::name()
    }
}

/// Trait for authenticated block cipher modes
pub trait AuthenticatedCipherMode<C: BlockCipher>: BlockCipherMode<C> {
    /// Tag type with appropriate size constraint
    type Tag: AsRef<[u8]> + AsMut<[u8]> + Clone;

    /// Encrypts plaintext with associated data
    fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;

    /// Decrypts ciphertext with associated data
    fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;

    /// Returns the tag size in bytes
    fn tag_size() -> usize {
        Self::Mode::TAG_SIZE.unwrap_or(0)
    }
}

/// Type-level constants for AES-128
pub enum Aes128Algorithm {}

impl CipherAlgorithm for Aes128Algorithm {
    const KEY_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 16;

    fn name() -> &'static str {
        "AES-128"
    }
}

impl AesVariant for Aes128Algorithm {
    const ROUNDS: usize = 10;
}

/// Enhanced AES-128 implementation with type-level guarantees
#[derive(Clone)]
pub struct TypedAes128 {
    inner: aes::Aes128,
}

impl Zeroize for TypedAes128 {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for TypedAes128 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for TypedAes128 {}

// Add the missing CipherAlgorithm implementation for TypedAes128
impl CipherAlgorithm for TypedAes128 {
    const KEY_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 16;

    fn name() -> &'static str {
        "AES-128"
    }
}

impl BlockCipher for TypedAes128 {
    type Algorithm = Aes128Algorithm;
    type Key = SecretBytes<16>;

    fn new(key: &Self::Key) -> Self {
        Self {
            inner: aes::Aes128::new(key),
        }
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        validate::length("AES-128 block", block.len(), Self::Algorithm::BLOCK_SIZE)?;
        self.inner.encrypt_block(block)
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        validate::length("AES-128 block", block.len(), Self::Algorithm::BLOCK_SIZE)?;
        self.inner.decrypt_block(block)
    }

    fn generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Key> {
        let mut key = [0u8; 16];
        rng.try_fill_bytes(&mut key)?;
        Ok(SecretBytes::new(key))
    }
}

/// Type-level constants for CBC mode
pub enum CbcMode {}

impl CipherMode for CbcMode {
    const REQUIRES_IV: bool = true;
    const IS_AUTHENTICATED: bool = false;
    const IV_SIZE: usize = 16; // For AES
    const TAG_SIZE: Option<usize> = None;

    fn name() -> &'static str {
        "CBC"
    }
}

/// Enhanced CBC mode implementation with type parameters
pub struct TypedCbc<C: BlockCipher + CipherAlgorithm + Zeroize + ZeroizeOnDrop> {
    inner: modes::cbc::Cbc<C>,
    _phantom: core::marker::PhantomData<C>,
}

impl<C: BlockCipher + CipherAlgorithm + Zeroize + ZeroizeOnDrop> BlockCipherMode<C>
    for TypedCbc<C>
{
    type Mode = CbcMode;
    type Nonce = Nonce<16>;

    fn new(cipher: C, nonce: &Self::Nonce) -> Result<Self> {
        // Validate that the nonce size matches the block size
        validate::length(
            "CBC initialization vector",
            nonce.as_ref().len(),
            C::BLOCK_SIZE,
        )?;

        let inner = modes::cbc::Cbc::new(cipher, nonce)?;
        Ok(Self {
            inner,
            _phantom: core::marker::PhantomData,
        })
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Validate that plaintext is a multiple of block size
        if plaintext.len() % C::BLOCK_SIZE != 0 {
            return Err(Error::Length {
                context: "CBC plaintext",
                expected: ((plaintext.len() / C::BLOCK_SIZE) + 1) * C::BLOCK_SIZE,
                actual: plaintext.len(),
            });
        }

        self.inner.encrypt(plaintext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Validate that ciphertext is a multiple of block size
        if ciphertext.len() % C::BLOCK_SIZE != 0 {
            return Err(Error::Length {
                context: "CBC ciphertext",
                expected: ((ciphertext.len() / C::BLOCK_SIZE) + 1) * C::BLOCK_SIZE,
                actual: ciphertext.len(),
            });
        }

        self.inner.decrypt(ciphertext)
    }

    fn generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Nonce> {
        let mut nonce = [0u8; 16];
        rng.try_fill_bytes(&mut nonce)?;
        Ok(Nonce::new(nonce))
    }
}
