//! AES-GCM authenticated encryption.
//!
//! This module implements AES-GCM as specified by NIST SP 800-38D. Random
//! keys and nonces are produced only from an explicitly supplied
//! cryptographic RNG.
//!
//! ```
//! use dcrypt_symmetric::{
//!     Aead, Aes128Gcm, Aes128Key, ChaCha20Rng, Result, SymmetricCipher,
//! };
//!
//! fn example() -> Result<()> {
//!     let mut rng = ChaCha20Rng::from_seed([7; 32]);
//!     let key = Aes128Key::generate(&mut rng)?;
//!     let nonce = Aes128Gcm::generate_nonce(&mut rng)?;
//!     let cipher = Aes128Gcm::new(&key)?;
//!     let ciphertext = cipher.encrypt(&nonce, b"secret message", None)?;
//!     assert_eq!(cipher.decrypt(&nonce, &ciphertext, None)?, b"secret message");
//!     Ok(())
//! }
//! # example().unwrap();
//! ```

use alloc::vec::Vec;
use dcrypt_algorithms::{
    aead::Gcm,
    block::{
        aes::{Aes128, Aes256},
        BlockCipher,
    },
    error::Error as PrimitiveError,
    types::Nonce,
};
use dcrypt_api::types::SecretBytes;
use dcrypt_internal::{CryptoRng, ZeroizingBytes};

use crate::{
    aes::keys::{Aes128Key, Aes256Key},
    cipher::{Aead, SymmetricCipher},
    error::{from_primitive_error, validate, Error, Result},
};

pub mod aes128;
pub mod aes256;
pub mod types;

pub use aes128::{aes128_decrypt, aes128_decrypt_package, aes128_encrypt, aes128_encrypt_package};
pub use aes256::{aes256_decrypt, aes256_decrypt_package, aes256_encrypt, aes256_encrypt_package};
pub use types::{AesCiphertextPackage, GcmNonce};

/// AES-128-GCM implementation.
pub struct Aes128Gcm {
    pub(crate) key: Aes128Key,
}

/// AES-256-GCM implementation.
pub struct Aes256Gcm {
    pub(crate) key: Aes256Key,
}

impl Aes128Gcm {
    pub(crate) fn decrypt_protected(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<ZeroizingBytes> {
        let key_bytes = SecretBytes::<16>::from_slice(self.key.as_bytes())?;
        let primitive_nonce = Nonce::<12>::new(*nonce);
        let gcm = Gcm::new(Aes128::new(&key_bytes))?;
        gcm.internal_decrypt_protected(&primitive_nonce, ciphertext, aad)
            .map_err(|error| map_authentication_error(error, "AES-128-GCM"))
    }
}

impl Aes256Gcm {
    pub(crate) fn decrypt_protected(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<ZeroizingBytes> {
        let key_bytes = SecretBytes::<32>::from_slice(self.key.as_bytes())?;
        let primitive_nonce = Nonce::<12>::new(*nonce);
        let gcm = Gcm::new(Aes256::new(&key_bytes))?;
        gcm.internal_decrypt_protected(&primitive_nonce, ciphertext, aad)
            .map_err(|error| map_authentication_error(error, "AES-256-GCM"))
    }
}

impl SymmetricCipher for Aes128Gcm {
    type Key = Aes128Key;

    fn new(key: &Self::Key) -> Result<Self> {
        Ok(Self { key: key.clone() })
    }

    fn name() -> &'static str {
        "AES-128-GCM"
    }
}

impl Aead for Aes128Gcm {
    type Nonce = GcmNonce;

    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        validate::length("GCM nonce", nonce.as_bytes().len(), 12)?;
        let key_bytes = SecretBytes::<16>::from_slice(self.key.as_bytes())?;
        let primitive_nonce = Nonce::<12>::from_slice(nonce.as_bytes())?;
        let gcm = Gcm::new(Aes128::new(&key_bytes))?;
        gcm.internal_encrypt(&primitive_nonce, plaintext, aad)
            .map_err(from_primitive_error)
    }

    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        validate::length("GCM nonce", nonce.as_bytes().len(), 12)?;
        let key_bytes = SecretBytes::<16>::from_slice(self.key.as_bytes())?;
        let primitive_nonce = Nonce::<12>::from_slice(nonce.as_bytes())?;
        let gcm = Gcm::new(Aes128::new(&key_bytes))?;
        gcm.internal_decrypt(&primitive_nonce, ciphertext, aad)
            .map_err(|error| map_authentication_error(error, "AES-128-GCM"))
    }

    fn generate_nonce<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self::Nonce> {
        GcmNonce::generate(rng)
    }
}

impl SymmetricCipher for Aes256Gcm {
    type Key = Aes256Key;

    fn new(key: &Self::Key) -> Result<Self> {
        Ok(Self { key: key.clone() })
    }

    fn name() -> &'static str {
        "AES-256-GCM"
    }
}

impl Aead for Aes256Gcm {
    type Nonce = GcmNonce;

    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        validate::length("GCM nonce", nonce.as_bytes().len(), 12)?;
        let key_bytes = SecretBytes::<32>::from_slice(self.key.as_bytes())?;
        let primitive_nonce = Nonce::<12>::from_slice(nonce.as_bytes())?;
        let gcm = Gcm::new(Aes256::new(&key_bytes))?;
        gcm.internal_encrypt(&primitive_nonce, plaintext, aad)
            .map_err(from_primitive_error)
    }

    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        validate::length("GCM nonce", nonce.as_bytes().len(), 12)?;
        let key_bytes = SecretBytes::<32>::from_slice(self.key.as_bytes())?;
        let primitive_nonce = Nonce::<12>::from_slice(nonce.as_bytes())?;
        let gcm = Gcm::new(Aes256::new(&key_bytes))?;
        gcm.internal_decrypt(&primitive_nonce, ciphertext, aad)
            .map_err(|error| map_authentication_error(error, "AES-256-GCM"))
    }

    fn generate_nonce<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self::Nonce> {
        GcmNonce::generate(rng)
    }
}

fn map_authentication_error(error: PrimitiveError, algorithm: &'static str) -> Error {
    match error {
        PrimitiveError::Authentication { .. } => Error::AuthenticationFailed {
            context: algorithm,
            #[cfg(feature = "std")]
            message: "authentication tag verification failed".into(),
        },
        other => from_primitive_error(other),
    }
}
