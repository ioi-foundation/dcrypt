//! XChaCha20Poly1305 authenticated encryption with proper error handling
//!
//! This module implements the XChaCha20Poly1305 Authenticated Encryption with
//! Associated Data (AEAD) algorithm, which extends ChaCha20Poly1305 with a
//! 24-byte nonce.
//!
//! dcrypt v1.2.3 is confirmed to have used a nonstandard construction under
//! this name; the exact earlier introduced-version range is under investigation.
//! This standard implementation intentionally does not decrypt
//! those bytes. Migrate legacy data only through a separately isolated,
//! decrypt-only compatibility tool; never relabel it as XChaCha20-Poly1305.

use crate::aead::chacha20poly1305::{CHACHA20POLY1305_KEY_SIZE, CHACHA20POLY1305_TAG_SIZE};
use crate::error::{validate, Result};
use crate::types::nonce::XChaCha20Compatible;
use crate::types::Nonce;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305 as BackendXChaCha20Poly1305, XNonce};
use dcrypt_api::traits::AuthenticatedCipher;
use dcrypt_common::security::{SecretBuffer, SecureZeroingType};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Size of the XChaCha20Poly1305 nonce in bytes
pub const XCHACHA20POLY1305_NONCE_SIZE: usize = 24;

/// Standard XChaCha20-Poly1305 with an extended 24-byte nonce.
///
/// This type does not accept the nonstandard ciphertext format emitted by
/// the affected legacy format (confirmed in dcrypt v1.2.3).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct XChaCha20Poly1305 {
    key: SecretBuffer<CHACHA20POLY1305_KEY_SIZE>,
}

impl XChaCha20Poly1305 {
    /// Create a new XChaCha20Poly1305 instance
    pub fn new(key: &[u8; CHACHA20POLY1305_KEY_SIZE]) -> Self {
        Self {
            key: SecretBuffer::new(*key),
        }
    }

    /// Creates an instance from raw key bytes
    pub fn from_key(key: &[u8]) -> Result<Self> {
        validate::length(
            "XChaCha20Poly1305 key",
            key.len(),
            CHACHA20POLY1305_KEY_SIZE,
        )?;

        let mut key_bytes = Zeroizing::new([0u8; CHACHA20POLY1305_KEY_SIZE]);
        key_bytes.copy_from_slice(&key[..CHACHA20POLY1305_KEY_SIZE]);
        Ok(Self {
            key: SecretBuffer::new(*key_bytes),
        })
    }

    /// Encrypt plaintext using XChaCha20Poly1305
    pub fn encrypt<const N: usize>(
        &self,
        nonce: &Nonce<N>,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>
    where
        Nonce<N>: XChaCha20Compatible,
    {
        validate::length(
            "XChaCha20Poly1305 nonce",
            nonce.as_ref().len(),
            XCHACHA20POLY1305_NONCE_SIZE,
        )?;
        let cipher = BackendXChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| crate::error::Error::param("key", "invalid XChaCha20 key"))?;
        cipher
            .encrypt(
                XNonce::from_slice(nonce.as_ref()),
                Payload {
                    msg: plaintext,
                    aad: aad.unwrap_or(&[]),
                },
            )
            .map_err(|_| crate::error::Error::Processing {
                operation: "XChaCha20Poly1305 encryption",
                details: "message is too long",
            })
    }

    /// Decrypt ciphertext using XChaCha20Poly1305
    pub fn decrypt<const N: usize>(
        &self,
        nonce: &Nonce<N>,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>
    where
        Nonce<N>: XChaCha20Compatible,
    {
        validate::length(
            "XChaCha20Poly1305 nonce",
            nonce.as_ref().len(),
            XCHACHA20POLY1305_NONCE_SIZE,
        )?;
        let cipher = BackendXChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| crate::error::Error::param("key", "invalid XChaCha20 key"))?;
        cipher
            .decrypt(
                XNonce::from_slice(nonce.as_ref()),
                Payload {
                    msg: ciphertext,
                    aad: aad.unwrap_or(&[]),
                },
            )
            .map_err(|_| crate::error::Error::Authentication {
                algorithm: "XChaCha20Poly1305",
            })
    }
}

// Implement SecureZeroingType for XChaCha20Poly1305
impl SecureZeroingType for XChaCha20Poly1305 {
    fn zeroed() -> Self {
        Self {
            key: SecretBuffer::zeroed(),
        }
    }

    fn secure_clone(&self) -> Self {
        Self {
            key: self.key.secure_clone(),
        }
    }
}

// Implement the marker trait AuthenticatedCipher correctly
impl AuthenticatedCipher for XChaCha20Poly1305 {
    const TAG_SIZE: usize = CHACHA20POLY1305_TAG_SIZE;
    const ALGORITHM_ID: &'static str = "XChaCha20Poly1305";
}

#[cfg(test)]
mod tests;
