//! Standard XChaCha20-Poly1305 authenticated encryption.
//!
//! This module implements the construction from the XChaCha draft: HChaCha20
//! derives a subkey from the key and the first 16 nonce bytes, then the owned
//! RFC 8439 ChaCha20-Poly1305 implementation uses the nonce
//! `00000000 || nonce[16..24]`.
//!
//! dcrypt v1.2.3 is confirmed to have used a nonstandard construction under
//! this name; the exact earlier introduced-version range is under investigation.
//! This standard implementation intentionally does not decrypt
//! those bytes. Migrate legacy data only through a separately isolated,
//! decrypt-only compatibility tool; never relabel it as XChaCha20-Poly1305.

use crate::aead::chacha20poly1305::{
    ChaCha20Poly1305, CHACHA20POLY1305_KEY_SIZE, CHACHA20POLY1305_TAG_SIZE,
};
use crate::error::{validate, Error, Result};
use crate::stream::chacha::chacha20::{hchacha20, CHACHA20_NONCE_SIZE};
use crate::types::nonce::XChaCha20Compatible;
use crate::types::Nonce;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use dcrypt_api::traits::AuthenticatedCipher;
use dcrypt_common::security::{SecretBuffer, SecureZeroingType};
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Size of the XChaCha20Poly1305 nonce in bytes
pub const XCHACHA20POLY1305_NONCE_SIZE: usize = 24;

/// Standard XChaCha20-Poly1305 with an extended 24-byte nonce.
///
/// This type does not accept the nonstandard ciphertext format emitted by
/// the affected legacy format (confirmed in dcrypt v1.2.3).
#[derive(Clone)]
pub struct XChaCha20Poly1305 {
    key: SecretBuffer<CHACHA20POLY1305_KEY_SIZE>,
}

impl Zeroize for XChaCha20Poly1305 {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for XChaCha20Poly1305 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for XChaCha20Poly1305 {}

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

    /// Derive the HChaCha20 subkey and RFC 8439 nonce used by the inner AEAD.
    fn derive_subkey_and_nonce(
        &self,
        nonce: &[u8],
    ) -> (
        Zeroizing<[u8; CHACHA20POLY1305_KEY_SIZE]>,
        [u8; CHACHA20_NONCE_SIZE],
    ) {
        let mut hchacha_nonce = [0u8; 16];
        hchacha_nonce.copy_from_slice(&nonce[..16]);

        let key: &[u8; CHACHA20POLY1305_KEY_SIZE] = self
            .key
            .as_ref()
            .try_into()
            .expect("SecretBuffer has the declared XChaCha20 key size");
        let subkey = Zeroizing::new(hchacha20(key, &hchacha_nonce));

        // XChaCha20's IETF ChaCha20 nonce is 32 zero bits followed by the
        // final 64 bits of the extended nonce.
        let mut chacha_nonce = [0u8; CHACHA20_NONCE_SIZE];
        chacha_nonce[4..].copy_from_slice(&nonce[16..24]);

        hchacha_nonce.zeroize();
        (subkey, chacha_nonce)
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
        let (subkey, chacha_nonce) = self.derive_subkey_and_nonce(nonce.as_ref());
        ChaCha20Poly1305::new(&subkey).encrypt_with_nonce(&chacha_nonce, plaintext, aad)
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
        let (subkey, chacha_nonce) = self.derive_subkey_and_nonce(nonce.as_ref());
        ChaCha20Poly1305::new(&subkey)
            .decrypt_with_nonce(&chacha_nonce, ciphertext, aad)
            .map_err(|error| match error {
                Error::Authentication { .. } => Error::Authentication {
                    algorithm: "XChaCha20Poly1305",
                },
                other => other,
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
