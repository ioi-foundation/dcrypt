//! AES-128 cipher implementations

use alloc::vec::Vec;
use dcrypt_internal::CryptoRng;

use super::types::{AesCiphertextPackage, GcmNonce};
use super::Aes128Gcm;
use crate::aes::keys::Aes128Key;
use crate::cipher::{Aead, SymmetricCipher};
use crate::error::Result;

impl Aes128Gcm {
    /// Generates an AES-128-GCM instance using caller-owned randomness.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<(Self, Aes128Key)> {
        let key = Aes128Key::generate(rng)?;
        let cipher = Self::new(&key)?;
        Ok((cipher, key))
    }

    /// Encrypts with a nonce drawn from caller-owned randomness.
    pub fn encrypt_with_random_nonce<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, GcmNonce)> {
        let nonce = Self::generate_nonce(rng)?;
        let ciphertext = self.encrypt(&nonce, plaintext, aad)?;
        Ok((ciphertext, nonce))
    }

    /// Helper method to decrypt and verify all in one step
    pub fn decrypt_and_verify(
        &self,
        ciphertext: &[u8],
        nonce: &GcmNonce,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.decrypt(nonce, ciphertext, aad)
    }

    /// Returns the key used by this instance
    pub fn key(&self) -> &Aes128Key {
        &self.key
    }

    /// Encrypts data and returns a package containing both nonce and ciphertext
    pub fn encrypt_to_package<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<AesCiphertextPackage> {
        let (ciphertext, nonce) = self.encrypt_with_random_nonce(rng, plaintext, aad)?;
        Ok(AesCiphertextPackage::new(nonce, ciphertext))
    }

    /// Decrypts a package containing both nonce and ciphertext
    pub fn decrypt_package(
        &self,
        package: &AesCiphertextPackage,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.decrypt(&package.nonce, &package.ciphertext, aad)
    }
}

// Additional standalone functions

/// Creates an AES-128-GCM key and nonce from caller-owned randomness and encrypts data.
pub fn aes128_encrypt<R: CryptoRng + ?Sized>(
    rng: &mut R,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<(Vec<u8>, Aes128Key, GcmNonce)> {
    let key = Aes128Key::generate(rng)?;
    let cipher = Aes128Gcm::new(&key)?;
    let nonce = Aes128Gcm::generate_nonce(rng)?;

    let ciphertext = cipher.encrypt(&nonce, plaintext, aad)?;

    Ok((ciphertext, key, nonce))
}

/// Decrypts data using AES-128-GCM
pub fn aes128_decrypt(
    ciphertext: &[u8],
    key: &Aes128Key,
    nonce: &GcmNonce,
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let cipher = Aes128Gcm::new(key)?;
    cipher.decrypt(nonce, ciphertext, aad)
}

/// Encrypts data and returns a complete package with everything needed for decryption
pub fn aes128_encrypt_package<R: CryptoRng + ?Sized>(
    rng: &mut R,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<(AesCiphertextPackage, Aes128Key)> {
    let key = Aes128Key::generate(rng)?;
    let cipher = Aes128Gcm::new(&key)?;
    let package = cipher.encrypt_to_package(rng, plaintext, aad)?;

    Ok((package, key))
}

/// Decrypts a package using the provided key
pub fn aes128_decrypt_package(
    package: &AesCiphertextPackage,
    key: &Aes128Key,
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let cipher = Aes128Gcm::new(key)?;
    cipher.decrypt_package(package, aad)
}
