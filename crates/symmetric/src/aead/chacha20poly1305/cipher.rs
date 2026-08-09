//! ChaCha20-Poly1305 authenticated encryption.

use alloc::vec::Vec;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use core::fmt;
use dcrypt_algorithms::{
    aead::{
        chacha20poly1305::{ChaCha20Poly1305, CHACHA20POLY1305_TAG_SIZE},
        xchacha20poly1305::XChaCha20Poly1305,
    },
    error::Error as PrimitiveError,
    types::Nonce,
};
use dcrypt_internal::CryptoRng;

use super::common::{
    ChaCha20Poly1305CiphertextPackage, ChaCha20Poly1305Key, ChaCha20Poly1305Nonce,
};
use crate::{
    cipher::{Aead, SymmetricCipher},
    error::{fill_random, from_primitive_error, validate, Error, Result},
};

/// ChaCha20-Poly1305 authenticated encryption.
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
    pub(crate) key: ChaCha20Poly1305Key,
}

impl SymmetricCipher for ChaCha20Poly1305Cipher {
    type Key = ChaCha20Poly1305Key;

    fn new(key: &Self::Key) -> Result<Self> {
        validate::length("ChaCha20Poly1305 key", key.as_bytes().len(), 32)?;
        Ok(Self {
            cipher: ChaCha20Poly1305::new(key.as_bytes()),
            key: key.clone(),
        })
    }

    fn name() -> &'static str {
        "ChaCha20Poly1305"
    }
}

impl Aead for ChaCha20Poly1305Cipher {
    type Nonce = ChaCha20Poly1305Nonce;

    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let primitive_nonce = Nonce::<12>::from_slice(nonce.as_bytes())?;
        self.cipher
            .encrypt(&primitive_nonce, plaintext, aad)
            .map_err(from_primitive_error)
    }

    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        validate::min_length(
            "ChaCha20Poly1305 ciphertext",
            ciphertext.len(),
            CHACHA20POLY1305_TAG_SIZE,
        )?;
        let primitive_nonce = Nonce::<12>::from_slice(nonce.as_bytes())?;
        self.cipher
            .decrypt(&primitive_nonce, ciphertext, aad)
            .map_err(|error| map_authentication_error(error, "ChaCha20Poly1305"))
    }

    fn generate_nonce<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self::Nonce> {
        ChaCha20Poly1305Nonce::generate(rng)
    }
}

impl ChaCha20Poly1305Cipher {
    /// Generates a cipher and key using caller-owned randomness.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<(Self, ChaCha20Poly1305Key)> {
        let key = ChaCha20Poly1305Key::generate(rng)?;
        let cipher = Self::new(&key)?;
        Ok((cipher, key))
    }

    /// Encrypts with a nonce drawn from caller-owned randomness.
    pub fn encrypt_with_random_nonce<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, ChaCha20Poly1305Nonce)> {
        let nonce = Self::generate_nonce(rng)?;
        let ciphertext = self.encrypt(&nonce, plaintext, aad)?;
        Ok((ciphertext, nonce))
    }

    /// Decrypts and verifies a ciphertext.
    pub fn decrypt_and_verify(
        &self,
        ciphertext: &[u8],
        nonce: &ChaCha20Poly1305Nonce,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.decrypt(nonce, ciphertext, aad)
    }

    /// Returns the key used by this instance.
    pub const fn key(&self) -> &ChaCha20Poly1305Key {
        &self.key
    }

    /// Encrypts into a package with a caller-randomized nonce.
    pub fn encrypt_to_package<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<ChaCha20Poly1305CiphertextPackage> {
        let (ciphertext, nonce) = self.encrypt_with_random_nonce(rng, plaintext, aad)?;
        Ok(ChaCha20Poly1305CiphertextPackage::new(nonce, ciphertext))
    }

    /// Decrypts a packaged ciphertext.
    pub fn decrypt_package(
        &self,
        package: &ChaCha20Poly1305CiphertextPackage,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.decrypt(&package.nonce, &package.ciphertext, aad)
    }
}

/// Standard XChaCha20-Poly1305 authenticated encryption with a 24-byte nonce.
///
/// This type intentionally rejects the nonstandard construction emitted under
/// the same name by the affected legacy implementation (confirmed in dcrypt
/// v1.2.3). Legacy data requires an isolated decrypt-only migration tool.
pub struct XChaCha20Poly1305Cipher {
    cipher: XChaCha20Poly1305,
}

impl SymmetricCipher for XChaCha20Poly1305Cipher {
    type Key = ChaCha20Poly1305Key;

    fn new(key: &Self::Key) -> Result<Self> {
        validate::length("XChaCha20Poly1305 key", key.as_bytes().len(), 32)?;
        Ok(Self {
            cipher: XChaCha20Poly1305::new(key.as_bytes()),
        })
    }

    fn name() -> &'static str {
        "XChaCha20Poly1305"
    }
}

/// Extended 24-byte nonce for XChaCha20-Poly1305.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XChaCha20Poly1305Nonce([u8; 24]);

impl XChaCha20Poly1305Nonce {
    /// Creates a nonce from raw bytes.
    pub const fn new(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    /// Creates a nonce using caller-owned cryptographic randomness.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut nonce = [0u8; 24];
        fill_random(rng, &mut nonce, "XChaCha20-Poly1305 nonce generation")?;
        Ok(Self(nonce))
    }

    /// Returns the raw nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }

    /// Parses a base64 nonce.
    pub fn from_string(encoded: &str) -> Result<Self> {
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| Error::SerializationError {
                context: "XChaCha20Poly1305 nonce base64 decode",
                #[cfg(feature = "std")]
                message: "invalid base64 encoding".into(),
            })?;
        validate::length("XChaCha20Poly1305 nonce", bytes.len(), 24)?;
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&bytes);
        Ok(Self(nonce))
    }
}

impl fmt::Display for XChaCha20Poly1305Nonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&STANDARD.encode(self.0))
    }
}

impl Aead for XChaCha20Poly1305Cipher {
    type Nonce = XChaCha20Poly1305Nonce;

    fn encrypt(
        &self,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let primitive_nonce = Nonce::<24>::from_slice(nonce.as_bytes())?;
        self.cipher
            .encrypt(&primitive_nonce, plaintext, aad)
            .map_err(from_primitive_error)
    }

    fn decrypt(
        &self,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        validate::min_length(
            "XChaCha20Poly1305 ciphertext",
            ciphertext.len(),
            CHACHA20POLY1305_TAG_SIZE,
        )?;
        let primitive_nonce = Nonce::<24>::from_slice(nonce.as_bytes())?;
        self.cipher
            .decrypt(&primitive_nonce, ciphertext, aad)
            .map_err(|error| map_authentication_error(error, "XChaCha20Poly1305"))
    }

    fn generate_nonce<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self::Nonce> {
        XChaCha20Poly1305Nonce::generate(rng)
    }
}

impl XChaCha20Poly1305Cipher {
    /// Generates a cipher and key using caller-owned randomness.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<(Self, ChaCha20Poly1305Key)> {
        let key = ChaCha20Poly1305Key::generate(rng)?;
        let cipher = Self::new(&key)?;
        Ok((cipher, key))
    }

    /// Encrypts with an explicit, caller-managed 24-byte nonce.
    pub fn encrypt(
        &self,
        nonce: &XChaCha20Poly1305Nonce,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        <Self as Aead>::encrypt(self, nonce, plaintext, aad)
    }

    /// Decrypts with the explicit nonce used for encryption.
    pub fn decrypt(
        &self,
        nonce: &XChaCha20Poly1305Nonce,
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        <Self as Aead>::decrypt(self, nonce, ciphertext, aad)
    }

    /// Decrypts and verifies a ciphertext.
    pub fn decrypt_and_verify(
        &self,
        ciphertext: &[u8],
        nonce: &XChaCha20Poly1305Nonce,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.decrypt(nonce, ciphertext, aad)
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
