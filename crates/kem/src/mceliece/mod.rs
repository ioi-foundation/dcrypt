// File: dcrypt-kem/src/mceliece/mod.rs

use dcrypt_api::{Error, Kem, Result};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// McEliece-348864 KEM
pub struct McEliece348864;

#[derive(Clone, Zeroize)]
pub struct McEliecePublicKey(pub Vec<u8>);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct McElieceSecretKey(pub Vec<u8>);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct McElieceSharedSecret(pub Vec<u8>);

#[derive(Clone)]
pub struct McElieceCiphertext(pub Vec<u8>);

// McEliecePublicKey methods
impl McEliecePublicKey {
    /// Create a new public key from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the length of the public key
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the public key is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Export the public key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Get a reference to the inner bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create from a byte slice
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.to_vec()))
    }
}

// McElieceSecretKey methods
impl McElieceSecretKey {
    /// Create a new secret key from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the length of the secret key
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the secret key is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Export the secret key to bytes with zeroization
    pub fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.clone())
    }

    /// Get a reference to the inner bytes (internal use only)
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create from a byte slice
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.to_vec()))
    }
}

// McElieceSharedSecret methods
impl McElieceSharedSecret {
    /// Create a new shared secret from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the length of the shared secret
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the shared secret is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Export the shared secret to bytes with zeroization
    pub fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.clone())
    }

    /// Get a reference to the inner bytes (internal use only)
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// McElieceCiphertext methods
impl McElieceCiphertext {
    /// Create a new ciphertext from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the length of the ciphertext
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the ciphertext is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Export the ciphertext to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Get a reference to the inner bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create from a byte slice
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.to_vec()))
    }
}

// NO AsRef or AsMut implementations - this prevents direct byte access

impl Kem for McEliece348864 {
    type PublicKey = McEliecePublicKey;
    type SecretKey = McElieceSecretKey;
    type SharedSecret = McElieceSharedSecret;
    type Ciphertext = McElieceCiphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "McEliece-348864"
    }

    fn keypair<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<(Self::PublicKey, Self::SecretKey)> {
        Err(Error::NotImplemented {
            feature: "McEliece-348864 key generation",
        })
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn encapsulate<R: CryptoRng + RngCore>(
        _rng: &mut R,
        _public_key: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
        Err(Error::NotImplemented {
            feature: "McEliece-348864 encapsulation",
        })
    }

    fn decapsulate(
        _secret_key: &Self::SecretKey,
        _ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret> {
        Err(Error::NotImplemented {
            feature: "McEliece-348864 decapsulation",
        })
    }
}

/// McEliece-6960119 KEM
pub struct McEliece6960119;

impl Kem for McEliece6960119 {
    type PublicKey = McEliecePublicKey;
    type SecretKey = McElieceSecretKey;
    type SharedSecret = McElieceSharedSecret;
    type Ciphertext = McElieceCiphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "McEliece-6960119"
    }

    fn keypair<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<(Self::PublicKey, Self::SecretKey)> {
        Err(Error::NotImplemented {
            feature: "McEliece-6960119 key generation",
        })
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn encapsulate<R: CryptoRng + RngCore>(
        _rng: &mut R,
        _public_key: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
        Err(Error::NotImplemented {
            feature: "McEliece-6960119 encapsulation",
        })
    }

    fn decapsulate(
        _secret_key: &Self::SecretKey,
        _ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret> {
        Err(Error::NotImplemented {
            feature: "McEliece-6960119 decapsulation",
        })
    }
}