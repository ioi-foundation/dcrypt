// File: dcrypt-sign/src/sphincs/mod.rs

use dcrypt_api::{Error, Result, Signature as SignatureTrait};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// SPHINCS+ signature scheme using SHA-2
pub struct SphincsSha2;

#[derive(Clone, Zeroize)]
pub struct SphincsPublicKey(pub Vec<u8>);

#[derive(Clone, Zeroize)]
pub struct SphincsSecretKey(pub Vec<u8>);

#[derive(Clone)]
pub struct SphincsSignature(pub Vec<u8>);

impl AsRef<[u8]> for SphincsPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for SphincsPublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for SphincsSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for SphincsSecretKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for SphincsSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for SphincsSignature {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl SignatureTrait for SphincsSha2 {
    type PublicKey = SphincsPublicKey;
    type SecretKey = SphincsSecretKey;
    type SignatureData = SphincsSignature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "SPHINCS+-SHA2"
    }

    fn keypair<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<Self::KeyPair> {
        Err(Error::NotImplemented {
            feature: "SPHINCS+-SHA2 key generation",
        })
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn sign(_message: &[u8], _secret_key: &Self::SecretKey) -> Result<Self::SignatureData> {
        Err(Error::NotImplemented {
            feature: "SPHINCS+-SHA2 signing",
        })
    }

    fn verify(
        _message: &[u8],
        _signature: &Self::SignatureData,
        _public_key: &Self::PublicKey,
    ) -> Result<()> {
        Err(Error::NotImplemented {
            feature: "SPHINCS+-SHA2 verification",
        })
    }
}

/// SPHINCS+ signature scheme using SHAKE
pub struct SphincsShake;

impl SignatureTrait for SphincsShake {
    type PublicKey = SphincsPublicKey;
    type SecretKey = SphincsSecretKey;
    type SignatureData = SphincsSignature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "SPHINCS+-SHAKE"
    }

    fn keypair<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<Self::KeyPair> {
        Err(Error::NotImplemented {
            feature: "SPHINCS+-SHAKE key generation",
        })
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn sign(_message: &[u8], _secret_key: &Self::SecretKey) -> Result<Self::SignatureData> {
        Err(Error::NotImplemented {
            feature: "SPHINCS+-SHAKE signing",
        })
    }

    fn verify(
        _message: &[u8],
        _signature: &Self::SignatureData,
        _public_key: &Self::PublicKey,
    ) -> Result<()> {
        Err(Error::NotImplemented {
            feature: "SPHINCS+-SHAKE verification",
        })
    }
}