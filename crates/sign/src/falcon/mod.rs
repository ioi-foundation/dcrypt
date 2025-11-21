// File: dcrypt-sign/src/falcon/mod.rs

use dcrypt_api::{Error, Result, Signature as SignatureTrait};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Falcon-512 signature scheme
pub struct Falcon512;

#[derive(Clone, Zeroize)]
pub struct FalconPublicKey(pub Vec<u8>);

#[derive(Clone, Zeroize)]
pub struct FalconSecretKey(pub Vec<u8>);

#[derive(Clone)]
pub struct FalconSignature(pub Vec<u8>);

impl AsRef<[u8]> for FalconPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for FalconPublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for FalconSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for FalconSecretKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for FalconSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for FalconSignature {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl SignatureTrait for Falcon512 {
    type PublicKey = FalconPublicKey;
    type SecretKey = FalconSecretKey;
    type SignatureData = FalconSignature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "Falcon-512"
    }

    fn keypair<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<Self::KeyPair> {
        Err(Error::NotImplemented {
            feature: "Falcon-512 key generation",
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
            feature: "Falcon-512 signing",
        })
    }

    fn verify(
        _message: &[u8],
        _signature: &Self::SignatureData,
        _public_key: &Self::PublicKey,
    ) -> Result<()> {
        Err(Error::NotImplemented {
            feature: "Falcon-512 verification",
        })
    }
}

/// Falcon-1024 signature scheme
pub struct Falcon1024;

impl SignatureTrait for Falcon1024 {
    type PublicKey = FalconPublicKey;
    type SecretKey = FalconSecretKey;
    type SignatureData = FalconSignature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "Falcon-1024"
    }

    fn keypair<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<Self::KeyPair> {
        Err(Error::NotImplemented {
            feature: "Falcon-1024 key generation",
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
            feature: "Falcon-1024 signing",
        })
    }

    fn verify(
        _message: &[u8],
        _signature: &Self::SignatureData,
        _public_key: &Self::PublicKey,
    ) -> Result<()> {
        Err(Error::NotImplemented {
            feature: "Falcon-1024 verification",
        })
    }
}