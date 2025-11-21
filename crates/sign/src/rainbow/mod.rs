// File: dcrypt-sign/src/rainbow/mod.rs

use dcrypt_api::{Error, Result, Signature as SignatureTrait};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Rainbow-I signature scheme
pub struct RainbowI;

#[derive(Clone, Zeroize)]
pub struct RainbowPublicKey(pub Vec<u8>);

#[derive(Clone, Zeroize)]
pub struct RainbowSecretKey(pub Vec<u8>);

#[derive(Clone)]
pub struct RainbowSignature(pub Vec<u8>);

impl AsRef<[u8]> for RainbowPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for RainbowPublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for RainbowSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for RainbowSecretKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for RainbowSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for RainbowSignature {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl SignatureTrait for RainbowI {
    type PublicKey = RainbowPublicKey;
    type SecretKey = RainbowSecretKey;
    type SignatureData = RainbowSignature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "Rainbow-I"
    }

    fn keypair<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<Self::KeyPair> {
        Err(Error::NotImplemented {
            feature: "Rainbow-I key generation",
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
            feature: "Rainbow-I signing",
        })
    }

    fn verify(
        _message: &[u8],
        _signature: &Self::SignatureData,
        _public_key: &Self::PublicKey,
    ) -> Result<()> {
        Err(Error::NotImplemented {
            feature: "Rainbow-I verification",
        })
    }
}

/// Rainbow-III signature scheme
pub struct RainbowIII;

impl SignatureTrait for RainbowIII {
    type PublicKey = RainbowPublicKey;
    type SecretKey = RainbowSecretKey;
    type SignatureData = RainbowSignature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "Rainbow-III"
    }

    fn keypair<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<Self::KeyPair> {
        Err(Error::NotImplemented {
            feature: "Rainbow-III key generation",
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
            feature: "Rainbow-III signing",
        })
    }

    fn verify(
        _message: &[u8],
        _signature: &Self::SignatureData,
        _public_key: &Self::PublicKey,
    ) -> Result<()> {
        Err(Error::NotImplemented {
            feature: "Rainbow-III verification",
        })
    }
}

/// Rainbow-V signature scheme
pub struct RainbowV;

impl SignatureTrait for RainbowV {
    type PublicKey = RainbowPublicKey;
    type SecretKey = RainbowSecretKey;
    type SignatureData = RainbowSignature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "Rainbow-V"
    }

    fn keypair<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<Self::KeyPair> {
        Err(Error::NotImplemented {
            feature: "Rainbow-V key generation",
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
            feature: "Rainbow-V signing",
        })
    }

    fn verify(
        _message: &[u8],
        _signature: &Self::SignatureData,
        _public_key: &Self::PublicKey,
    ) -> Result<()> {
        Err(Error::NotImplemented {
            feature: "Rainbow-V verification",
        })
    }
}