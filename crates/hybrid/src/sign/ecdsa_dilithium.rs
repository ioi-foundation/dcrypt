// File: crates/hybrid/src/sign/ecdsa_dilithium.rs
//! ECDSA + Dilithium hybrid signature scheme
//!
//! This module implements a hybrid signature scheme that combines ECDSA and Dilithium.

use dcrypt_api::{Signature as SignatureTrait, Result};
use dcrypt_sign::ecdsa::EcdsaP384;
use dcrypt_sign::dilithium::Dilithium3;
use zeroize::Zeroize;
use rand::{CryptoRng, RngCore};

/// Hybrid signature scheme combining ECDSA P-384 and Dilithium3
pub struct EcdsaDilithiumHybrid;

#[derive(Clone, Zeroize)]
pub struct HybridPublicKey {
    ecdsa_pk: <EcdsaP384 as SignatureTrait>::PublicKey,
    dilithium_pk: <Dilithium3 as SignatureTrait>::PublicKey,
}

#[derive(Clone, Zeroize)]
pub struct HybridSecretKey {
    ecdsa_sk: <EcdsaP384 as SignatureTrait>::SecretKey,
    dilithium_sk: <Dilithium3 as SignatureTrait>::SecretKey,
}

#[derive(Clone)]
pub struct HybridSignature {
    ecdsa_sig: <EcdsaP384 as SignatureTrait>::SignatureData,
    dilithium_sig: <Dilithium3 as SignatureTrait>::SignatureData,
}

impl AsRef<[u8]> for HybridPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.ecdsa_pk.as_ref()
    }
}

impl AsMut<[u8]> for HybridPublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        self.ecdsa_pk.as_mut()
    }
}

impl AsRef<[u8]> for HybridSecretKey {
    fn as_ref(&self) -> &[u8] {
        self.ecdsa_sk.as_ref()
    }
}

// REMOVED: AsMut<[u8]> for HybridSecretKey - Inner keys do not support mutable access for security

impl AsRef<[u8]> for HybridSignature {
    fn as_ref(&self) -> &[u8] {
        self.ecdsa_sig.as_ref()
    }
}

impl AsMut<[u8]> for HybridSignature {
    fn as_mut(&mut self) -> &mut [u8] {
        self.ecdsa_sig.as_mut()
    }
}

impl SignatureTrait for EcdsaDilithiumHybrid {
    type PublicKey = HybridPublicKey;
    type SecretKey = HybridSecretKey;
    type SignatureData = HybridSignature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDSA-P384 + Dilithium3 Hybrid"
    }

    fn keypair<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> Result<Self::KeyPair> {
        // Generate keypairs for both algorithms
        let (ecdsa_pk, ecdsa_sk) = EcdsaP384::keypair(rng)?;
        let (dilithium_pk, dilithium_sk) = Dilithium3::keypair(rng)?;

        let public_key = HybridPublicKey {
            ecdsa_pk,
            dilithium_pk,
        };

        let secret_key = HybridSecretKey {
            ecdsa_sk,
            dilithium_sk,
        };

        Ok((public_key, secret_key))
    }
    
    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }
    
    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn sign(
        message: &[u8],
        secret_key: &Self::SecretKey,
    ) -> Result<Self::SignatureData> {
        // Sign with both algorithms
        let ecdsa_sig = EcdsaP384::sign(message, &secret_key.ecdsa_sk)?;
        let dilithium_sig = Dilithium3::sign(message, &secret_key.dilithium_sk)?;

        Ok(HybridSignature {
            ecdsa_sig,
            dilithium_sig,
        })
    }

    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> Result<()> {
        // Verify both signatures
        EcdsaP384::verify(message, &signature.ecdsa_sig, &public_key.ecdsa_pk)?;
        Dilithium3::verify(message, &signature.dilithium_sig, &public_key.dilithium_pk)?;
        
        // If both verifications pass, return Ok
        Ok(())
    }
}