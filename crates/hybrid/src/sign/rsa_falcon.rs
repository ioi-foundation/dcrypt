// File: crates/hybrid/src/sign/rsa_falcon.rs

use dcrypt_api::{Signature as SignatureTrait, Result};
// use dcrypt_sign::traditional::rsa::RsaPss; // RsaPss not yet implemented/exposed in dcrypt-sign
use dcrypt_sign::falcon::Falcon512;
use zeroize::Zeroize;
use rand::{CryptoRng, RngCore};

// Stub for RsaPss until implemented in dcrypt-sign
// This prevents compilation errors while RsaPss is missing
pub struct RsaPss;
impl SignatureTrait for RsaPss {
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;
    type SignatureData = Vec<u8>;
    type KeyPair = (Vec<u8>, Vec<u8>);
    fn name() -> &'static str { "RSA-PSS-STUB" }
    fn keypair<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<Self::KeyPair> { Ok((vec![], vec![])) }
    fn public_key(kp: &Self::KeyPair) -> Self::PublicKey { kp.0.clone() }
    fn secret_key(kp: &Self::KeyPair) -> Self::SecretKey { kp.1.clone() }
    fn sign(_m: &[u8], _sk: &Self::SecretKey) -> Result<Self::SignatureData> { Ok(vec![]) }
    fn verify(_m: &[u8], _s: &Self::SignatureData, _pk: &Self::PublicKey) -> Result<()> { Ok(()) }
}

/// Hybrid signature scheme combining RSA-PSS and Falcon-512
pub struct RsaFalconHybrid;

#[derive(Clone, Zeroize)]
pub struct HybridPublicKey {
    rsa_pk: <RsaPss as SignatureTrait>::PublicKey,
    falcon_pk: <Falcon512 as SignatureTrait>::PublicKey,
}

#[derive(Clone, Zeroize)]
pub struct HybridSecretKey {
    rsa_sk: <RsaPss as SignatureTrait>::SecretKey,
    falcon_sk: <Falcon512 as SignatureTrait>::SecretKey,
}

#[derive(Clone)]
pub struct HybridSignature {
    rsa_sig: <RsaPss as SignatureTrait>::SignatureData,
    falcon_sig: <Falcon512 as SignatureTrait>::SignatureData,
}

impl AsRef<[u8]> for HybridPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.rsa_pk.as_ref()
    }
}

impl AsMut<[u8]> for HybridPublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        self.rsa_pk.as_mut()
    }
}

impl AsRef<[u8]> for HybridSecretKey {
    fn as_ref(&self) -> &[u8] {
        self.rsa_sk.as_ref()
    }
}

// REMOVED: AsMut<[u8]> for HybridSecretKey - Inner keys may not support mutable access

impl AsRef<[u8]> for HybridSignature {
    fn as_ref(&self) -> &[u8] {
        self.rsa_sig.as_ref()
    }
}

impl AsMut<[u8]> for HybridSignature {
    fn as_mut(&mut self) -> &mut [u8] {
        self.rsa_sig.as_mut()
    }
}

impl SignatureTrait for RsaFalconHybrid {
    type PublicKey = HybridPublicKey;
    type SecretKey = HybridSecretKey;
    type SignatureData = HybridSignature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "RSA-PSS + Falcon-512 Hybrid"
    }

    fn keypair<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> Result<Self::KeyPair> {
        // Generate keypairs for both algorithms
        let (rsa_pk, rsa_sk) = RsaPss::keypair(rng)?;
        let (falcon_pk, falcon_sk) = Falcon512::keypair(rng)?;

        let public_key = HybridPublicKey {
            rsa_pk,
            falcon_pk,
        };

        let secret_key = HybridSecretKey {
            rsa_sk,
            falcon_sk,
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
        let rsa_sig = RsaPss::sign(message, &secret_key.rsa_sk)?;
        let falcon_sig = Falcon512::sign(message, &secret_key.falcon_sk)?;

        Ok(HybridSignature {
            rsa_sig,
            falcon_sig,
        })
    }

    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> Result<()> {
        // Verify both signatures
        RsaPss::verify(message, &signature.rsa_sig, &public_key.rsa_pk)?;
        Falcon512::verify(message, &signature.falcon_sig, &public_key.falcon_pk)?;
        
        // If both verifications pass, return Ok
        Ok(())
    }
}