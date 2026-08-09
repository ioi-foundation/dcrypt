// File: crates/hybrid/src/kem/ecdh_k256_kyber_512.rs

//! Hybrid KEM combining ECDH on secp256k1 and Kyber-512.

use super::engine::{HybridCiphertext, HybridKemEngine, HybridPublicKey, HybridSecretKey};
use dcrypt_api::{error::Result as ApiResult, Kem};
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_kem::{
    ecdh::EcdhK256,
    kyber::{Kyber512, KyberSharedSecret},
};

/// A concrete hybrid KEM struct for EcdhK256 + Kyber512.
pub struct EcdhK256Kyber512;

impl Kem for EcdhK256Kyber512 {
    // Define associated types using the generic building blocks
    type PublicKey = HybridPublicKey<EcdhK256, Kyber512>;
    type SecretKey = HybridSecretKey<EcdhK256, Kyber512>;
    type SharedSecret = KyberSharedSecret;
    type Ciphertext = HybridCiphertext<EcdhK256, Kyber512>;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "EcdhK256-Kyber512"
    }

    // Delegate all logic to the generic engine
    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        HybridKemEngine::<EcdhK256, Kyber512>::keypair(rng)
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        public_key: &Self::PublicKey,
    ) -> ApiResult<(Self::Ciphertext, Self::SharedSecret)> {
        HybridKemEngine::<EcdhK256, Kyber512>::encapsulate(rng, public_key)
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        HybridKemEngine::<EcdhK256, Kyber512>::decapsulate(secret_key, ciphertext)
    }
}
