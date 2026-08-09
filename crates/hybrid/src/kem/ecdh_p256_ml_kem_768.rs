// File: crates/hybrid/src/kem/ecdh_p256_ml_kem_768.rs

//! Hybrid KEM combining ECDH on P-256 and MlKem-768.

use super::engine::{
    HybridCiphertext, HybridKemEngine, HybridPublicKey, HybridSecretKey, HybridSharedSecret,
};
use dcrypt_api::{error::Result as ApiResult, Kem};
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_kem::{ecdh::EcdhP256, ml_kem::MlKem768};

/// A concrete hybrid KEM struct for EcdhP256 + MlKem768.
pub struct EcdhP256MlKem768;

impl Kem for EcdhP256MlKem768 {
    // Define associated types using the generic building blocks
    type PublicKey = HybridPublicKey<EcdhP256, MlKem768>;
    type SecretKey = HybridSecretKey<EcdhP256, MlKem768>;
    type SharedSecret = HybridSharedSecret;
    type Ciphertext = HybridCiphertext<EcdhP256, MlKem768>;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-P256-ML-KEM-768"
    }

    // Delegate all logic to the generic engine
    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        HybridKemEngine::<EcdhP256, MlKem768>::keypair(rng)
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
        HybridKemEngine::<EcdhP256, MlKem768>::encapsulate(rng, public_key)
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        HybridKemEngine::<EcdhP256, MlKem768>::decapsulate(secret_key, ciphertext)
    }
}
