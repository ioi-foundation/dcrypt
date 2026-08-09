// File: crates/hybrid/src/kem/ecdh_p256_ml_kem_512.rs

//! Hybrid KEM combining ECDH on P-256 and MlKem-512.

use super::engine::{
    HybridCiphertext, HybridKemEngine, HybridPublicKey, HybridSecretKey, HybridSharedSecret,
};
use dcrypt_api::{error::Result as ApiResult, Kem};
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_kem::{ecdh::EcdhP256, ml_kem::MlKem512};

/// A concrete hybrid KEM struct for EcdhP256 + MlKem512.
pub struct EcdhP256MlKem512;

impl Kem for EcdhP256MlKem512 {
    // Define associated types using the generic building blocks
    type PublicKey = HybridPublicKey<EcdhP256, MlKem512>;
    type SecretKey = HybridSecretKey<EcdhP256, MlKem512>;
    type SharedSecret = HybridSharedSecret;
    type Ciphertext = HybridCiphertext<EcdhP256, MlKem512>;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-P256-ML-KEM-512"
    }

    // Delegate all logic to the generic engine
    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        HybridKemEngine::<EcdhP256, MlKem512>::keypair(rng)
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
        HybridKemEngine::<EcdhP256, MlKem512>::encapsulate(rng, public_key)
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        HybridKemEngine::<EcdhP256, MlKem512>::decapsulate(secret_key, ciphertext)
    }
}
