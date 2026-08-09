// File: crates/hybrid/src/kem/ecdh_p384_ml_kem_1024.rs

//! Hybrid KEM combining ECDH on P-384 and MlKem-1024.

use super::engine::{
    HybridCiphertext, HybridKemEngine, HybridPublicKey, HybridSecretKey, HybridSharedSecret,
};
use dcrypt_api::{error::Result as ApiResult, Kem};
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_kem::{ecdh::EcdhP384, ml_kem::MlKem1024};

/// A concrete hybrid KEM struct for EcdhP384 + MlKem1024.
pub struct EcdhP384MlKem1024;

impl Kem for EcdhP384MlKem1024 {
    // Define associated types using the generic building blocks
    type PublicKey = HybridPublicKey<EcdhP384, MlKem1024>;
    type SecretKey = HybridSecretKey<EcdhP384, MlKem1024>;
    type SharedSecret = HybridSharedSecret;
    type Ciphertext = HybridCiphertext<EcdhP384, MlKem1024>;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-P384-ML-KEM-1024"
    }

    // Delegate all logic to the generic engine
    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        HybridKemEngine::<EcdhP384, MlKem1024>::keypair(rng)
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
        HybridKemEngine::<EcdhP384, MlKem1024>::encapsulate(rng, public_key)
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        HybridKemEngine::<EcdhP384, MlKem1024>::decapsulate(secret_key, ciphertext)
    }
}
