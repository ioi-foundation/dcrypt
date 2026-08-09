//! Digital Signature Schemes
//!
//! This crate implements various digital signature schemes,
//! both traditional and post-quantum.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod error;
#[cfg(feature = "post-quantum")]
#[path = "dilithium/mod.rs"]
pub mod mldsa;

#[cfg(feature = "post-quantum")]
pub use mldsa::{MlDsa44, MlDsa65, MlDsa87};

#[cfg(feature = "traditional")]
pub mod ecdsa;
#[cfg(feature = "traditional")]
pub mod eddsa;

#[cfg(feature = "traditional")]
pub use ecdsa::{
    EcdsaP224, EcdsaP224PublicKey, EcdsaP224SecretKey, EcdsaP224Signature, EcdsaP256,
    EcdsaP256PublicKey, EcdsaP256SecretKey, EcdsaP256Signature, EcdsaP384, EcdsaP384PublicKey,
    EcdsaP384SecretKey, EcdsaP384Signature, EcdsaP521, EcdsaP521PublicKey, EcdsaP521SecretKey,
    EcdsaP521Signature,
};

// Re-export EdDSA types
#[cfg(feature = "traditional")]
pub use eddsa::Ed25519;

#[cfg(test)]
mod rng_failure_tests {
    use super::*;
    use dcrypt_api::Signature;
    use dcrypt_internal::{CryptoRng, Error as RngError, RngCore};

    struct FailingRng;

    impl RngCore for FailingRng {
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            destination.fill(0xa5);
            Err(RngError)
        }
    }

    impl CryptoRng for FailingRng {}

    macro_rules! keypair_propagates_rng_failure {
        ($name:ident, $scheme:ty) => {
            #[test]
            fn $name() {
                assert!(<$scheme>::keypair(&mut FailingRng).is_err());
            }
        };
    }

    #[cfg(feature = "traditional")]
    keypair_propagates_rng_failure!(p224_keypair_rng_failure, EcdsaP224);
    #[cfg(feature = "traditional")]
    keypair_propagates_rng_failure!(p256_keypair_rng_failure, EcdsaP256);
    #[cfg(feature = "traditional")]
    keypair_propagates_rng_failure!(p384_keypair_rng_failure, EcdsaP384);
    #[cfg(feature = "traditional")]
    keypair_propagates_rng_failure!(p521_keypair_rng_failure, EcdsaP521);
    #[cfg(feature = "traditional")]
    #[test]
    fn ed25519_keypair_rng_failure() {
        assert!(matches!(
            Ed25519::keypair(&mut FailingRng),
            Err(dcrypt_api::Error::RandomGenerationError { .. })
        ));
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn mldsa44_keypair_rng_failure() {
        assert!(matches!(
            MlDsa44::keypair(&mut FailingRng),
            Err(dcrypt_api::Error::RandomGenerationError { .. })
        ));
    }

    #[cfg(feature = "post-quantum")]
    #[test]
    fn mldsa_randomized_signing_propagates_rng_failure() {
        let mut keygen_rng = dcrypt_internal::ChaCha20Rng::from_seed([0x42; 32]);
        let (_, secret) = MlDsa44::keypair(&mut keygen_rng).unwrap();
        assert!(matches!(
            MlDsa44::sign_with_rng(b"message", &secret, &mut FailingRng),
            Err(dcrypt_api::Error::RandomGenerationError { .. })
        ));
    }
}
