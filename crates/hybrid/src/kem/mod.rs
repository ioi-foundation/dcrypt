// File: crates/hybrid/src/kem/mod.rs

//! Hybrid Key Encapsulation Mechanisms (KEMs).
//!
//! This module provides KEMs that combine a classical primitive (like ECDH)
//! with a post-quantum primitive (like ML-KEM) to provide security against
//! both classical and quantum adversaries.

// Internal modules
pub(crate) mod engine;
mod traits;

// Concrete hybrid KEM implementations
mod ecdh_k256_ml_kem_512;
mod ecdh_p256_ml_kem_512;
mod ecdh_p256_ml_kem_768;
mod ecdh_p384_ml_kem_1024;
mod ecdh_p521_ml_kem_1024;

// Tests
#[cfg(test)]
mod tests;

// Re-export the primary hybrid KEM structs for easy access.
pub use ecdh_k256_ml_kem_512::EcdhK256MlKem512;
pub use ecdh_p256_ml_kem_512::EcdhP256MlKem512;
pub use ecdh_p256_ml_kem_768::EcdhP256MlKem768;
pub use ecdh_p384_ml_kem_1024::EcdhP384MlKem1024;
pub use ecdh_p521_ml_kem_1024::EcdhP521MlKem1024;
pub use engine::HybridSharedSecret;
