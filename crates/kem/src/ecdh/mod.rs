// File: crates/kem/src/ecdh/mod.rs
//! ECDH-KEM implementations for NIST curves
//!
//! This module provides ECDH-based KEMs using P-224, P-256, P-384,
//! P-521, and secp256k1. These are domain-separated dcrypt constructions,
//! not RFC 9180 HPKE suites.

pub mod k256;
pub mod p224;
pub mod p256;
pub mod p384;
pub mod p521;

// Re-export the P-224 types
pub use p224::{
    EcdhP224, EcdhP224Ciphertext, EcdhP224PublicKey, EcdhP224SecretKey, EcdhP224SharedSecret,
};

// Re-export the P-256 types
pub use p256::{
    EcdhP256, EcdhP256Ciphertext, EcdhP256PublicKey, EcdhP256SecretKey, EcdhP256SharedSecret,
};

// Re-export the P-384 types
pub use p384::{
    EcdhP384, EcdhP384Ciphertext, EcdhP384PublicKey, EcdhP384SecretKey, EcdhP384SharedSecret,
};

// Re-export the P-521 types
pub use p521::{
    EcdhP521, EcdhP521Ciphertext, EcdhP521PublicKey, EcdhP521SecretKey, EcdhP521SharedSecret,
};

// Re-export the K-256 (secp256k1) types
pub use k256::{
    EcdhK256, EcdhK256Ciphertext, EcdhK256PublicKey, EcdhK256SecretKey, EcdhK256SharedSecret,
};
