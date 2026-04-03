// File: crates/kem/src/ecdh/mod.rs
//! ECDH-KEM implementations for NIST curves
//!
//! This module provides constant-time implementations of ECDH-KEM
//! using the NIST P-192, P-224, P-256, P-384, and P-521 curves,
//! following standard practices for key encapsulation mechanisms.
//! It now also includes support for Koblitz (secp256k1) and Binary (sect283k1) curves.

pub mod b283k;
pub mod k256; // Koblitz curve secp256k1
pub mod p192;
pub mod p224;
pub mod p256;
pub mod p384;
pub mod p521; // Binary curve sect283k1

// Re-export the P-192 types
pub use p192::{
    EcdhP192, EcdhP192Ciphertext, EcdhP192PublicKey, EcdhP192SecretKey, EcdhP192SharedSecret,
};

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

// Re-export the B-283k (sect283k1) types
pub use b283k::{
    EcdhB283k, EcdhB283kCiphertext, EcdhB283kPublicKey, EcdhB283kSecretKey, EcdhB283kSharedSecret,
};
