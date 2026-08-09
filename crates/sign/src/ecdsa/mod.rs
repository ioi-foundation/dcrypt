//! ECDSA signature implementations for NIST curves
//!
//! This module provides secure implementations of the Elliptic Curve Digital
//! Signature Algorithm (ECDSA) using the NIST P-224, P-256, P-384, and P-521 curves.

pub mod common;
pub mod p224;
pub mod p256;
pub mod p384;
pub mod p521;

// Re-export P-224 types
pub use p224::{EcdsaP224, EcdsaP224PublicKey, EcdsaP224SecretKey, EcdsaP224Signature};

// Re-export P-256 types
pub use p256::{EcdsaP256, EcdsaP256PublicKey, EcdsaP256SecretKey, EcdsaP256Signature};

// Re-export P-384 types
pub use p384::{EcdsaP384, EcdsaP384PublicKey, EcdsaP384SecretKey, EcdsaP384Signature};

// Re-export P-521 types
pub use p521::{EcdsaP521, EcdsaP521PublicKey, EcdsaP521SecretKey, EcdsaP521Signature};
