//! Digital Signature Schemes
//!
//! This crate implements various digital signature schemes,
//! both traditional and post-quantum.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod dilithium;
pub mod error;
pub mod falcon;
pub mod rainbow;
pub mod sphincs;

pub use dilithium::{Dilithium2, Dilithium3, Dilithium5, MlDsa44, MlDsa65, MlDsa87};
pub use falcon::{Falcon1024, Falcon512};
pub use rainbow::{RainbowI, RainbowIII, RainbowV};
pub use sphincs::{SphincsSha2, SphincsShake};

pub mod ecdsa;
pub mod eddsa;

pub use ecdsa::{
    EcdsaP256, EcdsaP256PublicKey, EcdsaP256SecretKey, EcdsaP256Signature, EcdsaP384,
    EcdsaP384PublicKey, EcdsaP384SecretKey, EcdsaP384Signature,
};

// Re-export EdDSA types
pub use eddsa::Ed25519;
