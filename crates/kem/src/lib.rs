//! Key Encapsulation Mechanisms (KEM) and Key Exchange
//!
//! This crate implements various key encapsulation mechanisms and key exchange
//! protocols, both traditional and post-quantum.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod ecdh;
pub mod error;
pub mod kyber;

// Re-exports
pub use ecdh::{EcdhP192, EcdhP224, EcdhP256, EcdhP384, EcdhP521}; // Added EcdhP192
pub use kyber::{Kyber1024, Kyber512, Kyber768};
