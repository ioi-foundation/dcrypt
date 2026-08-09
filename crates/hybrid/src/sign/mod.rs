//! Hybrid Digital Signature Schemes
//!
//! This module provides hybrid signature schemes that combine traditional and
//! post-quantum algorithms.

mod ecdsa_dilithium;
mod rsa_falcon;

pub use ecdsa_dilithium::{EcdsaDilithiumHybrid, EcdsaMlDsa65Hybrid};
pub use rsa_falcon::RsaFalconHybrid;
