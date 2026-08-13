//! Symmetric encryption algorithms for the dcrypt library
//!
//! This crate provides high-level symmetric encryption built from the owned
//! primitives in `dcrypt-algorithms`. Randomized operations always use an
//! explicit caller-owned [`CryptoRng`]. The allocation-backed core supports
//! `no_std`; authenticated I/O streams require the `std` feature.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod aead;
pub mod aes;
pub mod cipher;
pub mod error;
#[cfg(feature = "std")]
pub mod streaming;

// Re-export main types for convenience
pub use aead::chacha20poly1305::{
    derive_chacha20poly1305_key, generate_salt, ChaCha20Poly1305Cipher,
    ChaCha20Poly1305CiphertextPackage, ChaCha20Poly1305Key, ChaCha20Poly1305Nonce,
    XChaCha20Poly1305Cipher, XChaCha20Poly1305Nonce,
};
pub use aead::gcm::{Aes128Gcm, Aes256Gcm, AesCiphertextPackage, GcmNonce};
pub use aes::{Aes128Key, Aes256Key};
pub use cipher::{Aead, SymmetricCipher};
pub use dcrypt_internal::{ChaCha20Rng, CryptoRng, RngCore};

// Re-export the API error system instead of custom error types
pub use dcrypt_api::error::{Error, Result};

// Re-export commonly used validation utilities
pub use dcrypt_api::error::validate;
