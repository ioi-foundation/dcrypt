//! Symmetric encryption algorithms for the dcrypt library
//!
//! This crate provides high-level symmetric encryption algorithms built on top of
//! the primitives in dcrypt-primitives and uses the unified API error system.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod aead;
pub mod aes;
pub mod cipher;
pub mod error;
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

// Re-export the API error system instead of custom error types
pub use dcrypt_api::error::{Error, Result};

// Re-export commonly used validation and error handling utilities
pub use dcrypt_api::error::{validate, ResultExt, SecureErrorHandling, ERROR_REGISTRY};
