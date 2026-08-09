//! EdDSA (Edwards-curve Digital Signature Algorithm) implementations
//!
//! This module provides a dcrypt-owned, safe-Rust Ed25519 implementation with
//! strict canonical and prime-subgroup validation. This description is not an
//! independent audit or production-safety claim.
//!
//! # Security Features
//!
//! - **Immutable secret keys**: Prevents accidental key corruption
//! - **Automatic zeroization**: Clears sensitive data from memory
//! - **Secure API design**: Minimal surface area, maximum safety
//! - **Fixed-schedule secret arithmetic**: Secret scalar multiplication uses
//!   constant-time selection rather than secret-dependent branches
//! - **Type safety**: Strong typing prevents key confusion
//!
//! # Features
//!
//! - RFC 8032 Ed25519 signing and strict verification
//! - Deterministic signature generation
//! - Secure key generation and handling
//! - Comprehensive input validation
//! - Key derivation and persistence support
//!
//! # Security Guidelines
//!
//! 1. **Supply a CSPRNG**: Key generation uses only the caller-provided RNG;
//!    this crate does not obtain entropy from the operating system
//! 2. **Protect seeds**: Encrypt before storage, decrypt only when needed
//! 3. **Verify public keys**: Confirm authenticity through secure channels
//! 4. **Clear sensitive data**: Automatic for secret keys, manual for seeds
//!
//! # Example
//!
//! ```
//! use dcrypt_sign::eddsa::{Ed25519, Ed25519SecretKey};
//! use dcrypt_api::Signature;
//!
//! # fn main() -> dcrypt_api::Result<()> {
//! // Load a seed supplied by the application's key-management boundary.
//! let seed = [42u8; 32];
//! let secret_key = Ed25519SecretKey::from_seed(&seed)?;
//! let public_key = secret_key.public_key()?;
//!
//! // Sign a message
//! let message = b"Hello, Ed25519!";
//! let signature = Ed25519::sign(message, &secret_key)?;
//!
//! // Verify the signature
//! assert!(Ed25519::verify(message, &signature, &public_key).is_ok());
//!
//! // Save the secret key seed (encrypt in production!)
//! let seed = secret_key.seed();
//!
//! // Later, reconstruct the secret key
//! let reconstructed_secret = Ed25519SecretKey::from_seed(seed)?;
//! let reconstructed_public = reconstructed_secret.public_key()?;
//!
//! // The reconstructed keys work identically
//! assert_eq!(public_key.0, reconstructed_public.0);
//! # Ok(())
//! # }
//! ```

mod constants;
mod ed25519;
mod field;
mod point;
mod scalar;

// Re-export Ed25519 types
pub use ed25519::{Ed25519, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};
