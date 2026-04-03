//! EdDSA (Edwards-curve Digital Signature Algorithm) implementations
//!
//! This module provides a production-ready, security-hardened implementation
//! of Ed25519, the most widely used EdDSA variant, as specified in RFC 8032.
//!
//! # Security Features
//!
//! - **Immutable secret keys**: Prevents accidental key corruption
//! - **Automatic zeroization**: Clears sensitive data from memory
//! - **Secure API design**: Minimal surface area, maximum safety
//! - **Constant-time operations**: Where applicable to prevent timing attacks
//! - **Type safety**: Strong typing prevents key confusion
//!
//! # Features
//!
//! - Full Ed25519 signature scheme with actual curve arithmetic
//! - Deterministic signature generation
//! - Secure key generation and handling
//! - Comprehensive input validation
//! - Key derivation and persistence support
//!
//! # Security Guidelines
//!
//! 1. **Always use a CSPRNG**: Use `rand::rngs::OsRng` for key generation
//! 2. **Protect seeds**: Encrypt before storage, decrypt only when needed
//! 3. **Verify public keys**: Confirm authenticity through secure channels
//! 4. **Clear sensitive data**: Automatic for secret keys, manual for seeds
//!
//! # Example
//!
//! ```
//! use dcrypt_sign::eddsa::{Ed25519, Ed25519SecretKey};
//! use dcrypt_api::Signature;
//! use rand::rngs::OsRng;
//!
//! # fn main() -> dcrypt_api::Result<()> {
//! let mut rng = OsRng;
//!
//! // Generate a new keypair
//! let (public_key, secret_key) = Ed25519::keypair(&mut rng)?;
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
mod operations;
mod point;
mod scalar;

// Re-export Ed25519 types
pub use ed25519::{Ed25519, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};

// The curve arithmetic modules are internal and not exported.
// They provide the mathematical operations needed by Ed25519.
