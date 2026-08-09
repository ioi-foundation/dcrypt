// File: crates/api/src/traits/kem.rs

//! Trait definition for Key Encapsulation Mechanisms (KEM) with enhanced type safety
//!
//! This module provides a type-safe interface for key encapsulation mechanisms,
//! which are used for secure key exchange in public-key cryptography.

use super::serialize::{Serialize, SerializeSecret};
use crate::Result;
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::Zeroize;

/// Trait for Key Encapsulation Mechanism (KEM) with domain-specific types.
///
/// # Security Design
///
/// This trait enforces strong type safety and clear contracts for serialization,
/// preventing common security vulnerabilities.
pub trait Kem {
    /// Public key type with appropriate constraints.
    ///
    /// # Security Note
    /// Implements `Serialize` to guarantee safe `from_bytes` and `to_bytes` methods.
    type PublicKey: Clone + Serialize;

    /// Secret key type with security guarantees.
    ///
    /// # Security Note
    /// - Implements `Zeroize` for secure memory cleanup.
    /// - Implements `SerializeSecret` to guarantee safe `from_bytes` and `to_bytes_zeroizing` methods.
    type SecretKey: Zeroize + Clone + SerializeSecret;

    /// Shared secret type with security guarantees.
    ///
    /// # Security Note
    /// - Implements `Zeroize` for secure memory cleanup.
    /// - Implements `SerializeSecret` for secure serialization.
    /// - Should be converted to application keys immediately after generation.
    type SharedSecret: Zeroize + Clone + SerializeSecret;

    /// Ciphertext type for the encapsulated key.
    ///
    /// # Security Note
    /// Implements `Serialize` for safe `from_bytes` and `to_bytes` methods.
    type Ciphertext: Clone + Serialize;

    /// Keypair type for efficient storage of related keys. It is an intermediate type
    /// and does not require a serialization contract itself.
    type KeyPair: Clone;

    /// Returns the KEM algorithm name.
    fn name() -> &'static str;

    /// Generate a new keypair.
    ///
    /// # Security Requirements
    /// - Must use the provided CSPRNG for all randomness.
    /// - Keys must be generated according to the algorithm specification.
    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self::KeyPair>;

    /// Extract public key from keypair.
    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey;

    /// Extract secret key from keypair.
    ///
    /// # Security Note
    /// The returned secret key should be protected and zeroized after use.
    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey;

    /// Encapsulate a shared secret using the recipient's public key.
    ///
    /// # Security Requirements
    /// - Must validate the public key internally.
    /// - Must use fresh randomness from the provided RNG.
    /// - Must be resistant to side-channel attacks.
    fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        public_key: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)>;

    /// Decapsulate a shared secret using the private key.
    ///
    /// # Security Requirements
    /// - Must be constant-time.
    /// - Should use implicit rejection for IND-CCA2 security where applicable.
    /// - Must not leak information about the secret key.
    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret>;
}
