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
/// This trait defines distinct types and explicit serialization contracts for
/// KEM inputs and outputs. Implementations remain responsible for validating
/// encodings and meeting their algorithm-specific security requirements.
pub trait Kem {
    /// Public key type with appropriate constraints.
    ///
    /// # Security Note
    /// Implements `Serialize` for the public encoding boundary.
    type PublicKey: Clone + Serialize;

    /// Secret key type with an explicit clearing and serialization contract.
    ///
    /// # Security Note
    /// - Implements `Zeroize` for best-effort clearing of owned initialized storage.
    /// - Implements `SerializeSecret` for exact-size protected exports.
    type SecretKey: Zeroize + Clone + SerializeSecret;

    /// Shared-secret type with an explicit clearing and serialization contract.
    ///
    /// # Security Note
    /// - Implements `Zeroize` for best-effort clearing of owned initialized storage.
    /// - Implements `SerializeSecret` for exact-size protected exports.
    /// - Should be converted to application keys immediately after generation.
    type SharedSecret: Zeroize + Clone + SerializeSecret;

    /// Ciphertext type for the encapsulated key.
    ///
    /// # Security Note
    /// Implements `Serialize` for the public encoding boundary.
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
    /// The returned secret key should be protected and explicitly cleared after use.
    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey;

    /// Encapsulate a shared secret using the recipient's public key.
    ///
    /// # Security Requirements
    /// - Must validate the public key internally.
    /// - Must use fresh randomness from the provided RNG.
    /// - Must not intentionally branch or index memory on secret material.
    ///   Concrete compiler/target behavior requires separate validation.
    fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        public_key: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)>;

    /// Decapsulate a shared secret using the private key.
    ///
    /// # Security Requirements
    /// - Must not intentionally branch or index memory on secret material.
    ///   Concrete compiler/target behavior requires separate validation.
    /// - Should use implicit rejection for IND-CCA2 security where applicable.
    /// - Must not leak information about the secret key.
    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret>;
}
