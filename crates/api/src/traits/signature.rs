//! Digital signature traits for dcrypt
//!
//! This module defines the traits that all signature algorithms must implement.
//! The design prioritizes security by not requiring mutable access to secret keys.

use crate::{Result, ZeroizingBytes};
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::Zeroize;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

/// Core trait for digital signature algorithms
///
/// This trait defines the minimal interface that all signature algorithms
/// must implement. It intentionally does not require `AsRef` or `AsMut`
/// implementations for secret keys to prevent accidental key corruption.
///
/// # Type Safety
///
/// Secret keys are opaque types that cannot be directly manipulated as bytes.
/// This prevents common security vulnerabilities where keys are accidentally
/// modified or exposed.
///
/// # Example Implementation
///
/// See the implementation modules for examples of how to implement this trait
/// for specific algorithms like Ed25519, ECDSA, etc.
pub trait Signature {
    /// Public key type for this algorithm
    type PublicKey: Clone;

    /// Secret key type - must be zeroizable but not byte-accessible
    ///
    /// # Security Note
    ///
    /// This type should not implement `AsMut<[u8]>` to prevent corruption
    /// of key material. Use explicit serialization methods if needed.
    type SecretKey: Zeroize + Clone;

    /// Signature data type
    type SignatureData: Clone;

    /// Key pair type (typically a tuple of public and secret keys)
    type KeyPair;

    /// Returns the name of this signature algorithm
    fn name() -> &'static str;

    /// Generate a new key pair using the provided RNG
    ///
    /// # Security Requirements
    ///
    /// Implementations must use the provided cryptographically secure RNG
    /// for all random number generation.
    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self::KeyPair>;

    /// Extract the public key from a key pair
    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey;

    /// Extract the secret key from a key pair
    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey;

    /// Sign a message with the given secret key
    ///
    /// # Security Requirements
    ///
    /// - Implementations should be deterministic when possible (e.g., Ed25519)
    /// - Must not leak information about the secret key through timing
    fn sign(message: &[u8], secret_key: &Self::SecretKey) -> Result<Self::SignatureData>;

    /// Verify a signature against a message and public key
    ///
    /// # Security Requirements
    ///
    /// - Must be constant-time with respect to the signature value
    /// - Should validate all inputs before processing
    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> Result<()>;
}

/// Optional trait for signature algorithms that support key serialization
///
/// This trait should only be implemented for algorithms where key
/// import/export is safe and well-defined.
pub trait SignatureSerialize: Signature {
    /// Size of serialized public keys in bytes
    const PUBLIC_KEY_SIZE: usize;

    /// Size of serialized secret keys in bytes
    const SECRET_KEY_SIZE: usize;

    /// Size of serialized signatures in bytes
    const SIGNATURE_SIZE: usize;

    /// Export a public key to bytes
    fn serialize_public_key(key: &Self::PublicKey) -> Vec<u8>;

    /// Import a public key from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are malformed or invalid
    fn deserialize_public_key(bytes: &[u8]) -> Result<Self::PublicKey>;

    /// Export a secret key to bytes
    ///
    /// # Security Warning
    ///
    /// The returned bytes contain sensitive key material and must be
    /// handled with appropriate care. The exact-size zeroizing wrapper ensures
    /// every initialized byte is cleared from memory when dropped.
    fn serialize_secret_key(key: &Self::SecretKey) -> ZeroizingBytes;

    /// Import a secret key from bytes
    ///
    /// # Security Requirements
    ///
    /// - Input bytes should be zeroized after use
    /// - Implementation must validate the key format
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are malformed or invalid
    fn deserialize_secret_key(bytes: &[u8]) -> Result<Self::SecretKey>;

    /// Export a signature to bytes
    fn serialize_signature(sig: &Self::SignatureData) -> Vec<u8>;

    /// Import a signature from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are malformed or invalid
    fn deserialize_signature(bytes: &[u8]) -> Result<Self::SignatureData>;
}

/// Optional trait for signature algorithms that support key derivation
///
/// This trait is for algorithms that can derive keys from seed material
/// in a deterministic way.
pub trait SignatureDerive: Signature {
    /// Minimum seed size in bytes
    const MIN_SEED_SIZE: usize;

    /// Derive a key pair from seed material
    ///
    /// # Security Requirements
    ///
    /// - The seed must have sufficient entropy
    /// - Derivation must be deterministic
    /// - Same seed must always produce same key pair
    ///
    /// # Errors
    ///
    /// Returns an error if the seed is too short or invalid
    fn derive_keypair(seed: &[u8]) -> Result<Self::KeyPair>;

    /// Derive the public key from a secret key
    ///
    /// This is useful when you have a secret key and need to
    /// recover the corresponding public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key is invalid
    fn derive_public_key(secret_key: &Self::SecretKey) -> Result<Self::PublicKey>;
}

/// Optional trait for signature algorithms with message size limits
///
/// Some algorithms may have restrictions on message sizes or require
/// pre-hashing for large messages.
pub trait SignatureMessageLimits: Signature {
    /// Maximum message size that can be signed directly (in bytes)
    ///
    /// `None` indicates no limit
    const MAX_MESSAGE_SIZE: Option<usize>;

    /// Whether this algorithm requires pre-hashing of messages
    const REQUIRES_PREHASH: bool;
}

/// Optional trait for batch signature verification
///
/// Some algorithms (like Ed25519) support efficient batch verification
/// of multiple signatures.
pub trait SignatureBatchVerify: Signature {
    /// Verify multiple signatures in a batch
    ///
    /// # Parameters
    ///
    /// - `messages`: Slice of messages to verify
    /// - `signatures`: Corresponding signatures
    /// - `public_keys`: Corresponding public keys
    ///
    /// All three slices must have the same length.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all signatures are valid
    /// - `Err(_)` if any signature is invalid or inputs are malformed
    ///
    /// # Performance
    ///
    /// This should be significantly faster than verifying each signature
    /// individually when the batch size is large.
    fn batch_verify(
        messages: &[&[u8]],
        signatures: &[Self::SignatureData],
        public_keys: &[Self::PublicKey],
    ) -> Result<()>;
}

/// Extension trait for convenient public key operations
///
/// This trait can be implemented for public key types that have
/// a byte representation.
pub trait PublicKeyBytes: Sized {
    /// Create from byte representation
    fn from_bytes(bytes: &[u8]) -> Result<Self>;

    /// Convert to byte representation
    fn to_bytes(&self) -> Vec<u8>;
}

/// Extension trait for convenient signature operations
///
/// This trait can be implemented for signature types that have
/// a byte representation.
pub trait SignatureBytes: Sized {
    /// Create from byte representation
    fn from_bytes(bytes: &[u8]) -> Result<Self>;

    /// Convert to byte representation
    fn to_bytes(&self) -> Vec<u8>;
}
