//! Type-safe wrappers for cryptographic types
//!
//! This module provides domain-specific types with compile-time and runtime
//! guarantees for cryptographic operations, designed to be ergonomic while
//! preventing common mistakes.

// Submodules
pub mod algorithms;
pub mod digest;
pub mod key;
pub mod nonce;
pub mod salt;
pub mod tag;

// Sealed trait module (not public)
pub(crate) mod sealed;

// Re-export main types
pub use digest::Digest;
pub use key::{AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey};
pub use nonce::Nonce;
pub use salt::Salt;
pub use tag::Tag;

// Import and re-export core types
pub use dcrypt_api::types::{Ciphertext, Key, SecretBytes, SecretVec};

// Import and re-export security types from dcrypt-core
pub use dcrypt_common::security::{
    EphemeralSecret,
    SecretBuffer,
    SecureZeroingType, // Use the trait from core
    ZeroizeGuard,
};

/// Marker trait for validating symmetric key sizes for specific algorithms.
///
/// This trait ensures that a symmetric key type has a valid size for the
/// specified algorithm. It's sealed to prevent external implementations.
pub trait ValidKeySize<A: key::SymmetricAlgorithm, const N: usize>: sealed::Sealed {}

/// Marker trait for validating asymmetric secret key sizes for specific algorithms.
///
/// This trait ensures that an asymmetric secret key type has a valid size for the
/// specified algorithm. It's sealed to prevent external implementations.
pub trait ValidSecretKeySize<A: key::AsymmetricAlgorithm, const N: usize>: sealed::Sealed {}

/// Marker trait for validating asymmetric public key sizes for specific algorithms.
///
/// This trait ensures that an asymmetric public key type has a valid size for the
/// specified algorithm. It's sealed to prevent external implementations.
pub trait ValidPublicKeySize<A: key::AsymmetricAlgorithm, const N: usize>: sealed::Sealed {}

// Common cryptographic traits
use rand::{CryptoRng, RngCore};

/// Trait for cryptographic types with constant-time equality
pub trait ConstantTimeEq {
    /// Compare two values in constant time
    fn ct_eq(&self, other: &Self) -> bool;
}

/// Trait for cryptographic types that can be randomly generated
pub trait RandomGeneration: Sized {
    /// Generate a random instance using the provided RNG
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> crate::error::Result<Self>;
}

/// Trait for types that have a fixed size
pub trait FixedSize {
    /// Get the size in bytes
    fn size() -> usize;
}

/// Trait for types that can be serialized to a byte representation
pub trait ByteSerializable: Sized {
    /// Convert to a byte vector
    fn to_bytes(&self) -> Vec<u8>;

    /// Try to create from a byte slice
    fn from_bytes(bytes: &[u8]) -> crate::error::Result<Self>;
}

/// Trait for types compatible with algorithms that have specific size requirements
pub trait AlgorithmCompatible<A> {}

// Re-export algorithm compatibility traits from submodules
pub use nonce::{AesCtrCompatible, AesGcmCompatible, ChaCha20Compatible, XChaCha20Compatible};

pub use salt::{Argon2Compatible, HkdfCompatible, Pbkdf2Compatible};

pub use digest::{Blake2bCompatible, Keccak256Compatible, Sha256Compatible, Sha512Compatible};

pub use tag::{ChaCha20Poly1305Compatible, GcmCompatible, HmacCompatible, Poly1305Compatible};

// Re-export algorithm marker types
#[cfg(feature = "ec")] // Guard these EC related algo markers
pub use algorithms::{
    Ed25519,
    P256,
    P384,
    P521, // Added NIST curves
    X25519,
};

pub use algorithms::{
    // These are generally always available or controlled by other features
    Aes128,
    Aes256,
    ChaCha20,
    ChaCha20Poly1305,
};

// Re-export key algorithm traits
pub use key::{AsymmetricAlgorithm, SymmetricAlgorithm};

// Re-export key type aliases for convenience
pub use algorithms::{
    // Symmetric keys
    Aes128Key,
    Aes256Key,
    ChaCha20Key,
    ChaCha20Poly1305Key,
    Ed25519PublicKey,
    // Asymmetric keys
    Ed25519SecretKey,
    P256PublicKeyCompressed,
    P256PublicKeyUncompressed,
    P256SecretKey,
    P384PublicKeyCompressed,
    P384PublicKeyUncompressed,
    P384SecretKey,
    P521PublicKeyCompressed,
    P521PublicKeyUncompressed,
    P521SecretKey,
    X25519PublicKey,
    X25519SecretKey,
};
