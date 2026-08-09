//! Type-safe salt implementation with validation
//!
//! Provides the `Salt` type, representing a cryptographic
//! salt with appropriate validation and randomization capabilities.

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;

use core::fmt;
use core::ops::{Deref, DerefMut};
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::Zeroize;

use crate::error::{validate, Result};
use crate::types::sealed::Sealed;
use crate::types::{
    ByteSerializable, ConstantTimeEq, FixedSize, RandomGeneration, SecureZeroingType,
};

/// A cryptographic salt with compile-time size guarantee
#[derive(Clone)]
pub struct Salt<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> Zeroize for Salt<N> {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

// Mark Salt types as sealed
impl<const N: usize> Sealed for Salt<N> {}

impl<const N: usize> Salt<N> {
    /// Create a new salt from an existing array
    pub fn new(data: [u8; N]) -> Self {
        Self { data }
    }

    /// Create from a slice, if it has the correct length
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        validate::length("Salt::from_slice", slice.len(), N)?;

        let mut data = [0u8; N];
        data.copy_from_slice(slice);

        Ok(Self { data })
    }

    /// Create a zeroed salt (not recommended for cryptographic use)
    pub fn zeroed() -> Self {
        Self { data: [0u8; N] }
    }

    /// Generate a random salt
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut data = [0u8; N];
        rng.try_fill_bytes(&mut data)?;
        Ok(Self { data })
    }

    /// Generate a random salt with a specific size
    pub fn random_with_size<R: RngCore + CryptoRng>(rng: &mut R, size: usize) -> Result<Self> {
        validate::length("Salt::random_with_size", size, N)?;
        Self::random(rng)
    }

    /// Get the size of this salt in bytes
    pub fn size() -> usize {
        N
    }

    /// Get the length of the salt
    pub fn len(&self) -> usize {
        N
    }

    /// Check if the salt is empty
    pub fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> AsRef<[u8]> for Salt<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> AsMut<[u8]> for Salt<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> Deref for Salt<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for Salt<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<const N: usize> PartialEq for Salt<N> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<const N: usize> Eq for Salt<N> {}

impl<const N: usize> fmt::Debug for Salt<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Salt<{}>", N)
    }
}

impl<const N: usize> ConstantTimeEq for Salt<N> {
    fn ct_eq(&self, other: &Self) -> bool {
        dcrypt_internal::constant_time::ct_eq(self.data, other.data)
    }
}

impl<const N: usize> RandomGeneration for Salt<N> {
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        Self::random(rng)
    }
}

impl<const N: usize> SecureZeroingType for Salt<N> {
    fn zeroed() -> Self {
        Self::zeroed()
    }
}

impl<const N: usize> FixedSize for Salt<N> {
    fn size() -> usize {
        N
    }
}

impl<const N: usize> ByteSerializable for Salt<N> {
    type Bytes = Vec<u8>;

    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_slice(bytes)
    }
}

// Common sizes and algorithm compatibility

/// Recommended minimum salt size (16 bytes)
pub const RECOMMENDED_MIN_SIZE: usize = 16;

// Common salt size type aliases
/// An 8-byte (64-bit) salt, suitable for most cryptographic applications.
pub type Salt8 = Salt<8>;

/// A 16-byte (128-bit) salt, suitable for most cryptographic applications.
pub type Salt16 = Salt<16>;

/// A 32-byte (256-bit) salt, providing extra security margin for high-security applications.
pub type Salt32 = Salt<32>;

// Algorithm compatibility marker traits
/// PBKDF2 compatible salt sizes
pub trait Pbkdf2Compatible: Sealed {}

// Explicitly implement for recommended salt sizes instead of trying to use where clauses
impl Pbkdf2Compatible for Salt<16> {}
impl Pbkdf2Compatible for Salt<24> {}
impl Pbkdf2Compatible for Salt<32> {}
impl Pbkdf2Compatible for Salt<64> {}

/// Argon2 compatible salt sizes
pub trait Argon2Compatible: Sealed {}

// Explicitly implement for recommended salt sizes
impl Argon2Compatible for Salt<8> {}
impl Argon2Compatible for Salt<16> {}
impl Argon2Compatible for Salt<24> {}
impl Argon2Compatible for Salt<32> {}
impl Argon2Compatible for Salt<64> {}

/// HKDF compatible salt sizes
pub trait HkdfCompatible: Sealed {}

// Changed from blanket implementation to explicit implementations
// for better compile-time resolution of trait bounds

impl HkdfCompatible for Salt<16> {}
impl HkdfCompatible for Salt<24> {}
impl HkdfCompatible for Salt<32> {}
impl HkdfCompatible for Salt<64> {}
