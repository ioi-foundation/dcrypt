//! Type-safe authentication tag implementation with size guarantees
//!
//! Provides the `Tag` type, representing a cryptographic authentication tag
//! with compile-time size guarantees.

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

/// A cryptographic authentication tag with fixed size
#[derive(Clone)]
pub struct Tag<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> Zeroize for Tag<N> {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

// Mark Tag types as sealed
impl<const N: usize> Sealed for Tag<N> {}

impl<const N: usize> Tag<N> {
    /// Create a new tag from an existing array
    pub fn new(data: [u8; N]) -> Self {
        Self { data }
    }

    /// Create from a slice, if it has the correct length
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        validate::length("Tag::from_slice", slice.len(), N)?;

        let mut data = [0u8; N];
        data.copy_from_slice(slice);

        Ok(Self { data })
    }

    /// Create a zeroed tag
    pub fn zeroed() -> Self {
        Self { data: [0u8; N] }
    }

    /// Get the length of the tag in bytes
    pub fn len(&self) -> usize {
        N
    }

    /// Check if the tag is empty
    pub fn is_empty(&self) -> bool {
        N == 0
    }

    /// Get the size of this tag in bytes
    pub fn size() -> usize {
        N
    }

    /// Convert to a hexadecimal string
    pub fn to_hex(&self) -> String {
        let mut result = String::with_capacity(N * 2);
        for &byte in &self.data {
            result.push_str(&format!("{:02x}", byte));
        }
        result
    }
}

impl<const N: usize> AsRef<[u8]> for Tag<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> AsMut<[u8]> for Tag<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> Deref for Tag<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for Tag<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<const N: usize> PartialEq for Tag<N> {
    fn eq(&self, other: &Self) -> bool {
        // Note: We deliberately use a non-constant time equality here
        // because Tag equality is expected to leak timing information
        // for performance. For security-sensitive tag verification,
        // use the ct_eq method instead.
        self.data == other.data
    }
}

impl<const N: usize> Eq for Tag<N> {}

impl<const N: usize> fmt::Debug for Tag<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag<{}>({})", N, self.to_hex())
    }
}

impl<const N: usize> fmt::Display for Tag<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl<const N: usize> ConstantTimeEq for Tag<N> {
    fn ct_eq(&self, other: &Self) -> bool {
        dcrypt_internal::constant_time::ct_eq(self.data, other.data)
    }
}

impl<const N: usize> RandomGeneration for Tag<N> {
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut data = [0u8; N];
        rng.try_fill_bytes(&mut data)?;
        Ok(Self { data })
    }
}

impl<const N: usize> SecureZeroingType for Tag<N> {
    fn zeroed() -> Self {
        Self::zeroed()
    }
}

impl<const N: usize> FixedSize for Tag<N> {
    fn size() -> usize {
        N
    }
}

impl<const N: usize> ByteSerializable for Tag<N> {
    type Bytes = Vec<u8>;

    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_slice(bytes)
    }
}

// Algorithm compatibility marker traits
/// Poly1305 compatible tag sizes
pub trait Poly1305Compatible: Sealed {}
impl Poly1305Compatible for Tag<16> {}

/// HMAC compatible tag sizes (dependent on hash function)
pub trait HmacCompatible: Sealed {}
impl HmacCompatible for Tag<32> {} // HMAC-SHA256
impl HmacCompatible for Tag<64> {} // HMAC-SHA512

/// GCM compatible tag sizes
pub trait GcmCompatible: Sealed {}
impl GcmCompatible for Tag<16> {}

/// ChaCha20Poly1305 compatible tag sizes
pub trait ChaCha20Poly1305Compatible: Sealed {}
impl ChaCha20Poly1305Compatible for Tag<16> {}
