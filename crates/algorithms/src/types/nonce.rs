//! Type-safe nonce implementation with generic size parameter
//!
//! This module provides a generic nonce type with compile-time size guarantees
//! for various cryptographic algorithms, ensuring proper type safety and validation.

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;

use core::fmt;
use core::ops::{Deref, DerefMut};
use dcrypt_internal::constant_time::ConstantTimeEq;
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::Zeroize;

use crate::error::{validate, Result};
use crate::types::sealed::Sealed;
use crate::types::{
    ByteSerializable, ConstantTimeEq as LocalConstantEq, FixedSize, RandomGeneration,
    SecureZeroingType,
};

/// Generic nonce type with compile-time size guarantee
#[derive(Clone)]
pub struct Nonce<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> Zeroize for Nonce<N> {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

// Mark Nonce types as sealed
impl<const N: usize> Sealed for Nonce<N> {}

impl<const N: usize> Nonce<N> {
    /// Create a new nonce from an existing array
    pub fn new(data: [u8; N]) -> Self {
        Self { data }
    }

    /// Create a zeroed nonce
    pub fn zeroed() -> Self {
        Self { data: [0u8; N] }
    }

    /// Create from a slice, if it has the correct length
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        // Use the validation helper instead of direct error creation
        validate::length("Nonce", slice.len(), N)?;

        let mut data = [0u8; N];
        data.copy_from_slice(slice);

        Ok(Self { data })
    }

    /// Generate a random nonce
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut data = [0u8; N];
        rng.try_fill_bytes(&mut data)?;
        Ok(Self { data })
    }

    /// Get the size of this nonce in bytes
    pub fn size() -> usize {
        N
    }
}

impl<const N: usize> AsRef<[u8]> for Nonce<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> AsMut<[u8]> for Nonce<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> Deref for Nonce<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for Nonce<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<const N: usize> PartialEq for Nonce<N> {
    fn eq(&self, other: &Self) -> bool {
        self.data.ct_eq(&other.data).into()
    }
}

impl<const N: usize> Eq for Nonce<N> {}

impl<const N: usize> fmt::Debug for Nonce<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce<{}>({:?})", N, &self.data[..])
    }
}

impl<const N: usize> LocalConstantEq for Nonce<N> {
    fn ct_eq(&self, other: &Self) -> bool {
        self.data.ct_eq(&other.data).into()
    }
}

impl<const N: usize> RandomGeneration for Nonce<N> {
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> crate::error::Result<Self> {
        Self::random(rng)
    }
}

impl<const N: usize> SecureZeroingType for Nonce<N> {
    fn zeroed() -> Self {
        Self::zeroed()
    }
}

impl<const N: usize> FixedSize for Nonce<N> {
    fn size() -> usize {
        N
    }
}

impl<const N: usize> ByteSerializable for Nonce<N> {
    type Bytes = Vec<u8>;

    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> crate::error::Result<Self> {
        Self::from_slice(bytes)
    }
}

// Algorithm compatibility marker traits
/// ChaCha20 compatible nonce sizes
pub trait ChaCha20Compatible: Sealed {}
impl ChaCha20Compatible for Nonce<12> {}

/// XChaCha20 compatible nonce sizes
pub trait XChaCha20Compatible: Sealed {}
impl XChaCha20Compatible for Nonce<24> {}

/// AES-GCM compatible nonce sizes
pub trait AesGcmCompatible: Sealed {}
impl AesGcmCompatible for Nonce<12> {}
impl AesGcmCompatible for Nonce<15> {} // Added support for 120-bit nonces (ACVP test vectors)
impl AesGcmCompatible for Nonce<16> {}

/// AES-CTR compatible nonce sizes
pub trait AesCtrCompatible: Sealed {}
// Update to allow all nonce sizes with CTR mode
impl<const N: usize> AesCtrCompatible for Nonce<N> {}
