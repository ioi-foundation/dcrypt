//! Type-safe digest implementation with size guarantees
//!
//! Provides the `Digest` type, representing the output of a
//! cryptographic hash function with compile-time size guarantees.

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;

use core::fmt;
use core::ops::{Deref, DerefMut};
use dcrypt_internal::zeroing::Zeroize;
use hex;

use crate::error::{Error, Result};
use crate::types::{ByteSerializable, ConstantTimeEq, FixedSize, SecureZeroingType};

/// A cryptographic digest with a fixed size
#[derive(Clone)]
pub struct Digest<const N: usize> {
    data: [u8; N],
    len: usize, // Actual length of valid data (for variable-length algorithms)
}

impl<const N: usize> Zeroize for Digest<N> {
    fn zeroize(&mut self) {
        self.data.zeroize();
        self.len.zeroize();
    }
}

impl<const N: usize> Digest<N> {
    /// Create a new digest from an existing array
    pub fn new(data: [u8; N]) -> Self {
        Self { data, len: N }
    }

    /// Create a new digest with a specified logical length
    /// This is particularly useful for hash functions with variable output size
    pub fn with_len(data: [u8; N], len: usize) -> Self {
        if len > N {
            panic!("Logical length {} cannot exceed buffer size {}", len, N);
        }
        Self { data, len }
    }

    /// Create from a slice, if it has the correct length
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        // Using custom check since we allow slices smaller than N
        if slice.len() > N {
            return Err(Error::Length {
                context: "Digest::from_slice",
                expected: N,
                actual: slice.len(),
            });
        }

        let mut data = [0u8; N];
        data[..slice.len()].copy_from_slice(slice);

        Ok(Self {
            data,
            len: slice.len(),
        })
    }

    /// Get the length of the digest
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if the digest is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Convert to a hexadecimal string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.data[..self.len])
    }

    /// Create from a hexadecimal string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| Error::param("hex_str", "Invalid hexadecimal string"))?;

        Self::from_slice(&bytes)
    }
}

impl<const N: usize> AsRef<[u8]> for Digest<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl<const N: usize> AsMut<[u8]> for Digest<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

impl<const N: usize> Deref for Digest<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data[..self.len]
    }
}

impl<const N: usize> DerefMut for Digest<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data[..self.len]
    }
}

impl<const N: usize> PartialEq for Digest<N> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.data[..self.len] == other.data[..other.len]
    }
}

impl<const N: usize> Eq for Digest<N> {}

impl<const N: usize> fmt::Debug for Digest<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest<{}>({}) [len={}]", N, self.to_hex(), self.len)
    }
}

impl<const N: usize> fmt::Display for Digest<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl<const N: usize> ConstantTimeEq for Digest<N> {
    fn ct_eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        dcrypt_internal::constant_time::ct_eq(&self.data[..self.len], &other.data[..other.len])
    }
}

impl<const N: usize> SecureZeroingType for Digest<N> {
    fn zeroed() -> Self {
        Self {
            data: [0u8; N],
            len: N,
        }
    }
}

impl<const N: usize> FixedSize for Digest<N> {
    fn size() -> usize {
        N
    }
}

impl<const N: usize> ByteSerializable for Digest<N> {
    fn to_bytes(&self) -> Vec<u8> {
        self.data[..self.len].to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_slice(bytes)
    }
}

// Algorithm compatibility marker traits
/// SHA-256 compatible digest size
pub trait Sha256Compatible {}
impl Sha256Compatible for Digest<32> {}

/// SHA-512 compatible digest size
pub trait Sha512Compatible {}
impl Sha512Compatible for Digest<64> {}

/// BLAKE2b compatible digest sizes
pub trait Blake2bCompatible {}
impl Blake2bCompatible for Digest<32> {}
impl Blake2bCompatible for Digest<64> {}

/// Keccak-256 compatible digest size
pub trait Keccak256Compatible {}
impl Keccak256Compatible for Digest<32> {}
