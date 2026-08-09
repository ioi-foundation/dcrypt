// File: crates/api/src/traits/serialize.rs

//! Traits for byte serialization of cryptographic types.

use crate::Result;
use zeroize::Zeroizing;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

/// A trait for public types that can be serialized to and from bytes.
pub trait Serialize: Sized {
    /// Creates an object from a byte slice.
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
    /// Converts the object to a byte vector.
    fn to_bytes(&self) -> Vec<u8>;
}

/// A trait for secret types that can be securely serialized.
pub trait SerializeSecret: Sized {
    /// Creates an object from a byte slice. Input should be zeroized after use.
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
    /// Converts the object to a byte vector that is zeroized on drop.
    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>>;
}
