//! secp256k1 scalar arithmetic operations

use crate::ec::k256::constants::K256_SCALAR_SIZE;
use crate::error::{validate, Error, Result};
use dcrypt_common::security::SecretBuffer;
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop};

/// secp256k1 scalar value for use in elliptic curve operations
#[derive(Clone, Debug)]
pub struct Scalar(SecretBuffer<K256_SCALAR_SIZE>);

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Scalar {}

impl Scalar {
    /// Create a new scalar from raw bytes.
    ///
    /// The value must use the canonical big-endian encoding in `1..n`.
    /// Out-of-range inputs are rejected rather than reduced.
    pub fn new(data: [u8; K256_SCALAR_SIZE]) -> Result<Self> {
        Self::validate_canonical_nonzero(&data)?;
        Ok(Scalar(SecretBuffer::new(data)))
    }

    /// Create a scalar from a `SecretBuffer`.
    ///
    /// The buffer contents must be a canonical non-zero scalar.
    pub fn from_secret_buffer(buffer: SecretBuffer<K256_SCALAR_SIZE>) -> Result<Self> {
        let mut bytes = [0u8; K256_SCALAR_SIZE];
        bytes.copy_from_slice(buffer.as_ref());
        Self::new(bytes)
    }

    /// Get a reference to the underlying `SecretBuffer`.
    pub fn as_secret_buffer(&self) -> &SecretBuffer<K256_SCALAR_SIZE> {
        &self.0
    }

    /// Serialize this scalar to bytes.
    pub fn serialize(&self) -> [u8; K256_SCALAR_SIZE] {
        let mut result = [0u8; K256_SCALAR_SIZE];
        result.copy_from_slice(self.0.as_ref());
        result
    }

    /// Deserialize a canonical non-zero scalar.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        validate::length("K256 Scalar", bytes.len(), K256_SCALAR_SIZE)?;
        let mut scalar = [0u8; K256_SCALAR_SIZE];
        scalar.copy_from_slice(bytes);
        Self::new(scalar)
    }

    /// Check if this scalar is zero.
    pub fn is_zero(&self) -> bool {
        let mut any = 0u8;
        for &byte in self.0.as_ref() {
            any |= byte;
        }
        any == 0
    }

    fn validate_canonical_nonzero(bytes: &[u8; K256_SCALAR_SIZE]) -> Result<()> {
        let mut any = 0u8;
        for &byte in bytes {
            any |= byte;
        }
        if any == 0 {
            return Err(Error::param("K256 Scalar", "Scalar cannot be zero"));
        }

        let mut borrow = 0u8;
        for i in (0..K256_SCALAR_SIZE).rev() {
            let (difference, borrow_order) = bytes[i].overflowing_sub(Self::ORDER[i]);
            let (_, borrow_previous) = difference.overflowing_sub(borrow);
            borrow = (borrow_order | borrow_previous) as u8;
        }
        if borrow == 1 {
            Ok(())
        } else {
            Err(Error::param(
                "K256 Scalar",
                "Scalar must be less than the group order",
            ))
        }
    }

    const ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
}
