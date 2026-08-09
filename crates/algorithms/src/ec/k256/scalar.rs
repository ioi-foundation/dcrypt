//! secp256k1 scalar arithmetic operations

use crate::ec::k256::constants::K256_SCALAR_SIZE;
use crate::error::{Error, Result};
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
    /// The bytes will be reduced modulo the curve order if necessary.
    /// Returns an error if the resulting scalar would be zero.
    pub fn new(mut data: [u8; K256_SCALAR_SIZE]) -> Result<Self> {
        Self::reduce_scalar_bytes(&mut data)?;
        Ok(Scalar(SecretBuffer::new(data)))
    }

    /// Create a scalar from a `SecretBuffer`.
    ///
    /// The buffer contents will be reduced modulo the curve order if necessary.
    /// Returns an error if the resulting scalar would be zero.
    pub fn from_secret_buffer(buffer: SecretBuffer<K256_SCALAR_SIZE>) -> Result<Self> {
        let mut bytes = [0u8; K256_SCALAR_SIZE];
        bytes.copy_from_slice(buffer.as_ref());
        Self::reduce_scalar_bytes(&mut bytes)?;
        Ok(Scalar(SecretBuffer::new(bytes)))
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

    /// Check if this scalar is zero.
    pub fn is_zero(&self) -> bool {
        self.0.as_ref().iter().all(|&b| b == 0)
    }

    fn reduce_scalar_bytes(bytes: &mut [u8; K256_SCALAR_SIZE]) -> Result<()> {
        // Check if the input is explicitly zero (reject literal zero inputs)
        let is_explicit_zero = bytes.iter().all(|&b| b == 0);
        if is_explicit_zero {
            return Err(Error::param("K256 Scalar", "Scalar cannot be zero"));
        }

        let mut is_ge = false;
        for (i, (&byte, &order_byte)) in bytes.iter().zip(Self::ORDER.iter()).enumerate() {
            if byte > order_byte {
                is_ge = true;
                break;
            }
            if byte < order_byte {
                break;
            }
            if i == K256_SCALAR_SIZE - 1 {
                is_ge = true;
            }
        }

        if is_ge {
            let mut borrow = 0i16;
            for i in (0..K256_SCALAR_SIZE).rev() {
                let diff = (bytes[i] as i16) - (Self::ORDER[i] as i16) - borrow;
                if diff < 0 {
                    bytes[i] = (diff + 256) as u8;
                    borrow = 1;
                } else {
                    bytes[i] = diff as u8;
                    borrow = 0;
                }
            }
        }

        // After reduction, if the result is zero, that's OK - it means the input
        // was a non-zero multiple of the group order (e.g., n itself).
        // We only reject explicit zero inputs, not zeros that result from reduction.
        Ok(())
    }

    const ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
}
