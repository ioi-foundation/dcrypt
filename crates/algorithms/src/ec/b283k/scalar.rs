//! sect283k1 scalar arithmetic operations

use crate::ec::b283k::constants::B283K_SCALAR_SIZE;
use crate::error::{Error, Result};
use dcrypt_common::security::SecretBuffer;
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop};

/// sect283k1 scalar value for use in elliptic curve operations
#[derive(Clone, Debug)]
pub struct Scalar(SecretBuffer<B283K_SCALAR_SIZE>);

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
    /// The most significant bit is masked to ensure the scalar is < 2^283.
    /// Returns an error if the resulting scalar would be zero.
    pub fn new(mut data: [u8; B283K_SCALAR_SIZE]) -> Result<Self> {
        Self::reduce_scalar_bytes(&mut data)?;
        Ok(Scalar(SecretBuffer::new(data)))
    }

    /// Create a scalar from a `SecretBuffer`.
    ///
    /// The buffer contents will be reduced modulo the curve order if necessary.
    /// Returns an error if the resulting scalar would be zero.
    pub fn from_secret_buffer(buffer: SecretBuffer<B283K_SCALAR_SIZE>) -> Result<Self> {
        let mut bytes = [0u8; B283K_SCALAR_SIZE];
        bytes.copy_from_slice(buffer.as_ref());
        Self::reduce_scalar_bytes(&mut bytes)?;
        Ok(Scalar(SecretBuffer::new(bytes)))
    }

    /// Get a reference to the underlying `SecretBuffer`.
    pub fn as_secret_buffer(&self) -> &SecretBuffer<B283K_SCALAR_SIZE> {
        &self.0
    }

    /// Serialize this scalar to bytes.
    pub fn serialize(&self) -> [u8; B283K_SCALAR_SIZE] {
        let mut result = [0u8; B283K_SCALAR_SIZE];
        result.copy_from_slice(self.0.as_ref());
        result
    }

    /// Check if this scalar is zero.
    pub fn is_zero(&self) -> bool {
        self.0.as_ref().iter().all(|&b| b == 0)
    }

    fn reduce_scalar_bytes(bytes: &mut [u8; B283K_SCALAR_SIZE]) -> Result<()> {
        bytes[0] &= 0x01; // Ensure the scalar is < 2^283
        if bytes.iter().all(|&b| b == 0) {
            return Err(Error::param("B283k Scalar", "Scalar cannot be zero"));
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
            if i == B283K_SCALAR_SIZE - 1 {
                is_ge = true;
            }
        }

        if is_ge {
            let mut borrow = 0i16;
            for i in (0..B283K_SCALAR_SIZE).rev() {
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

        if bytes.iter().all(|&b| b == 0) {
            return Err(Error::param(
                "B283k Scalar",
                "Reduction resulted in zero scalar",
            ));
        }
        Ok(())
    }

    const ORDER: [u8; 36] = [
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x96, 0xE4, 0x04, 0x28,
        0x2D, 0xD3, 0x23, 0x22, 0x83, 0xE5,
    ];
}
