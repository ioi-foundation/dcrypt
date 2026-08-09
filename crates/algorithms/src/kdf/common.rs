//! Common utilities for key derivation functions

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

use dcrypt_internal::constant_time::ConstantTimeEq;
use dcrypt_internal::random::{CryptoRng, Error as RandomError};
use dcrypt_internal::zeroing::Zeroizing;

/// Security level for KDFs in bits
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// 128-bit security level
    L128,
    /// 192-bit security level
    L192,
    /// 256-bit security level
    L256,
    /// Custom security level (in bits)
    Custom(u32),
}

impl SecurityLevel {
    /// Get the security level in bits
    pub fn bits(&self) -> u32 {
        match self {
            SecurityLevel::L128 => 128,
            SecurityLevel::L192 => 192,
            SecurityLevel::L256 => 256,
            SecurityLevel::Custom(bits) => *bits,
        }
    }

    /// Get the recommended output size in bytes for this security level
    pub fn recommended_output_size(&self) -> usize {
        // For KDFs, output size is typically twice the security level
        // to account for birthday attacks
        (self.bits() / 4) as usize
    }

    /// Check if this security level meets a minimum requirement
    pub fn meets_minimum(&self, minimum: SecurityLevel) -> bool {
        self.bits() >= minimum.bits()
    }
}

/// Compare two slices in constant time
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Generate a salt using a caller-owned cryptographic randomness source.
///
/// Randomness failures are returned to the caller; this function never falls
/// back to operating-system entropy or deterministic bytes.
#[cfg(feature = "alloc")]
pub fn generate_salt<R: CryptoRng + ?Sized>(
    rng: &mut R,
    len: usize,
) -> core::result::Result<Zeroizing<Vec<u8>>, RandomError> {
    let mut salt = vec![0u8; len];
    rng.try_fill_bytes(&mut salt)?;
    Ok(Zeroizing::new(salt))
}
