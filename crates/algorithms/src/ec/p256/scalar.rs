//! P-256 scalar arithmetic operations

use crate::ec::p256::constants::P256_SCALAR_SIZE;
use crate::error::{validate, Error, Result};
use dcrypt_common::security::SecretBuffer;
use dcrypt_params::traditional::ecdsa::NIST_P256;
use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// P-256 scalar value for use in elliptic curve operations
///
/// Represents integers modulo the curve order n. Used for private keys
/// and scalar multiplication. Automatically zeroized on drop for security.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Debug)]
pub struct Scalar(SecretBuffer<P256_SCALAR_SIZE>);

impl Scalar {
    /// Create a scalar from raw bytes with modular reduction
    ///
    /// Ensures the scalar is in the valid range [1, n-1] where n is the curve order.
    /// Performs modular reduction if the input is >= n.
    /// Returns an error if the result would be zero (invalid for cryptographic use).
    pub fn new(mut data: [u8; P256_SCALAR_SIZE]) -> Result<Self> {
        Self::reduce_scalar_bytes(&mut data)?;
        Ok(Scalar(SecretBuffer::new(data)))
    }

    /// Internal constructor that allows zero values
    ///
    /// Used for intermediate arithmetic operations where zero is a valid result.
    /// Should NOT be used for secret keys, nonces, or final signature components.
    fn from_bytes_unchecked(bytes: [u8; P256_SCALAR_SIZE]) -> Self {
        Scalar(SecretBuffer::new(bytes))
    }

    /// Create a scalar from an existing SecretBuffer
    ///
    /// Performs the same validation and reduction as `new()` but starts
    /// from a SecretBuffer instead of a raw byte array.
    pub fn from_secret_buffer(buffer: SecretBuffer<P256_SCALAR_SIZE>) -> Result<Self> {
        let mut bytes = [0u8; P256_SCALAR_SIZE];
        bytes.copy_from_slice(buffer.as_ref());

        Self::reduce_scalar_bytes(&mut bytes)?;
        Ok(Scalar(SecretBuffer::new(bytes)))
    }

    /// Access the underlying SecretBuffer containing the scalar value
    pub fn as_secret_buffer(&self) -> &SecretBuffer<P256_SCALAR_SIZE> {
        &self.0
    }

    /// Serialize the scalar to a byte array
    ///
    /// Returns the scalar in big-endian byte representation.
    /// The output is suitable for storage or transmission.
    pub fn serialize(&self) -> [u8; P256_SCALAR_SIZE] {
        let mut result = [0u8; P256_SCALAR_SIZE];
        result.copy_from_slice(self.0.as_ref());
        result
    }

    /// Deserialize a scalar from bytes with validation
    ///
    /// Parses bytes as a big-endian scalar value and ensures it's
    /// in the valid range for P-256 operations.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        validate::length("P-256 Scalar", bytes.len(), P256_SCALAR_SIZE)?;

        let mut scalar_bytes = [0u8; P256_SCALAR_SIZE];
        scalar_bytes.copy_from_slice(bytes);

        Self::new(scalar_bytes)
    }

    /// Check if the scalar represents zero
    ///
    /// Constant-time check to determine if the scalar is the
    /// additive identity (which is invalid for most cryptographic operations).
    pub fn is_zero(&self) -> bool {
        self.0.as_ref().iter().all(|&b| b == 0)
    }

    /// Convert big-endian bytes to little-endian limbs
    /// Properly extracts 4-byte chunks from BE array and converts to LE limbs
    #[inline(always)]
    fn to_le_limbs(bytes_be: &[u8; 32]) -> [u32; 8] {
        let mut limbs = [0u32; 8];

        // limb-0 must hold the 4 least-significant bytes, limb-7 the 4 most-significant
        #[allow(clippy::needless_range_loop)] // Index used for offset calculation
        for i in 0..8 {
            let start = 28 - i * 4; // index of the MS-byte of this limb
            limbs[i] = u32::from_le_bytes([
                bytes_be[start + 3],
                bytes_be[start + 2],
                bytes_be[start + 1],
                bytes_be[start],
            ]);
        }
        limbs
    }

    /// Add two scalars modulo the curve order n
    pub fn add_mod_n(&self, other: &Self) -> Result<Self> {
        let self_limbs = Self::to_le_limbs(&self.serialize());
        let other_limbs = Self::to_le_limbs(&other.serialize());

        let mut r = [0u32; 8];
        let mut carry = 0u64;

        // Plain 256-bit add
        #[allow(clippy::needless_range_loop)] // Index used for multiple arrays
        for i in 0..8 {
            let tmp = self_limbs[i] as u64 + other_limbs[i] as u64 + carry;
            r[i] = tmp as u32;
            carry = tmp >> 32;
        }

        let unreduced = Self::from_bytes_unchecked(Self::limbs_to_be(&r));
        let mut reduced = r;
        let borrow = Self::sub_in_place(&mut reduced, &Self::N_LIMBS);
        let need_reduce = Choice::from((carry as u8) | ((borrow ^ 1) as u8));

        Ok(Self::conditional_select(
            &unreduced,
            &Self::from_bytes_unchecked(Self::limbs_to_be(&reduced)),
            need_reduce,
        ))
    }

    /// Subtract two scalars modulo the curve order n
    pub fn sub_mod_n(&self, other: &Self) -> Result<Self> {
        let self_limbs = Self::to_le_limbs(&self.serialize());
        let other_limbs = Self::to_le_limbs(&other.serialize());

        let mut r = [0u32; 8];
        let mut borrow = 0u64;

        #[allow(clippy::needless_range_loop)] // Index used for multiple arrays
        for i in 0..8 {
            let tmp = (self_limbs[i] as u64)
                .wrapping_sub(other_limbs[i] as u64)
                .wrapping_sub(borrow);
            r[i] = tmp as u32;
            borrow = (tmp >> 63) & 1;
        }

        let unreduced = Self::from_bytes_unchecked(Self::limbs_to_be(&r));
        let mut reduced = r;
        let mut carry = 0u64;
        #[allow(clippy::needless_range_loop)] // Index used for multiple arrays
        for i in 0..8 {
            let tmp = reduced[i] as u64 + Self::N_LIMBS[i] as u64 + carry;
            reduced[i] = tmp as u32;
            carry = tmp >> 32;
        }

        Ok(Self::conditional_select(
            &unreduced,
            &Self::from_bytes_unchecked(Self::limbs_to_be(&reduced)),
            Choice::from(borrow as u8),
        ))
    }

    /// Multiply two scalars modulo the curve order n
    ///
    /// Uses constant-time double-and-add algorithm for correctness and security.
    /// Processes bits from MSB to LSB to ensure correct powers of 2.
    pub fn mul_mod_n(&self, other: &Self) -> Result<Self> {
        // Start with zero (additive identity)
        let mut acc = Self::from_bytes_unchecked([0u8; P256_SCALAR_SIZE]);

        // Process each bit from MSB to LSB
        for byte in other.serialize() {
            for i in (0..8).rev() {
                // MSB first within each byte
                // Double the accumulator: acc = acc * 2 (mod n)
                acc = acc.add_mod_n(&acc)?;

                let acc_plus_self = acc.add_mod_n(self)?;
                let choice = Choice::from((byte >> i) & 1);
                acc = Self::conditional_select(&acc, &acc_plus_self, choice);
            }
        }

        Ok(acc)
    }

    /// Compute multiplicative inverse modulo n using Fermat's little theorem
    /// a^(-1) ≡ a^(n-2) (mod n).  Left-to-right binary exponentiation.
    pub fn inv_mod_n(&self) -> Result<Self> {
        // zero has no inverse
        if self.is_zero() {
            return Err(Error::param("P-256 Scalar", "Cannot invert zero scalar"));
        }

        // Step 1: form exponent = n-2
        let mut exp = NIST_P256.n; // big-endian [u8;32]
                                   // subtract 2 with borrow
        let mut borrow = 2u16;
        for i in (0..P256_SCALAR_SIZE).rev() {
            let v = exp[i] as i16 - (borrow as i16);
            if v < 0 {
                exp[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                exp[i] = v as u8;
                borrow = 0;
            }
        }

        // Step 2: binary exponentiation, left-to-right:
        //    result = 1
        //    for each bit of exp from MSB to LSB:
        //        result = result^2 mod n
        //        if bit == 1 { result = result * a mod n }
        let mut result = {
            let mut one = [0u8; P256_SCALAR_SIZE];
            one[P256_SCALAR_SIZE - 1] = 1;
            // from_bytes_unchecked is fine here because 1 < n
            Self::from_bytes_unchecked(one)
        };
        let base = self.clone();

        for byte in exp {
            for bit in (0..8).rev() {
                // square
                result = result.mul_mod_n(&result)?;
                // multiply if this exp-bit is 1
                if (byte >> bit) & 1 == 1 {
                    result = result.mul_mod_n(&base)?;
                }
            }
        }

        Ok(result)
    }

    /// Compute the additive inverse (negation) modulo n
    ///
    /// Returns -self mod n, which is equivalent to n - self when self != 0
    /// Returns 0 when self is 0
    pub fn negate(&self) -> Self {
        // If self is zero, return zero
        if self.is_zero() {
            return Self::from_bytes_unchecked([0u8; P256_SCALAR_SIZE]);
        }

        // Otherwise compute n - self
        let n_limbs = Self::N_LIMBS;
        let self_limbs = Self::to_le_limbs(&self.serialize());
        let mut res = [0u32; 8];

        // Subtract self from n
        let mut borrow = 0i64;
        #[allow(clippy::needless_range_loop)] // Index used for multiple arrays
        for i in 0..8 {
            let tmp = n_limbs[i] as i64 - self_limbs[i] as i64 - borrow;
            if tmp < 0 {
                res[i] = (tmp + (1i64 << 32)) as u32;
                borrow = 1;
            } else {
                res[i] = tmp as u32;
                borrow = 0;
            }
        }

        // No borrow should occur since self < n
        debug_assert_eq!(borrow, 0);

        Self::from_bytes_unchecked(Self::limbs_to_be(&res))
    }

    // Private helper methods

    /// Reduce scalar modulo the curve order n using constant-time arithmetic
    ///
    /// The curve order n for P-256 is:
    /// n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    ///
    /// Algorithm:
    /// 1. Check if input is zero (invalid)
    /// 2. Compare with curve order using constant-time comparison
    /// 3. Conditionally subtract n if input >= n
    /// 4. Verify result is still non-zero
    fn reduce_scalar_bytes(bytes: &mut [u8; P256_SCALAR_SIZE]) -> Result<()> {
        let order = &NIST_P256.n;

        // Reject zero scalars immediately
        if bytes.iter().all(|&b| b == 0) {
            return Err(Error::param("P-256 Scalar", "Scalar cannot be zero"));
        }

        // Constant-time comparison with curve order
        // We want to check: is bytes >= order?
        let mut gt = 0u8; // set if bytes > order
        let mut lt = 0u8; // set if bytes < order

        for i in 0..P256_SCALAR_SIZE {
            let x = bytes[i];
            let y = order[i];
            gt |= ((x > y) as u8) & (!lt);
            lt |= ((x < y) as u8) & (!gt);
        }
        let ge = gt | ((!lt) & 1); // ge = gt || eq (if not less, then greater or equal)

        if ge == 1 {
            // If scalar >= order, perform modular reduction
            let mut borrow = 0u16;
            let mut temp_bytes = *bytes;

            for i in (0..P256_SCALAR_SIZE).rev() {
                let diff = (temp_bytes[i] as i16) - (order[i] as i16) - (borrow as i16);
                if diff < 0 {
                    temp_bytes[i] = (diff + 256) as u8;
                    borrow = 1;
                } else {
                    temp_bytes[i] = diff as u8;
                    borrow = 0;
                }
            }

            *bytes = temp_bytes;
        }

        // Check for zero after reduction
        if bytes.iter().all(|&b| b == 0) {
            return Err(Error::param(
                "P-256 Scalar",
                "Reduction resulted in zero scalar",
            ));
        }

        Ok(())
    }

    // Helper constants - stored in little-endian limb order
    const N_LIMBS: [u32; 8] = [
        0xFC63_2551,
        0xF3B9_CAC2,
        0xA717_9E84,
        0xBCE6_FAAD,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0x0000_0000,
        0xFFFF_FFFF,
    ];

    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let a_bytes = a.serialize();
        let b_bytes = b.serialize();
        let mut out = [0u8; P256_SCALAR_SIZE];
        for i in 0..P256_SCALAR_SIZE {
            out[i] = u8::conditional_select(&a_bytes[i], &b_bytes[i], choice);
        }
        Self::from_bytes_unchecked(out)
    }

    /// Compare two limb arrays for greater-than-or-equal
    #[inline(always)]
    fn geq(a: &[u32; 8], b: &[u32; 8]) -> bool {
        for i in (0..8).rev() {
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
        }
        true // equal
    }

    /// Subtract b from a in-place
    #[inline(always)]
    fn sub_in_place(a: &mut [u32; 8], b: &[u32; 8]) -> u64 {
        let mut borrow = 0u64;
        #[allow(clippy::needless_range_loop)] // Index used for multiple arrays
        for i in 0..8 {
            let tmp = (a[i] as u64).wrapping_sub(b[i] as u64).wrapping_sub(borrow);
            a[i] = tmp as u32;
            borrow = (tmp >> 63) & 1; // 1 if we wrapped
        }
        borrow
    }

    /// Convert little-endian limbs to big-endian bytes
    /// The inverse of to_le_limbs
    #[inline(always)]
    fn limbs_to_be(limbs: &[u32; 8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, &w) in limbs.iter().enumerate() {
            let be = w.to_le_bytes(); // limb itself is little-endian
            let start = 28 - i * 4;
            out[start] = be[3];
            out[start + 1] = be[2];
            out[start + 2] = be[1];
            out[start + 3] = be[0];
        }
        out
    }
}
