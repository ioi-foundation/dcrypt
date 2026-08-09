//! P-224 scalar arithmetic operations

use crate::ec::p224::constants::P224_SCALAR_SIZE;
use crate::error::{validate, Error, Result};
use dcrypt_common::security::SecretBuffer;
use dcrypt_internal::constant_time::{Choice, ConditionallySelectable};
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop};
use dcrypt_params::traditional::ecdsa::NIST_P224;

/// P-224 scalar value for use in elliptic curve operations
///
/// Represents integers modulo the curve order n. Used for private keys
/// and scalar multiplication. Automatically zeroized on drop for security.
#[derive(Clone, Debug)]
pub struct Scalar(SecretBuffer<P224_SCALAR_SIZE>);

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
    /// Create a canonical non-zero scalar from raw bytes.
    ///
    /// Private keys, nonces, and serialized signature components must be in
    /// `1..n`. Non-canonical inputs are rejected rather than reduced.
    pub fn new(data: [u8; P224_SCALAR_SIZE]) -> Result<Self> {
        Self::validate_canonical_nonzero(&data)?;
        Ok(Scalar(SecretBuffer::new(data)))
    }

    /// Interpret a 224-bit integer modulo the group order, including zero.
    ///
    /// This constructor is intended for standards-defined mathematical
    /// intermediates such as ECDSA hash and x-coordinate reduction. Use
    /// [`Self::new`] for private scalars, nonces, and serialized signature
    /// components, where zero is invalid.
    pub fn from_bytes_reduced(mut data: [u8; P224_SCALAR_SIZE]) -> Self {
        Self::reduce_scalar_bytes_allow_zero(&mut data);
        Self::from_bytes_unchecked(data)
    }

    /// Internal constructor that allows zero values
    ///
    /// Used for intermediate arithmetic operations where zero is a valid result.
    /// Should NOT be used for secret keys, nonces, or final signature components.
    fn from_bytes_unchecked(bytes: [u8; P224_SCALAR_SIZE]) -> Self {
        Scalar(SecretBuffer::new(bytes))
    }

    /// Create a scalar from an existing SecretBuffer
    ///
    /// Performs the same canonical validation as `new()` but starts
    /// from a SecretBuffer instead of a raw byte array.
    pub fn from_secret_buffer(buffer: SecretBuffer<P224_SCALAR_SIZE>) -> Result<Self> {
        let mut bytes = [0u8; P224_SCALAR_SIZE];
        bytes.copy_from_slice(buffer.as_ref());

        Self::new(bytes)
    }

    /// Access the underlying SecretBuffer containing the scalar value
    pub fn as_secret_buffer(&self) -> &SecretBuffer<P224_SCALAR_SIZE> {
        &self.0
    }

    /// Serialize the scalar to a byte array
    ///
    /// Returns the scalar in big-endian byte representation.
    /// The output is suitable for storage or transmission.
    pub fn serialize(&self) -> [u8; P224_SCALAR_SIZE] {
        let mut result = [0u8; P224_SCALAR_SIZE];
        result.copy_from_slice(self.0.as_ref());
        result
    }

    /// Deserialize a scalar from bytes with validation
    ///
    /// Parses bytes as a big-endian scalar value and ensures it's
    /// in the valid range for P-224 operations.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        validate::length("P-224 Scalar", bytes.len(), P224_SCALAR_SIZE)?;

        let mut scalar_bytes = [0u8; P224_SCALAR_SIZE];
        scalar_bytes.copy_from_slice(bytes);

        Self::new(scalar_bytes)
    }

    /// Check if the scalar represents zero
    ///
    /// Constant-time check to determine if the scalar is the
    /// additive identity (which is invalid for most cryptographic operations).
    pub fn is_zero(&self) -> bool {
        let mut any = 0u8;
        for &byte in self.0.as_ref() {
            any |= byte;
        }
        any == 0
    }

    /// Convert big-endian bytes to little-endian limbs
    /// Input bytes are already big-endian from parameter tables
    #[inline(always)]
    fn to_le_limbs(bytes_be: &[u8; 28]) -> [u32; 7] {
        let mut limbs = [0u32; 7];

        // Read big-endian bytes directly into little-endian limbs
        // bytes[0..4] is most significant, goes to limbs[6]
        // bytes[24..28] is least significant, goes to limbs[0]
        for i in 0..7 {
            let offset = i * 4;
            limbs[6 - i] = u32::from_be_bytes([
                bytes_be[offset],
                bytes_be[offset + 1],
                bytes_be[offset + 2],
                bytes_be[offset + 3],
            ]);
        }
        limbs
    }

    /// Convert little-endian limbs to big-endian bytes
    /// The inverse of to_le_limbs
    #[inline(always)]
    fn limbs_to_be(limbs: &[u32; 7]) -> [u8; 28] {
        let mut out = [0u8; 28];

        // Write little-endian limbs to big-endian bytes
        // limbs[6] is most significant, goes to bytes[0..4]
        // limbs[0] is least significant, goes to bytes[24..28]
        for i in 0..7 {
            let bytes = limbs[6 - i].to_be_bytes();
            let offset = i * 4;
            out[offset..offset + 4].copy_from_slice(&bytes);
        }
        out
    }

    /// Add two scalars modulo the curve order n
    pub fn add_mod_n(&self, other: &Self) -> Result<Self> {
        let self_limbs = Self::to_le_limbs(&self.serialize());
        let other_limbs = Self::to_le_limbs(&other.serialize());

        let mut r = [0u32; 7];
        let mut carry = 0u64;

        // Plain 224-bit add
        for (i, result) in r.iter_mut().enumerate() {
            let tmp = self_limbs[i] as u64 + other_limbs[i] as u64 + carry;
            *result = tmp as u32;
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

        let mut r = [0u32; 7];
        let mut borrow = 0u64;

        for (i, result) in r.iter_mut().enumerate() {
            let tmp = (self_limbs[i] as u64)
                .wrapping_sub(other_limbs[i] as u64)
                .wrapping_sub(borrow);
            *result = tmp as u32;
            borrow = (tmp >> 63) & 1;
        }

        let unreduced = Self::from_bytes_unchecked(Self::limbs_to_be(&r));
        let mut reduced = r;
        let mut carry = 0u64;
        for (i, result) in reduced.iter_mut().enumerate() {
            let tmp = *result as u64 + Self::N_LIMBS[i] as u64 + carry;
            *result = tmp as u32;
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
        let mut acc = Self::from_bytes_unchecked([0u8; P224_SCALAR_SIZE]);

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
            return Err(Error::param("P-224 Scalar", "Cannot invert zero scalar"));
        }

        // Step 1: form exponent = n-2
        let mut exp = NIST_P224.n; // big-endian [u8;28]
                                   // subtract 2 with borrow
        let mut borrow = 2u16;
        for i in (0..P224_SCALAR_SIZE).rev() {
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
            let mut one = [0u8; P224_SCALAR_SIZE];
            one[P224_SCALAR_SIZE - 1] = 1;
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
        // Compute n - self, then select zero for the zero input.
        let n_limbs = Self::N_LIMBS;
        let self_limbs = Self::to_le_limbs(&self.serialize());
        let mut res = [0u32; 7];

        // Subtract self from n
        let mut borrow = 0u64;
        for (i, result) in res.iter_mut().enumerate() {
            let tmp = (n_limbs[i] as u64)
                .wrapping_sub(self_limbs[i] as u64)
                .wrapping_sub(borrow);
            *result = tmp as u32;
            borrow = (tmp >> 63) & 1;
        }
        let negated = Self::from_bytes_unchecked(Self::limbs_to_be(&res));
        Self::conditional_select(
            &negated,
            &Self::from_bytes_unchecked([0u8; P224_SCALAR_SIZE]),
            Choice::from(self.is_zero() as u8),
        )
    }

    // Private helper methods

    fn validate_canonical_nonzero(bytes: &[u8; P224_SCALAR_SIZE]) -> Result<()> {
        let mut any = 0u8;
        for &byte in bytes {
            any |= byte;
        }
        if any == 0 {
            return Err(Error::param("P-224 Scalar", "Scalar cannot be zero"));
        }

        let (_, borrow) = Self::subtract_order(bytes);
        if borrow == 0 {
            return Err(Error::param(
                "P-224 Scalar",
                "Scalar must be less than the group order",
            ));
        }

        Ok(())
    }

    /// Reduce an arbitrary 224-bit integer modulo the group order.
    fn reduce_scalar_bytes_allow_zero(bytes: &mut [u8; P224_SCALAR_SIZE]) {
        let original = *bytes;
        let (candidate, borrow) = Self::subtract_order(&original);
        let reduce = Choice::from(borrow ^ 1);
        for i in 0..P224_SCALAR_SIZE {
            bytes[i] = u8::conditional_select(&original[i], &candidate[i], reduce);
        }
    }

    #[inline(always)]
    fn subtract_order(bytes: &[u8; P224_SCALAR_SIZE]) -> ([u8; P224_SCALAR_SIZE], u8) {
        let mut result = [0u8; P224_SCALAR_SIZE];
        let mut borrow = 0u8;
        for i in (0..P224_SCALAR_SIZE).rev() {
            let (difference, borrow_order) = bytes[i].overflowing_sub(NIST_P224.n[i]);
            let (difference, borrow_previous) = difference.overflowing_sub(borrow);
            result[i] = difference;
            borrow = (borrow_order | borrow_previous) as u8;
        }
        (result, borrow)
    }

    // Helper constants - stored in little-endian limb order
    const N_LIMBS: [u32; 7] = [
        0x5C5C_2A3D,
        0x13DD_2945,
        0xE0B8_F03E,
        0xFFFF_16A2,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
    ];

    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let a_bytes = a.serialize();
        let b_bytes = b.serialize();
        let mut out = [0u8; P224_SCALAR_SIZE];
        for i in 0..P224_SCALAR_SIZE {
            out[i] = u8::conditional_select(&a_bytes[i], &b_bytes[i], choice);
        }
        Self::from_bytes_unchecked(out)
    }

    /// Subtract b from a in-place
    #[inline(always)]
    fn sub_in_place(a: &mut [u32; 7], b: &[u32; 7]) -> u64 {
        let mut borrow = 0u64;
        for (i, elem) in a.iter_mut().enumerate() {
            let tmp = (*elem as u64)
                .wrapping_sub(b[i] as u64)
                .wrapping_sub(borrow);
            *elem = tmp as u32;
            borrow = (tmp >> 63) & 1; // 1 if we wrapped
        }
        borrow
    }
}
