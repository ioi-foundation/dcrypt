//! P-256 scalar arithmetic operations

use crate::ec::p256::constants::P256_SCALAR_SIZE;
use crate::error::{validate, Error, Result};
use dcrypt_common::security::SecretBuffer;
use dcrypt_internal::constant_time::{Choice, ConditionallySelectable};
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};
use dcrypt_params::traditional::ecdsa::NIST_P256;

/// P-256 scalar value for use in elliptic curve operations
///
/// Represents integers modulo the curve order n. Used for private keys
/// and scalar multiplication. Automatically zeroized on drop for security.
#[derive(Clone, Debug)]
pub struct Scalar(SecretBuffer<P256_SCALAR_SIZE>);

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
    /// the interval `1..n`; out-of-range inputs are rejected rather than
    /// reduced. Use [`Self::from_bytes_reduced`] only for mathematical
    /// intermediates whose specification explicitly requires reduction.
    pub fn new(data: [u8; P256_SCALAR_SIZE]) -> Result<Self> {
        Self::from_secret_buffer(SecretBuffer::new(data))
    }

    /// Interpret a 256-bit integer modulo the group order, including zero.
    ///
    /// This is for ECDSA hash and x-coordinate conversion, where FIPS 186
    /// requires reduction rather than private-scalar validation.
    pub fn from_bytes_reduced(data: [u8; P256_SCALAR_SIZE]) -> Self {
        let mut protected = SecretBuffer::new(data);
        Self::reduce_scalar_bytes_allow_zero(&mut protected);
        Self::from_secret_buffer_unchecked(protected)
    }

    /// Internal constructor that allows zero values
    ///
    /// Used for intermediate arithmetic operations where zero is a valid result.
    /// Should NOT be used for secret keys, nonces, or final signature components.
    fn from_secret_buffer_unchecked(buffer: SecretBuffer<P256_SCALAR_SIZE>) -> Self {
        Scalar(buffer)
    }

    /// Create a scalar from an existing SecretBuffer
    ///
    /// Performs the same canonical validation as `new()` but starts
    /// from a SecretBuffer instead of a raw byte array.
    pub fn from_secret_buffer(buffer: SecretBuffer<P256_SCALAR_SIZE>) -> Result<Self> {
        Self::validate_canonical_nonzero(buffer.as_ref())?;
        Ok(Self::from_secret_buffer_unchecked(buffer))
    }

    /// Access the underlying SecretBuffer containing the scalar value
    pub fn as_secret_buffer(&self) -> &SecretBuffer<P256_SCALAR_SIZE> {
        &self.0
    }

    /// Serialize the scalar to protected exact-size storage.
    ///
    /// Returns the scalar in big-endian byte representation.
    /// The output clears itself on drop. Callers that deliberately expose a
    /// public signature component may copy from its borrowed slice.
    pub fn serialize(&self) -> SecretBuffer<P256_SCALAR_SIZE> {
        self.0.clone()
    }

    /// Deserialize a scalar from bytes with validation
    ///
    /// Parses bytes as a big-endian scalar value and ensures it's
    /// in the valid range for P-256 operations.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        validate::length("P-256 Scalar", bytes.len(), P256_SCALAR_SIZE)?;

        let mut protected = SecretBuffer::zeroed();
        protected.as_mut().copy_from_slice(bytes);
        Self::from_secret_buffer(protected)
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
    /// Properly extracts 4-byte chunks from BE array and converts to LE limbs
    #[inline(always)]
    fn to_le_limbs(bytes_be: &[u8]) -> Zeroizing<[u32; 8]> {
        let mut limbs = Zeroizing::new([0u32; 8]);

        // limb-0 must hold the 4 least-significant bytes, limb-7 the 4 most-significant
        #[allow(clippy::needless_range_loop)] // Index used for offset calculation
        for i in 0..8 {
            let start = 28 - i * 4; // index of the MS-byte of this limb
            limbs[i] = ((bytes_be[start] as u32) << 24)
                | ((bytes_be[start + 1] as u32) << 16)
                | ((bytes_be[start + 2] as u32) << 8)
                | bytes_be[start + 3] as u32;
        }
        limbs
    }

    /// Add two scalars modulo the curve order n
    pub fn add_mod_n(&self, other: &Self) -> Result<Self> {
        let self_limbs = Self::to_le_limbs(self.0.as_ref());
        let other_limbs = Self::to_le_limbs(other.0.as_ref());

        let mut r = Zeroizing::new([0u32; 8]);
        let mut carry = 0u64;

        // Plain 256-bit add
        #[allow(clippy::needless_range_loop)] // Index used for multiple arrays
        for i in 0..8 {
            let tmp = self_limbs[i] as u64 + other_limbs[i] as u64 + carry;
            r[i] = tmp as u32;
            carry = tmp >> 32;
        }

        let unreduced = Self::from_secret_buffer_unchecked(Self::limbs_to_secret_buffer(&r));
        let borrow = Self::sub_in_place(&mut r, &Self::N_LIMBS);
        let need_reduce = Choice::from((carry as u8) | ((borrow ^ 1) as u8));
        let reduced = Self::from_secret_buffer_unchecked(Self::limbs_to_secret_buffer(&r));

        Ok(Self::conditional_select(&unreduced, &reduced, need_reduce))
    }

    /// Subtract two scalars modulo the curve order n
    pub fn sub_mod_n(&self, other: &Self) -> Result<Self> {
        let self_limbs = Self::to_le_limbs(self.0.as_ref());
        let other_limbs = Self::to_le_limbs(other.0.as_ref());

        let mut r = Zeroizing::new([0u32; 8]);
        let mut borrow = 0u64;

        #[allow(clippy::needless_range_loop)] // Index used for multiple arrays
        for i in 0..8 {
            let tmp = (self_limbs[i] as u64)
                .wrapping_sub(other_limbs[i] as u64)
                .wrapping_sub(borrow);
            r[i] = tmp as u32;
            borrow = (tmp >> 63) & 1;
        }

        let unreduced = Self::from_secret_buffer_unchecked(Self::limbs_to_secret_buffer(&r));
        let mut carry = 0u64;
        #[allow(clippy::needless_range_loop)] // Index used for multiple arrays
        for i in 0..8 {
            let tmp = r[i] as u64 + Self::N_LIMBS[i] as u64 + carry;
            r[i] = tmp as u32;
            carry = tmp >> 32;
        }
        let reduced = Self::from_secret_buffer_unchecked(Self::limbs_to_secret_buffer(&r));

        Ok(Self::conditional_select(
            &unreduced,
            &reduced,
            Choice::from(borrow as u8),
        ))
    }

    /// Multiply two scalars modulo the curve order n
    ///
    /// Uses constant-time double-and-add algorithm for correctness and security.
    /// Processes bits from MSB to LSB to ensure correct powers of 2.
    pub fn mul_mod_n(&self, other: &Self) -> Result<Self> {
        // Start with zero (additive identity)
        let mut acc = Self::zero();

        // Process each bit from MSB to LSB
        for &byte in other.0.as_ref() {
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
        let mut exp = Zeroizing::new(NIST_P256.n); // public, fixed exponent
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
        let mut result = { Self::one() };
        let base = self.clone();

        for &byte in exp.iter() {
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
        let self_limbs = Self::to_le_limbs(self.0.as_ref());
        let mut res = Zeroizing::new([0u32; 8]);

        // Subtract self from n
        let mut borrow = 0u64;
        #[allow(clippy::needless_range_loop)] // Index used for multiple arrays
        for i in 0..8 {
            let tmp = (Self::N_LIMBS[i] as u64)
                .wrapping_sub(self_limbs[i] as u64)
                .wrapping_sub(borrow);
            res[i] = tmp as u32;
            borrow = (tmp >> 63) & 1;
        }
        let negated = Self::from_secret_buffer_unchecked(Self::limbs_to_secret_buffer(&res));
        Self::conditional_select(&negated, &Self::zero(), Choice::from(self.is_zero() as u8))
    }

    // Private helper methods

    /// Reduce scalar modulo the curve order n using constant-time arithmetic
    ///
    /// The curve order n for P-256 is:
    /// n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    ///
    /// The input is at most 2^256-1 and the order is greater than 2^255,
    /// so at most one subtraction is required. Zero is intentionally allowed.
    fn reduce_scalar_bytes_allow_zero(bytes: &mut SecretBuffer<P256_SCALAR_SIZE>) {
        let (candidate, borrow) = Self::subtract_order(bytes.as_ref());
        let reduce = Choice::from(borrow ^ 1);
        *bytes = Self::select_secret_buffer(bytes, &candidate, reduce);
    }

    #[inline(always)]
    fn subtract_order(bytes: &[u8]) -> (SecretBuffer<P256_SCALAR_SIZE>, u8) {
        let mut result = SecretBuffer::zeroed();
        let mut borrow = 0u8;
        for i in (0..P256_SCALAR_SIZE).rev() {
            let (difference, borrow_order) = bytes[i].overflowing_sub(NIST_P256.n[i]);
            let (difference, borrow_previous) = difference.overflowing_sub(borrow);
            result[i] = difference;
            borrow = (borrow_order | borrow_previous) as u8;
        }
        (result, borrow)
    }

    fn validate_canonical_nonzero(bytes: &[u8]) -> Result<()> {
        let mut any = 0u8;
        for &byte in bytes {
            any |= byte;
        }
        if any == 0 {
            return Err(Error::param("P-256 Scalar", "Scalar cannot be zero"));
        }

        let (_, borrow) = Self::subtract_order(bytes);
        if borrow == 1 {
            return Ok(());
        }

        Err(Error::param(
            "P-256 Scalar",
            "Scalar must be less than the group order",
        ))
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

    #[inline(never)]
    fn select_secret_buffer(
        a: &SecretBuffer<P256_SCALAR_SIZE>,
        b: &SecretBuffer<P256_SCALAR_SIZE>,
        choice: Choice,
    ) -> SecretBuffer<P256_SCALAR_SIZE> {
        let mut out = SecretBuffer::zeroed();
        for i in 0..P256_SCALAR_SIZE {
            out[i] = u8::conditional_select(&a[i], &b[i], choice);
        }
        out
    }

    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::from_secret_buffer_unchecked(Self::select_secret_buffer(&a.0, &b.0, choice))
    }

    fn zero() -> Self {
        Self::from_secret_buffer_unchecked(SecretBuffer::zeroed())
    }

    fn one() -> Self {
        let mut one = SecretBuffer::zeroed();
        one[P256_SCALAR_SIZE - 1] = 1;
        Self::from_secret_buffer_unchecked(one)
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
    fn limbs_to_secret_buffer(limbs: &[u32; 8]) -> SecretBuffer<P256_SCALAR_SIZE> {
        let mut out = SecretBuffer::zeroed();
        for (i, &w) in limbs.iter().enumerate() {
            let start = 28 - i * 4;
            out[start] = (w >> 24) as u8;
            out[start + 1] = (w >> 16) as u8;
            out[start + 2] = (w >> 8) as u8;
            out[start + 3] = w as u8;
        }
        out
    }
}
