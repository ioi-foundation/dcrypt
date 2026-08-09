//! P-384 scalar arithmetic operations

use crate::ec::p384::constants::P384_SCALAR_SIZE;
use crate::error::{validate, Error, Result};
use dcrypt_common::security::SecretBuffer;
use dcrypt_internal::constant_time::{Choice, ConditionallySelectable};
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};
use dcrypt_params::traditional::ecdsa::NIST_P384;

/// P-384 scalar value for use in elliptic curve operations
///
/// Represents integers modulo the curve order n. Used for private keys
/// and scalar multiplication. Automatically zeroized on drop for security.
#[derive(Clone, Debug)]
pub struct Scalar(SecretBuffer<P384_SCALAR_SIZE>);

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
    pub fn new(data: [u8; P384_SCALAR_SIZE]) -> Result<Self> {
        Self::from_secret_buffer(SecretBuffer::new(data))
    }

    /// Interpret a 384-bit integer modulo the group order, including zero.
    ///
    /// This constructor is intended for standards-defined mathematical
    /// intermediates such as ECDSA hash and x-coordinate reduction. Use
    /// [`Self::new`] for private scalars, nonces, and serialized signature
    /// components, where zero is invalid.
    pub fn from_bytes_reduced(data: [u8; P384_SCALAR_SIZE]) -> Self {
        let mut protected = SecretBuffer::new(data);
        Self::reduce_scalar_bytes_allow_zero(&mut protected);
        Self::from_secret_buffer_unchecked(protected)
    }

    /// Internal constructor that allows zero values
    ///
    /// Used for intermediate arithmetic operations where zero is a valid result.
    /// Should NOT be used for secret keys, nonces, or final signature components.
    fn from_secret_buffer_unchecked(buffer: SecretBuffer<P384_SCALAR_SIZE>) -> Self {
        Scalar(buffer)
    }

    /// Create a scalar from an existing SecretBuffer
    ///
    /// Performs the same canonical validation as `new()` but starts
    /// from a SecretBuffer instead of a raw byte array.
    pub fn from_secret_buffer(buffer: SecretBuffer<P384_SCALAR_SIZE>) -> Result<Self> {
        Self::validate_canonical_nonzero(buffer.as_ref())?;
        Ok(Self::from_secret_buffer_unchecked(buffer))
    }

    /// Access the underlying SecretBuffer containing the scalar value
    pub fn as_secret_buffer(&self) -> &SecretBuffer<P384_SCALAR_SIZE> {
        &self.0
    }

    /// Serialize the scalar to protected exact-size storage.
    ///
    /// Returns the scalar in big-endian byte representation.
    /// The output clears itself on drop. Callers that deliberately expose a
    /// public signature component may copy from its borrowed slice.
    pub fn serialize(&self) -> SecretBuffer<P384_SCALAR_SIZE> {
        self.0.clone()
    }

    /// Deserialize a scalar from bytes with validation
    ///
    /// Parses bytes as a big-endian scalar value and ensures it's
    /// in the valid range for P-384 operations.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        validate::length("P-384 Scalar", bytes.len(), P384_SCALAR_SIZE)?;

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

    /// Convert big-endian 48-byte array → 12 little-endian u32 limbs
    #[inline(always)]
    fn to_le_limbs(bytes_be: &[u8]) -> Zeroizing<[u32; 12]> {
        let mut limbs = Zeroizing::new([0u32; 12]);
        for (i, limb) in limbs.iter_mut().enumerate() {
            // MS limb first ⇒ start index counts back from the end
            let start = 44 - i * 4;
            *limb = ((bytes_be[start] as u32) << 24)
                | ((bytes_be[start + 1] as u32) << 16)
                | ((bytes_be[start + 2] as u32) << 8)
                | bytes_be[start + 3] as u32;
        }
        limbs
    }

    /// Convert 12 little-endian limbs back to big-endian 48-byte array  
    /// (inverse of `to_le_limbs`)
    #[inline(always)]
    fn limbs_to_secret_buffer(limbs: &[u32; 12]) -> SecretBuffer<P384_SCALAR_SIZE> {
        let mut out = SecretBuffer::zeroed();
        for (i, &w) in limbs.iter().enumerate() {
            let start = 44 - i * 4;
            out[start] = (w >> 24) as u8;
            out[start + 1] = (w >> 16) as u8;
            out[start + 2] = (w >> 8) as u8;
            out[start + 3] = w as u8;
        }
        out
    }

    /// Add two scalars modulo the curve order n
    pub fn add_mod_n(&self, other: &Self) -> Result<Self> {
        let a = Self::to_le_limbs(self.0.as_ref());
        let b = Self::to_le_limbs(other.0.as_ref());

        let mut r = Zeroizing::new([0u32; 12]);
        let mut carry = 0u64;

        // plain 384-bit addition
        for i in 0..12 {
            let tmp = a[i] as u64 + b[i] as u64 + carry;
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
        let a = Self::to_le_limbs(self.0.as_ref());
        let b = Self::to_le_limbs(other.0.as_ref());

        let mut r = Zeroizing::new([0u32; 12]);
        let mut borrow = 0u64;

        for (i, r_limb) in r.iter_mut().enumerate() {
            let tmp = (a[i] as u64).wrapping_sub(b[i] as u64).wrapping_sub(borrow);
            *r_limb = tmp as u32;
            borrow = (tmp >> 63) & 1;
        }

        let unreduced = Self::from_secret_buffer_unchecked(Self::limbs_to_secret_buffer(&r));
        let mut carry = 0u64;
        for (i, r_limb) in r.iter_mut().enumerate() {
            let tmp = *r_limb as u64 + Self::N_LIMBS[i] as u64 + carry;
            *r_limb = tmp as u32;
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
    pub fn inv_mod_n(&self) -> Result<Self> {
        // Fast fail on zero - no multiplicative inverse exists
        if self.is_zero() {
            return Err(Error::param("P-384 Scalar", "Cannot invert zero scalar"));
        }

        // n-2 for P-384 in big-endian
        // n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
        // n-2 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52971
        const N_MINUS_2: [u8; 48] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81,
            0xF4, 0x37, 0x2D, 0xDF, 0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC,
            0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x71,
        ];

        let mut result = Self::one();
        let base = self.clone();

        for byte in N_MINUS_2 {
            for bit in (0..8).rev() {
                result = result.mul_mod_n(&result)?;
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
        let mut res = Zeroizing::new([0u32; 12]);

        // Subtract self from n
        let mut borrow = 0u64;
        for i in 0..12 {
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

    fn validate_canonical_nonzero(bytes: &[u8]) -> Result<()> {
        let mut any = 0u8;
        for &byte in bytes {
            any |= byte;
        }
        if any == 0 {
            return Err(Error::param("P-384 Scalar", "Scalar cannot be zero"));
        }

        let (_, borrow) = Self::subtract_order(bytes);
        if borrow == 0 {
            return Err(Error::param(
                "P-384 Scalar",
                "Scalar must be less than the group order",
            ));
        }

        Ok(())
    }

    /// Reduce an arbitrary 384-bit integer modulo the group order.
    fn reduce_scalar_bytes_allow_zero(bytes: &mut SecretBuffer<P384_SCALAR_SIZE>) {
        let (candidate, borrow) = Self::subtract_order(bytes.as_ref());
        let reduce = Choice::from(borrow ^ 1);
        *bytes = Self::select_secret_buffer(bytes, &candidate, reduce);
    }

    #[inline(always)]
    fn subtract_order(bytes: &[u8]) -> (SecretBuffer<P384_SCALAR_SIZE>, u8) {
        let mut result = SecretBuffer::zeroed();
        let mut borrow = 0u8;
        for i in (0..P384_SCALAR_SIZE).rev() {
            let (difference, borrow_order) = bytes[i].overflowing_sub(NIST_P384.n[i]);
            let (difference, borrow_previous) = difference.overflowing_sub(borrow);
            result[i] = difference;
            borrow = (borrow_order | borrow_previous) as u8;
        }
        (result, borrow)
    }

    // Helper constants
    // The curve order n for P-384 in little-endian limbs
    // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    const N_LIMBS: [u32; 12] = [
        0xCCC5_2973,
        0xECEC_196A,
        0x48B0_A77A,
        0x581A_0DB2,
        0xF437_2DDF,
        0xC763_4D81,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
    ];

    #[inline(never)]
    fn select_secret_buffer(
        a: &SecretBuffer<P384_SCALAR_SIZE>,
        b: &SecretBuffer<P384_SCALAR_SIZE>,
        choice: Choice,
    ) -> SecretBuffer<P384_SCALAR_SIZE> {
        let mut out = SecretBuffer::zeroed();
        for i in 0..P384_SCALAR_SIZE {
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
        one[P384_SCALAR_SIZE - 1] = 1;
        Self::from_secret_buffer_unchecked(one)
    }

    /// a ← a − b   (little-endian limbs), ignores final borrow
    #[inline(always)]
    fn sub_in_place(a: &mut [u32; 12], b: &[u32; 12]) -> u64 {
        let mut borrow = 0u64;
        for i in 0..12 {
            let tmp = (a[i] as u64).wrapping_sub(b[i] as u64).wrapping_sub(borrow);
            a[i] = tmp as u32;
            borrow = (tmp >> 63) & 1;
        }
        borrow
    }
}
