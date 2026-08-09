//! P-521 scalar arithmetic operations

use crate::ec::p521::constants::P521_SCALAR_SIZE;
use crate::error::{validate, Error, Result};
use dcrypt_common::security::SecretBuffer;
use dcrypt_internal::constant_time::{Choice, ConditionallySelectable};
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};
use dcrypt_params::traditional::ecdsa::NIST_P521;

/// P-521 scalar value for use in elliptic curve operations.
/// Represents integers modulo the curve order n. Used for private keys
/// and scalar multiplication. Automatically zeroized on drop for security.
#[derive(Clone, Debug)]
pub struct Scalar(SecretBuffer<P521_SCALAR_SIZE>);

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
    /// `1..n`. Non-canonical 528-bit encodings are rejected rather than reduced.
    pub fn new(data: [u8; P521_SCALAR_SIZE]) -> Result<Self> {
        Self::from_secret_buffer(SecretBuffer::new(data))
    }

    /// Interpret a 528-bit encoding modulo the group order, including zero.
    ///
    /// P-521 scalars use a 66-byte encoding. This constructor is intended for
    /// standards-defined mathematical intermediates such as ECDSA hash and
    /// x-coordinate reduction. Use [`Self::new`] for private scalars, nonces,
    /// and serialized signature components, where zero is invalid.
    pub fn from_bytes_reduced(data: [u8; P521_SCALAR_SIZE]) -> Self {
        let mut protected = SecretBuffer::new(data);
        Self::reduce_scalar_bytes_allow_zero(&mut protected);
        Self::from_secret_buffer_unchecked(protected)
    }

    /// Internal constructor that allows zero values.
    /// Used for intermediate arithmetic operations where zero is a valid result.
    /// Should NOT be used for secret keys, nonces, or final signature components.
    fn from_secret_buffer_unchecked(buffer: SecretBuffer<P521_SCALAR_SIZE>) -> Self {
        Scalar(buffer)
    }

    /// Create a scalar from an existing SecretBuffer.
    /// Performs the same canonical validation as `new()` but starts
    /// from a SecretBuffer instead of a raw byte array.
    pub fn from_secret_buffer(buffer: SecretBuffer<P521_SCALAR_SIZE>) -> Result<Self> {
        Self::validate_canonical_nonzero(buffer.as_ref())?;
        Ok(Self::from_secret_buffer_unchecked(buffer))
    }

    /// Access the underlying SecretBuffer containing the scalar value
    pub fn as_secret_buffer(&self) -> &SecretBuffer<P521_SCALAR_SIZE> {
        &self.0
    }

    /// Serialize the scalar to protected exact-size storage.
    /// Returns the scalar in big-endian byte representation.
    /// The output clears itself on drop. Callers that deliberately expose a
    /// public signature component may copy from its borrowed slice.
    pub fn serialize(&self) -> SecretBuffer<P521_SCALAR_SIZE> {
        self.0.clone()
    }

    /// Deserialize a scalar from bytes with validation.
    /// Parses bytes as a big-endian scalar value and ensures it's
    /// in the valid range for P-521 operations.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        validate::length("P-521 Scalar", bytes.len(), P521_SCALAR_SIZE)?;

        let mut protected = SecretBuffer::zeroed();
        protected.as_mut().copy_from_slice(bytes);
        Self::from_secret_buffer(protected)
    }

    /// Check if the scalar represents zero.
    /// Constant-time check to determine if the scalar is the
    /// additive identity (which is invalid for most cryptographic operations).
    pub fn is_zero(&self) -> bool {
        let mut any = 0u8;
        for &byte in self.0.as_ref() {
            any |= byte;
        }
        any == 0
    }

    /// Convert big-endian 66-byte array to 17 little-endian u32 limbs
    #[inline(always)]
    fn to_le_limbs(bytes_be: &[u8]) -> Zeroizing<[u32; 17]> {
        let mut limbs = Zeroizing::new([0u32; 17]);
        for i in 0..16 {
            let offset = P521_SCALAR_SIZE - 4 - i * 4;
            limbs[i] = ((bytes_be[offset] as u32) << 24)
                | ((bytes_be[offset + 1] as u32) << 16)
                | ((bytes_be[offset + 2] as u32) << 8)
                | bytes_be[offset + 3] as u32;
        }
        limbs[16] = (((bytes_be[0] as u32) << 8) | bytes_be[1] as u32) & 0x1ff;
        limbs
    }

    /// Convert 17 little-endian limbs back to big-endian 66-byte array
    #[inline(always)]
    fn limbs_to_secret_buffer(limbs: &[u32; 17]) -> SecretBuffer<P521_SCALAR_SIZE> {
        let mut out = SecretBuffer::zeroed();
        for (i, &limb) in limbs.iter().take(16).enumerate() {
            let offset = P521_SCALAR_SIZE - 4 - i * 4;
            out[offset] = (limb >> 24) as u8;
            out[offset + 1] = (limb >> 16) as u8;
            out[offset + 2] = (limb >> 8) as u8;
            out[offset + 3] = limb as u8;
        }
        let most_significant = limbs[16] & 0x1ff;
        out[0] = (most_significant >> 8) as u8;
        out[1] = most_significant as u8;
        out
    }

    /// Add two scalars modulo the curve order n
    pub fn add_mod_n(&self, other: &Self) -> Result<Self> {
        let a = Self::to_le_limbs(self.0.as_ref());
        let b = Self::to_le_limbs(other.0.as_ref());
        let mut r = Zeroizing::new([0u32; 17]);
        let mut carry = 0u64;
        for i in 0..17 {
            let sum = a[i] as u64 + b[i] as u64 + carry;
            r[i] = sum as u32;
            carry = sum >> 32;
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
        let mut r = Zeroizing::new([0u32; 17]);
        let mut borrow = 0u64;
        for i in 0..17 {
            let difference = (a[i] as u64).wrapping_sub(b[i] as u64).wrapping_sub(borrow);
            r[i] = difference as u32;
            borrow = (difference >> 63) & 1;
        }
        let unreduced = Self::from_secret_buffer_unchecked(Self::limbs_to_secret_buffer(&r));
        let mut carry = 0u64;
        for i in 0..17 {
            let sum = r[i] as u64 + Self::N_LIMBS[i] as u64 + carry;
            r[i] = sum as u32;
            carry = sum >> 32;
        }
        let reduced = Self::from_secret_buffer_unchecked(Self::limbs_to_secret_buffer(&r));

        Ok(Self::conditional_select(
            &unreduced,
            &reduced,
            Choice::from(borrow as u8),
        ))
    }

    /// Multiply two scalars modulo the curve order n.
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
    /// a^(-1) ≡ a^(n-2) (mod n). Left-to-right binary exponentiation.
    pub fn inv_mod_n(&self) -> Result<Self> {
        // zero has no inverse
        if self.is_zero() {
            return Err(Error::param("P-521 Scalar", "Cannot invert zero scalar"));
        }

        // Step 1: form exponent = n-2
        let mut exp = Zeroizing::new(NIST_P521.n); // public, fixed exponent
                                                   // subtract 2 with borrow
        let mut borrow = 2u16;
        for i in (0..P521_SCALAR_SIZE).rev() {
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
    /// Returns -self mod n, which is equivalent to n - self when self != 0
    /// Returns 0 when self is 0
    pub fn negate(&self) -> Self {
        // Compute n - self, then select zero for the zero input.
        let self_limbs = Self::to_le_limbs(self.0.as_ref());
        let mut res = Zeroizing::new([0u32; 17]);

        // Subtract self from n
        let mut borrow = 0u64;
        for i in 0..17 {
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

    /// Reduce scalar modulo the curve order n using constant-time arithmetic.
    /// The curve order n for P-521 is:
    /// n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
    ///
    fn validate_canonical_nonzero(bytes: &[u8]) -> Result<()> {
        let mut any = 0u8;
        for &byte in bytes {
            any |= byte;
        }
        if any == 0 {
            return Err(Error::param("P-521 Scalar", "Scalar cannot be zero"));
        }

        let (_, borrow) = Self::subtract_order(bytes);
        if borrow == 0 {
            return Err(Error::param(
                "P-521 Scalar",
                "Scalar must be less than the group order",
            ));
        }

        Ok(())
    }

    /// Reduce an arbitrary 528-bit encoding modulo the group order.
    fn reduce_scalar_bytes_allow_zero(bytes: &mut SecretBuffer<P521_SCALAR_SIZE>) {
        for _ in 0..128 {
            let (candidate, borrow) = Self::subtract_order(bytes.as_ref());

            let choice = Choice::from(borrow ^ 1);
            *bytes = Self::select_secret_buffer(bytes, &candidate, choice);
        }
    }

    #[inline(always)]
    fn subtract_order(bytes: &[u8]) -> (SecretBuffer<P521_SCALAR_SIZE>, u8) {
        let mut result = SecretBuffer::zeroed();
        let mut borrow = 0u8;
        for i in (0..P521_SCALAR_SIZE).rev() {
            let (difference, borrow_order) = bytes[i].overflowing_sub(NIST_P521.n[i]);
            let (difference, borrow_previous) = difference.overflowing_sub(borrow);
            result[i] = difference;
            borrow = (borrow_order | borrow_previous) as u8;
        }
        (result, borrow)
    }

    /// n (group order) in 17 little-endian 32-bit limbs
    const N_LIMBS: [u32; 17] = [
        0x9138_6409, // limb 0  – least-significant
        0xBB6F_B71E, // limb 1
        0x899C_47AE, // limb 2
        0x3BB5_C9B8, // limb 3
        0xF709_A5D0, // limb 4
        0x7FCC_0148, // limb 5
        0xBF2F_966B, // limb 6
        0x5186_8783, // limb 7
        0xFFFF_FFFA, // limb 8
        0xFFFF_FFFF, // limb 9
        0xFFFF_FFFF, // limb 10
        0xFFFF_FFFF, // limb 11
        0xFFFF_FFFF, // limb 12
        0xFFFF_FFFF, // limb 13
        0xFFFF_FFFF, // limb 14
        0xFFFF_FFFF, // limb 15
        0x0000_01FF, // limb 16 – most-significant 9 bits
    ];

    #[inline(never)]
    fn select_secret_buffer(
        a: &SecretBuffer<P521_SCALAR_SIZE>,
        b: &SecretBuffer<P521_SCALAR_SIZE>,
        choice: Choice,
    ) -> SecretBuffer<P521_SCALAR_SIZE> {
        let mut out = SecretBuffer::zeroed();
        for i in 0..P521_SCALAR_SIZE {
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
        one[P521_SCALAR_SIZE - 1] = 1;
        Self::from_secret_buffer_unchecked(one)
    }

    #[inline(always)]
    fn sub_in_place(a: &mut [u32; 17], b: &[u32; 17]) -> u64 {
        let mut borrow = 0u64;
        for i in 0..17 {
            let difference = (a[i] as u64).wrapping_sub(b[i] as u64).wrapping_sub(borrow);
            a[i] = difference as u32;
            borrow = (difference >> 63) & 1;
        }
        borrow
    }
}
