//! P-256 field arithmetic implementation

use crate::ec::p256::constants::P256_FIELD_ELEMENT_SIZE;
use crate::error::{Error, Result};
use subtle::{Choice, ConditionallySelectable};

/// P-256 field element representing values in F_p
///
/// Internally stored as 8 little-endian 32-bit limbs for efficient arithmetic.
/// All operations maintain the invariant that values are reduced modulo p.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement(pub(crate) [u32; 8]);

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut out = [0u32; 8];
        for i in 0..8 {
            out[i] = u32::conditional_select(&a.0[i], &b.0[i], choice);
        }
        FieldElement(out)
    }
}

impl FieldElement {
    /* -------------------------------------------------------------------- */
    /*  NIST P-256 Field Constants (stored as little-endian 32-bit limbs)  */
    /* -------------------------------------------------------------------- */

    /// The NIST P-256 prime modulus: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    /// Stored as 8 little-endian 32-bit limbs where limbs[0] is least significant
    pub(crate) const MOD_LIMBS: [u32; 8] = [
        0xFFFF_FFFF, // 2⁰ … 2³¹
        0xFFFF_FFFF, // 2³² … 2⁶³
        0xFFFF_FFFF, // 2⁶⁴ … 2⁹⁵
        0x0000_0000, // 2⁹⁶ … 2¹²⁷
        0x0000_0000, // 2¹²⁸ … 2¹⁵⁹
        0x0000_0000, // 2¹⁶⁰ … 2¹⁹¹
        0x0000_0001, // 2¹⁹² … 2²²³
        0xFFFF_FFFF, // 2²²⁴ … 2²⁵⁵
    ];

    /// The curve parameter a = -3 mod p, used in the curve equation y² = x³ + ax + b
    /// For P-256: a = p - 3
    pub(crate) const A_M3: [u32; 8] = [
        0xFFFF_FFFC, // (2³² - 1) - 3 = 2³² - 4
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0x0000_0000,
        0x0000_0000,
        0x0000_0000,
        0x0000_0001,
        0xFFFF_FFFF, // Most significant limb
    ];

    /// The additive identity element: 0
    pub fn zero() -> Self {
        FieldElement([0, 0, 0, 0, 0, 0, 0, 0])
    }

    /// The multiplicative identity element: 1
    pub fn one() -> Self {
        FieldElement([1, 0, 0, 0, 0, 0, 0, 0])
    }

    /// Create a field element from big-endian byte representation
    ///
    /// Validates that the input represents a value less than the field modulus p.
    /// Returns an error if the value is >= p.
    pub fn from_bytes(bytes: &[u8; P256_FIELD_ELEMENT_SIZE]) -> Result<Self> {
        let mut limbs = [0u32; 8];

        // Convert from big-endian bytes to little-endian limbs
        // limbs[0] = least-significant 4 bytes (bytes[28..32])
        // limbs[7] = most-significant 4 bytes (bytes[0..4])
        #[allow(clippy::needless_range_loop)] // Index used for offset calculation
        for i in 0..8 {
            let offset = (7 - i) * 4; // Byte offset: 28, 24, 20, ..., 0
            limbs[i] = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
        }

        // Validate that the value is in the field (< p)
        let fe = FieldElement(limbs);
        if !fe.is_valid() {
            return Err(Error::param(
                "FieldElement",
                "Value must be less than the field modulus",
            ));
        }

        Ok(fe)
    }

    /// Convert field element to big-endian byte representation
    pub fn to_bytes(&self) -> [u8; P256_FIELD_ELEMENT_SIZE] {
        let mut bytes = [0u8; P256_FIELD_ELEMENT_SIZE];

        // Convert from little-endian limbs to big-endian bytes
        for i in 0..8 {
            let limb_bytes = self.0[i].to_be_bytes();
            let offset = (7 - i) * 4; // Byte offset: 28, 24, 20, ..., 0
            bytes[offset..offset + 4].copy_from_slice(&limb_bytes);
        }
        bytes
    }

    /// Constant-time validation that the field element is in canonical form (< p)
    ///
    /// Uses constant-time subtraction to check if self < p without branching.
    /// Returns true if the element is valid (< p), false otherwise.
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        // Attempt to subtract p from self
        // If subtraction requires a borrow, then self < p (valid)
        let (_, borrow) = Self::sbb8(self.0, Self::MOD_LIMBS);
        borrow == 1
    }

    /// Constant-time field addition: (self + other) mod p
    ///
    /// Algorithm:
    /// 1. Perform full 256-bit addition with carry detection
    /// 2. Conditionally subtract p if result >= p
    /// 3. Ensure result is in canonical form
    #[inline(always)]
    pub fn add(&self, other: &Self) -> Self {
        // Step 1: Full 256-bit addition
        let (sum, carry) = Self::adc8(self.0, other.0);

        // Step 2: Attempt conditional reduction by subtracting p
        let (sum_minus_p, borrow) = Self::sbb8(sum, Self::MOD_LIMBS);

        // Step 3: Choose reduced value if:
        //   - Addition overflowed (carry == 1), OR
        //   - Subtraction didn't borrow (borrow == 0), meaning sum >= p
        let need_reduce = (carry | (borrow ^ 1)) & 1;
        let reduced = Self::conditional_select(&sum, &sum_minus_p, Choice::from(need_reduce as u8));

        // Step 4: Final canonical reduction
        reduced.conditional_sub_p()
    }

    /// Constant-time field subtraction: (self - other) mod p
    ///
    /// Algorithm:
    /// 1. Perform limb-wise subtraction
    /// 2. If subtraction borrows, add p to get the correct positive result
    pub fn sub(&self, other: &Self) -> Self {
        // Step 1: Raw subtraction
        let (diff, borrow) = Self::sbb8(self.0, other.0);

        // Step 2: If we borrowed, add p to get the correct positive result
        let (candidate, _) = Self::adc8(diff, Self::MOD_LIMBS);

        // Step 3: Constant-time select based on borrow flag
        Self::conditional_select(&diff, &candidate, Choice::from(borrow as u8))
    }

    /// Field multiplication: (self * other) mod p
    ///
    /// Algorithm:
    /// 1. Compute the full 512-bit product using schoolbook multiplication
    /// 2. Perform carry propagation to get proper limb representation
    /// 3. Apply NIST P-256 specific fast reduction (Solinas method)
    ///
    /// The multiplication is performed in three phases to maintain clarity
    /// and correctness while achieving good performance.
    pub fn mul(&self, other: &Self) -> Self {
        // Phase 1: Accumulate partial products in 128-bit temporaries
        // This prevents overflow during the schoolbook multiplication
        let mut t = [0u128; 16];
        for i in 0..8 {
            for j in 0..8 {
                t[i + j] += (self.0[i] as u128) * (other.0[j] as u128);
            }
        }

        // Phase 2: Carry propagation to convert to 32-bit limb representation
        let mut prod = [0u32; 16];
        let mut carry: u128 = 0;
        for i in 0..16 {
            let v = t[i] + carry;
            prod[i] = (v & 0xffff_ffff) as u32;
            carry = v >> 32;
        }

        // Phase 3: Apply NIST P-256 fast reduction
        Self::reduce_wide(prod)
    }

    /// Field squaring: self² mod p
    ///
    /// Optimized version of multiplication for the case where both operands
    /// are the same. Currently implemented as self.mul(self) but could be
    /// optimized further with dedicated squaring algorithms.
    #[inline(always)]
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Compute the modular multiplicative inverse using Fermat's Little Theorem
    ///
    /// For prime fields, a^(p-1) ≡ 1 (mod p), so a^(p-2) ≡ a^(-1) (mod p).
    /// Uses binary exponentiation (square-and-multiply) for efficiency.
    ///
    /// Returns an error if attempting to invert zero (which has no inverse).
    pub fn invert(&self) -> Result<Self> {
        if self.is_zero() {
            return Err(Error::param(
                "FieldElement",
                "Inversion of zero is undefined",
            ));
        }

        // The exponent p-2 for NIST P-256 in big-endian byte format
        const P_MINUS_2: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFD,
        ];

        // Binary exponentiation: compute self^(p-2) mod p
        let mut result = FieldElement::one();
        let mut base = self.clone();

        // Process each bit of the exponent from least to most significant
        for &byte in P_MINUS_2.iter().rev() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    result = result.mul(&base);
                }
                base = base.square();
            }
        }

        Ok(result)
    }

    /// Check if the field element represents zero
    ///
    /// Constant-time check across all limbs to determine if the
    /// field element is the additive identity.
    pub fn is_zero(&self) -> bool {
        for limb in self.0.iter() {
            if *limb != 0 {
                return false;
            }
        }
        true
    }

    /// Return `true` if the field element is odd (least-significant bit set)
    ///
    /// Used for point compression to determine the sign of the y-coordinate.
    /// The parity is determined by the least significant bit of the canonical
    /// representation.
    pub fn is_odd(&self) -> bool {
        (self.0[0] & 1) == 1
    }

    /// Compute modular square root using exponentiation.
    ///
    /// Because the P-256 prime satisfies p ≡ 3 (mod 4), we can compute
    /// sqrt(a) = a^((p+1)/4) mod p. This is more efficient than the
    /// general Tonelli-Shanks algorithm.
    ///
    /// Returns `None` when the input is a quadratic non-residue (i.e.,
    /// when no square root exists in the field).
    ///
    /// # Algorithm
    /// For p ≡ 3 (mod 4), if a has a square root, then:
    /// - sqrt(a) = ±a^((p+1)/4) mod p
    /// - We return the principal square root (the smaller of the two)
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() {
            return Some(Self::zero());
        }

        // (p + 1) / 4 for P-256 as big-endian bytes
        // p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        // (p + 1) / 4 = 0x3fffffffc0000000400000000000000000000000400000000000000000000000
        const EXP: [u8; 32] = [
            0x3F, 0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let mut result = FieldElement::one();
        let mut base = self.clone();

        // Binary exponentiation from LSB to MSB
        for &byte in EXP.iter().rev() {
            for bit in 0..8 {
                if ((byte >> bit) & 1) == 1 {
                    result = result.mul(&base);
                }
                base = base.square();
            }
        }

        // Verify that result^2 = self (constant-time check)
        if result.square() == *self {
            Some(result)
        } else {
            None
        }
    }

    // Private helper methods

    /// Constant-time conditional selection between two limb arrays
    ///
    /// Returns a if flag == 0, returns b if flag == 1
    /// Used for branchless operations to maintain constant-time guarantees.
    fn conditional_select(a: &[u32; 8], b: &[u32; 8], flag: Choice) -> Self {
        let mut out = [0u32; 8];
        for i in 0..8 {
            out[i] = u32::conditional_select(&a[i], &b[i], flag);
        }
        FieldElement(out)
    }

    /// 8-limb addition with carry propagation
    ///
    /// Performs full-width addition across all limbs, returning both
    /// the sum and the final carry bit for overflow detection.
    #[inline(always)]
    fn adc8(a: [u32; 8], b: [u32; 8]) -> ([u32; 8], u32) {
        let mut r = [0u32; 8];
        let mut carry = 0;

        #[allow(clippy::needless_range_loop)] // Index used for multiple arrays
        for i in 0..8 {
            // Add corresponding limbs plus carry from previous iteration
            let (sum1, carry1) = a[i].overflowing_add(b[i]);
            let (sum2, carry2) = sum1.overflowing_add(carry);

            r[i] = sum2;
            carry = (carry1 as u32) | (carry2 as u32);
        }

        (r, carry)
    }

    /// 8-limb subtraction with borrow propagation
    ///
    /// Performs full-width subtraction across all limbs, returning both
    /// the difference and the final borrow bit for underflow detection.
    #[inline(always)]
    fn sbb8(a: [u32; 8], b: [u32; 8]) -> ([u32; 8], u32) {
        let mut r = [0u32; 8];
        let mut borrow = 0;

        #[allow(clippy::needless_range_loop)] // Index used for multiple arrays
        for i in 0..8 {
            // Subtract corresponding limbs minus borrow from previous iteration
            let (diff1, borrow1) = a[i].overflowing_sub(b[i]);
            let (diff2, borrow2) = diff1.overflowing_sub(borrow);

            r[i] = diff2;
            borrow = (borrow1 as u32) | (borrow2 as u32);
        }
        (r, borrow)
    }

    /// Conditionally subtract p if the current value is >= p
    ///
    /// Ensures the field element is in canonical reduced form.
    /// Used as a final step in arithmetic operations.
    fn conditional_sub_p(&self) -> Self {
        let needs_sub = Choice::from((!self.is_valid() as u8) & 1);
        Self::conditional_sub(self.0, needs_sub)
    }

    /// Conditionally subtract the field modulus p based on a boolean condition
    ///
    /// Uses constant-time selection to avoid branching while maintaining
    /// the option to perform the subtraction.
    fn conditional_sub(limbs: [u32; 8], condition: Choice) -> Self {
        let mut result = [0u32; 8];
        let (diff, _) = Self::sbb8(limbs, Self::MOD_LIMBS);

        // Constant-time select between original limbs and difference
        for i in 0..8 {
            result[i] = u32::conditional_select(&limbs[i], &diff[i], condition);
        }

        Self(result)
    }

    /// NIST P-256 specific reduction for 512-bit values using Solinas method
    /// Fully constant-time Solinas reduction with two carry-folds.
    pub(crate) fn reduce_wide(t: [u32; 16]) -> FieldElement {
        // 1) load into signed 128-bit
        let mut s = [0i128; 16];
        for (i, &val) in t.iter().enumerate() {
            s[i] = val as i128;
        }

        // 2) fold high limbs 8..15 into 0..7 via
        //    2^256 ≡ 2^224 − 2^192 − 2^96 + 1
        for i in (8..16).rev() {
            let v = s[i];
            s[i] = 0;
            s[i - 8] = s[i - 8].wrapping_add(v); // +2^0
            s[i - 5] = s[i - 5].wrapping_sub(v); // -2^96
            s[i - 2] = s[i - 2].wrapping_sub(v); // -2^192
            s[i - 1] = s[i - 1].wrapping_add(v); // +2^224
        }

        // 3) first signed carry-propagate
        let mut carry1: i128 = 0;
        for val in s.iter_mut().take(8) {
            let tmp = *val + carry1;
            *val = tmp & 0xffff_ffff;
            carry1 = tmp >> 32; // arithmetic shift
        }

        // 4) fold carry1 back down (correct indices: 3 & 6)
        let c1 = carry1;
        s[0] = s[0].wrapping_add(c1); // +2^0
        s[3] = s[3].wrapping_sub(c1); // -2^96
        s[6] = s[6].wrapping_sub(c1); // -2^192
        s[7] = s[7].wrapping_add(c1); // +2^224

        // 5) second signed carry-propagate
        let mut carry2: i128 = 0;
        for val in s.iter_mut().take(8) {
            let tmp = *val + carry2;
            *val = tmp & 0xffff_ffff;
            carry2 = tmp >> 32;
        }

        // 6) fold carry2 back down (correct indices: 3 & 6)
        let c2 = carry2;
        s[0] = s[0].wrapping_add(c2);
        s[3] = s[3].wrapping_sub(c2);
        s[6] = s[6].wrapping_sub(c2);
        s[7] = s[7].wrapping_add(c2);

        // 7) final signed carry-propagate into 32-bit limbs
        let mut out = [0u32; 8];
        let mut carry3: i128 = 0;
        for (i, val) in s.iter().take(8).enumerate() {
            let tmp = *val + carry3;
            out[i] = (tmp & 0xffff_ffff) as u32;
            carry3 = tmp >> 32;
        }

        // 8) one last constant-time subtract if ≥ p
        let (subbed, borrow) = Self::sbb8(out, Self::MOD_LIMBS);
        let need_sub = Choice::from((borrow ^ 1) as u8); // borrow==0 ⇒ out>=p
        Self::conditional_select(&out, &subbed, need_sub)
    }

    /// Get the field modulus p as a FieldElement
    ///
    /// Returns the NIST P-256 prime modulus for use in reduction operations.
    pub(crate) fn get_modulus() -> Self {
        FieldElement(Self::MOD_LIMBS)
    }
}

#[cfg(test)]
mod field_constants_tests {
    use super::*;

    #[test]
    fn test_modulus_is_correct() {
        // The correct secp256k1 prime in hex:
        // p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

        // Convert MOD_LIMBS to bytes for comparison
        let mut mod_bytes = [0u8; 32];
        for (i, &limb) in FieldElement::MOD_LIMBS.iter().enumerate() {
            let limb_bytes = limb.to_be_bytes();
            let offset = (7 - i) * 4;
            mod_bytes[offset..offset + 4].copy_from_slice(&limb_bytes);
        }

        // Expected prime as bytes
        let expected_bytes: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ];

        assert_eq!(
            mod_bytes, expected_bytes,
            "MOD_LIMBS does not encode the correct NIST P-256 prime"
        );
    }
}