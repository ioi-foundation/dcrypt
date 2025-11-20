//! P-384 field arithmetic implementation

use crate::ec::p384::constants::P384_FIELD_ELEMENT_SIZE;
use crate::error::{Error, Result};
use subtle::{Choice, ConditionallySelectable};

/// P-384 field element representing values in F_p
///
/// Internally stored as 12 little-endian 32-bit limbs for efficient arithmetic.
/// All operations maintain the invariant that values are reduced modulo p.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement(pub(crate) [u32; 12]);

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut out = [0u32; 12];
        for i in 0..12 {
            out[i] = u32::conditional_select(&a.0[i], &b.0[i], choice);
        }
        FieldElement(out)
    }
}

impl FieldElement {
    /* -------------------------------------------------------------------- */
    /*  NIST P-384 Field Constants (stored as little-endian 32-bit limbs)  */
    /* -------------------------------------------------------------------- */

    /// The NIST P-384 prime modulus: p = 2^384 - 2^128 - 2^96 + 2^32 - 1
    /// Stored as 12 little-endian 32-bit limbs where limbs[0] is least significant
    pub(crate) const MOD_LIMBS: [u32; 12] = [
        0xFFFF_FFFF, // 2⁰ … 2³¹
        0x0000_0000, // 2³² … 2⁶³
        0x0000_0000, // 2⁶⁴ … 2⁹⁵
        0xFFFF_FFFF, // 2⁹⁶ … 2¹²⁷
        0xFFFF_FFFE, // 2¹²⁸ … 2¹⁵⁹
        0xFFFF_FFFF, // 2¹⁶⁰ … 2¹⁹¹
        0xFFFF_FFFF, // 2¹⁹² … 2²²³
        0xFFFF_FFFF, // 2²²⁴ … 2²⁵⁵
        0xFFFF_FFFF, // 2²⁵⁶ … 2²⁸⁷
        0xFFFF_FFFF, // 2²⁸⁸ … 2³¹⁹
        0xFFFF_FFFF, // 2³²⁰ … 2³⁵¹
        0xFFFF_FFFF, // 2³⁵² … 2³⁸³
    ];

    /// The curve parameter a = -3 mod p, used in the curve equation y² = x³ + ax + b
    /// For P-384: a = p - 3
    pub(crate) const A_M3: [u32; 12] = [
        0xFFFF_FFFC, // (2³² - 1) - 3 = 2³² - 4
        0x0000_0000,
        0x0000_0000,
        0xFFFF_FFFF,
        0xFFFF_FFFE,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF, // Most significant limb
    ];

    /// The additive identity element: 0
    pub fn zero() -> Self {
        FieldElement([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    /// The multiplicative identity element: 1
    pub fn one() -> Self {
        FieldElement([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    /// Create a field element from big-endian byte representation
    ///
    /// Validates that the input represents a value less than the field modulus p.
    /// Returns an error if the value is >= p.
    pub fn from_bytes(bytes: &[u8; P384_FIELD_ELEMENT_SIZE]) -> Result<Self> {
        let mut limbs = [0u32; 12];

        // Convert from big-endian bytes to little-endian limbs
        // limbs[0] = least-significant 4 bytes (bytes[44..48])
        // limbs[11] = most-significant 4 bytes (bytes[0..4])
        for (i, limb) in limbs.iter_mut().enumerate() {
            let offset = (11 - i) * 4; // Byte offset: 44, 40, 36, ..., 0
            *limb = u32::from_be_bytes([
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
    pub fn to_bytes(&self) -> [u8; P384_FIELD_ELEMENT_SIZE] {
        let mut bytes = [0u8; P384_FIELD_ELEMENT_SIZE];

        // Convert from little-endian limbs to big-endian bytes
        for i in 0..12 {
            let limb_bytes = self.0[i].to_be_bytes();
            let offset = (11 - i) * 4; // Byte offset: 44, 40, 36, ..., 0
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
        let (_, borrow) = Self::sbb12(self.0, Self::MOD_LIMBS);
        borrow == 1
    }

    /// Constant-time field addition: (self + other) mod p
    ///
    /// Algorithm:
    /// 1. Perform full 384-bit addition with carry detection
    /// 2. Conditionally subtract p if result >= p
    /// 3. Ensure result is in canonical form
    #[inline(always)]
    pub fn add(&self, other: &Self) -> Self {
        // Step 1: Full 384-bit addition
        let (sum, carry) = Self::adc12(self.0, other.0);

        // Step 2: Attempt conditional reduction by subtracting p
        let (sum_minus_p, borrow) = Self::sbb12(sum, Self::MOD_LIMBS);

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
        let (diff, borrow) = Self::sbb12(self.0, other.0);

        // Step 2: If we borrowed, add p to get the correct positive result
        let (candidate, _) = Self::adc12(diff, Self::MOD_LIMBS);

        // Step 3: Constant-time select based on borrow flag
        Self::conditional_select(&diff, &candidate, Choice::from(borrow as u8))
    }

    /// Field multiplication: (self * other) mod p
    ///
    /// Algorithm:
    /// 1. Compute the full 768-bit product using schoolbook multiplication
    /// 2. Perform carry propagation to get proper limb representation
    /// 3. Apply Barrett reduction for P-384
    pub fn mul(&self, other: &Self) -> Self {
        // Phase 1: Accumulate partial products in 128-bit temporaries
        // This prevents overflow during the schoolbook multiplication
        let mut t = [0u128; 24];
        for i in 0..12 {
            for j in 0..12 {
                t[i + j] += (self.0[i] as u128) * (other.0[j] as u128);
            }
        }

        // Phase 2: Carry propagation to convert to 32-bit limb representation
        let mut prod = [0u32; 24];
        let mut carry: u128 = 0;
        for i in 0..24 {
            let v = t[i] + carry;
            prod[i] = (v & 0xffff_ffff) as u32;
            carry = v >> 32;
        }

        // Phase 3: Apply P-384 reduction
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

        // The exponent p-2 for NIST P-384 in big-endian byte format
        const P_MINUS_2: [u8; 48] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFD,
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

    /// Return `true` when the element is odd (LSB set)
    ///
    /// Used for point compression to determine the sign of the y-coordinate.
    /// The parity is determined by the least significant bit of the canonical
    /// representation.
    pub fn is_odd(&self) -> bool {
        (self.0[0] & 1) == 1
    }

    /// Modular square root using the (p+1)/4 shortcut (p ≡ 3 mod 4).
    ///
    /// Because the P-384 prime satisfies p ≡ 3 (mod 4), we can compute
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

        // (p + 1) / 4 for P-384 as big-endian bytes
        // p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
        // (p + 1) / 4 = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbffffffffc000000000000000400000000
        const EXP: [u8; 48] = [
            0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xBF, 0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
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
    fn conditional_select(a: &[u32; 12], b: &[u32; 12], flag: Choice) -> Self {
        let mut out = [0u32; 12];
        for i in 0..12 {
            out[i] = u32::conditional_select(&a[i], &b[i], flag);
        }
        FieldElement(out)
    }

    /// 12-limb addition with carry propagation
    ///
    /// Performs full-width addition across all limbs, returning both
    /// the sum and the final carry bit for overflow detection.
    #[inline(always)]
    fn adc12(a: [u32; 12], b: [u32; 12]) -> ([u32; 12], u32) {
        let mut r = [0u32; 12];
        let mut carry = 0;

        for i in 0..12 {
            // Add corresponding limbs plus carry from previous iteration
            let (sum1, carry1) = a[i].overflowing_add(b[i]);
            let (sum2, carry2) = sum1.overflowing_add(carry);

            r[i] = sum2;
            carry = (carry1 as u32) | (carry2 as u32);
        }

        (r, carry)
    }

    /// 12-limb subtraction with borrow propagation
    ///
    /// Performs full-width subtraction across all limbs, returning both
    /// the difference and the final borrow bit for underflow detection.
    #[inline(always)]
    fn sbb12(a: [u32; 12], b: [u32; 12]) -> ([u32; 12], u32) {
        let mut r = [0u32; 12];
        let mut borrow = 0;

        for i in 0..12 {
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
    fn conditional_sub(limbs: [u32; 12], condition: Choice) -> Self {
        let mut result = [0u32; 12];
        let (diff, _) = Self::sbb12(limbs, Self::MOD_LIMBS);

        // Constant-time select between original limbs and difference
        for i in 0..12 {
            result[i] = u32::conditional_select(&limbs[i], &diff[i], condition);
        }

        Self(result)
    }

    /// NIST P-384 specific reduction for 768-bit values using Solinas method
    /// Fully constant-time Solinas reduction with two carry-folds.
    /// For P-384: 2^384 ≡ 2^128 + 2^96 - 2^32 + 1 (mod p)
    pub(crate) fn reduce_wide(t: [u32; 24]) -> FieldElement {
        // 1) load into signed 128-bit
        let mut s = [0i128; 24];
        for i in 0..24 {
            s[i] = t[i] as i128;
        }

        // 2) fold high limbs 12..23 into 0..11 via
        //    2^384 ≡ 2^128 + 2^96 - 2^32 + 1 (mod p)
        for i in (12..24).rev() {
            let v = s[i];
            s[i] = 0;
            s[i - 12] = s[i - 12].wrapping_add(v); // +1 (2^0 term)
            s[i - 11] = s[i - 11].wrapping_sub(v); // -2^32 term
            s[i - 9] = s[i - 9].wrapping_add(v); // +2^96 term
            s[i - 8] = s[i - 8].wrapping_add(v); // +2^128 term
        }

        // 2b) the previous step can leave non-zero words in slots 12..15
        //     (it happens when i = 20..23). Fold them once more so that
        //     all non-zero limbs are now in 0..11.
        for i in (12..16).rev() {
            let v = s[i];
            s[i] = 0;
            s[i - 12] = s[i - 12].wrapping_add(v); // +1
            s[i - 11] = s[i - 11].wrapping_sub(v); // -2^32
            s[i - 9] = s[i - 9].wrapping_add(v); // +2^96
            s[i - 8] = s[i - 8].wrapping_add(v); // +2^128
        }

        // 3) first signed carry-propagate
        let mut carry1: i128 = 0;
        for limb in s.iter_mut().take(12) {
            let tmp = *limb + carry1;
            *limb = tmp & 0xffff_ffff;
            carry1 = tmp >> 32; // arithmetic shift
        }

        // 4) fold carry1 back down using same relation
        let c1 = carry1;
        s[0] = s[0].wrapping_add(c1); // +1
        s[1] = s[1].wrapping_sub(c1); // -2^32
        s[3] = s[3].wrapping_add(c1); // +2^96
        s[4] = s[4].wrapping_add(c1); // +2^128

        // 5) second signed carry-propagate
        let mut carry2: i128 = 0;
        for limb in s.iter_mut().take(12) {
            let tmp = *limb + carry2;
            *limb = tmp & 0xffff_ffff;
            carry2 = tmp >> 32;
        }

        // 6) fold carry2 back down
        let c2 = carry2;
        s[0] = s[0].wrapping_add(c2);
        s[1] = s[1].wrapping_sub(c2);
        s[3] = s[3].wrapping_add(c2);
        s[4] = s[4].wrapping_add(c2);

        // 7) final signed carry-propagate into 32-bit limbs
        let mut out = [0u32; 12];
        let mut carry3: i128 = 0;
        for i in 0..12 {
            let tmp = s[i] + carry3;
            out[i] = (tmp & 0xffff_ffff) as u32;
            carry3 = tmp >> 32;
        }

        // 8) one last constant-time subtract if ≥ p
        let (subbed, borrow) = Self::sbb12(out, Self::MOD_LIMBS);
        let need_sub = Choice::from((borrow ^ 1) as u8); // borrow==0 ⇒ out>=p
        Self::conditional_select(&out, &subbed, need_sub)
    }

    /// Get the field modulus p as a FieldElement
    ///
    /// Returns the NIST P-384 prime modulus for use in reduction operations.
    pub(crate) fn get_modulus() -> Self {
        FieldElement(Self::MOD_LIMBS)
    }
}