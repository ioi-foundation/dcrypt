//! P-224 field arithmetic implementation

use crate::ec::p224::constants::P224_FIELD_ELEMENT_SIZE;
use crate::error::{Error, Result};
use dcrypt_internal::{
    constant_time::{Choice, ConditionallySelectable},
    Zeroize, Zeroizing,
};

/// P-224 field element representing values in F_p
///
/// Internally stored as 7 little-endian 32-bit limbs for efficient arithmetic.
/// All operations maintain the invariant that values are reduced modulo p.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldElement(pub(crate) [u32; 7]);

// P-224 does not need the `ConditionallySelectable: Copy` compromise: its
// field element remains non-`Copy`. Explicit arithmetic buffers still use
// `Zeroizing` so every initialized owner is cleared on every exit path.
impl Default for FieldElement {
    fn default() -> Self {
        Self::zero()
    }
}

impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// put this right after `#[derive(...)]` in field.rs –
//  it's only needed for ad-hoc tests, not for production code:
impl From<[u32; 7]> for FieldElement {
    fn from(limbs: [u32; 7]) -> Self {
        FieldElement(limbs)
    }
}

impl FieldElement {
    /* -------------------------------------------------------------------- */
    /*  NIST P-224 Field Constants (stored as little-endian 32-bit limbs)  */
    /* -------------------------------------------------------------------- */

    /// The NIST P-224 prime modulus: p = 2^224 - 2^96 + 1
    /// Stored as 7 little-endian 32-bit limbs where limbs[0] is least significant
    pub(crate) const MOD_LIMBS: [u32; 7] = [
        0x0000_0001, // 2⁰ … 2³¹
        0x0000_0000, // 2³² … 2⁶³
        0x0000_0000, // 2⁶⁴ … 2⁹⁵
        0xFFFF_FFFF, // 2⁹⁶ … 2¹²⁷
        0xFFFF_FFFF, // 2¹²⁸ … 2¹⁵⁹
        0xFFFF_FFFF, // 2¹⁶⁰ … 2¹⁹¹
        0xFFFF_FFFF, // 2¹⁹² … 2²²³
    ];

    /// The curve parameter a = -3 mod p, used in the curve equation y² = x³ + ax + b
    /// For P-224: a = p - 3
    pub(crate) const A_M3: [u32; 7] = [
        0xFFFF_FFFE, // (2³² - 1) - 2 = 2³² - 3 (with borrow from p)
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFE,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
    ];

    /// The additive identity element: 0
    pub fn zero() -> Self {
        FieldElement([0, 0, 0, 0, 0, 0, 0])
    }

    /// The multiplicative identity element: 1
    pub fn one() -> Self {
        FieldElement([1, 0, 0, 0, 0, 0, 0])
    }

    /// Create a field element from big-endian byte representation
    ///
    /// Validates that the input represents a value less than the field modulus p.
    /// Returns an error if the value is >= p.
    pub fn from_bytes(bytes: &[u8; P224_FIELD_ELEMENT_SIZE]) -> Result<Self> {
        let mut limbs = Zeroizing::new([0u32; 7]);

        // Convert from big-endian bytes to little-endian limbs
        // limbs[0] = least-significant 4 bytes (bytes[24..28])
        // limbs[6] = most-significant 4 bytes (bytes[0..4])
        for (i, limb) in limbs.iter_mut().enumerate() {
            let offset = (6 - i) * 4; // Byte offset: 24, 20, 16, ..., 0
            *limb = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
        }

        // Validate that the value is in the field (< p)
        let fe = Zeroizing::new(FieldElement(limbs.into_inner()));
        if !fe.is_valid() {
            return Err(Error::param(
                "FieldElement",
                "Value must be less than the field modulus",
            ));
        }

        Ok(fe.into_inner())
    }

    /// Convert field element to big-endian byte representation
    pub fn to_bytes(&self) -> [u8; P224_FIELD_ELEMENT_SIZE] {
        let mut bytes = Zeroizing::new([0u8; P224_FIELD_ELEMENT_SIZE]);

        // Convert from little-endian limbs to big-endian bytes
        for i in 0..7 {
            let limb_bytes = Zeroizing::new(self.0[i].to_be_bytes());
            let offset = (6 - i) * 4; // Byte offset: 24, 20, 16, ..., 0
            bytes[offset..offset + 4].copy_from_slice(&limb_bytes[..]);
        }
        bytes.into_inner()
    }

    /// Constant-time validation that the field element is in canonical form (< p)
    ///
    /// Uses constant-time subtraction to check if self < p without branching.
    /// Returns true if the element is valid (< p), false otherwise.
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        // Attempt to subtract p from self
        // If subtraction requires a borrow, then self < p (valid)
        let (_difference, borrow) = Self::sbb7(&self.0, &Self::MOD_LIMBS);
        borrow == 1
    }

    /// Constant-time field addition: (self + other) mod p
    ///
    /// Algorithm:
    /// 1. Perform full 224-bit addition with carry detection
    /// 2. Conditionally subtract p if result >= p
    /// 3. Ensure result is in canonical form
    #[inline(always)]
    pub fn add(&self, other: &Self) -> Self {
        // Step 1: Full 224-bit addition
        let (sum, carry) = Self::adc7(&self.0, &other.0);

        // Step 2: Attempt conditional reduction by subtracting p
        let (sum_minus_p, borrow) = Self::sbb7(&sum, &Self::MOD_LIMBS);

        // Step 3: Choose reduced value if:
        //   - Addition overflowed (carry == 1), OR
        //   - Subtraction didn't borrow (borrow == 0), meaning sum >= p
        let need_reduce = (carry | (borrow ^ 1)) & 1;
        let reduced = Zeroizing::new(Self::conditional_select(
            &sum,
            &sum_minus_p,
            Choice::from(need_reduce as u8),
        ));

        // Step 4: Final canonical reduction
        let result = Zeroizing::new(reduced.conditional_sub_p());
        result.into_inner()
    }

    /// Constant-time field subtraction: (self - other) mod p
    ///
    /// Algorithm:
    /// 1. Perform limb-wise subtraction
    /// 2. If subtraction borrows, add p to get the correct positive result
    pub fn sub(&self, other: &Self) -> Self {
        // Step 1: Raw subtraction
        let (diff, borrow) = Self::sbb7(&self.0, &other.0);

        // Step 2: If we borrowed, add p to get the correct positive result
        let (candidate, _carry) = Self::adc7(&diff, &Self::MOD_LIMBS);

        // Step 3: Constant-time select based on borrow flag
        let result = Zeroizing::new(Self::conditional_select(
            &diff,
            &candidate,
            Choice::from(borrow as u8),
        ));
        result.into_inner()
    }

    /// Field multiplication: (self * other) mod p
    ///
    /// Algorithm:
    /// 1. Compute the full 448-bit product using schoolbook multiplication
    /// 2. Perform carry propagation to get proper limb representation
    /// 3. Apply NIST P-224 specific fast reduction
    pub fn mul(&self, other: &Self) -> Self {
        // Phase 1: Accumulate partial products in 128-bit temporaries
        // This prevents overflow during the schoolbook multiplication
        let mut t = Zeroizing::new([0u128; 14]);
        for i in 0..7 {
            for j in 0..7 {
                t[i + j] += (self.0[i] as u128) * (other.0[j] as u128);
            }
        }

        // Phase 2: Carry propagation to convert to 32-bit limb representation
        let mut prod = Zeroizing::new([0u32; 14]);
        let mut carry: u128 = 0;
        for i in 0..14 {
            let v = t[i] + carry;
            prod[i] = (v & 0xffff_ffff) as u32;
            carry = v >> 32;
        }

        // Phase 3: Apply NIST P-224 fast reduction
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

        // The exponent p-2 for NIST P-224 in big-endian byte format
        const P_MINUS_2: [u8; 28] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];

        // Binary exponentiation: compute self^(p-2) mod p
        let mut result = Zeroizing::new(FieldElement::one());
        let mut base = Zeroizing::new(self.clone());

        // Process each bit of the exponent from least to most significant
        for &byte in P_MINUS_2.iter().rev() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    let product = Zeroizing::new(result.mul(&base));
                    result.zeroize();
                    *result = product.into_inner();
                }
                let squared = Zeroizing::new(base.square());
                base.zeroize();
                *base = squared.into_inner();
            }
        }

        Ok(result.into_inner())
    }

    /// Check if the field element represents zero
    ///
    /// Constant-time check across all limbs to determine if the
    /// field element is the additive identity.
    pub fn is_zero(&self) -> bool {
        let mut any = Zeroizing::new(0u32);
        for &limb in &self.0 {
            *any |= limb;
        }
        *any == 0
    }

    /// Return `true` if the field element is odd (least-significant bit set)
    ///
    /// Used for point compression to determine the sign of the y-coordinate.
    /// The parity is determined by the least significant bit of the canonical
    /// representation.
    pub fn is_odd(&self) -> bool {
        (self.0[0] & 1) == 1
    }

    /// Compute the modular square root using Tonelli‑Shanks.
    ///
    /// Because the P‑224 prime satisfies **p ≡ 1 (mod 4)**, we cannot use the
    /// simple `(p+1)/4` exponent trick.  Instead we implement the general
    /// Tonelli‑Shanks algorithm which works for any odd prime.
    ///
    /// ‑ Returns `Some(root)` with *any* square‑root of `self` when the element
    ///   is a quadratic residue.
    /// ‑ Returns `None` when no square‑root exists.
    pub fn sqrt(&self) -> Option<Self> {
        // 0 and 1 are their own square roots – handle these fast.
        if self.is_zero() {
            return Some(Self::zero());
        }
        if self == &Self::one() {
            return Some(Self::one());
        }

        /* ------------------------------------------------------------------
         * 1.  Check quadratic‑residue with Euler's criterion
         * ------------------------------------------------------------------ */
        // (p‑1)/2 = 2²²³ − 2⁹⁵
        // In hex: one 0x7F, fifteen 0xFF, one 0x80, eleven 0x00
        const LEGENDRE_EXP: [u8; 28] = [
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let legendre = Zeroizing::new(self.pow(&LEGENDRE_EXP));
        if &*legendre != &Self::one() {
            return None; // not a quadratic residue
        }

        /* ------------------------------------------------------------------
         * 2.  Tonelli‑Shanks setup   (p‑1 = q · 2^s  with  q odd)
         * ------------------------------------------------------------------ */
        // For P‑224   s = 96,   q = 2¹²⁸ − 1.
        const S: usize = 96;
        // Constant q in 28‑byte BE: 12 leading zeros + 16 × 0xFF.
        const Q: [u8; 28] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 12 × 0
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF,
        ];
        // (q+1)/2  = 2¹²⁷  → 0x80 followed by 15 × 0, plus the 12 zero prefix.
        const QPLUS1_OVER2: [u8; 28] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        /* r = self^{(q+1)/2};      t = self^q;      c = z^q */
        // We still need a non‑residue z.  Trial small integers 2,3,4…
        let mut z = Zeroizing::new(Self::one().add(&Self::one())); // 2
        loop {
            // Use the same corrected LEGENDRE_EXP for consistency
            let z_legendre = Zeroizing::new(z.pow(&LEGENDRE_EXP));
            if &*z_legendre != &Self::one() {
                break;
            }
            let next = Zeroizing::new(z.add(&Self::one()));
            z.zeroize();
            *z = next.into_inner(); // next integer
        }

        let mut c = Zeroizing::new(z.pow(&Q));
        let mut t = Zeroizing::new(self.pow(&Q));
        let mut r = Zeroizing::new(self.pow(&QPLUS1_OVER2));
        let mut m = S;

        /* ------------------------------------------------------------------
         * 3.  Main Tonelli‑Shanks loop
         * ------------------------------------------------------------------ */
        while &*t != &Self::one() {
            // Find least i (0 < i < m) s.t. t^{2^i} = 1.
            let mut i = 1usize;
            let mut t2i = Zeroizing::new(t.square());
            while i < m {
                if &*t2i == &Self::one() {
                    break;
                }
                let squared = Zeroizing::new(t2i.square());
                t2i.zeroize();
                *t2i = squared.into_inner();
                i += 1;
            }

            // If we didn't find such i, something is inconsistent.
            if i == m {
                return None;
            }

            // b = c^{2^{m‑i‑1}}
            let mut b = Zeroizing::new((*c).clone());
            for _ in 0..(m - i - 1) {
                let squared = Zeroizing::new(b.square());
                b.zeroize();
                *b = squared.into_inner();
            }

            // Updates
            let updated_r = Zeroizing::new(r.mul(&b));
            r.zeroize();
            *r = updated_r.into_inner();
            let b2 = Zeroizing::new(b.square());
            let updated_t = Zeroizing::new(t.mul(&b2));
            t.zeroize();
            *t = updated_t.into_inner();
            c.zeroize();
            *c = b2.into_inner();
            m = i;
        }

        Some(r.into_inner())
    }

    /* ----------------------------------------------------------------------
     * Small helper: generic square‑and‑multiply  (base^exp)  where exp is a
     * big‑endian byte slice.
     * ------------------------------------------------------------------ */
    fn pow(&self, exp_be: &[u8]) -> Self {
        let mut result = Zeroizing::new(Self::one());
        let mut base = Zeroizing::new(self.clone());

        // Iterate bits from LSB → MSB  (rev bytes, then 0..7)
        for &byte in exp_be.iter().rev() {
            let mut b = byte;
            for _ in 0..8 {
                if (b & 1) == 1 {
                    let product = Zeroizing::new(result.mul(&base));
                    result.zeroize();
                    *result = product.into_inner();
                }
                let squared = Zeroizing::new(base.square());
                base.zeroize();
                *base = squared.into_inner();
                b >>= 1;
            }
        }

        result.into_inner()
    }

    // Private helper methods

    /// Constant-time conditional selection between two limb arrays
    ///
    /// Returns a if flag == 0, returns b if flag == 1
    /// Used for branchless operations to maintain constant-time guarantees.
    fn conditional_select(a: &[u32; 7], b: &[u32; 7], flag: Choice) -> Self {
        let mut out = Zeroizing::new([0u32; 7]);
        for (i, out_elem) in out.iter_mut().enumerate() {
            *out_elem = u32::conditional_select(&a[i], &b[i], flag);
        }
        FieldElement(out.into_inner())
    }

    /// 7-limb addition with carry propagation
    ///
    /// Performs full-width addition across all limbs, returning both
    /// the sum and the final carry bit for overflow detection.
    #[inline(always)]
    fn adc7(a: &[u32; 7], b: &[u32; 7]) -> (Zeroizing<[u32; 7]>, u32) {
        let mut r = Zeroizing::new([0u32; 7]);
        let mut carry = 0;

        for (i, r_elem) in r.iter_mut().enumerate() {
            // Add corresponding limbs plus carry from previous iteration
            let (sum1, carry1) = a[i].overflowing_add(b[i]);
            let (sum2, carry2) = sum1.overflowing_add(carry);

            *r_elem = sum2;
            carry = (carry1 as u32) | (carry2 as u32);
        }

        (r, carry)
    }

    /// 7-limb subtraction with borrow propagation
    ///
    /// Performs full-width subtraction across all limbs, returning both
    /// the difference and the final borrow bit for underflow detection.
    #[inline(always)]
    fn sbb7(a: &[u32; 7], b: &[u32; 7]) -> (Zeroizing<[u32; 7]>, u32) {
        let mut r = Zeroizing::new([0u32; 7]);
        let mut borrow = 0;

        for (i, r_elem) in r.iter_mut().enumerate() {
            // Subtract corresponding limbs minus borrow from previous iteration
            let (diff1, borrow1) = a[i].overflowing_sub(b[i]);
            let (diff2, borrow2) = diff1.overflowing_sub(borrow);

            *r_elem = diff2;
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
        Self::conditional_sub(&self.0, needs_sub)
    }

    /// Conditionally subtract the field modulus p based on a boolean condition
    ///
    /// Uses constant-time selection to avoid branching while maintaining
    /// the option to perform the subtraction.
    fn conditional_sub(limbs: &[u32; 7], condition: Choice) -> Self {
        let mut result = Zeroizing::new([0u32; 7]);
        let (diff, _borrow) = Self::sbb7(limbs, &Self::MOD_LIMBS);

        // Constant-time select between original limbs and difference
        for (i, result_elem) in result.iter_mut().enumerate() {
            *result_elem = u32::conditional_select(&limbs[i], &diff[i], condition);
        }

        Self(result.into_inner())
    }

    /// Reduce a 448-bit value (14 little-endian `u32` limbs) modulo  
    ///  p = 2²²⁴ − 2⁹⁶ + 1  (NIST P-224).
    ///
    /// Strategy (constant-time Solinas):
    /// 1.  Fold limbs 7‥13 back into 0‥6 with
    ///     2²²⁴ ≡ 2⁹⁶ − 1   (mod p)
    ///     → `s[i-4] += v` and `s[i-7] -= v`.
    ///     A single top-down pass is enough because we process the new "middle"
    ///     limbs (indices 7-9) later in the same loop.
    /// 2.  Signed carry-propagate over the 7 low limbs.
    /// 3.  Whatever carry leaked beyond bit 224 is one more "2²²⁴"; fold it
    ///     again with the *same* relation (add to limb 3, subtract from limb 0).
    /// 4.  A second carry sweep + one more tiny fold guarantee canonical limbs.
    /// 5.  Final constant-time subtract of p if the value is ≥ p.
    #[inline(always)]
    pub(crate) fn reduce_wide(t: Zeroizing<[u32; 14]>) -> FieldElement {
        /* ── 1. load into signed 128-bit ─────────────────────────────────── */
        let mut s = Zeroizing::new([0i128; 14]);
        for (i, s_elem) in s.iter_mut().enumerate().take(14) {
            *s_elem = t[i] as i128;
        }

        /* ── 2. main folding pass (7‥13 → 0‥6) ──────────────────────────── */
        for i in (7..14).rev() {
            let v = s[i];
            s[i] = 0;
            s[i - 7] = s[i - 7].wrapping_sub(v); // −v · 2^(32(i-7))
            s[i - 4] = s[i - 4].wrapping_add(v); // +v · 2^(32(i-4))
        }

        /* ── 3. first signed carry sweep over the 7 low limbs ────────────── */
        let mut carry: i128 = 0;
        for elem in s.iter_mut().take(7) {
            let tmp = *elem + carry;
            *elem = tmp & 0xffff_ffff;
            carry = tmp >> 32; // arithmetic shift
        }

        /* ── 4. fold that carry (k · 2²²⁴) once more:  +k→limb3  −k→limb0  */
        s[3] = s[3].wrapping_add(carry);
        s[0] = s[0].wrapping_sub(carry);

        /* ── 5. second signed carry sweep ────────────────────────────────── */
        carry = 0;
        for elem in s.iter_mut().take(7) {
            let tmp = *elem + carry;
            *elem = tmp & 0xffff_ffff;
            carry = tmp >> 32;
        }

        /* ── 6. (tiny) second carry fold, identical indices ─────────────── */
        s[3] = s[3].wrapping_add(carry);
        s[0] = s[0].wrapping_sub(carry);

        /* ── 7. final carry sweep into ordinary u32 limbs ────────────────── */
        let mut out = Zeroizing::new([0u32; 7]);
        carry = 0;
        for (i, out_elem) in out.iter_mut().enumerate() {
            let tmp = s[i] + carry;
            *out_elem = (tmp & 0xffff_ffff) as u32;
            carry = tmp >> 32;
        }
        let _ = carry;

        /* ── 8. last conditional subtract if ≥ p ─────────────────────────── */
        let (sub, borrow) = Self::sbb7(&out, &Self::MOD_LIMBS);
        let need_sub = Choice::from((borrow ^ 1) as u8); // borrow==0 ⇒ out≥p
        let result = Zeroizing::new(Self::conditional_select(&out, &sub, need_sub));
        result.into_inner()
    }

    /// Get the field modulus p as a FieldElement
    ///
    /// Returns the NIST P-224 prime modulus for use in reduction operations.
    pub(crate) fn get_modulus() -> Self {
        FieldElement(Self::MOD_LIMBS)
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn zeroize_clears_owned_non_copy_field_element() {
        let original = FieldElement::one();
        let mut owned_clone = original.clone();

        owned_clone.zeroize();

        assert!(owned_clone.is_zero());
        assert!(!original.is_zero());
    }
}
