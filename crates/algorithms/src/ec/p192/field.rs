//! P-192 field arithmetic implementation

use crate::ec::p192::constants::P192_FIELD_ELEMENT_SIZE;
use crate::error::{Error, Result};
use dcrypt_internal::constant_time::{Choice, ConditionallySelectable};

/// Number of 32‐bit limbs for a P-192 field element (6 × 32 = 192 bits)
const NLIMBS: usize = 6;

/// NIST P-192 coefficient b (big-endian, 24 bytes)
pub const B: [u8; 24] = [
    0x64, 0x21, 0x05, 0x19, 0xE5, 0x9C, 0x80, 0xE7, 0x0F, 0xA7, 0xE9, 0xAB, 0x72, 0x24, 0x30, 0x49,
    0xFE, 0xB8, 0xDE, 0xEC, 0xC1, 0x46, 0xB9, 0xB1,
];

/// P-192 field element representing values in 𝔽ₚ, where
/// p = 2¹⁹² − 2⁶⁴ − 1.
/// Internally stored as 6 little‐endian 32‐bit limbs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldElement(pub(crate) [u32; NLIMBS]);

impl FieldElement {
    /* ---------------------------------------------------------------- */
    /*  NIST P-192 Field Constants (little‐endian 32‐bit limbs)        */
    /* ---------------------------------------------------------------- */

    /// p = 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF FFFFFFFF
    /// which equals 2¹⁹² − 2⁶⁴ − 1.
    /// Stored as six 32-bit words, little‐endian.
    /// Big‐endian words: [FFFFFFFF, FFFFFFFF, FFFFFFFF, FFFFFFFE, FFFFFFFF, FFFFFFFF]
    /// Little‐endian limbs become: [FFFFFFFF, FFFFFFFF, FFFFFFFE, FFFFFFFF, FFFFFFFF, FFFFFFFF]
    pub(crate) const MOD_LIMBS: [u32; NLIMBS] = [
        0xFFFFFFFF, // least significant
        0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, // most significant
    ];

    /// a = −3 mod p = p − 3 = 2¹⁹² − 2⁶⁴ − 4.
    /// In limbs that is:
    /// subtract 3 from the least‐significant limb 0xFFFFFFFF → 0xFFFFFFFC.
    pub(crate) const A_M3: [u32; NLIMBS] = [
        0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    ];

    /* ================================================================= */
    /*  Tiny helpers                                                     */
    /* ================================================================= */

    /// Build a field element from a small literal (`0 ≤ n < 2³²`)
    #[inline]
    pub fn from_u32(n: u32) -> Self {
        let mut limbs = [0u32; NLIMBS];
        limbs[0] = n;
        FieldElement(limbs)
    }

    /// The additive identity: 0
    #[inline]
    pub fn zero() -> Self {
        FieldElement([0u32; NLIMBS])
    }

    /// The multiplicative identity: 1
    #[inline]
    pub fn one() -> Self {
        let mut limbs = [0u32; NLIMBS];
        limbs[0] = 1;
        FieldElement(limbs)
    }

    /// Create a field element from big‐endian bytes.
    /// Validates that the value < p. Returns Err if ≥ p.
    pub fn from_bytes(bytes: &[u8; P192_FIELD_ELEMENT_SIZE]) -> Result<Self> {
        // Convert big‐endian → little‐endian limbs
        let mut limbs = [0u32; NLIMBS];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let offset = (NLIMBS - 1 - i) * 4;
            *limb = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
        }
        // ── canonicalise ───────────────────────────────────────────────
        let (sub, borrow) = Self::sbb6(limbs, Self::MOD_LIMBS);
        if borrow == 1 {
            // limbs < p  → already canonical
            return Ok(FieldElement(limbs));
        }

        // limbs ≥ p
        if limbs == Self::MOD_LIMBS {
            // exact modulus is forbidden
            return Err(Error::param("FieldElement P-192", "Value ≥ modulus"));
        }

        // Reduce once (limbs − p) — always < p now
        Ok(FieldElement(sub))
    }

    /// Convert this field element into big‐endian bytes.
    pub fn to_bytes(&self) -> [u8; P192_FIELD_ELEMENT_SIZE] {
        let mut out = [0u8; P192_FIELD_ELEMENT_SIZE];
        for (i, &limb) in self.0.iter().enumerate() {
            let limb_bytes = limb.to_be_bytes();
            let offset = (NLIMBS - 1 - i) * 4;
            out[offset..offset + 4].copy_from_slice(&limb_bytes);
        }
        out
    }

    /// Constant‐time check: is self < p ?
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        let (_, borrow) = Self::sbb6(self.0, Self::MOD_LIMBS);
        // If borrow == 1, then self < p
        borrow == 1
    }

    /// Check if element is zero
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&w| w == 0)
    }

    /// Return true if the element is odd (least‐significant bit = 1).
    pub fn is_odd(&self) -> bool {
        (self.0[0] & 1) == 1
    }

    /// Constant‐time addition: (self + other) mod p
    pub fn add(&self, other: &Self) -> Self {
        // 1. Full 192-bit addition
        let (sum, carry) = Self::adc6(self.0, other.0);

        // 2. Reduce if necessary
        // If carry = 1 or sum >= p, subtract p
        let (reduced, borrow) = Self::sbb6(sum, Self::MOD_LIMBS);
        let need_reduce = (carry | (borrow ^ 1)) & 1;

        Self::conditional_select(&sum, &reduced, Choice::from(need_reduce as u8))
    }

    /// Constant‐time subtraction: (self - other) mod p
    pub fn sub(&self, other: &Self) -> Self {
        let (diff, borrow) = Self::sbb6(self.0, other.0);
        // If borrow == 1, we add p back
        let (diff_plus_p, _) = Self::adc6(diff, Self::MOD_LIMBS);
        Self::conditional_select(&diff, &diff_plus_p, Choice::from(borrow as u8))
    }

    /// Field multiplication: (self * other) mod p
    /// Implements schoolbook 6×6 → 12‐limb product, then reduction
    pub fn mul(&self, other: &Self) -> Self {
        // Phase 1: 6×6 → 12 128-bit partial accumulators
        let mut t = [0u128; NLIMBS * 2];
        for i in 0..NLIMBS {
            for j in 0..NLIMBS {
                t[i + j] += (self.0[i] as u128) * (other.0[j] as u128);
            }
        }

        // Phase 2: Carry‐propagate into 12 × u32 limbs
        let mut wide = [0u32; NLIMBS * 2];
        let mut carry: u128 = 0;
        for i in 0..(NLIMBS * 2) {
            let v = t[i] + carry;
            wide[i] = (v & 0xFFFF_FFFF) as u32;
            carry = v >> 32;
        }

        // Phase 3: Reduce 12 limbs → 6 limbs mod p
        Self::reduce_wide(wide)
    }

    /// Field squaring: (self²) mod p
    #[inline(always)]
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Compute multiplicative inverse via Fermat: a^(p-2) mod p
    pub fn invert(&self) -> Result<Self> {
        if self.is_zero() {
            return Err(Error::param("FieldElement P-192", "Inverse of zero"));
        }

        // P-192 prime: p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF
        // p-2 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFD
        const P_MINUS_2: [u8; 24] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD,
        ];

        // Binary exponentiation
        let mut result = FieldElement::one();
        let base = self.clone();

        for &byte in P_MINUS_2.iter() {
            for bit in (0..8).rev() {
                result = result.square();
                if (byte >> bit) & 1 == 1 {
                    result = result.mul(&base);
                }
            }
        }

        Ok(result)
    }

    /// Negate this field element: returns p - self if non-zero, else zero
    pub fn negate(&self) -> Self {
        if self.is_zero() {
            self.clone()
        } else {
            FieldElement::zero().sub(self)
        }
    }

    /// Compute square root using the fact that p ≡ 3 (mod 4)
    /// For such primes, sqrt(x) = x^((p+1)/4)
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() {
            return Some(FieldElement::zero());
        }

        // Correct exponent  (p + 1) / 4  =  2¹⁹⁰ − 2⁶²
        const EXP: [u8; 24] = [
            0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // Compute self^exp using square-and-multiply
        let mut result = FieldElement::one();
        let base = self.clone();

        for &byte in EXP.iter() {
            for i in (0..8).rev() {
                result = result.square();
                if (byte >> i) & 1 == 1 {
                    result = result.mul(&base);
                }
            }
        }

        // Verify that result^2 == self
        if result.square() == *self {
            Some(result)
        } else {
            None
        }
    }

    /* ================================================================= */
    /*  Private helper methods (constant‐time arithmetic)                */
    /* ================================================================= */

    /// 6‐limb addition with carry
    #[inline(always)]
    fn adc6(a: [u32; 6], b: [u32; 6]) -> ([u32; 6], u32) {
        let mut r = [0u32; 6];
        let mut carry = 0u64;
        for ((&a_limb, &b_limb), r_limb) in a.iter().zip(b.iter()).zip(r.iter_mut()) {
            let tmp = (a_limb as u64) + (b_limb as u64) + carry;
            *r_limb = (tmp & 0xFFFF_FFFF) as u32;
            carry = tmp >> 32;
        }
        (r, carry as u32)
    }

    /// 6‐limb subtraction with borrow (constant-time)
    #[inline(always)]
    fn sbb6(a: [u32; 6], b: [u32; 6]) -> ([u32; 6], u32) {
        let mut r = [0u32; 6];
        let mut borrow = 0u32;

        for ((&a_limb, &b_limb), r_limb) in a.iter().zip(b.iter()).zip(r.iter_mut()) {
            //  Compute:  a[i] – b[i] – borrow
            //
            //  `sub` is done in u64 to avoid rust's 'add with borrow'
            //   undefined-behaviour rules, then truncated back to 32 bits.
            let ai = a_limb as u64;
            let bi = b_limb as u64;
            let tmp = ai.wrapping_sub(bi + borrow as u64);

            *r_limb = tmp as u32;

            // New borrow = 1  iff  ai < bi + old_borrow
            borrow = (ai < bi + borrow as u64) as u32;
        }

        (r, borrow)
    }

    /// Constant‐time select: if flag == 0 return a else return b
    fn conditional_select(a: &[u32; 6], b: &[u32; 6], flag: Choice) -> Self {
        let mut out = [0u32; 6];
        for ((a_limb, b_limb), out_limb) in a.iter().zip(b.iter()).zip(out.iter_mut()) {
            *out_limb = u32::conditional_select(a_limb, b_limb, flag);
        }
        FieldElement(out)
    }

    /// Reduce a 12-word (384-bit) value modulo  
    /// `p = 2¹⁹² − 2⁶⁴ − 1`.
    ///
    /// Algorithm: FIPS-186-5 B.3.3 (low + high + high·2⁶⁴)  
    /// followed by two conditional subtractions of *p*.
    fn reduce_wide(t: [u32; 12]) -> FieldElement {
        //------------------------------------------------------------------
        // step 1  –  r = low + high + (high << 64)
        //------------------------------------------------------------------
        let mut r = [0u64; 6];

        /* low  */
        for (i, r_limb) in r.iter_mut().enumerate() {
            *r_limb = t[i] as u64;
        }

        /* high + high << 64  */
        for j in 0..6 {
            let hi = t[j + 6] as u64;

            r[j] += hi; // + high
            r[(j + 2) % 6] += hi; // + high·2⁶⁴   (wrap at 192)

            // *** extra wrap for j = 4, 5  (hi·2¹⁹² term) ***
            if j >= 4 {
                r[j - 2] += hi; // + hi·2⁶⁴ that
                                //   arises from 2¹⁹² ≡ 2⁶⁴ + 1
            }
        }

        //------------------------------------------------------------------
        // step 2  –  propagate carries once over the six 32-bit limbs
        //------------------------------------------------------------------
        let mut carry = 0u64;
        for limb in &mut r {
            let tmp = *limb + carry;
            *limb = tmp & 0xFFFF_FFFF;
            carry = tmp >> 32;
        }

        //------------------------------------------------------------------
        // step 3  – fold the single residual carry
        //          using  2¹⁹² ≡ 2⁶⁴ + 1  (mod p)
        //------------------------------------------------------------------
        while carry != 0 {
            let c = carry; // c is 1 at most

            let tmp0 = r[0] + c;
            r[0] = tmp0 & 0xFFFF_FFFF;
            carry = tmp0 >> 32;

            let tmp2 = r[2] + c + carry;
            r[2] = tmp2 & 0xFFFF_FFFF;
            carry = tmp2 >> 32;
        }

        //------------------------------------------------------------------
        // step 4  –  at most two conditional subtractions of p
        //------------------------------------------------------------------
        let mut out = [0u32; 6];
        for (i, out_limb) in out.iter_mut().enumerate() {
            *out_limb = r[i] as u32;
        }

        for _ in 0..2 {
            let (sub, borrow) = Self::sbb6(out, Self::MOD_LIMBS);
            /* if borrow == 0  → out ≥ p  → use the subtracted value */
            let selected = Self::conditional_select(&out, &sub, Choice::from((borrow ^ 1) as u8));
            out = selected.0;
        }

        FieldElement(out)
    }
}
