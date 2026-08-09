//! P-521 field arithmetic implementation (Fₚ for p = 2^521 − 1)
//!
//! This file implements the heavy-weight primitives for P-521 field arithmetic:
//! full-width multiplication, squaring, modular inversion and modular square-root.
//! The design philosophy matches our existing P-256 / P-384 field modules:
//!   * pure Rust, constant-time where it matters.
//!   * 32-bit little-endian limbs stored in `[u32; 17]` (544 bits, only the
//!     lower 521 are used).
//!   * reduction uses the Mersenne trick for p = 2^521 − 1:
//!     (H · 2^521 + L)  ≡  H + L   (mod p)

use crate::ec::p521::constants::{
    p521_bytes_to_limbs, p521_limbs_to_bytes, P521_FIELD_ELEMENT_SIZE, P521_LIMBS,
};
use crate::error::{Error, Result};
use dcrypt_internal::constant_time::{Choice, ConditionallySelectable};
use dcrypt_internal::zeroing::Zeroize;

/// P-521 field element representing values in Fₚ (p = 2^521 − 1).
/// Internally stored as 17 little-endian 32-bit limbs; only the low 9 bits
/// of limb 16 are significant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldElement(pub(crate) [u32; P521_LIMBS]);

impl Zeroize for FieldElement {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/* ========================================================================== */
/*  Constants                                                                 */
/* ========================================================================== */

impl FieldElement {
    /// p = 2^521 − 1  (little-endian limbs).
    pub(crate) const MOD_LIMBS: [u32; P521_LIMBS] = [
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0x0000_01FF, // limb 16 (only 9 bits used)
    ];

    /// a = −3 mod p  = 2^521 − 4  (little-endian limbs)
    pub(crate) const A_M3: [u32; P521_LIMBS] = [
        0xFFFF_FFFC,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0x0000_01FF,
    ];

    /// The additive identity element: 0
    #[inline]
    pub fn zero() -> Self {
        FieldElement([0u32; P521_LIMBS])
    }

    /// The multiplicative identity element: 1
    #[inline]
    pub fn one() -> Self {
        let mut limbs = [0u32; P521_LIMBS];
        limbs[0] = 1;
        Self(limbs)
    }
}

/* ========================================================================== */
/*  (De)Serialisation                                                         */
/* ========================================================================== */

impl FieldElement {
    /// Create a field element from big-endian byte representation.
    ///
    /// Validates that the input represents a value less than the field modulus p.
    /// Returns an error if the value is >= p.
    pub fn from_bytes(bytes: &[u8; P521_FIELD_ELEMENT_SIZE]) -> Result<Self> {
        let limbs = p521_bytes_to_limbs(bytes);
        let fe = FieldElement(limbs);
        if !fe.is_valid() {
            return Err(Error::param("FieldElement P-521", "Value >= modulus"));
        }
        Ok(fe)
    }

    /// Convert field element to big-endian byte representation
    pub fn to_bytes(&self) -> [u8; P521_FIELD_ELEMENT_SIZE] {
        p521_limbs_to_bytes(&self.0)
    }

    /// Check if the field element represents zero
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        let mut any = 0u32;
        for &limb in &self.0 {
            any |= limb;
        }
        any == 0
    }

    /// Return `true` if the field element is odd (least-significant bit set)
    #[inline(always)]
    pub fn is_odd(&self) -> bool {
        (self.0[0] & 1) == 1
    }

    /// self < p ?   (constant-time)
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        let (_, borrow) = Self::sbb_n(self.0, Self::MOD_LIMBS);
        borrow == 1 // borrow = 1  ⇒  self < p
    }
}

/* ========================================================================== */
/*  Core helpers: limb add / sub                                              */
/* ========================================================================== */

impl FieldElement {
    /// N-limb addition with carry.
    #[inline(always)]
    pub(crate) fn adc_n<const N: usize>(a: [u32; N], b: [u32; N]) -> ([u32; N], u32) {
        let mut out = [0u32; N];
        let mut carry = 0u64;
        for i in 0..N {
            let t = a[i] as u64 + b[i] as u64 + carry;
            out[i] = t as u32;
            carry = t >> 32;
        }
        (out, carry as u32)
    }

    /// N-limb subtraction with borrow.
    #[inline(always)]
    pub(crate) fn sbb_n<const N: usize>(a: [u32; N], b: [u32; N]) -> ([u32; N], u32) {
        let mut out = [0u32; N];
        let mut borrow = 0i64;
        for i in 0..N {
            let t = a[i] as i64 - b[i] as i64 - borrow;
            out[i] = t as u32;
            borrow = (t >> 63) & 1; // 1 if negative
        }
        (out, borrow as u32)
    }

    /// Conditionally select (`flag` = 0 ⇒ *a*, `flag` = 1 ⇒ *b*).
    #[inline(always)]
    fn conditional_select(a: &[u32; P521_LIMBS], b: &[u32; P521_LIMBS], flag: Choice) -> Self {
        let mut out = [0u32; P521_LIMBS];
        for i in 0..P521_LIMBS {
            out[i] = u32::conditional_select(&a[i], &b[i], flag);
        }
        FieldElement(out)
    }

    /// Constant-time conditional swap
    ///
    /// Swaps the two field elements if choice is 1, leaves them unchanged if choice is 0.
    /// This operation is performed in constant time to prevent timing attacks.
    #[inline(always)]
    pub fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        for i in 0..P521_LIMBS {
            let tmp = u32::conditional_select(&a.0[i], &b.0[i], choice);
            b.0[i] = u32::conditional_select(&b.0[i], &a.0[i], choice);
            a.0[i] = tmp;
        }
    }
}

/* ========================================================================== */
/*  P-521 reduction helper                                                    */
/* ========================================================================== */

impl FieldElement {
    /// Reduce a 34-limb value (little-endian u32) modulo
    /// p = 2²⁵²¹ − 1.  Runs in constant time.
    fn reduce_wide(t: [u32; 34]) -> Self {
        // Split exactly at bit 521 and use 2^521 == 1 (mod p).  The high
        // half spans 18 limbs because the product is at most 1088 bits.
        let mut first = [0u32; 18];
        let mut carry = 0u64;
        for i in 0..16 {
            let high = ((t[i + 16] >> 9) | (t[i + 17] << 23)) as u64;
            let value = t[i] as u64 + high + carry;
            first[i] = value as u32;
            carry = value >> 32;
        }
        let high_16 = ((t[32] >> 9) | (t[33] << 23)) as u64;
        let value_16 = (t[16] & 0x1ff) as u64 + high_16 + carry;
        first[16] = value_16 as u32;
        carry = value_16 >> 32;

        let value_17 = ((t[33] as u64) >> 9) + carry;
        first[17] = value_17 as u32;

        // Fold the at-most-47-bit remainder above bit 521 back into the low
        // limbs.  Carry propagation always traverses every limb.
        let extra = ((first[16] >> 9) as u64) | ((first[17] as u64) << 23);
        let mut limbs = [0u32; P521_LIMBS];
        carry = extra;
        for i in 0..P521_LIMBS {
            let low = if i == 16 { first[i] & 0x1ff } else { first[i] };
            let value = low as u64 + carry;
            limbs[i] = value as u32;
            carry = value >> 32;
        }

        // The previous fold yields a value below 2^521 + 2.  One conditional
        // subtraction therefore produces the unique canonical representative.

        let (sub, borrow) = Self::sbb_n(limbs, Self::MOD_LIMBS);
        Self::conditional_select(&limbs, &sub, Choice::from((borrow ^ 1) as u8))
    }
}

/* ========================================================================== */
/*  Public API: add / sub / mul / square / invert / sqrt                      */
/* ========================================================================== */

impl FieldElement {
    /// Constant-time addition modulo p
    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = Self::adc_n(self.0, other.0);
        // If there was a carry OR the sum ≥ p  ⇒ subtract once.
        let (sub, borrow) = Self::sbb_n(sum, Self::MOD_LIMBS);
        let need_sub = Choice::from(((carry | (borrow ^ 1)) & 1) as u8);
        Self::conditional_select(&sum, &sub, need_sub)
    }

    /// Constant-time subtraction modulo p
    pub fn sub(&self, other: &Self) -> Self {
        let (diff, borrow) = Self::sbb_n(self.0, other.0);
        // If we borrowed ⇒ add p back.
        let (sum, _) = Self::adc_n(diff, Self::MOD_LIMBS);
        Self::conditional_select(&diff, &sum, Choice::from(borrow as u8))
    }

    /// Field multiplication using school-book multiply + Mersenne reduction.
    pub fn mul(&self, other: &Self) -> Self {
        // ── 1. 17×17 → 34 partial products (128-bit accumulator) ----------
        let mut wide = [0u128; 34];
        for i in 0..17 {
            for j in 0..17 {
                wide[i + j] += (self.0[i] as u128) * (other.0[j] as u128);
            }
        }

        // ── 2. Carry-propagate 128-bit → 34 × 32-bit limbs -----------------
        let mut limbs = [0u32; 34];
        let mut carry: u128 = 0;
        for i in 0..34 {
            let v = wide[i] + carry;
            limbs[i] = (v & 0xFFFF_FFFF) as u32;
            carry = v >> 32;
        }
        // Index 33 is an explicit empty carry limb (the largest product term
        // is at index 32), so the final carry is zero by construction.
        let _ = carry;

        // ── 3. Reduce back to 17 limbs -------------------------------------
        Self::reduce_wide(limbs)
    }

    /// Field squaring – just a specialised multiplication.
    #[inline(always)]
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Fermat-inversion  a^(p−2)  via left-to-right square-and-multiply.
    pub fn invert(&self) -> Result<Self> {
        if self.is_zero() {
            return Err(Error::param("FieldElement P-521", "Inverse of zero"));
        }

        // Prepare exponent  p−2  =  (2^521 − 1) − 2  =  2^521 − 3
        //   p  in bytes is   0x01 | 0xFF * 65
        let mut exp = [0u8; P521_FIELD_ELEMENT_SIZE];
        exp[0] = 0x01;
        for byte in exp.iter_mut().skip(1) {
            *byte = 0xFF;
        }
        // subtract 2                                      (big-endian)
        let mut borrow = 2u16;
        for i in (0..66).rev() {
            let v = exp[i] as i16 - borrow as i16;
            exp[i] = if v < 0 { (v + 256) as u8 } else { v as u8 };
            borrow = if v < 0 { 1 } else { 0 };
        }

        // Left-to-right binary exponentiation
        let mut result = FieldElement::one();
        let base = self.clone();
        for byte in exp.iter() {
            for bit in (0..8).rev() {
                result = result.square();
                if (byte >> bit) & 1 == 1 {
                    result = result.mul(&base);
                }
            }
        }
        Ok(result)
    }

    /// Square-root via  a^{(p+1)/4}  (because p ≡ 3 mod 4).
    /// (p+1)/4 = 2^519.
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() {
            return Some(Self::zero());
        }
        // a^{2^519}
        let mut res = self.clone();
        for _ in 0..519 {
            res = res.square();
        }
        // verify
        if res.square() == *self {
            Some(res)
        } else {
            None
        }
    }

    /// Get the field modulus p as a FieldElement
    pub(crate) fn get_modulus() -> Self {
        FieldElement(Self::MOD_LIMBS)
    }
}
