//! secp256k1 field arithmetic implementation.
//! Field prime p = 2^256 - 2^32 - 977.

use crate::ec::k256::constants::K256_FIELD_ELEMENT_SIZE;
use crate::error::{Error, Result};
use subtle::{Choice, ConditionallySelectable};

/// secp256k1 field element representing values in F_p
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
    /// The secp256k1 prime modulus: p = 2^256 - 2^32 - 977
    pub(crate) const MOD_LIMBS: [u32; 8] = [
        0xFFFF_FC2F,
        0xFFFF_FFFE,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
    ];

    /// The additive identity element: 0
    pub fn zero() -> Self {
        FieldElement([0; 8])
    }

    /// The multiplicative identity element: 1
    pub fn one() -> Self {
        let mut limbs = [0; 8];
        limbs[0] = 1;
        FieldElement(limbs)
    }

    /// Create a field element from its canonical byte representation.
    ///
    /// Returns an error if the value is greater than or equal to the field modulus.
    pub fn from_bytes(bytes: &[u8; K256_FIELD_ELEMENT_SIZE]) -> Result<Self> {
        let mut limbs = [0u32; 8];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let offset = (7 - i) * 4;
            *limb = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
        }
        let fe = FieldElement(limbs);
        if !fe.is_valid() {
            return Err(Error::param(
                "FieldElement K256",
                "Value must be less than the field modulus",
            ));
        }
        Ok(fe)
    }

    /// Convert this field element to its canonical byte representation.
    pub fn to_bytes(&self) -> [u8; K256_FIELD_ELEMENT_SIZE] {
        let mut bytes = [0u8; K256_FIELD_ELEMENT_SIZE];
        for i in 0..8 {
            let limb_bytes = self.0[i].to_be_bytes();
            let offset = (7 - i) * 4;
            bytes[offset..offset + 4].copy_from_slice(&limb_bytes);
        }
        bytes
    }

    /// Check if this field element is less than the field modulus.
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        let (_, borrow) = Self::sbb8(self.0, Self::MOD_LIMBS);
        borrow == 1
    }

    /// Check if this field element is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&l| l == 0)
    }

    /// Check if this field element is odd (least significant bit is 1).
    pub fn is_odd(&self) -> bool {
        // limbs[0] contains the least significant 32 bits
        (self.0[0] & 1) == 1
    }

    /// Add two field elements modulo p.
    #[inline(always)]
    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = Self::adc8(self.0, other.0);
        let (sum_minus_p, borrow) = Self::sbb8(sum, Self::MOD_LIMBS);
        let needs_reduce = (carry | (borrow ^ 1)) & 1;
        Self::conditional_select(&sum, &sum_minus_p, Choice::from(needs_reduce as u8))
    }

    /// Subtract two field elements modulo p.
    pub fn sub(&self, other: &Self) -> Self {
        let (diff, borrow) = Self::sbb8(self.0, other.0);
        let (candidate, _) = Self::adc8(diff, Self::MOD_LIMBS);
        Self::conditional_select(&diff, &candidate, Choice::from(borrow as u8))
    }

    /// Negate a field element modulo p.
    pub fn negate(&self) -> Self {
        if self.is_zero() {
            return *self;
        }
        FieldElement(Self::MOD_LIMBS).sub(self)
    }

    /// Multiply two field elements modulo p.
    pub fn mul(&self, other: &Self) -> Self {
        let mut t = [0u128; 16];
        for i in 0..8 {
            for j in 0..8 {
                t[i + j] += (self.0[i] as u128) * (other.0[j] as u128);
            }
        }
        let mut prod = [0u32; 16];
        let mut carry: u128 = 0;
        for i in 0..16 {
            let v = t[i] + carry;
            prod[i] = (v & 0xffff_ffff) as u32;
            carry = v >> 32;
        }
        Self::reduce_wide(prod)
    }

    /// Square a field element modulo p.
    #[inline(always)]
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Double a field element (multiply by 2) modulo p.
    pub fn double(&self) -> Self {
        self.add(self)
    }

    /// Compute the multiplicative inverse of a field element.
    ///
    /// Returns an error if the element is zero.
    pub fn invert(&self) -> Result<Self> {
        if self.is_zero() {
            return Err(Error::param(
                "FieldElement K256",
                "Inversion of zero is undefined",
            ));
        }
        const P_MINUS_2: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xFF, 0xFF, 0xFC, 0x2D,
        ];
        self.pow(&P_MINUS_2)
    }

    /// Compute the square root of a field element.
    ///
    /// Returns None if the element is not a quadratic residue.
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() {
            return Some(Self::zero());
        }
        // p mod 4 = 3, so sqrt(a) = a^((p+1)/4)
        const P_PLUS_1_DIV_4: [u8; 32] = [
            0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xBF, 0xFF, 0xFF, 0x0C,
        ];
        let root = self.pow(&P_PLUS_1_DIV_4).ok()?;
        if root.square() == *self {
            Some(root)
        } else {
            None
        }
    }

    fn pow(&self, exp_be: &[u8]) -> Result<Self> {
        let mut result = Self::one();
        let base = *self;
        for &byte in exp_be.iter() {
            for i in (0..8).rev() {
                result = result.square();
                if (byte >> i) & 1 == 1 {
                    result = result.mul(&base);
                }
            }
        }
        Ok(result)
    }

    fn conditional_select(a: &[u32; 8], b: &[u32; 8], flag: Choice) -> Self {
        let mut out = [0u32; 8];
        for i in 0..8 {
            out[i] = u32::conditional_select(&a[i], &b[i], flag);
        }
        FieldElement(out)
    }

    fn adc8(a: [u32; 8], b: [u32; 8]) -> ([u32; 8], u32) {
        let mut r = [0u32; 8];
        let mut carry: u64 = 0;
        for i in 0..8 {
            let tmp = (a[i] as u64) + (b[i] as u64) + carry;
            r[i] = tmp as u32;
            carry = tmp >> 32;
        }
        (r, carry as u32)
    }

    fn sbb8(a: [u32; 8], b: [u32; 8]) -> ([u32; 8], u32) {
        let mut r = [0u32; 8];
        let mut borrow: i64 = 0;
        for i in 0..8 {
            let tmp = (a[i] as i64) - (b[i] as i64) - borrow;
            r[i] = tmp as u32;
            borrow = (tmp >> 63) & 1;
        }
        (r, borrow as u32)
    }

    /// Reduce a 512-bit number modulo p = 2^256 - 2^32 - 977
    /// Uses the special form of secp256k1's prime for efficient reduction
    fn reduce_wide(t: [u32; 16]) -> Self {
        // For p = 2^256 - 2^32 - 977, we can use the fact that
        // 2^256 ≡ 2^32 + 977 (mod p)
        // This allows us to reduce the high 256 bits efficiently

        // Split t into low 256 bits (t_low) and high 256 bits (t_high)
        let mut t_low = [0u32; 8];
        let mut t_high = [0u32; 8];
        t_low.copy_from_slice(&t[..8]);
        t_high.copy_from_slice(&t[8..]);

        // We need to compute: t_low + t_high * 2^256
        // Since 2^256 ≡ 2^32 + 977 (mod p), we compute:
        // t_low + t_high * (2^32 + 977)
        // = t_low + (t_high << 32) + t_high * 977

        // First, compute t_high * 977
        let mut t_high_977 = [0u64; 9];
        for i in 0..8 {
            t_high_977[i] += (t_high[i] as u64) * 977u64;
        }
        // Propagate carries
        for i in 0..8 {
            t_high_977[i + 1] += t_high_977[i] >> 32;
            t_high_977[i] &= 0xFFFF_FFFF;
        }

        // Now add: t_low + (t_high << 32) + t_high_977
        let mut result = [0u64; 9];

        // Add t_low
        for i in 0..8 {
            result[i] += t_low[i] as u64;
        }

        // Add t_high << 32 (which means t_high[i] goes to position i+1)
        for i in 0..8 {
            result[i + 1] += t_high[i] as u64;
        }

        // Add t_high_977
        for i in 0..9 {
            result[i] += t_high_977[i];
        }

        // Propagate all carries
        for i in 0..8 {
            result[i + 1] += result[i] >> 32;
            result[i] &= 0xFFFF_FFFF;
        }

        // If result[8] is non-zero, we need another reduction step
        if result[8] > 0 {
            // result[8] * 2^256 ≡ result[8] * (2^32 + 977) (mod p)
            let overflow = result[8];
            result[8] = 0;

            // Add overflow * 977 to result[0]
            result[0] += overflow * 977;
            // Add overflow to result[1] (for the 2^32 part)
            result[1] += overflow;

            // Propagate carries again
            for i in 0..8 {
                if i < 7 {
                    result[i + 1] += result[i] >> 32;
                }
                result[i] &= 0xFFFF_FFFF;
            }
        }

        // Convert back to u32 array
        let mut r = [0u32; 8];
        for i in 0..8 {
            r[i] = result[i] as u32;
        }

        // Final reduction if r >= p
        let fe = FieldElement(r);
        if !fe.is_valid() {
            let (reduced, _) = Self::sbb8(r, Self::MOD_LIMBS);
            FieldElement(reduced)
        } else {
            fe
        }
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
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xFF, 0xFF, 0xFC, 0x2F,
        ];

        assert_eq!(
            mod_bytes, expected_bytes,
            "MOD_LIMBS does not encode the correct secp256k1 prime"
        );
    }
}