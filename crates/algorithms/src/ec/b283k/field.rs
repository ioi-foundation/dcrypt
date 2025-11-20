//! sect283k1 binary field arithmetic GF(2^283)
//! Irreducible polynomial: x^283 + x^12 + x^7 + x^5 + 1

use crate::ec::b283k::constants::B283K_FIELD_ELEMENT_SIZE;
use crate::error::{Error, Result};
use subtle::{Choice, ConditionallySelectable};

/// A field element in GF(2^283) represented by 5 u64 limbs (320 bits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement(pub(crate) [u64; 5]);

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut out = [0u64; 5];
        for i in 0..5 {
            out[i] = u64::conditional_select(&a.0[i], &b.0[i], choice);
        }
        FieldElement(out)
    }
}

impl FieldElement {
    // The irreducible polynomial for sect283k1: f(x) = x^283 + x^12 + x^7 + x^5 + 1
    const REDUCER: [u64; 5] = [1 << 12 | 1 << 7 | 1 << 5 | 1, 0, 0, 0, 0];

    /// The additive identity element (zero).
    pub fn zero() -> Self {
        FieldElement([0; 5])
    }

    /// The multiplicative identity element (one).
    pub fn one() -> Self {
        FieldElement([1, 0, 0, 0, 0])
    }

    /// Create a field element from its canonical byte representation.
    ///
    /// The bytes are interpreted as a big-endian representation of the field element.
    pub fn from_bytes(bytes: &[u8; B283K_FIELD_ELEMENT_SIZE]) -> Result<Self> {
        let mut limbs = [0u64; 5];
        // Read 36 bytes big-endian into 5 u64 limbs
        // bytes[0..4] contains the top 27 bits (283-256)
        limbs[4] = u64::from_be_bytes([0, 0, 0, 0, bytes[0], bytes[1], bytes[2], bytes[3]]);
        limbs[3] = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
        limbs[2] = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
        limbs[1] = u64::from_be_bytes(bytes[20..28].try_into().unwrap());
        limbs[0] = u64::from_be_bytes(bytes[28..36].try_into().unwrap());

        // Verify that the highest bits are zero (only 283 bits should be used)
        if limbs[4] & !((1u64 << 27) - 1) != 0 {
            return Err(Error::param(
                "FieldElement B283k",
                "Value exceeds field size",
            ));
        }

        Ok(FieldElement(limbs))
    }

    /// Convert this field element to its canonical byte representation.
    ///
    /// The bytes are a big-endian representation of the field element.
    pub fn to_bytes(&self) -> [u8; B283K_FIELD_ELEMENT_SIZE] {
        let mut bytes = [0u8; B283K_FIELD_ELEMENT_SIZE];
        // Write 5 u64 limbs to 36 bytes big-endian
        // Only use the lower 4 bytes of limb[4] since we only need 283 bits
        let top_limb_bytes = self.0[4].to_be_bytes();
        bytes[0..4].copy_from_slice(&top_limb_bytes[4..]);
        bytes[4..12].copy_from_slice(&self.0[3].to_be_bytes());
        bytes[12..20].copy_from_slice(&self.0[2].to_be_bytes());
        bytes[20..28].copy_from_slice(&self.0[1].to_be_bytes());
        bytes[28..36].copy_from_slice(&self.0[0].to_be_bytes());
        bytes
    }

    /// Check if this field element is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&l| l == 0)
    }

    /// Add two field elements in GF(2^283).
    ///
    /// In binary fields, addition is performed using XOR.
    pub fn add(&self, other: &Self) -> Self {
        let mut res = [0u64; 5];
        for (i, (a, b)) in self.0.iter().zip(other.0.iter()).enumerate() {
            res[i] = a ^ b;
        }
        FieldElement(res)
    }

    /// Multiply two field elements in GF(2^283).
    ///
    /// Uses the irreducible polynomial for reduction.
    pub fn mul(&self, other: &Self) -> Self {
        let mut res = FieldElement::zero();
        let mut a = *self;
        let mut b = *other;

        for _ in 0..283 {
            if (b.0[0] & 1) == 1 {
                res = res.add(&a);
            }
            b = b.shr1();
            a = a.shl1();

            // After shifting left, check if bit 283 is set
            // Bit 283 is at position 27 in limb[4] (since 283 = 256 + 27)
            if (a.0[4] >> 27) & 1 == 1 {
                // Reduce by XORing with the reduction polynomial
                a = a.add(&FieldElement(Self::REDUCER));
                // Clear the overflow bit
                a.0[4] &= (1u64 << 27) - 1;
            }
        }
        res
    }

    /// Square a field element in GF(2^283).
    pub fn square(&self) -> Self {
        self.mul(self) // Non-optimized square
    }

    /// Compute the multiplicative inverse of a field element.
    ///
    /// Uses Fermat's Little Theorem: a^(2^m - 2) = a^(-1) in GF(2^m).
    /// Returns an error if the element is zero.
    pub fn invert(&self) -> Result<Self> {
        if self.is_zero() {
            return Err(Error::param("FieldElement B283k", "Inversion of zero"));
        }
        // Fermat's Little Theorem: a^(2^m - 2)
        let mut res = *self;
        for _ in 1..282 {
            res = res.square();
            res = res.mul(self);
        }
        res = res.square();
        Ok(res)
    }

    /// Compute the square root of a field element.
    ///
    /// In binary fields of characteristic 2, sqrt(x) = x^(2^(m-1)).
    pub fn sqrt(&self) -> Self {
        // sqrt(x) = x^(2^(m-1))
        let mut res = *self;
        for _ in 0..282 {
            res = res.square();
        }
        res
    }

    // Shift left by 1
    fn shl1(&self) -> Self {
        let mut r = [0u64; 5];
        r[0] = self.0[0] << 1;

        // Use zip to iterate over current and previous elements
        for (i, (&curr, &prev)) in self.0[1..].iter().zip(self.0[..4].iter()).enumerate() {
            r[i + 1] = (curr << 1) | (prev >> 63);
        }

        // Ensure we don't have bits beyond position 282
        r[4] &= (1u64 << 28) - 1; // Allow up to bit 283 for overflow detection
        FieldElement(r)
    }

    // Shift right by 1
    fn shr1(&self) -> Self {
        let mut r = [0u64; 5];

        // Use zip to iterate over current and next elements
        for (i, (&curr, &next)) in self.0[..4].iter().zip(self.0[1..].iter()).enumerate() {
            r[i] = (curr >> 1) | (next << 63);
        }

        r[4] = self.0[4] >> 1;
        FieldElement(r)
    }

    /// Get the trace of the element.
    ///
    /// The trace is Tr(z) = z + z^2 + z^4 + ... + z^(2^(m-1)).
    /// For compressed points, it's used to disambiguate the y-coordinate.
    pub fn trace(&self) -> u64 {
        let mut res = *self;
        let mut temp = *self;
        for _ in 0..282 {
            temp = temp.square();
            res = res.add(&temp);
        }
        res.0[0] & 1
    }
}