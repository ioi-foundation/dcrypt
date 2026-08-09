//! Field arithmetic modulo `p = 2^255 - 19`.
//!
//! The implementation uses five radix-2^51 limbs.  Every operation has a
//! fixed control-flow shape; in particular, values derived from secret
//! scalars are never used as branch conditions.

#![forbid(unsafe_code)]

use dcrypt_internal::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize, Zeroizing};

const LIMB_BITS: u32 = 51;
const LIMB_MASK: u64 = (1u64 << LIMB_BITS) - 1;
const MODULUS_LIMBS: [u64; 5] = [LIMB_MASK - 18, LIMB_MASK, LIMB_MASK, LIMB_MASK, LIMB_MASK];
const MODULUS_BYTES: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

const P_MINUS_TWO: [u8; 32] = [
    0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

const P_PLUS_THREE_OVER_EIGHT: [u8; 32] = [
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
];

/// A field element modulo `2^255 - 19`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FieldElement([u64; 5]);

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

impl FieldElement {
    pub(crate) const fn zero() -> Self {
        Self([0; 5])
    }

    pub(crate) const fn one() -> Self {
        Self([1, 0, 0, 0, 0])
    }

    /// Decode a canonical little-endian field element.
    pub(crate) fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self> {
        if !bytes_less_than(bytes, &MODULUS_BYTES) {
            return None;
        }
        Some(Self::from_bytes_unchecked(bytes))
    }

    /// Decode a value known to be below the field modulus.
    pub(crate) fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 5];
        for bit in 0..255 {
            let value = u64::from((bytes[bit / 8] >> (bit % 8)) & 1);
            limbs[bit / LIMB_BITS as usize] |= value << (bit % LIMB_BITS as usize);
        }
        Self(limbs)
    }

    pub(crate) fn add(&self, rhs: &Self) -> Self {
        let mut limbs = Zeroizing::new([0u128; 5]);
        for (index, limb) in limbs.iter_mut().enumerate() {
            *limb = u128::from(self.0[index]) + u128::from(rhs.0[index]);
        }
        Self(reduce_limbs(limbs).into_inner())
    }

    pub(crate) fn sub(&self, rhs: &Self) -> Self {
        // Adding 2p before subtracting keeps every unsigned limb non-negative.
        let mut limbs = Zeroizing::new([0u128; 5]);
        for (index, limb) in limbs.iter_mut().enumerate() {
            *limb = u128::from(self.0[index]) + 2 * u128::from(MODULUS_LIMBS[index])
                - u128::from(rhs.0[index]);
        }
        Self(reduce_limbs(limbs).into_inner())
    }

    pub(crate) fn neg(&self) -> Self {
        Self::zero().sub(self)
    }

    pub(crate) fn double(&self) -> Self {
        self.add(self)
    }

    pub(crate) fn mul(&self, rhs: &Self) -> Self {
        let mut a = Zeroizing::new([0u128; 5]);
        let mut b = Zeroizing::new([0u128; 5]);
        for index in 0..5 {
            a[index] = u128::from(self.0[index]);
            b[index] = u128::from(rhs.0[index]);
        }

        // Terms whose limb index wraps past 255 bits acquire a factor of 19,
        // since 2^255 == 19 (mod p).
        let limbs = Zeroizing::new([
            a[0] * b[0] + 19 * (a[1] * b[4] + a[2] * b[3] + a[3] * b[2] + a[4] * b[1]),
            a[0] * b[1] + a[1] * b[0] + 19 * (a[2] * b[4] + a[3] * b[3] + a[4] * b[2]),
            a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + 19 * (a[3] * b[4] + a[4] * b[3]),
            a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + 19 * a[4] * b[4],
            a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0],
        ]);
        Self(reduce_limbs(limbs).into_inner())
    }

    pub(crate) fn square(&self) -> Self {
        self.mul(self)
    }

    pub(crate) fn invert(&self) -> Self {
        self.pow(&P_MINUS_TWO)
    }

    /// Return a square root of `self`, if one exists.
    pub(crate) fn sqrt(&self) -> Option<Self> {
        let mut root = self.pow(&P_PLUS_THREE_OVER_EIGHT);
        if !bool::from(root.square().ct_eq(self)) {
            root = root.mul(&sqrt_m1());
        }
        if bool::from(root.square().ct_eq(self)) {
            Some(root)
        } else {
            None
        }
    }

    pub(crate) fn is_zero(&self) -> Choice {
        let bytes = self.to_bytes();
        bytes[..].ct_eq(&[0u8; 32])
    }

    pub(crate) fn is_negative(&self) -> Choice {
        Choice::from(self.to_bytes()[0] & 1)
    }

    pub(crate) fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        let limbs = canonical_limbs(&self.0);
        let mut bytes = Zeroizing::new([0u8; 32]);
        for bit in 0..255 {
            let value = ((limbs[bit / LIMB_BITS as usize] >> (bit % LIMB_BITS as usize)) & 1) as u8;
            bytes[bit / 8] |= value << (bit % 8);
        }
        bytes
    }

    fn pow(&self, exponent: &[u8; 32]) -> Self {
        let mut accumulator = Zeroizing::new(Self::one());
        for bit in (0..256).rev() {
            let squared = Zeroizing::new(accumulator.square());
            let multiplied = Zeroizing::new(squared.mul(self));
            let choice = Choice::from((exponent[bit / 8] >> (bit % 8)) & 1);
            let selected = Zeroizing::new(Self::conditional_select(&squared, &multiplied, choice));
            accumulator.zeroize();
            *accumulator = *selected;
        }
        accumulator.into_inner()
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut limbs = [0u64; 5];
        for (index, limb) in limbs.iter_mut().enumerate() {
            *limb = u64::conditional_select(&a.0[index], &b.0[index], choice);
        }
        Self(limbs)
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        let left = self.to_bytes();
        let right = other.to_bytes();
        left[..].ct_eq(&right[..])
    }
}

fn reduce_limbs(mut limbs: Zeroizing<[u128; 5]>) -> Zeroizing<[u64; 5]> {
    // Three fixed carry rounds are sufficient for the multiplication bounds
    // above and avoid any data-dependent reduction loop.
    for _ in 0..3 {
        for index in 0..4 {
            let carry = limbs[index] >> LIMB_BITS;
            limbs[index] &= u128::from(LIMB_MASK);
            limbs[index + 1] += carry;
        }
        let carry = limbs[4] >> LIMB_BITS;
        limbs[4] &= u128::from(LIMB_MASK);
        limbs[0] += carry * 19;
    }

    let mut result = Zeroizing::new([0u64; 5]);
    for (destination, source) in result.iter_mut().zip(limbs.iter().copied()) {
        *destination = source as u64;
    }
    result
}

fn canonical_limbs(limbs: &[u64; 5]) -> Zeroizing<[u64; 5]> {
    let mut widened = Zeroizing::new([0u128; 5]);
    for (destination, source) in widened.iter_mut().zip(limbs) {
        *destination = u128::from(*source);
    }
    let reduced = reduce_limbs(widened);
    let mut difference = Zeroizing::new([0u64; 5]);
    let mut borrow = 0u64;
    const RADIX: u64 = 1u64 << LIMB_BITS;

    for index in 0..5 {
        let value = reduced[index] + RADIX - MODULUS_LIMBS[index] - borrow;
        difference[index] = value & LIMB_MASK;
        borrow = 1 ^ (value >> LIMB_BITS);
    }

    // No final borrow means the original value was at least p.
    let subtract = Choice::from((borrow ^ 1) as u8);
    let mut result = Zeroizing::new([0u64; 5]);
    for index in 0..5 {
        result[index] = u64::conditional_select(&reduced[index], &difference[index], subtract);
    }
    result
}

fn bytes_less_than(lhs: &[u8; 32], rhs: &[u8; 32]) -> bool {
    for index in (0..32).rev() {
        if lhs[index] < rhs[index] {
            return true;
        }
        if lhs[index] > rhs[index] {
            return false;
        }
    }
    false
}

fn sqrt_m1() -> FieldElement {
    // sqrt(-1) modulo p, in canonical little-endian form.
    const BYTES: [u8; 32] = [
        0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43,
        0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24,
        0x83, 0x2b,
    ];
    FieldElement::from_bytes_unchecked(&BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(hex_value: &str) -> FieldElement {
        let bytes: [u8; 32] = hex::decode(hex_value).unwrap().try_into().unwrap();
        FieldElement::from_canonical_bytes(&bytes).unwrap()
    }

    #[test]
    fn canonical_encoding_rejects_modulus() {
        assert!(FieldElement::from_canonical_bytes(&MODULUS_BYTES).is_none());
        let mut p_minus_one = MODULUS_BYTES;
        p_minus_one[0] -= 1;
        let field = FieldElement::from_canonical_bytes(&p_minus_one).unwrap();
        assert_eq!(&*field.to_bytes(), &p_minus_one);
    }

    #[test]
    fn inversion_and_square_roots_round_trip() {
        for value in [1u8, 2, 19, 42, 255] {
            let mut bytes = [0u8; 32];
            bytes[0] = value;
            let field = FieldElement::from_canonical_bytes(&bytes).unwrap();
            assert!(bool::from(
                field.mul(&field.invert()).ct_eq(&FieldElement::one())
            ));
            let square = field.square();
            let root = square.sqrt().unwrap();
            assert!(bool::from(root.square().ct_eq(&square)));
        }
    }

    #[test]
    fn arithmetic_known_answers() {
        let a = field("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let b = field("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
        assert_eq!(
            a.mul(&b).to_bytes(),
            field("83ebb0050ff2d3d928e636402711238253bce1e8f630bcbd5ab8fb49c89be956").to_bytes()
        );
        assert_eq!(&*a.add(&b).to_bytes(), &[0x1f; 32]);
        assert_eq!(
            a.sub(&b).to_bytes(),
            field("e1e2e4e6e8eaeceef0f2f4f6f8fafcfe00030507090b0d0f11131517191b1d1f").to_bytes()
        );
        assert_eq!(
            a.invert().to_bytes(),
            field("4dcd88822d0589ded58c28d85290e85dcd88822d0589ded58c28d85290e85d73").to_bytes()
        );
    }
}
