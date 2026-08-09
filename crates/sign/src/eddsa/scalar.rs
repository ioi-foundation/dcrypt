//! Scalar arithmetic modulo the Ed25519 subgroup order.

#![forbid(unsafe_code)]

use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// `L = 2^252 + 27742317777372353535851937790883648493`.
pub(crate) const GROUP_ORDER_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

const GROUP_ORDER: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
];

/// A canonical scalar modulo `L`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Scalar([u64; 4]);

impl Scalar {
    pub(crate) fn zero() -> Self {
        Self([0; 4])
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let scalar = Self(load_limbs(bytes));
        let (_, borrow) = subtract_limbs(&scalar.0, &GROUP_ORDER);
        if borrow == 1 {
            Some(scalar)
        } else {
            None
        }
    }

    pub(crate) fn reduce_32(bytes: &[u8; 32]) -> Self {
        Self::reduce_bits(bytes)
    }

    pub(crate) fn reduce_64(bytes: &[u8; 64]) -> Self {
        Self::reduce_bits(bytes)
    }

    pub(crate) fn add(&self, rhs: &Self) -> Self {
        let mut sum = [0u64; 4];
        let mut carry = false;
        for (index, destination) in sum.iter_mut().enumerate() {
            let (partial, carry_one) = self.0[index].overflowing_add(rhs.0[index]);
            let (value, carry_two) = partial.overflowing_add(u64::from(carry));
            *destination = value;
            carry = carry_one | carry_two;
        }
        let _ = carry;
        Self(conditional_subtract_order(sum))
    }

    pub(crate) fn mul(&self, rhs: &Self) -> Self {
        // Fixed-length double-and-add.  Both candidate paths are evaluated and
        // selected without branching on scalar bits.
        let mut accumulator = Self::zero();
        for bit in (0..256).rev() {
            let doubled = accumulator.add(&accumulator);
            let with_rhs = doubled.add(self);
            let choice = Choice::from(((rhs.0[bit / 64] >> (bit % 64)) & 1) as u8);
            accumulator = Self::select(&doubled, &with_rhs, choice);
        }
        accumulator
    }

    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (index, limb) in self.0.iter().enumerate() {
            bytes[index * 8..(index + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        bytes
    }

    pub(crate) fn bit(&self, bit: usize) -> Choice {
        Choice::from(((self.0[bit / 64] >> (bit % 64)) & 1) as u8)
    }

    fn reduce_bits(bytes: &[u8]) -> Self {
        let mut accumulator = Self::zero();
        for bit in (0..bytes.len() * 8).rev() {
            let doubled = accumulator.add(&accumulator);
            let plus_one = doubled.add(&Self([1, 0, 0, 0]));
            let choice = Choice::from((bytes[bit / 8] >> (bit % 8)) & 1);
            accumulator = Self::select(&doubled, &plus_one, choice);
        }
        accumulator
    }

    fn select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut limbs = [0u64; 4];
        for (index, limb) in limbs.iter_mut().enumerate() {
            *limb = u64::conditional_select(&a.0[index], &b.0[index], choice);
        }
        Self(limbs)
    }
}

fn load_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[index * 8..(index + 1) * 8]);
        *limb = u64::from_le_bytes(chunk);
    }
    limbs
}

fn subtract_limbs(lhs: &[u64; 4], rhs: &[u64; 4]) -> ([u64; 4], u8) {
    let mut difference = [0u64; 4];
    let mut borrow = false;
    for index in 0..4 {
        let (partial, borrow_one) = lhs[index].overflowing_sub(rhs[index]);
        let (value, borrow_two) = partial.overflowing_sub(u64::from(borrow));
        difference[index] = value;
        borrow = borrow_one | borrow_two;
    }
    (difference, borrow as u8)
}

fn conditional_subtract_order(value: [u64; 4]) -> [u64; 4] {
    let (difference, borrow) = subtract_limbs(&value, &GROUP_ORDER);
    let subtract = Choice::from(borrow ^ 1);
    let mut result = [0u64; 4];
    for index in 0..4 {
        result[index] = u64::conditional_select(&value[index], &difference[index], subtract);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex_value: &str) -> [u8; 32] {
        hex::decode(hex_value).unwrap().try_into().unwrap()
    }

    #[test]
    fn canonical_order_boundary() {
        assert!(Scalar::from_canonical_bytes(&GROUP_ORDER_BYTES).is_none());
        let mut below = GROUP_ORDER_BYTES;
        below[0] -= 1;
        assert_eq!(
            Scalar::from_canonical_bytes(&below).unwrap().to_bytes(),
            below
        );
    }

    #[test]
    fn reduction_handles_order_and_wide_maximum() {
        assert_eq!(Scalar::reduce_32(&GROUP_ORDER_BYTES).to_bytes(), [0u8; 32]);
        let maximum = [0xffu8; 64];
        assert!(Scalar::from_canonical_bytes(&Scalar::reduce_64(&maximum).to_bytes()).is_some());
    }

    #[test]
    fn multiplication_matches_small_values() {
        let a = Scalar([7, 0, 0, 0]);
        let b = Scalar([9, 0, 0, 0]);
        assert_eq!(a.mul(&b).to_bytes()[0], 63);
    }

    #[test]
    fn arithmetic_known_answers() {
        let input: [u8; 64] = core::array::from_fn(|index| index as u8);
        assert_eq!(
            Scalar::reduce_64(&input).to_bytes(),
            bytes("7a3c6282f02d37a05023b60d5428e6cc5961d4c31221937adae0b574e4d07205")
        );
        let a = Scalar::reduce_32(&core::array::from_fn(|index| index as u8));
        let b = Scalar::reduce_32(&core::array::from_fn(|index| (31 - index) as u8));
        assert_eq!(
            a.add(&b).to_bytes(),
            bytes("324b29c204bc0cc74882277c4025400a1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f0f")
        );
        assert_eq!(
            a.mul(&b).to_bytes(),
            bytes("81b0bc00068a26a78d6f223648e4d42a51b369602745b843ff36d110d325d108")
        );
    }
}
