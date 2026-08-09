//! Extended Edwards-coordinate arithmetic for Ed25519.

#![forbid(unsafe_code)]

use dcrypt_internal::{Choice, ConditionallySelectable, ConstantTimeEq, Zeroize, Zeroizing};

use super::field::FieldElement;
use super::scalar::{Scalar, GROUP_ORDER_BYTES};

const D_BYTES: [u8; 32] = [
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
];

const BASE_X_BYTES: [u8; 32] = [
    0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
    0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
];

const BASE_Y_BYTES: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// A point in extended coordinates `(X:Y:Z:T)`, with `x=X/Z`, `y=Y/Z`,
/// and `xy=T/Z`.
#[derive(Clone, Copy)]
pub(crate) struct EdwardsPoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl Default for EdwardsPoint {
    fn default() -> Self {
        Self::identity()
    }
}

impl Zeroize for EdwardsPoint {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
        self.t.zeroize();
    }
}

impl EdwardsPoint {
    pub(crate) fn identity() -> Self {
        Self {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::one(),
            t: FieldElement::zero(),
        }
    }

    pub(crate) fn basepoint() -> Self {
        let x = FieldElement::from_bytes_unchecked(&BASE_X_BYTES);
        let y = FieldElement::from_bytes_unchecked(&BASE_Y_BYTES);
        Self {
            x,
            y,
            z: FieldElement::one(),
            t: x.mul(&y),
        }
    }

    /// Complete extended-coordinate addition for the `a=-1` Edwards curve.
    pub(crate) fn add(&self, rhs: &Self) -> Self {
        let self_y_minus_x = Zeroizing::new(self.y.sub(&self.x));
        let rhs_y_minus_x = Zeroizing::new(rhs.y.sub(&rhs.x));
        let a = Zeroizing::new(self_y_minus_x.mul(&rhs_y_minus_x));
        let self_y_plus_x = Zeroizing::new(self.y.add(&self.x));
        let rhs_y_plus_x = Zeroizing::new(rhs.y.add(&rhs.x));
        let b = Zeroizing::new(self_y_plus_x.mul(&rhs_y_plus_x));
        let t_product = Zeroizing::new(self.t.mul(&rhs.t));
        let c = Zeroizing::new(t_product.mul(&curve_d().double()));
        let z_product = Zeroizing::new(self.z.mul(&rhs.z));
        let d = Zeroizing::new(z_product.double());
        let e = Zeroizing::new(b.sub(&a));
        let f = Zeroizing::new(d.sub(&c));
        let g = Zeroizing::new(d.add(&c));
        let h = Zeroizing::new(b.add(&a));
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    pub(crate) fn double(&self) -> Self {
        let a = Zeroizing::new(self.x.square());
        let b = Zeroizing::new(self.y.square());
        let z_squared = Zeroizing::new(self.z.square());
        let c = Zeroizing::new(z_squared.double());
        let d = Zeroizing::new(a.neg());
        let x_plus_y = Zeroizing::new(self.x.add(&self.y));
        let x_plus_y_squared = Zeroizing::new(x_plus_y.square());
        let x_plus_y_squared_minus_a = Zeroizing::new(x_plus_y_squared.sub(&a));
        let e = Zeroizing::new(x_plus_y_squared_minus_a.sub(&b));
        let g = Zeroizing::new(d.add(&b));
        let f = Zeroizing::new(g.sub(&c));
        let h = Zeroizing::new(d.sub(&b));
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// Fixed-iteration, branch-free scalar multiplication.
    pub(crate) fn scalar_mult(&self, scalar: &Scalar) -> Self {
        let mut accumulator = Zeroizing::new(Self::identity());
        for bit in (0..256).rev() {
            let doubled = Zeroizing::new(accumulator.double());
            let added = Zeroizing::new(doubled.add(self));
            let selected =
                Zeroizing::new(Self::conditional_select(&doubled, &added, scalar.bit(bit)));
            accumulator.zeroize();
            *accumulator = *selected;
        }
        accumulator.into_inner()
    }

    fn scalar_mult_public_bytes(&self, scalar: &[u8; 32]) -> Self {
        let mut accumulator = Self::identity();
        for bit in (0..256).rev() {
            let doubled = accumulator.double();
            let added = doubled.add(self);
            let choice = Choice::from((scalar[bit / 8] >> (bit % 8)) & 1);
            accumulator = Self::conditional_select(&doubled, &added, choice);
        }
        accumulator
    }

    pub(crate) fn compress(&self) -> [u8; 32] {
        let inverse_z = Zeroizing::new(self.z.invert());
        let x = Zeroizing::new(self.x.mul(&inverse_z));
        let y = Zeroizing::new(self.y.mul(&inverse_z));
        let mut bytes = y.to_bytes();
        bytes[31] |= x.is_negative().unwrap_u8() << 7;
        bytes.into_inner()
    }

    /// Decode one and only one canonical RFC 8032 point encoding.
    pub(crate) fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        let sign = Choice::from(bytes[31] >> 7);
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;
        let y = FieldElement::from_canonical_bytes(&y_bytes)?;
        let y_squared = y.square();
        let numerator = y_squared.sub(&FieldElement::one());
        let denominator = curve_d().mul(&y_squared).add(&FieldElement::one());
        let x_squared = numerator.mul(&denominator.invert());
        let root = x_squared.sqrt()?;

        // RFC 8032 forbids the otherwise ambiguous encoding x=0, sign=1.
        if bool::from(root.is_zero() & sign) {
            return None;
        }
        let negate = root.is_negative() ^ sign;
        let x = FieldElement::conditional_select(&root, &root.neg(), negate);
        let point = Self {
            x,
            y,
            z: FieldElement::one(),
            t: x.mul(&y),
        };

        // This also guards the decoder against future normalization mistakes.
        if bool::from(point.compress().ct_eq(bytes)) {
            Some(point)
        } else {
            None
        }
    }

    pub(crate) fn is_identity(&self) -> Choice {
        self.x.is_zero() & self.y.ct_eq(&self.z)
    }

    pub(crate) fn is_small_order(&self) -> Choice {
        self.double().double().double().is_identity()
    }

    pub(crate) fn is_torsion_free(&self) -> Choice {
        self.scalar_mult_public_bytes(&GROUP_ORDER_BYTES)
            .is_identity()
    }

    pub(crate) fn is_strict_prime_order(&self) -> bool {
        !bool::from(self.is_identity())
            && !bool::from(self.is_small_order())
            && bool::from(self.is_torsion_free())
    }
}

impl ConditionallySelectable for EdwardsPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
            t: FieldElement::conditional_select(&a.t, &b.t, choice),
        }
    }
}

impl ConstantTimeEq for EdwardsPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        let left_x = Zeroizing::new(self.x.mul(&other.z));
        let right_x = Zeroizing::new(other.x.mul(&self.z));
        let left_y = Zeroizing::new(self.y.mul(&other.z));
        let right_y = Zeroizing::new(other.y.mul(&self.z));
        let x_equal = left_x.ct_eq(&right_x);
        let y_equal = left_y.ct_eq(&right_y);
        x_equal & y_equal
    }
}

fn curve_d() -> FieldElement {
    FieldElement::from_bytes_unchecked(&D_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basepoint_round_trip() {
        let basepoint = EdwardsPoint::basepoint();
        assert_eq!(basepoint.compress(), BASE_Y_BYTES);
        let decoded = EdwardsPoint::decompress(&BASE_Y_BYTES).unwrap();
        assert!(bool::from(decoded.ct_eq(&basepoint)));
        assert!(decoded.is_strict_prime_order());
    }

    #[test]
    fn identity_and_negative_zero_are_distinctly_rejected_by_policy() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let point = EdwardsPoint::decompress(&identity).unwrap();
        assert!(bool::from(point.is_identity()));
        assert!(!point.is_strict_prime_order());

        identity[31] |= 0x80;
        assert!(EdwardsPoint::decompress(&identity).is_none());
    }

    #[test]
    fn mixed_torsion_point_is_not_torsion_free() {
        // y=0 is a canonical order-four point.  Adding it to B produces a
        // point that is neither small order nor in the prime-order subgroup.
        let torsion = EdwardsPoint::decompress(&[0u8; 32]).unwrap();
        let mixed = EdwardsPoint::basepoint().add(&torsion);
        assert!(!bool::from(mixed.is_small_order()));
        assert!(!bool::from(mixed.is_torsion_free()));
        assert!(!mixed.is_strict_prime_order());
        let encoded = mixed.compress();
        assert!(EdwardsPoint::decompress(&encoded).is_some());
    }
}
