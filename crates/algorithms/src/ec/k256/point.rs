//! secp256k1 elliptic curve point operations

use crate::ec::k256::{
    constants::{
        K256_FIELD_ELEMENT_SIZE, K256_POINT_COMPRESSED_SIZE, K256_POINT_UNCOMPRESSED_SIZE,
    },
    field::FieldElement,
    scalar::Scalar,
};
use crate::error::{validate, Error, Result};
use dcrypt_internal::{
    constant_time::{Choice, ConditionallySelectable},
    Zeroize, ZeroizeOnDrop, Zeroizing,
};

/// Format of a serialized elliptic curve point
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointFormat {
    /// The point at infinity (identity element)
    Identity,
    /// Uncompressed format: 0x04 || x || y
    Uncompressed,
    /// Compressed format: 0x02/0x03 || x
    Compressed,
}

/// A point on the secp256k1 elliptic curve in affine coordinates
#[derive(Clone, Debug)]
pub struct Point {
    pub(crate) is_identity: Choice,
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
}

impl Default for Point {
    fn default() -> Self {
        Self::identity()
    }
}

impl Zeroize for Point {
    fn zeroize(&mut self) {
        self.is_identity.zeroize();
        self.x.zeroize();
        self.y.zeroize();
    }
}

impl Drop for Point {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Point {}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProjectivePoint {
    is_identity: Choice,
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

// `ConditionallySelectable` requires `Copy`, so compiler/register-created
// copies cannot be erased by safe Rust. Every explicit projective owner in
// secret arithmetic is nevertheless held in `Zeroizing` storage.
impl Default for ProjectivePoint {
    fn default() -> Self {
        Self::identity()
    }
}

impl Zeroize for ProjectivePoint {
    fn zeroize(&mut self) {
        self.is_identity.zeroize();
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        let self_is_identity: bool = self.is_identity.into();
        let other_is_identity: bool = other.is_identity.into();
        if self_is_identity || other_is_identity {
            return self_is_identity == other_is_identity;
        }
        self.x == other.x && self.y == other.y
    }
}

impl Point {
    /// Create a new point from uncompressed coordinates.
    ///
    /// Returns an error if the coordinates don't satisfy the curve equation.
    pub fn new_uncompressed(
        x: &[u8; K256_FIELD_ELEMENT_SIZE],
        y: &[u8; K256_FIELD_ELEMENT_SIZE],
    ) -> Result<Self> {
        let x_fe = Zeroizing::new(FieldElement::from_bytes(x)?);
        let y_fe = Zeroizing::new(FieldElement::from_bytes(y)?);
        if !Self::is_on_curve(&x_fe, &y_fe) {
            return Err(Error::param(
                "K256 Point",
                "Point coordinates do not satisfy curve equation",
            ));
        }
        Ok(Point {
            is_identity: Choice::from(0),
            x: x_fe.into_inner(),
            y: y_fe.into_inner(),
        })
    }

    /// Create the identity point (point at infinity).
    pub fn identity() -> Self {
        Point {
            is_identity: Choice::from(1),
            x: FieldElement::zero(),
            y: FieldElement::zero(),
        }
    }

    /// Check if this point is the identity element.
    pub fn is_identity(&self) -> bool {
        self.is_identity.into()
    }

    /// Check if this point is valid (on the curve).
    pub fn is_valid(&self) -> bool {
        if self.is_identity() {
            return true;
        }
        Self::is_on_curve(&self.x, &self.y)
    }

    /// Get the x-coordinate of this point as bytes.
    pub fn x_coordinate_bytes(&self) -> [u8; K256_FIELD_ELEMENT_SIZE] {
        self.x.to_bytes()
    }

    /// Get the y-coordinate of this point as bytes.
    pub fn y_coordinate_bytes(&self) -> [u8; K256_FIELD_ELEMENT_SIZE] {
        self.y.to_bytes()
    }

    /// Serialize this point in uncompressed format.
    ///
    /// For the identity this fixed-width API returns an all-zero internal
    /// sentinel. SEC 1 encodes identity as the single byte `0x00`, so the
    /// sentinel is deliberately rejected by the deserializer and must not be
    /// placed on the wire.
    pub fn serialize_uncompressed(&self) -> [u8; K256_POINT_UNCOMPRESSED_SIZE] {
        let mut out = Zeroizing::new([0u8; K256_POINT_UNCOMPRESSED_SIZE]);
        if self.is_identity() {
            return [0u8; K256_POINT_UNCOMPRESSED_SIZE];
        }
        out[0] = 0x04;
        let x_bytes = Zeroizing::new(self.x.to_bytes());
        let y_bytes = Zeroizing::new(self.y.to_bytes());
        out[1..33].copy_from_slice(&x_bytes[..]);
        out[33..].copy_from_slice(&y_bytes[..]);
        // Intentional public serialization boundary. This array exceeds the
        // MSRV's array-`Default` support, so `into_inner` is unavailable.
        let mut public_output = [0u8; K256_POINT_UNCOMPRESSED_SIZE];
        public_output.copy_from_slice(&out[..]);
        public_output
    }

    /// Deserialize a point from uncompressed format.
    ///
    /// Returns an error if the bytes don't represent a valid point.
    pub fn deserialize_uncompressed(bytes: &[u8]) -> Result<Self> {
        validate::length(
            "K256 Uncompressed Point",
            bytes.len(),
            K256_POINT_UNCOMPRESSED_SIZE,
        )?;

        if bytes[0] != 0x04 {
            return Err(Error::param(
                "K256 Point",
                "Invalid uncompressed point prefix (expected 0x04)",
            ));
        }

        let mut x_bytes = Zeroizing::new([0u8; K256_FIELD_ELEMENT_SIZE]);
        let mut y_bytes = Zeroizing::new([0u8; K256_FIELD_ELEMENT_SIZE]);
        x_bytes.copy_from_slice(&bytes[1..33]);
        y_bytes.copy_from_slice(&bytes[33..65]);

        Self::new_uncompressed(&x_bytes, &y_bytes)
    }

    /// Serialize this point in compressed format.
    ///
    /// For the identity this fixed-width API returns an all-zero internal
    /// sentinel, which is not a canonical SEC 1 encoding and is rejected by
    /// the deserializer.
    pub fn serialize_compressed(&self) -> [u8; K256_POINT_COMPRESSED_SIZE] {
        let mut out = Zeroizing::new([0u8; K256_POINT_COMPRESSED_SIZE]);
        if self.is_identity() {
            return [0u8; K256_POINT_COMPRESSED_SIZE];
        }
        out[0] = if self.y.is_odd() { 0x03 } else { 0x02 };
        let x_bytes = Zeroizing::new(self.x.to_bytes());
        out[1..].copy_from_slice(&x_bytes[..]);
        // Intentional public serialization boundary; see the uncompressed
        // serializer for the MSRV array-`Default` limitation.
        let mut public_output = [0u8; K256_POINT_COMPRESSED_SIZE];
        public_output.copy_from_slice(&out[..]);
        public_output
    }

    /// Deserialize a point from compressed format.
    ///
    /// Returns an error if the bytes don't represent a valid point.
    pub fn deserialize_compressed(bytes: &[u8]) -> Result<Self> {
        validate::length(
            "K256 Compressed Point",
            bytes.len(),
            K256_POINT_COMPRESSED_SIZE,
        )?;
        let tag = bytes[0];
        if tag != 0x02 && tag != 0x03 {
            return Err(Error::param(
                "K256 Point",
                "Invalid compressed point prefix",
            ));
        }
        let mut x_bytes = Zeroizing::new([0u8; K256_FIELD_ELEMENT_SIZE]);
        x_bytes.copy_from_slice(&bytes[1..]);
        let x_fe = Zeroizing::new(
            FieldElement::from_bytes(&x_bytes)
                .map_err(|_| Error::param("K256 Point", "Invalid x-coordinate"))?,
        );

        let x_squared = Zeroizing::new(x_fe.square());
        let x3 = Zeroizing::new(x_squared.mul(&x_fe));
        let mut seven = Zeroizing::new([0u32; 8]);
        seven[0] = 7;
        let b = Zeroizing::new(FieldElement(seven.into_inner()));
        let rhs = Zeroizing::new(x3.add(&b));
        let y_fe = Zeroizing::new(
            rhs.sqrt()
                .ok_or_else(|| Error::param("K256 Point", "Invalid compressed point: no sqrt"))?,
        );
        let y_final = Zeroizing::new(
            if (y_fe.is_odd() && tag == 0x03) || (!y_fe.is_odd() && tag == 0x02) {
                *y_fe
            } else {
                y_fe.negate()
            },
        );
        Ok(Point {
            is_identity: Choice::from(0),
            x: x_fe.into_inner(),
            y: y_final.into_inner(),
        })
    }

    /// Add two points using the group law.
    pub fn add(&self, other: &Self) -> Self {
        let left = self.to_projective();
        let right = other.to_projective();
        let sum = Zeroizing::new(left.add(&right));
        let affine = Zeroizing::new(sum.to_affine());
        affine.into_inner()
    }

    /// Double a point (add it to itself).
    pub fn double(&self) -> Self {
        let point = self.to_projective();
        let doubled = Zeroizing::new(point.double());
        let affine = Zeroizing::new(doubled.to_affine());
        affine.into_inner()
    }

    /// Scalar multiplication: compute scalar * self.
    ///
    /// Uses constant-time double-and-add algorithm.
    pub fn mul(&self, scalar: &Scalar) -> Result<Self> {
        let scalar_bytes = scalar.as_secret_buffer().as_ref();
        let base = self.to_projective();
        let mut result = Zeroizing::new(ProjectivePoint::identity());

        for byte in scalar_bytes.iter() {
            for bit_pos in (0..8).rev() {
                let doubled = Zeroizing::new(result.double());
                let bit = (byte >> bit_pos) & 1;
                let choice = Choice::from(bit);
                let result_added = Zeroizing::new(doubled.add(&base));
                let selected = Zeroizing::new(ProjectivePoint::conditional_select(
                    &doubled,
                    &result_added,
                    choice,
                ));
                result.zeroize();
                *result = selected.into_inner();
            }
        }
        let affine = Zeroizing::new(result.to_affine());
        Ok(affine.into_inner())
    }

    fn is_on_curve(x: &FieldElement, y: &FieldElement) -> bool {
        let y_squared = Zeroizing::new(y.square());
        let x_squared = Zeroizing::new(x.square());
        let x_cubed = Zeroizing::new(x_squared.mul(x));
        let mut seven_limbs = Zeroizing::new([0u32; 8]);
        seven_limbs[0] = 7;
        let seven = Zeroizing::new(FieldElement(seven_limbs.into_inner()));
        let rhs = Zeroizing::new(x_cubed.add(&seven));
        *y_squared == *rhs
    }

    fn to_projective(&self) -> Zeroizing<ProjectivePoint> {
        if self.is_identity() {
            return Zeroizing::new(ProjectivePoint::identity());
        }
        Zeroizing::new(ProjectivePoint {
            is_identity: Choice::from(0),
            x: self.x,
            y: self.y,
            z: FieldElement::one(),
        })
    }
}

impl ConditionallySelectable for ProjectivePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let selected = Zeroizing::new(Self {
            is_identity: Choice::conditional_select(&a.is_identity, &b.is_identity, choice),
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        });
        selected.into_inner()
    }
}

impl ProjectivePoint {
    pub fn identity() -> Self {
        ProjectivePoint {
            is_identity: Choice::from(1),
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::zero(),
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        // Constant-time add with no early returns
        let z1_sq = Zeroizing::new(self.z.square());
        let z2_sq = Zeroizing::new(other.z.square());
        let u1 = Zeroizing::new(self.x.mul(&z2_sq));
        let u2 = Zeroizing::new(other.x.mul(&z1_sq));
        let self_y_z2 = Zeroizing::new(self.y.mul(&z2_sq));
        let s1 = Zeroizing::new(self_y_z2.mul(&other.z));
        let other_y_z1 = Zeroizing::new(other.y.mul(&z1_sq));
        let s2 = Zeroizing::new(other_y_z1.mul(&self.z));

        let h = Zeroizing::new(u2.sub(&u1));
        let r = Zeroizing::new(s2.sub(&s1));

        // Generic addition
        let h_sq = Zeroizing::new(h.square());
        let h_cu = Zeroizing::new(h_sq.mul(&h));
        let v = Zeroizing::new(u1.mul(&h_sq));

        let r_sq = Zeroizing::new(r.square());
        let r_sq_minus_h_cu = Zeroizing::new(r_sq.sub(&h_cu));
        let two_v = Zeroizing::new(v.add(&v));
        let x3 = Zeroizing::new(r_sq_minus_h_cu.sub(&two_v));

        let v_minus_x3 = Zeroizing::new(v.sub(&x3));
        let r_times_difference = Zeroizing::new(r.mul(&v_minus_x3));
        let s1_h_cu = Zeroizing::new(s1.mul(&h_cu));
        let y3 = Zeroizing::new(r_times_difference.sub(&s1_h_cu));

        let z_product = Zeroizing::new(self.z.mul(&other.z));
        let z3 = Zeroizing::new(z_product.mul(&h));

        let generic = Zeroizing::new(ProjectivePoint {
            is_identity: Choice::from(0),
            x: x3.into_inner(),
            y: y3.into_inner(),
            z: z3.into_inner(),
        });

        // Double (fallback for P==Q)
        let double = Zeroizing::new(self.double());

        // Select results
        let h_is_zero = Choice::from((h.is_zero() as u8) & 1);
        let r_is_zero = Choice::from((r.is_zero() as u8) & 1);
        let p_eq_q = h_is_zero & r_is_zero;
        let p_eq_neg_q = h_is_zero & !r_is_zero;

        let mut result = Zeroizing::new(Self::conditional_select(&generic, &double, p_eq_q));
        let identity = Zeroizing::new(Self::identity());
        let selected = Zeroizing::new(Self::conditional_select(&result, &identity, p_eq_neg_q));
        result.zeroize();
        *result = selected.into_inner();
        let selected = Zeroizing::new(Self::conditional_select(&result, other, self.is_identity));
        result.zeroize();
        *result = selected.into_inner();
        let selected = Zeroizing::new(Self::conditional_select(&result, self, other.is_identity));
        result.zeroize();
        *result = selected.into_inner();

        result.into_inner()
    }

    pub fn double(&self) -> Self {
        // Jacobian doubling for a = 0 (y^2 = x^3 + 7)

        let y_sq = Zeroizing::new(self.y.square());
        let s_once = Zeroizing::new(self.x.mul(&y_sq));
        let s_twice = Zeroizing::new(s_once.add(&s_once)); // 2s
        let s = Zeroizing::new(s_twice.add(&s_twice)); // 4s -> S = 4*x*y^2

        let x_sq = Zeroizing::new(self.x.square());
        let m_twice = Zeroizing::new(x_sq.add(&x_sq));
        let m = Zeroizing::new(m_twice.add(&x_sq)); // M = 3*x^2 (a=0)

        let m_squared = Zeroizing::new(m.square());
        let s_plus_s = Zeroizing::new(s.add(&s));
        let x3 = Zeroizing::new(m_squared.sub(&s_plus_s)); // X3 = M^2 - 2S

        let s_minus_x3 = Zeroizing::new(s.sub(&x3));
        let m_term = Zeroizing::new(m.mul(&s_minus_x3));

        let y_sq_sq = Zeroizing::new(y_sq.square());
        let two_y4 = Zeroizing::new(y_sq_sq.add(&y_sq_sq));
        let four_y4 = Zeroizing::new(two_y4.add(&two_y4));
        let eight_y4 = Zeroizing::new(four_y4.add(&four_y4));
        let y3 = Zeroizing::new(m_term.sub(&eight_y4)); // Y3 = M(S - X3) - 8Y^4

        let yz = Zeroizing::new(self.y.mul(&self.z));
        let z3 = Zeroizing::new(yz.add(&yz)); // Z3 = 2*Y*Z

        let result = Zeroizing::new(ProjectivePoint {
            is_identity: Choice::from(0),
            x: x3.into_inner(),
            y: y3.into_inner(),
            z: z3.into_inner(),
        });

        // Explicitly handle identity or y=0 cases constant-time
        let is_y_zero = self.y.is_zero();
        let return_identity = self.is_identity | Choice::from(is_y_zero as u8);

        let identity = Zeroizing::new(Self::identity());
        let selected = Zeroizing::new(Self::conditional_select(
            &result,
            &identity,
            return_identity,
        ));
        selected.into_inner()
    }

    pub fn to_affine(&self) -> Point {
        let safe_z = Zeroizing::new(FieldElement::conditional_select(
            &self.z,
            &FieldElement::one(),
            self.is_identity,
        ));
        let z_inv = Zeroizing::new(safe_z.invert().expect("Nonzero Z should be invertible"));
        let z_inv_sq = Zeroizing::new(z_inv.square());
        let z_inv_cu = Zeroizing::new(z_inv_sq.mul(&z_inv));
        let x_aff = Zeroizing::new(self.x.mul(&z_inv_sq));
        let y_aff = Zeroizing::new(self.y.mul(&z_inv_cu));
        let x = Zeroizing::new(FieldElement::conditional_select(
            &x_aff,
            &FieldElement::zero(),
            self.is_identity,
        ));
        let y = Zeroizing::new(FieldElement::conditional_select(
            &y_aff,
            &FieldElement::zero(),
            self.is_identity,
        ));
        let point = Zeroizing::new(Point {
            is_identity: self.is_identity,
            x: x.into_inner(),
            y: y.into_inner(),
        });
        point.into_inner()
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn affine_drop_and_projective_copy_limit_are_explicit() {
        assert_zeroize_on_drop::<Point>();

        let mut affine = Point {
            is_identity: Choice::from(0),
            x: FieldElement::one(),
            y: FieldElement::one(),
        };
        affine.zeroize();
        assert!(affine.x.is_zero());
        assert!(affine.y.is_zero());

        let original = ProjectivePoint {
            is_identity: Choice::from(0),
            x: FieldElement::one(),
            y: FieldElement::one(),
            z: FieldElement::one(),
        };
        let mut owned_copy = original;
        owned_copy.zeroize();
        assert!(owned_copy.x.is_zero());
        assert!(!original.x.is_zero());
    }
}
