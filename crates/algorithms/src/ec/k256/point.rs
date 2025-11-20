//! secp256k1 elliptic curve point operations

use crate::ec::k256::{
    constants::{
        K256_FIELD_ELEMENT_SIZE, K256_POINT_COMPRESSED_SIZE, K256_POINT_UNCOMPRESSED_SIZE,
    },
    field::FieldElement,
    scalar::Scalar,
};
use crate::error::{validate, Error, Result};
use subtle::{Choice, ConditionallySelectable};

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

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProjectivePoint {
    is_identity: Choice,
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
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
        let x_fe = FieldElement::from_bytes(x)?;
        let y_fe = FieldElement::from_bytes(y)?;
        if !Self::is_on_curve(&x_fe, &y_fe) {
            return Err(Error::param(
                "K256 Point",
                "Point coordinates do not satisfy curve equation",
            ));
        }
        Ok(Point {
            is_identity: Choice::from(0),
            x: x_fe,
            y: y_fe,
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
    pub fn serialize_uncompressed(&self) -> [u8; K256_POINT_UNCOMPRESSED_SIZE] {
        let mut out = [0u8; K256_POINT_UNCOMPRESSED_SIZE];
        if self.is_identity() {
            return out;
        }
        out[0] = 0x04;
        out[1..33].copy_from_slice(&self.x.to_bytes());
        out[33..].copy_from_slice(&self.y.to_bytes());
        out
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

        if bytes.iter().all(|&b| b == 0) {
            return Ok(Self::identity());
        }

        if bytes[0] != 0x04 {
            return Err(Error::param(
                "K256 Point",
                "Invalid uncompressed point prefix (expected 0x04)",
            ));
        }

        let mut x_bytes = [0u8; K256_FIELD_ELEMENT_SIZE];
        let mut y_bytes = [0u8; K256_FIELD_ELEMENT_SIZE];
        x_bytes.copy_from_slice(&bytes[1..33]);
        y_bytes.copy_from_slice(&bytes[33..65]);

        Self::new_uncompressed(&x_bytes, &y_bytes)
    }

    /// Serialize this point in compressed format.
    pub fn serialize_compressed(&self) -> [u8; K256_POINT_COMPRESSED_SIZE] {
        let mut out = [0u8; K256_POINT_COMPRESSED_SIZE];
        if self.is_identity() {
            return out;
        }
        out[0] = if self.y.is_odd() { 0x03 } else { 0x02 };
        out[1..].copy_from_slice(&self.x.to_bytes());
        out
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
        if bytes.iter().all(|&b| b == 0) {
            return Ok(Self::identity());
        }
        let tag = bytes[0];
        if tag != 0x02 && tag != 0x03 {
            return Err(Error::param(
                "K256 Point",
                "Invalid compressed point prefix",
            ));
        }
        let mut x_bytes = [0u8; K256_FIELD_ELEMENT_SIZE];
        x_bytes.copy_from_slice(&bytes[1..]);
        let x_fe = FieldElement::from_bytes(&x_bytes)
            .map_err(|_| Error::param("K256 Point", "Invalid x-coordinate"))?;
        
        let rhs = {
            let x3 = x_fe.square().mul(&x_fe);
            let mut seven = [0u32; 8];
            seven[0] = 7;
            let b = FieldElement(seven);
            x3.add(&b)
        };
        let y_fe = rhs
            .sqrt()
            .ok_or_else(|| Error::param("K256 Point", "Invalid compressed point: no sqrt"))?;
        let y_final = if (y_fe.is_odd() && tag == 0x03) || (!y_fe.is_odd() && tag == 0x02) {
            y_fe
        } else {
            y_fe.negate()
        };
        Ok(Point {
            is_identity: Choice::from(0),
            x: x_fe,
            y: y_final,
        })
    }

    /// Add two points using the group law.
    pub fn add(&self, other: &Self) -> Self {
        self.to_projective().add(&other.to_projective()).to_affine()
    }

    /// Double a point (add it to itself).
    pub fn double(&self) -> Self {
        self.to_projective().double().to_affine()
    }

    /// Scalar multiplication: compute scalar * self.
    ///
    /// Uses constant-time double-and-add algorithm.
    pub fn mul(&self, scalar: &Scalar) -> Result<Self> {
        if scalar.is_zero() {
            return Ok(Self::identity());
        }
        let scalar_bytes = scalar.as_secret_buffer().as_ref();
        let base = self.to_projective();
        let mut result = ProjectivePoint::identity();

        for byte in scalar_bytes.iter() {
            for bit_pos in (0..8).rev() {
                result = result.double();
                let bit = (byte >> bit_pos) & 1;
                let choice = Choice::from(bit);
                let result_added = result.add(&base);
                result = ProjectivePoint::conditional_select(&result, &result_added, choice);
            }
        }
        Ok(result.to_affine())
    }

    fn is_on_curve(x: &FieldElement, y: &FieldElement) -> bool {
        let y_squared = y.square();
        let x_cubed = x.square().mul(x);
        let mut seven_limbs = [0u32; 8];
        seven_limbs[0] = 7;
        let seven = FieldElement(seven_limbs);
        let rhs = x_cubed.add(&seven);
        y_squared == rhs
    }

    fn to_projective(&self) -> ProjectivePoint {
        if self.is_identity() {
            return ProjectivePoint::identity();
        }
        ProjectivePoint {
            is_identity: Choice::from(0),
            x: self.x,
            y: self.y,
            z: FieldElement::one(),
        }
    }
}

impl ConditionallySelectable for ProjectivePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            is_identity: Choice::conditional_select(&a.is_identity, &b.is_identity, choice),
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
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
        let z1_sq = self.z.square();
        let z2_sq = other.z.square();
        let u1 = self.x.mul(&z2_sq);
        let u2 = other.x.mul(&z1_sq);
        let s1 = self.y.mul(&z2_sq).mul(&other.z);
        let s2 = other.y.mul(&z1_sq).mul(&self.z);

        let h = u2.sub(&u1);
        let r = s2.sub(&s1);
        
        // Generic addition
        let h_sq = h.square();
        let h_cu = h_sq.mul(&h);
        let v = u1.mul(&h_sq);

        let r_sq = r.square();
        let two_v = v.add(&v);
        let mut x3 = r_sq.sub(&h_cu);
        x3 = x3.sub(&two_v);

        let v_minus_x3 = v.sub(&x3);
        let mut y3 = r.mul(&v_minus_x3);
        let s1_h_cu = s1.mul(&h_cu);
        y3 = y3.sub(&s1_h_cu);

        let mut z3 = self.z.mul(&other.z);
        z3 = z3.mul(&h);

        let generic = ProjectivePoint {
            is_identity: Choice::from(0),
            x: x3,
            y: y3,
            z: z3,
        };

        // Double (fallback for P==Q)
        let double = self.double();

        // Select results
        let h_is_zero = Choice::from((h.is_zero() as u8) & 1);
        let r_is_zero = Choice::from((r.is_zero() as u8) & 1);
        let p_eq_q = h_is_zero & r_is_zero;
        let p_eq_neg_q = h_is_zero & !r_is_zero;

        let mut result = Self::conditional_select(&generic, &double, p_eq_q);
        result = Self::conditional_select(&result, &Self::identity(), p_eq_neg_q);
        result = Self::conditional_select(&result, other, self.is_identity);
        result = Self::conditional_select(&result, self, other.is_identity);

        result
    }

    pub fn double(&self) -> Self {
        // Jacobian doubling for a = 0 (y^2 = x^3 + 7)
        
        let y_sq = self.y.square();
        let mut s = self.x.mul(&y_sq);
        s = s.add(&s); // 2s
        s = s.add(&s); // 4s -> S = 4*x*y^2
        
        let x_sq = self.x.square();
        let mut m = x_sq.add(&x_sq);
        m = m.add(&x_sq); // M = 3*x^2 (a=0)

        let mut x3 = m.square();
        let s_plus_s = s.add(&s);
        x3 = x3.sub(&s_plus_s); // X3 = M^2 - 2S

        let mut y3 = s.sub(&x3);
        y3 = m.mul(&y3);
        
        let y_sq_sq = y_sq.square();
        let mut eight_y4 = y_sq_sq.add(&y_sq_sq); // 2
        eight_y4 = eight_y4.add(&eight_y4); // 4
        eight_y4 = eight_y4.add(&eight_y4); // 8
        y3 = y3.sub(&eight_y4); // Y3 = M(S - X3) - 8Y^4

        let mut z3 = self.y.mul(&self.z);
        z3 = z3.add(&z3); // Z3 = 2*Y*Z

        let result = ProjectivePoint {
            is_identity: Choice::from(0),
            x: x3,
            y: y3,
            z: z3,
        };

        // Explicitly handle identity or y=0 cases constant-time
        let is_y_zero = self.y.is_zero();
        let return_identity = self.is_identity | Choice::from(is_y_zero as u8);
        
        Self::conditional_select(&result, &Self::identity(), return_identity)
    }

    pub fn to_affine(&self) -> Point {
        if self.is_identity.into() {
            return Point::identity();
        }
        let z_inv = self.z.invert().expect("Nonzero Z should be invertible");
        let z_inv_sq = z_inv.square();
        let z_inv_cu = z_inv_sq.mul(&z_inv);
        let x_aff = self.x.mul(&z_inv_sq);
        let y_aff = self.y.mul(&z_inv_cu);
        Point {
            is_identity: Choice::from(0),
            x: x_aff,
            y: y_aff,
        }
    }
}