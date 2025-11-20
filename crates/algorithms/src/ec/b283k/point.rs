//! sect283k1 elliptic curve point operations

use crate::ec::b283k::{
    constants::{B283K_FIELD_ELEMENT_SIZE, B283K_POINT_COMPRESSED_SIZE},
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

/// A point on the sect283k1 elliptic curve
#[derive(Clone, Copy, Debug)]
pub struct Point {
    pub(crate) is_identity: Choice,
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
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

impl Eq for Point {}

impl ConditionallySelectable for Point {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            is_identity: Choice::conditional_select(&a.is_identity, &b.is_identity, choice),
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
        }
    }
}

impl Point {
    /// Create a new point from uncompressed coordinates.
    ///
    /// Returns an error if the coordinates don't satisfy the curve equation y² + xy = x³ + 1.
    pub fn new_uncompressed(
        x: &[u8; B283K_FIELD_ELEMENT_SIZE],
        y: &[u8; B283K_FIELD_ELEMENT_SIZE],
    ) -> Result<Self> {
        let x_fe = FieldElement::from_bytes(x)?;
        let y_fe = FieldElement::from_bytes(y)?;
        if !Self::is_on_curve(&x_fe, &y_fe) {
            return Err(Error::param(
                "B283k Point",
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

    /// Get the x-coordinate of this point as bytes.
    pub fn x_coordinate_bytes(&self) -> [u8; B283K_FIELD_ELEMENT_SIZE] {
        self.x.to_bytes()
    }

    /// Get the y-coordinate of this point as bytes.
    pub fn y_coordinate_bytes(&self) -> [u8; B283K_FIELD_ELEMENT_SIZE] {
        self.y.to_bytes()
    }

    /// Serialize this point in compressed format.
    ///
    /// The compressed format uses the trace to disambiguate the y-coordinate.
    pub fn serialize_compressed(&self) -> [u8; B283K_POINT_COMPRESSED_SIZE] {
        let mut out = [0u8; B283K_POINT_COMPRESSED_SIZE];
        if self.is_identity() {
            return out;
        }

        let y_tilde = self.x.invert().unwrap().mul(&self.y).trace();
        out[0] = if y_tilde == 1 { 0x03 } else { 0x02 };
        out[1..].copy_from_slice(&self.x.to_bytes());
        out
    }

    /// Deserialize a point from compressed format.
    ///
    /// Recovers the y-coordinate from the x-coordinate and the compression flag.
    /// Returns an error if the bytes don't represent a valid point.
    pub fn deserialize_compressed(bytes: &[u8]) -> Result<Self> {
        validate::length(
            "B283k Compressed Point",
            bytes.len(),
            B283K_POINT_COMPRESSED_SIZE,
        )?;
        if bytes.iter().all(|&b| b == 0) {
            return Ok(Self::identity());
        }
        let tag = bytes[0];
        if tag != 0x02 && tag != 0x03 {
            return Err(Error::param(
                "B283k Point",
                "Invalid compressed point prefix",
            ));
        }
        let mut x_bytes = [0u8; B283K_FIELD_ELEMENT_SIZE];
        x_bytes.copy_from_slice(&bytes[1..]);
        let x = FieldElement::from_bytes(&x_bytes)?;
        if x.is_zero() {
            return Ok(Point {
                is_identity: Choice::from(0),
                x,
                y: FieldElement::one().sqrt(),
            });
        }

        let rhs = x.add(&x.square().invert().unwrap());

        if rhs.trace() != 0 {
            return Err(Error::param("B283k Point", "Cannot decompress point"));
        }

        let mut z = Self::half_trace(&rhs);

        if z.trace() != (tag as u64 - 2) {
            z = z.add(&FieldElement::one());
        }

        let y = x.mul(&z);
        Ok(Point {
            is_identity: Choice::from(0),
            x,
            y,
        })
    }

    fn half_trace(a: &FieldElement) -> FieldElement {
        let mut ht = *a;
        let mut t = *a;
        for _ in 0..141 {
            t = t.square();
            t = t.square();
            ht = ht.add(&t);
        }
        ht
    }

    /// Constant-time Affine addition.
    /// Computes both addition and doubling paths and selects valid one.
    /// Handles division-by-zero safely via dummy inversion.
    pub fn add(&self, other: &Self) -> Self {
        // 1. Calculate flags
        let x_eq = self.x == other.x;
        let y_eq = self.y == other.y;
        
        // P == Q: x1 == x2 AND y1 == y2
        let p_eq_q = Choice::from((x_eq && y_eq) as u8);
        // P == -Q: x1 == x2 AND y1 != y2 (in binary field characteristic 2)
        let p_eq_neg_q = Choice::from((x_eq && !y_eq) as u8);
        
        // 2. Compute Generic Addition (valid when x1 != x2)
        // lambda = (y1 + y2) / (x1 + x2)
        let sum_y = self.y.add(&other.y);
        let sum_x = self.x.add(&other.x);
        
        // Safe inversion: if sum_x is zero (x1 == x2), invert 1 instead.
        // This produces garbage result, but we won't select it in that case.
        let sum_x_is_zero = Choice::from(sum_x.is_zero() as u8);
        let denom = FieldElement::conditional_select(&sum_x, &FieldElement::one(), sum_x_is_zero);
        let inv_denom = denom.invert().unwrap_or(FieldElement::zero());
        
        let lambda = sum_y.mul(&inv_denom);
        let x3 = lambda.square().add(&lambda).add(&self.x).add(&other.x);
        let y3 = lambda.mul(&(self.x.add(&x3))).add(&x3).add(&self.y);
        
        let generic = Point {
            is_identity: Choice::from(0),
            x: x3,
            y: y3,
        };

        // 3. Compute Doubling (valid when P == Q)
        let double = self.double();

        // 4. Select Result
        // Start with Generic. If P==Q, switch to Double.
        let mut result = Self::conditional_select(&generic, &double, p_eq_q);
        
        // If P == -Q, the result must be Identity.
        result = Self::conditional_select(&result, &Self::identity(), p_eq_neg_q);
        
        // If either input is identity, result is the other one.
        result = Self::conditional_select(&result, other, self.is_identity);
        result = Self::conditional_select(&result, self, other.is_identity);

        result
    }

    /// Constant-time Affine doubling.
    /// Computes doubling formula safely, handling the P at infinity case
    /// without branching.
    pub fn double(&self) -> Self {
        // lambda = x + y/x
        // Safe inversion: if x is zero, invert 1
        let x_is_zero = Choice::from(self.x.is_zero() as u8);
        let denom = FieldElement::conditional_select(&self.x, &FieldElement::one(), x_is_zero);
        let inv_x = denom.invert().unwrap_or(FieldElement::zero());
        
        let term = self.y.mul(&inv_x);
        let lambda = self.x.add(&term);
        
        let x2 = lambda.square().add(&lambda);
        let y2 = self.x.square().add(&lambda.mul(&x2)).add(&x2);

        let result = Point {
            is_identity: Choice::from(0),
            x: x2,
            y: y2,
        };

        Self::conditional_select(&result, &Self::identity(), self.is_identity)
    }

    /// Scalar multiplication: compute scalar * self.
    ///
    /// Uses constant-time double-and-add algorithm.
    pub fn mul(&self, scalar: &Scalar) -> Result<Self> {
        if scalar.is_zero() {
            return Ok(Self::identity());
        }
        let scalar_bytes = scalar.as_secret_buffer().as_ref();
        let mut res = Self::identity();
        let mut temp = self.clone();

        for byte in scalar_bytes.iter().rev() {
            for i in 0..8 {
                let bit = (byte >> i) & 1;
                let choice = Choice::from(bit);

                // Unconditionally compute addition
                let res_added = res.add(&temp);
                
                // Constant-time select
                res = Point::conditional_select(&res, &res_added, choice);

                // Unconditionally double
                temp = temp.double();
            }
        }
        Ok(res)
    }

    fn is_on_curve(x: &FieldElement, y: &FieldElement) -> bool {
        let y_sq = y.square();
        let xy = x.mul(y);
        let lhs = y_sq.add(&xy);

        let x_cubed = x.square().mul(x);
        let rhs = x_cubed.add(&FieldElement::one());

        lhs == rhs
    }
}