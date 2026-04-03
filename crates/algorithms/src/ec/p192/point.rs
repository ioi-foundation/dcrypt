//! P-192 elliptic curve point operations

use crate::ec::p192::{
    constants::{
        P192_FIELD_ELEMENT_SIZE, P192_POINT_COMPRESSED_SIZE, P192_POINT_UNCOMPRESSED_SIZE,
    },
    field::FieldElement,
    scalar::Scalar,
};
use crate::error::{validate, Error, Result};
use subtle::{Choice, ConditionallySelectable};

/// Format of a serialized elliptic‐curve point
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointFormat {
    /// Identity point (all zeros)
    Identity,
    /// Uncompressed: 0x04 ∥ x ∥ y
    Uncompressed,
    /// Compressed: 0x02/0x03 ∥ x
    Compressed,
}

/// Affine coordinates (x, y) or identity; 𝔽ₚ is built from FieldElement
#[derive(Clone, Debug)]
pub struct Point {
    pub(crate) is_identity: Choice,
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
}

/// Jacobian coordinates (X:Y:Z) for efficient arithmetic
#[derive(Clone, Debug)]
pub(crate) struct ProjectivePoint {
    pub(crate) is_identity: Choice,
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        let a_id: bool = self.is_identity.into();
        let b_id: bool = other.is_identity.into();
        if a_id || b_id {
            return a_id == b_id;
        }
        self.x == other.x && self.y == other.y
    }
}

impl Point {
    /// Create a new affine point from uncompressed byte coordinates
    pub fn new_uncompressed(
        x_bytes: &[u8; P192_FIELD_ELEMENT_SIZE],
        y_bytes: &[u8; P192_FIELD_ELEMENT_SIZE],
    ) -> Result<Self> {
        let x_fe = FieldElement::from_bytes(x_bytes)?;
        let y_fe = FieldElement::from_bytes(y_bytes)?;
        if !Self::is_on_curve(&x_fe, &y_fe) {
            return Err(Error::param("P-192 Point", "Point not on curve"));
        }
        Ok(Point {
            is_identity: Choice::from(0),
            x: x_fe,
            y: y_fe,
        })
    }

    /// The identity (point at infinity)
    pub fn identity() -> Self {
        Point {
            is_identity: Choice::from(1),
            x: FieldElement::zero(),
            y: FieldElement::zero(),
        }
    }

    /// Is this the identity point?
    pub fn is_identity(&self) -> bool {
        self.is_identity.into()
    }

    /// Extract x‐coordinate as big‐endian bytes
    pub fn x_coordinate_bytes(&self) -> [u8; P192_FIELD_ELEMENT_SIZE] {
        self.x.to_bytes()
    }

    /// Extract y‐coordinate as big‐endian bytes
    pub fn y_coordinate_bytes(&self) -> [u8; P192_FIELD_ELEMENT_SIZE] {
        self.y.to_bytes()
    }

    /// Detect serialized point format
    pub fn detect_format(bytes: &[u8]) -> Result<PointFormat> {
        if bytes.is_empty() {
            return Err(Error::param("P-192 Point", "Empty encoding"));
        }
        match (bytes[0], bytes.len()) {
            (0x00, P192_POINT_UNCOMPRESSED_SIZE) => {
                // all‐zeros encoding = identity
                if bytes.iter().all(|&b| b == 0) {
                    Ok(PointFormat::Identity)
                } else {
                    Err(Error::param("P-192 Point", "Invalid identity encoding"))
                }
            }
            (0x04, P192_POINT_UNCOMPRESSED_SIZE) => Ok(PointFormat::Uncompressed),
            (0x02 | 0x03, P192_POINT_COMPRESSED_SIZE) => Ok(PointFormat::Compressed),
            _ => Err(Error::param("P-192 Point", "Unknown or malformed format")),
        }
    }

    /// Serialize this point as uncompressed: 0x04 ∥ x ∥ y
    pub fn serialize_uncompressed(&self) -> [u8; P192_POINT_UNCOMPRESSED_SIZE] {
        let mut out = [0u8; P192_POINT_UNCOMPRESSED_SIZE];
        if self.is_identity() {
            return out; // all zeros
        }
        out[0] = 0x04;
        out[1..1 + P192_FIELD_ELEMENT_SIZE].copy_from_slice(&self.x.to_bytes());
        out[1 + P192_FIELD_ELEMENT_SIZE..].copy_from_slice(&self.y.to_bytes());
        out
    }

    /// Deserialize from uncompressed bytes (0x04 ∥ x ∥ y), or all‐zeros for identity
    pub fn deserialize_uncompressed(bytes: &[u8]) -> Result<Self> {
        validate::length("P-192 Point", bytes.len(), P192_POINT_UNCOMPRESSED_SIZE)?;
        if bytes.iter().all(|&b| b == 0) {
            return Ok(Self::identity());
        }
        if bytes[0] != 0x04 {
            return Err(Error::param(
                "P-192 Point",
                "Invalid prefix for uncompressed",
            ));
        }
        let mut xb = [0u8; P192_FIELD_ELEMENT_SIZE];
        let mut yb = [0u8; P192_FIELD_ELEMENT_SIZE];
        xb.copy_from_slice(&bytes[1..1 + P192_FIELD_ELEMENT_SIZE]);
        yb.copy_from_slice(&bytes[1 + P192_FIELD_ELEMENT_SIZE..]);
        Self::new_uncompressed(&xb, &yb)
    }

    /// Serialize this point in compressed form: 0x02/0x03 ∥ x
    pub fn serialize_compressed(&self) -> [u8; P192_POINT_COMPRESSED_SIZE] {
        let mut out = [0u8; P192_POINT_COMPRESSED_SIZE];
        if self.is_identity() {
            return out; // all zeros
        }
        out[0] = if self.y.is_odd() { 0x03 } else { 0x02 };
        out[1..].copy_from_slice(&self.x.to_bytes());
        out
    }

    /// Deserialize from compressed bytes (0x02/0x03 ∥ x) or all‐zeros for identity
    pub fn deserialize_compressed(bytes: &[u8]) -> Result<Self> {
        validate::length(
            "P-192 Compressed Point",
            bytes.len(),
            P192_POINT_COMPRESSED_SIZE,
        )?;
        if bytes.iter().all(|&b| b == 0) {
            return Ok(Self::identity());
        }
        let tag = bytes[0];
        if tag != 0x02 && tag != 0x03 {
            return Err(Error::param("P-192 Point", "Invalid compressed prefix"));
        }
        let mut xb = [0u8; P192_FIELD_ELEMENT_SIZE];
        xb.copy_from_slice(&bytes[1..]);
        let x_fe = FieldElement::from_bytes(&xb)
            .map_err(|_| Error::param("P-192 Point", "Invalid compressed point: x not in field"))?;
        // Compute rhs = x³ - 3x + b
        let rhs = {
            let x2 = x_fe.square();
            let x3 = x2.mul(&x_fe);
            let a = FieldElement(FieldElement::A_M3);
            let b_coeff = FieldElement::from_bytes(&crate::ec::p192::field::B).unwrap();
            x3.add(&a.mul(&x_fe)).add(&b_coeff)
        };
        let y_candidate = rhs
            .sqrt()
            .ok_or_else(|| Error::param("P-192 Point", "Invalid compressed point: no sqrt"))?;
        let y_final =
            if (y_candidate.is_odd() && tag == 0x03) || (!y_candidate.is_odd() && tag == 0x02) {
                y_candidate
            } else {
                y_candidate.negate() // p - y (cleaner than FieldElement::zero().sub(&y_candidate))
            };
        Ok(Point {
            is_identity: Choice::from(0),
            x: x_fe,
            y: y_final,
        })
    }

    /// Add two points (group law)
    pub fn add(&self, other: &Self) -> Self {
        let p1 = self.to_projective();
        let p2 = other.to_projective();
        let sum = p1.add(&p2);
        sum.to_affine()
    }

    /// Double this point: 2P
    pub fn double(&self) -> Self {
        let p = self.to_projective();
        let d = p.double();
        d.to_affine()
    }

    /// Scalar multiplication: P * scalar
    /// Constant‐time double‐and‐add
    pub fn mul(&self, scalar: &Scalar) -> Result<Self> {
        if scalar.is_zero() {
            return Ok(Self::identity());
        }
        let base = self.to_projective();
        let mut acc = ProjectivePoint::identity();
        let bytes = scalar.as_secret_buffer().as_ref();
        for &byte in bytes.iter() {
            for i in (0..8).rev() {
                acc = acc.double();
                let acc_added = acc.add(&base);
                let choice = Choice::from((byte >> i) & 1);
                acc = ProjectivePoint::conditional_select(&acc, &acc_added, choice);
            }
        }
        Ok(acc.to_affine())
    }

    /// Check that (x, y) satisfies y² = x³ - 3x + b
    fn is_on_curve(x: &FieldElement, y: &FieldElement) -> bool {
        let y2 = y.square();
        let x2 = x.square();
        let x3 = x2.mul(x);
        let a = FieldElement(FieldElement::A_M3);
        let b_coeff = FieldElement::from_bytes(&crate::ec::p192::field::B).unwrap();
        let rhs = x3.add(&a.mul(x)).add(&b_coeff);
        y2 == rhs
    }

    /// Convert affine to Jacobian for intermediate computations
    fn to_projective(&self) -> ProjectivePoint {
        if self.is_identity() {
            ProjectivePoint::identity()
        } else {
            ProjectivePoint {
                is_identity: Choice::from(0),
                x: self.x.clone(),
                y: self.y.clone(),
                z: FieldElement::one(),
            }
        }
    }
}

impl ProjectivePoint {
    /// Identity in Jacobian form: (0 : 1 : 0)
    pub fn identity() -> Self {
        ProjectivePoint {
            is_identity: Choice::from(1),
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::zero(),
        }
    }

    /// Constant‐time point addition (Jacobian coordinates)
    pub fn add(&self, other: &Self) -> Self {
        // Z₁², Z₂², Z₁³, Z₂³
        let z1_sq = self.z.square();
        let z2_sq = other.z.square();
        let z1_cu = z1_sq.mul(&self.z);
        let z2_cu = z2_sq.mul(&other.z);

        let u1 = self.x.mul(&z2_sq); // X₁·Z₂²
        let u2 = other.x.mul(&z1_sq); // X₂·Z₁²
        let s1 = self.y.mul(&z2_cu); // Y₁·Z₂³
        let s2 = other.y.mul(&z1_cu); // Y₂·Z₁³

        let h = u2.sub(&u1);
        let r = s2.sub(&s1);

        let h2 = h.square();
        let h3 = h2.mul(&h);
        let v = u1.mul(&h2);

        // X₃ = r² - h³ - 2v
        let r2 = r.square();
        let two_v = v.add(&v);
        let mut x3 = r2.sub(&h3);
        x3 = x3.sub(&two_v);

        // Y₃ = r·(v - X₃) - s1·h³
        let v_minus_x3 = v.sub(&x3);
        let r_times = r.mul(&v_minus_x3);
        let s1_h3 = s1.mul(&h3);
        let y3 = r_times.sub(&s1_h3);

        // Z₃ = Z₁·Z₂·h
        let z1z2 = self.z.mul(&other.z);
        let z3 = z1z2.mul(&h);

        let generic = ProjectivePoint {
            is_identity: Choice::from(0),
            x: x3,
            y: y3,
            z: z3,
        };

        let double_point = self.double();
        let h_is_zero = Choice::from(h.is_zero() as u8);
        let r_is_zero = Choice::from(r.is_zero() as u8);
        let p_eq_q = h_is_zero & r_is_zero;
        let p_eq_neg_q = h_is_zero & !r_is_zero;

        let mut result = Self::conditional_select(&generic, &double_point, p_eq_q);
        result = Self::conditional_select(&result, &Self::identity(), p_eq_neg_q);
        result = Self::conditional_select(&result, other, self.is_identity);
        result = Self::conditional_select(&result, self, other.is_identity);
        result
    }

    /// Constant‐time point doubling (Jacobian coordinates)
    pub fn double(&self) -> Self {
        // Standard SEC-1 formulas  (a = −3)
        //
        //   δ  = Z²
        //   γ  = Y²
        //   β  = X·γ
        //   α  = 3·(X − δ)·(X + δ)
        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = self.x.mul(&gamma);

        let t1 = self.x.add(&delta); // X + δ
        let t2 = self.x.sub(&delta); // X − δ
        let mut alpha = t1.mul(&t2); // (X − δ)(X + δ)
        let three = FieldElement::from_u32(3);
        alpha = alpha.mul(&three); // ×3

        // X₃ = α² − 8·β
        let eight_beta = {
            let two_beta = beta.add(&beta);
            let four_beta = two_beta.add(&two_beta);
            four_beta.add(&four_beta) // 8·β
        };
        let x3 = alpha.square().sub(&eight_beta);

        // Z₃ = (Y + Z)² − γ − δ
        let z3 = self.y.add(&self.z).square().sub(&gamma).sub(&delta);

        // Y₃ = α·(4·β − X₃) − 8·γ²
        let four_beta = {
            let two_beta = beta.add(&beta);
            two_beta.add(&two_beta)
        };
        let mut y3 = four_beta.sub(&x3);
        y3 = alpha.mul(&y3);

        let eight_gamma_sq = {
            let gamma_sq = gamma.square();
            let two = gamma_sq.add(&gamma_sq);
            let four = two.add(&two);
            four.add(&four) // 8·γ²
        };
        let y3 = y3.sub(&eight_gamma_sq);

        let result = ProjectivePoint {
            is_identity: Choice::from(0),
            x: x3,
            y: y3,
            z: z3,
        };

        let return_identity = self.is_identity | Choice::from(self.y.is_zero() as u8);
        Self::conditional_select(&result, &Self::identity(), return_identity)
    }

    /// Convert Jacobian back to affine coordinates
    pub fn to_affine(&self) -> Point {
        if self.is_identity.into() {
            return Point::identity();
        }
        let z_inv = self.z.invert().expect("Nonzero Z ⇒ invertible");
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

    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let select_field = |lhs: &FieldElement, rhs: &FieldElement| {
            let mut out = [0u32; 6];
            for (i, limb) in out.iter_mut().enumerate() {
                *limb = u32::conditional_select(&lhs.0[i], &rhs.0[i], choice);
            }
            FieldElement(out)
        };
        Self {
            is_identity: Choice::conditional_select(&a.is_identity, &b.is_identity, choice),
            x: select_field(&a.x, &b.x),
            y: select_field(&a.y, &b.y),
            z: select_field(&a.z, &b.z),
        }
    }
}
