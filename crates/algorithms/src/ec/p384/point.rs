//! P-384 elliptic curve point operations

use crate::ec::p384::{
    constants::{
        P384_FIELD_ELEMENT_SIZE, P384_POINT_COMPRESSED_SIZE, P384_POINT_UNCOMPRESSED_SIZE,
    },
    field::FieldElement,
    scalar::Scalar,
};
use crate::error::{validate, Error, Result};
use dcrypt_internal::constant_time::{Choice, ConditionallySelectable};
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};
use dcrypt_params::traditional::ecdsa::NIST_P384;

/// Format of a serialized elliptic curve point
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointFormat {
    /// SEC 1 identity point (`0x00`)
    Identity,
    /// Uncompressed format: 0x04 || x || y
    Uncompressed,
    /// Compressed format: 0x02/0x03 || x
    Compressed,
}

/// P-384 elliptic curve point in affine coordinates (x, y)
///
/// Represents points on the NIST P-384 curve. The special point at infinity
/// (identity element) is represented with is_identity = true.
#[derive(Clone, Debug)]
pub struct Point {
    /// Whether this point is the identity element (point at infinity)
    pub(crate) is_identity: Choice,
    /// X coordinate in affine representation
    pub(crate) x: FieldElement,
    /// Y coordinate in affine representation  
    pub(crate) y: FieldElement,
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

/// P-384 point in Jacobian projective coordinates (X:Y:Z) for efficient arithmetic
///
/// Jacobian coordinates represent affine point (x,y) as (X:Y:Z) where:
/// - x = X/Z²
/// - y = Y/Z³  
/// - Point at infinity has Z = 0
// `Copy` is retained because `ConditionallySelectable` requires it. Explicit
// scalar-derived projective values are always owned by `Zeroizing`, limiting
// source-visible copies even though register copies cannot be guaranteed wiped.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProjectivePoint {
    /// Whether this point is the identity element (point at infinity)
    is_identity: Choice,
    /// X coordinate in Jacobian representation
    x: FieldElement,
    /// Y coordinate in Jacobian representation
    y: FieldElement,
    /// Z coordinate (projective factor)
    z: FieldElement,
}

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
    /// Constant-time equality comparison for elliptic curve points
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
    /// Create a new elliptic curve point from uncompressed coordinates
    ///
    /// Validates that the given (x, y) coordinates satisfy the P-384 curve equation:
    /// y² = x³ - 3x + b (mod p)
    ///
    /// Returns an error if the point is not on the curve.
    pub fn new_uncompressed(
        x: &[u8; P384_FIELD_ELEMENT_SIZE],
        y: &[u8; P384_FIELD_ELEMENT_SIZE],
    ) -> Result<Self> {
        let x_fe = Zeroizing::new(FieldElement::from_bytes(x)?);
        let y_fe = Zeroizing::new(FieldElement::from_bytes(y)?);

        // Validate that the point lies on the curve
        if !Self::is_on_curve(&x_fe, &y_fe) {
            return Err(Error::param(
                "P-384 Point",
                "Point coordinates do not satisfy curve equation",
            ));
        }

        Ok(Point {
            is_identity: Choice::from(0),
            x: x_fe.into_inner(),
            y: y_fe.into_inner(),
        })
    }

    /// Create the identity element (point at infinity)
    ///
    /// The identity element serves as the additive neutral element
    /// for the elliptic curve group operation.
    pub fn identity() -> Self {
        Point {
            is_identity: Choice::from(1),
            x: FieldElement::zero(),
            y: FieldElement::zero(),
        }
    }

    /// Check if this point is the identity element
    pub fn is_identity(&self) -> bool {
        self.is_identity.into()
    }

    /// Get the x-coordinate as a byte array in big-endian format
    pub fn x_coordinate_bytes(&self) -> [u8; P384_FIELD_ELEMENT_SIZE] {
        self.x.to_bytes()
    }

    /// Get the y-coordinate as a byte array in big-endian format
    pub fn y_coordinate_bytes(&self) -> [u8; P384_FIELD_ELEMENT_SIZE] {
        self.y.to_bytes()
    }

    /// Detect point format from serialized bytes
    ///
    /// Analyzes the leading byte and length to determine the serialization format.
    pub fn detect_format(bytes: &[u8]) -> Result<PointFormat> {
        if bytes.is_empty() {
            return Err(Error::param("P-384 Point", "Empty point data"));
        }

        match (bytes[0], bytes.len()) {
            (0x00, 1) => Ok(PointFormat::Identity),
            (0x04, P384_POINT_UNCOMPRESSED_SIZE) => Ok(PointFormat::Uncompressed),
            (0x02 | 0x03, P384_POINT_COMPRESSED_SIZE) => Ok(PointFormat::Compressed),
            _ => Err(Error::param(
                "P-384 Point",
                "Unknown or malformed point format",
            )),
        }
    }

    /// Serialize point to uncompressed format: 0x04 || x || y
    ///
    /// For the identity this fixed-width API returns an all-zero internal
    /// sentinel. SEC 1 encodes identity as the single byte `0x00`, so the
    /// sentinel is deliberately rejected by the deserializer and must not be
    /// placed on the wire.
    pub fn serialize_uncompressed(&self) -> [u8; P384_POINT_UNCOMPRESSED_SIZE] {
        let mut result = [0u8; P384_POINT_UNCOMPRESSED_SIZE];

        // Special encoding for the identity element
        if self.is_identity() {
            return result; // All zeros represents identity
        }

        // Standard uncompressed format: 0x04 || x || y
        result[0] = 0x04;
        self.x.write_bytes(&mut result[1..49]);
        self.y.write_bytes(&mut result[49..97]);

        result
    }

    /// Deserialize point from uncompressed byte format
    ///
    /// Supports the standard uncompressed format (0x04 || x || y) and
    /// rejects non-canonical fixed-width encodings of the identity element.
    pub fn deserialize_uncompressed(bytes: &[u8]) -> Result<Self> {
        validate::length("P-384 Point", bytes.len(), P384_POINT_UNCOMPRESSED_SIZE)?;

        // Validate uncompressed format indicator
        if bytes[0] != 0x04 {
            return Err(Error::param(
                "P-384 Point",
                "Invalid uncompressed point format (expected 0x04 prefix)",
            ));
        }

        // Extract and validate coordinates
        let mut x_bytes = Zeroizing::new([0u8; P384_FIELD_ELEMENT_SIZE]);
        let mut y_bytes = Zeroizing::new([0u8; P384_FIELD_ELEMENT_SIZE]);

        x_bytes.copy_from_slice(&bytes[1..49]);
        y_bytes.copy_from_slice(&bytes[49..97]);

        Self::new_uncompressed(&x_bytes, &y_bytes)
    }

    /// Serialize point to SEC 1 compressed format (0x02/0x03 || x)
    ///
    /// The compressed format uses:
    /// - 0x02 prefix if y-coordinate is even
    /// - 0x03 prefix if y-coordinate is odd
    /// - Followed by the x-coordinate in big-endian format
    ///
    /// For the identity this fixed-width API returns an all-zero internal
    /// sentinel, which is not a canonical SEC 1 encoding and is rejected by
    /// the deserializer.
    pub fn serialize_compressed(&self) -> [u8; P384_POINT_COMPRESSED_SIZE] {
        let mut out = [0u8; P384_POINT_COMPRESSED_SIZE];

        // Identity → all zeros
        if self.is_identity() {
            return out;
        }

        // Determine prefix based on y-coordinate parity
        out[0] = if self.y.is_odd() { 0x03 } else { 0x02 };
        self.x.write_bytes(&mut out[1..]);
        out
    }

    /// Deserialize SEC 1 compressed point
    ///
    /// Recovers the full point from compressed format by computing y² = x³ - 3x + b
    /// and finding the square root.
    pub fn deserialize_compressed(bytes: &[u8]) -> Result<Self> {
        validate::length(
            "P-384 Compressed Point",
            bytes.len(),
            P384_POINT_COMPRESSED_SIZE,
        )?;

        let tag = bytes[0];
        if tag != 0x02 && tag != 0x03 {
            return Err(Error::param(
                "P-384 Point",
                "Invalid compressed point prefix (expected 0x02 or 0x03)",
            ));
        }

        // Extract x-coordinate
        let mut x_bytes = Zeroizing::new([0u8; P384_FIELD_ELEMENT_SIZE]);
        x_bytes.copy_from_slice(&bytes[1..]);

        let x_fe = Zeroizing::new(FieldElement::from_bytes(&x_bytes).map_err(|_| {
            Error::param(
                "P-384 Point",
                "Invalid compressed point: x-coordinate yields quadratic non-residue",
            )
        })?);

        // Compute right-hand side: y² = x³ - 3x + b
        let x2 = Zeroizing::new(x_fe.square());
        let x3 = Zeroizing::new(x2.mul(&x_fe));
        let a = Zeroizing::new(FieldElement(FieldElement::A_M3)); // a = -3
        let b = Zeroizing::new(FieldElement::from_bytes(&NIST_P384.b).unwrap());
        let ax = Zeroizing::new(a.mul(&x_fe));
        let x3_plus_ax = Zeroizing::new(x3.add(&ax));
        let rhs = Zeroizing::new(x3_plus_ax.add(&b));

        // Attempt to find square root
        let y_fe = Zeroizing::new(rhs.sqrt().ok_or_else(|| {
            Error::param(
                "P-384 Point",
                "Invalid compressed point: x-coordinate yields quadratic non-residue",
            )
        })?);

        // Select the correct root based on parity
        let y_matches = (y_fe.is_odd() && tag == 0x03) || (!y_fe.is_odd() && tag == 0x02);
        let y_final = if y_matches {
            Zeroizing::new(y_fe.into_inner())
        } else {
            // Use the negative root (p - y)
            let modulus = Zeroizing::new(FieldElement::get_modulus());
            Zeroizing::new(modulus.sub(&y_fe))
        };

        Ok(Point {
            is_identity: Choice::from(0),
            x: x_fe.into_inner(),
            y: y_final.into_inner(),
        })
    }

    /// Elliptic curve point addition using the group law
    ///
    /// Implements the abelian group operation for P-384 points.
    pub fn add(&self, other: &Self) -> Self {
        let p1 = Zeroizing::new(self.to_projective());
        let p2 = Zeroizing::new(other.to_projective());
        let result = Zeroizing::new(p1.add(&p2));
        result.to_affine()
    }

    /// Elliptic curve point doubling: 2 * self
    pub fn double(&self) -> Self {
        let p = Zeroizing::new(self.to_projective());
        let result = Zeroizing::new(p.double());
        result.to_affine()
    }

    /// Scalar multiplication: compute scalar * self
    ///
    /// Uses constant-time double-and-add algorithm.
    pub fn mul(&self, scalar: &Scalar) -> Result<Self> {
        let scalar_bytes = scalar.as_secret_buffer().as_ref();

        // Work in Jacobian/projective coordinates throughout
        let base = Zeroizing::new(self.to_projective());
        let mut result = Zeroizing::new(ProjectivePoint::identity());

        for byte in scalar_bytes.iter() {
            for bit_pos in (0..8).rev() {
                let mut bit = (byte >> bit_pos) & 1;
                let mut choice = Choice::from(bit);
                bit.zeroize();

                let doubled = Zeroizing::new(result.double());

                // Always compute the addition
                let result_added = Zeroizing::new(doubled.add(&base));

                // Constant-time select: if bit is 1, use added result, else keep result
                let selected = Zeroizing::new(ProjectivePoint::conditional_select(
                    &doubled,
                    &result_added,
                    choice,
                ));
                result.zeroize();
                *result = selected.into_inner();
                choice.zeroize();
            }
        }

        Ok(result.to_affine())
    }

    // Private helper methods

    /// Validate that coordinates satisfy the P-384 curve equation
    fn is_on_curve(x: &FieldElement, y: &FieldElement) -> bool {
        // Left-hand side: y²
        let y_squared = Zeroizing::new(y.square());

        // Right-hand side: x³ - 3x + b
        let x_squared = Zeroizing::new(x.square());
        let x_cubed = Zeroizing::new(x_squared.mul(x));
        let a_coeff = Zeroizing::new(FieldElement(FieldElement::A_M3)); // a = -3 mod p
        let ax = Zeroizing::new(a_coeff.mul(x));
        let b_coeff = Zeroizing::new(FieldElement::from_bytes(&NIST_P384.b).unwrap());

        // Compute x³ - 3x + b
        let x_cubed_plus_ax = Zeroizing::new(x_cubed.add(&ax));
        let rhs = Zeroizing::new(x_cubed_plus_ax.add(&b_coeff));

        *y_squared == *rhs
    }

    /// Convert affine point to Jacobian projective coordinates
    fn to_projective(&self) -> ProjectivePoint {
        let regular = Zeroizing::new(ProjectivePoint {
            is_identity: Choice::from(0),
            x: self.x,
            y: self.y,
            z: FieldElement::one(),
        });
        let identity = Zeroizing::new(ProjectivePoint::identity());
        let selected = Zeroizing::new(ProjectivePoint::conditional_select(
            &regular,
            &identity,
            self.is_identity,
        ));
        selected.into_inner()
    }
}

impl ConditionallySelectable for ProjectivePoint {
    #[inline(never)]
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
    /// Identity in Jacobian form: (0 : 1 : 0)
    pub fn identity() -> Self {
        ProjectivePoint {
            is_identity: Choice::from(1),
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::zero(),
        }
    }

    /// Projective point addition using constant-time formulas
    pub fn add(&self, other: &Self) -> Self {
        // 1. Compute Generic Addition (assuming P != Q, neither is identity)
        // Reference: "Guide to Elliptic Curve Cryptography" Algorithm 3.22
        let z1_squared = Zeroizing::new(self.z.square());
        let z2_squared = Zeroizing::new(other.z.square());
        let z1_cubed = Zeroizing::new(z1_squared.mul(&self.z));
        let z2_cubed = Zeroizing::new(z2_squared.mul(&other.z));

        let u1 = Zeroizing::new(self.x.mul(&z2_squared)); // X1 · Z2²
        let u2 = Zeroizing::new(other.x.mul(&z1_squared)); // X2 · Z1²
        let s1 = Zeroizing::new(self.y.mul(&z2_cubed)); // Y1 · Z2³
        let s2 = Zeroizing::new(other.y.mul(&z1_cubed)); // Y2 · Z1³

        // Compute differences
        let h = Zeroizing::new(u2.sub(&u1)); // X2·Z1² − X1·Z2²
        let r = Zeroizing::new(s2.sub(&s1)); // Y2·Z1³ − Y1·Z2³

        // General addition arithmetic
        let h_squared = Zeroizing::new(h.square());
        let h_cubed = Zeroizing::new(h_squared.mul(&h));
        let v = Zeroizing::new(u1.mul(&h_squared));

        // X3 = r² − h³ − 2·v
        let r_squared = Zeroizing::new(r.square());
        let two_v = Zeroizing::new(v.add(&v));
        let x3_minus_h_cubed = Zeroizing::new(r_squared.sub(&h_cubed));
        let x3 = Zeroizing::new(x3_minus_h_cubed.sub(&two_v));

        // Y3 = r·(v − X3) − s1·h³
        let v_minus_x3 = Zeroizing::new(v.sub(&x3));
        let r_times_diff = Zeroizing::new(r.mul(&v_minus_x3));
        let s1_times_h_cubed = Zeroizing::new(s1.mul(&h_cubed));
        let y3 = Zeroizing::new(r_times_diff.sub(&s1_times_h_cubed));

        // Z3 = Z1 · Z2 · h
        let z1_times_z2 = Zeroizing::new(self.z.mul(&other.z));
        let z3 = Zeroizing::new(z1_times_z2.mul(&h));

        let generic_point = Zeroizing::new(Self {
            is_identity: Choice::from(0),
            x: x3.into_inner(),
            y: y3.into_inner(),
            z: z3.into_inner(),
        });

        // 2. Compute Doubling (fallback for P==Q)
        let double_point = Zeroizing::new(self.double());

        // 3. Select Result based on state
        let mut h_is_zero = Choice::from((h.is_zero() as u8) & 1);
        let mut r_is_zero = Choice::from((r.is_zero() as u8) & 1);

        // Case: P == Q (h=0, r=0)
        let mut p_eq_q = h_is_zero & r_is_zero;
        // Case: P == -Q (h=0, r!=0)
        let mut p_eq_neg_q = h_is_zero & !r_is_zero;

        // Start with generic addition result
        let mut result = Zeroizing::new(Self::conditional_select(
            &generic_point,
            &double_point,
            p_eq_q,
        ));

        // If P == -Q, use identity
        let identity = Zeroizing::new(Self::identity());
        let selected = Zeroizing::new(Self::conditional_select(&result, &identity, p_eq_neg_q));
        result.zeroize();
        *result = selected.into_inner();

        // If either input is identity, result is the other
        let selected = Zeroizing::new(Self::conditional_select(&result, other, self.is_identity));
        result.zeroize();
        *result = selected.into_inner();
        let selected = Zeroizing::new(Self::conditional_select(&result, self, other.is_identity));
        result.zeroize();
        *result = selected.into_inner();

        h_is_zero.zeroize();
        r_is_zero.zeroize();
        p_eq_q.zeroize();
        p_eq_neg_q.zeroize();
        result.into_inner()
    }

    /// Projective point doubling using constant-time formulas
    #[inline]
    pub fn double(&self) -> Self {
        // ── 1. Pre-computations ─────────────────────────────────
        // Δ = Z₁²
        let delta = Zeroizing::new(self.z.square());

        // Γ = Y₁²
        let gamma = Zeroizing::new(self.y.square());

        // β = X₁·Γ
        let beta = Zeroizing::new(self.x.mul(&gamma));

        // α = 3·(X₁ − Δ)·(X₁ + Δ)       (valid because a = –3)
        let x_plus_delta = Zeroizing::new(self.x.add(&delta));
        let x_minus_delta = Zeroizing::new(self.x.sub(&delta));
        let alpha_base = Zeroizing::new(x_plus_delta.mul(&x_minus_delta));
        let two_alpha = Zeroizing::new(alpha_base.add(&alpha_base));
        let alpha = Zeroizing::new(two_alpha.add(&alpha_base)); // ×3

        // ── 2. Output coordinates ──────────────────────────────
        // X₃ = α² − 8·β
        let two_beta = Zeroizing::new(beta.add(&beta));
        let four_beta = Zeroizing::new(two_beta.add(&two_beta));
        let eight_beta = Zeroizing::new(four_beta.add(&four_beta));
        let alpha_squared = Zeroizing::new(alpha.square());
        let x3 = Zeroizing::new(alpha_squared.sub(&eight_beta));

        // Z₃ = (Y₁ + Z₁)² − Γ − Δ
        let y_plus_z = Zeroizing::new(self.y.add(&self.z));
        let y_plus_z_squared = Zeroizing::new(y_plus_z.square());
        let z3_minus_gamma = Zeroizing::new(y_plus_z_squared.sub(&gamma));
        let z3 = Zeroizing::new(z3_minus_gamma.sub(&delta));

        // Y₃ = α·(4·β − X₃) − 8·Γ²
        let four_beta_minus_x3 = Zeroizing::new(four_beta.sub(&x3));
        let alpha_times_difference = Zeroizing::new(alpha.mul(&four_beta_minus_x3));

        let gamma_sq = Zeroizing::new(gamma.square());
        let two_gamma_sq = Zeroizing::new(gamma_sq.add(&gamma_sq));
        let four_gamma_sq = Zeroizing::new(two_gamma_sq.add(&two_gamma_sq));
        let eight_gamma_sq = Zeroizing::new(four_gamma_sq.add(&four_gamma_sq));
        let y3 = Zeroizing::new(alpha_times_difference.sub(&eight_gamma_sq));

        let result = Zeroizing::new(Self {
            is_identity: Choice::from(0),
            x: x3.into_inner(),
            y: y3.into_inner(),
            z: z3.into_inner(),
        });

        // Explicitly handle identity or y=0 cases constant-time
        let mut return_identity = self.is_identity | Choice::from(self.y.is_zero() as u8);

        let identity = Zeroizing::new(Self::identity());
        let selected = Zeroizing::new(Self::conditional_select(
            &result,
            &identity,
            return_identity,
        ));
        return_identity.zeroize();
        selected.into_inner()
    }

    /// Convert Jacobian projective coordinates back to affine coordinates
    pub fn to_affine(&self) -> Point {
        // Select a non-zero denominator for the identity so conversion does
        // not branch on a scalar-derived result.
        let one = Zeroizing::new(FieldElement::one());
        let safe_z = Zeroizing::new(FieldElement::conditional_select(
            &self.z,
            &one,
            self.is_identity,
        ));
        let z_inv = Zeroizing::new(
            safe_z
                .invert()
                .expect("Non-zero Z coordinate should be invertible"),
        );
        let z_inv_squared = Zeroizing::new(z_inv.square());
        let z_inv_cubed = Zeroizing::new(z_inv_squared.mul(&z_inv));

        // Convert to affine coordinates: (x, y) = (X/Z², Y/Z³)
        let x_affine = Zeroizing::new(self.x.mul(&z_inv_squared));
        let y_affine = Zeroizing::new(self.y.mul(&z_inv_cubed));
        let zero = Zeroizing::new(FieldElement::zero());
        let x = Zeroizing::new(FieldElement::conditional_select(
            &x_affine,
            &zero,
            self.is_identity,
        ));
        let y = Zeroizing::new(FieldElement::conditional_select(
            &y_affine,
            &zero,
            self.is_identity,
        ));

        Point {
            is_identity: self.is_identity,
            x: x.into_inner(),
            y: y.into_inner(),
        }
    }
}
