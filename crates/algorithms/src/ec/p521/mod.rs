//! NIST P-521 Elliptic Curve Primitives
//!
//! This module implements NIST P-521 elliptic-curve arithmetic.
//! The curve equation is y² = x³ - 3x + b over the prime field F_p where:
//! - p = 2^521 - 1 (NIST P-521 prime, a Mersenne prime)
//! - The curve order n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
//!
//! Selected paths use fixed-iteration or conditional-selection techniques, but
//! no blanket constant-time claim is made for the module, compiler, or target.
//! The implementation uses:
//! - Mersenne reduction for field arithmetic (2^521 ≡ 1 mod p)
//! - Jacobian projective coordinates for efficient point operations
//! - Binary scalar multiplication with constant-time point selection

mod constants;
mod field;
mod point;
mod scalar;

pub use constants::{
    P521_FIELD_ELEMENT_SIZE, P521_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE, P521_POINT_COMPRESSED_SIZE,
    P521_POINT_UNCOMPRESSED_SIZE, P521_SCALAR_SIZE,
};
pub use field::FieldElement;
pub use point::{Point, PointFormat};
pub use scalar::Scalar;

use crate::error::{Error, Result};
use crate::hash::sha2::Sha512;
use crate::kdf::hkdf::Hkdf;
use crate::kdf::KeyDerivationFunction as KdfTrait;
use dcrypt_params::traditional::ecdsa::NIST_P521;
use rand::{CryptoRng, RngCore};

/// Get the standard base point G of the P-521 curve
///
/// Returns the generator point specified in the NIST P-521 standard.
/// This point generates the cyclic subgroup used for ECDH and ECDSA.
pub fn base_point_g() -> Point {
    Point::new_uncompressed(&NIST_P521.g_x, &NIST_P521.g_y)
        .expect("Standard base point must be valid")
}

/// Scalar multiplication with the base point: scalar * G
///
/// Efficiently computes scalar multiplication with the standard generator.
/// This is the core operation for generating public keys from private keys.
pub fn scalar_mult_base_g(scalar: &Scalar) -> Result<Point> {
    let g = base_point_g();
    g.mul(scalar)
}

/// Generate a cryptographically secure ECDH keypair
///
/// Uses rejection sampling to ensure the private key scalar is uniformly
/// distributed in the range [1, n-1]. The public key is computed as
/// private_key * G where G is the standard base point.
///
/// Returns (private_key, public_key) pair suitable for ECDH key agreement.
pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<(Scalar, Point)> {
    let mut scalar_bytes = [0u8; P521_SCALAR_SIZE];

    // Use rejection sampling for uniform distribution
    loop {
        rng.fill_bytes(&mut scalar_bytes);

        // Attempt to create a valid scalar (non-zero, < n)
        match Scalar::new(scalar_bytes) {
            Ok(private_key) => {
                // Compute corresponding public key
                let public_key = scalar_mult_base_g(&private_key)?;
                return Ok((private_key, public_key));
            }
            Err(_) => {
                // Invalid scalar generated, retry with new random bytes
                continue;
            }
        }
    }
}

/// General scalar multiplication: compute scalar * point
///
/// Performs scalar multiplication with an arbitrary point on the curve.
/// Used in ECDH key agreement and signature verification.
pub fn scalar_mult(scalar: &Scalar, point: &Point) -> Result<Point> {
    if point.is_identity() {
        // scalar * O = O (identity element)
        return Ok(Point::identity());
    }

    point.mul(scalar)
}

/// Key derivation function for ECDH shared secret using HKDF-SHA512
///
/// Derives a cryptographically strong shared secret from the ECDH raw output.
/// Uses HKDF (HMAC-based Key Derivation Function) with SHA-512 as specified
/// in RFC 5869 for secure key derivation.
///
/// SHA-512 is more appropriate for P-521 due to the larger curve size.
///
/// Parameters:
/// - ikm: Input key material (raw ECDH output, e.g., x-coordinate)
/// - info: Optional context information for domain separation
///
/// Returns a fixed-length derived key suitable for symmetric encryption.
pub fn kdf_hkdf_sha512_for_ecdh_kem(
    ikm: &[u8],
    info: Option<&[u8]>,
) -> Result<[u8; P521_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE]> {
    let hkdf_instance = <Hkdf<Sha512, 16> as KdfTrait>::new();

    // Perform HKDF key derivation
    let derived_key_vec = hkdf_instance.derive_key(
        ikm,
        None, // No salt for ECDH applications (uses zero-length salt)
        info, // Context info for domain separation
        P521_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE,
    )?;

    // Convert to fixed-size array
    let mut output_array = [0u8; P521_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE];
    if derived_key_vec.len() == P521_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE {
        output_array.copy_from_slice(&derived_key_vec);
        Ok(output_array)
    } else {
        Err(Error::Length {
            context: "KDF output for ECDH",
            expected: P521_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE,
            actual: derived_key_vec.len(),
        })
    }
}

#[cfg(test)]
mod tests;
