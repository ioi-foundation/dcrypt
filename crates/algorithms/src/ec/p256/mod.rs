//! NIST P-256 Elliptic Curve Primitives
//!
//! This module implements NIST P-256 elliptic-curve arithmetic.
//! The curve equation is y² = x³ - 3x + b over the prime field F_p where:
//! - p = 2^256 - 2^224 + 2^192 + 2^96 - 1 (NIST P-256 prime)
//! - The curve order n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
//!
//! Selected paths use fixed-iteration or conditional-selection techniques, but
//! no blanket constant-time claim is made for the module, compiler, or target.
//! The implementation uses:
//! - Montgomery reduction for field arithmetic
//! - Jacobian projective coordinates for efficient point operations
//! - Binary scalar multiplication with constant-time point selection

mod constants;
mod field;
mod point;
mod scalar;

pub use constants::{
    P256_FIELD_ELEMENT_SIZE, P256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE, P256_POINT_COMPRESSED_SIZE,
    P256_POINT_UNCOMPRESSED_SIZE, P256_SCALAR_SIZE,
};
pub use field::FieldElement;
pub use point::{Point, PointFormat};
pub use scalar::Scalar;

use crate::error::{Error, Result};
use crate::hash::sha2::Sha256;
use crate::kdf::hkdf::Hkdf;
use crate::kdf::KeyDerivationFunction as KdfTrait;
use dcrypt_internal::random::{try_fill_bytes_zeroing_on_error, CryptoRng, RngCore};
use dcrypt_internal::zeroing::Zeroizing;
use dcrypt_params::traditional::ecdsa::NIST_P256;

/// Get the standard base point G of the P-256 curve
///
/// Returns the generator point specified in the NIST P-256 standard.
/// This point generates the cyclic subgroup used for ECDH and ECDSA.
pub fn base_point_g() -> Point {
    Point::new_uncompressed(&NIST_P256.g_x, &NIST_P256.g_y)
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
    let mut scalar_bytes = Zeroizing::new([0u8; P256_SCALAR_SIZE]);

    // Use rejection sampling for uniform distribution
    loop {
        try_fill_bytes_zeroing_on_error(rng, &mut scalar_bytes[..])?;

        // Attempt to create a valid scalar (non-zero, < n)
        match Scalar::new(*scalar_bytes) {
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

/// Key derivation function for ECDH shared secret using HKDF-SHA256
///
/// Derives a cryptographically strong shared secret from the ECDH raw output.
/// Uses HKDF (HMAC-based Key Derivation Function) with SHA-256 as specified
/// in RFC 5869 for secure key derivation.
///
/// Parameters:
/// - ikm: Input key material (raw ECDH output, e.g., x-coordinate)
/// - info: Optional context information for domain separation
///
/// Returns a fixed-length derived key suitable for symmetric encryption.
pub fn kdf_hkdf_sha256_for_ecdh_kem(
    ikm: &[u8],
    info: Option<&[u8]>,
) -> Result<[u8; P256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE]> {
    let hkdf_instance = <Hkdf<Sha256, 16> as KdfTrait>::new();

    // Perform HKDF key derivation
    let derived_key_vec = hkdf_instance.derive_key(
        ikm,
        None, // No salt for ECDH applications (uses zero-length salt)
        info, // Context info for domain separation
        P256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE,
    )?;

    // Convert to fixed-size array
    let mut output_array = [0u8; P256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE];
    if derived_key_vec.len() == P256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE {
        output_array.copy_from_slice(&derived_key_vec);
        Ok(output_array)
    } else {
        Err(Error::Length {
            context: "KDF output for ECDH",
            expected: P256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE,
            actual: derived_key_vec.len(),
        })
    }
}

#[cfg(test)]
mod tests;
