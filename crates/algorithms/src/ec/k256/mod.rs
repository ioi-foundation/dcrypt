//! Koblitz secp256k1 Elliptic Curve Primitives
//!
//! This module implements secp256k1 elliptic-curve arithmetic.
//! The curve equation is y² = x³ + 7 over the prime field F_p where:
//! - p = 2^256 - 2^32 - 977
//! - The curve order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
//!
//! Selected paths use fixed-iteration or conditional-selection techniques, but
//! no blanket constant-time claim is made for the module, compiler, or target.

mod constants;
mod field;
mod point;
mod scalar;

pub use constants::{
    K256_FIELD_ELEMENT_SIZE, K256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE, K256_POINT_COMPRESSED_SIZE,
    K256_POINT_UNCOMPRESSED_SIZE, K256_SCALAR_SIZE,
};
pub use field::FieldElement;
pub use point::{Point, PointFormat};
pub use scalar::Scalar;

use crate::error::{Error, Result};
use crate::hash::sha2::Sha256;
use crate::kdf::hkdf::Hkdf;
use crate::kdf::KeyDerivationFunction as KdfTrait;
use dcrypt_internal::random::{CryptoRng, RngCore};

/// SECP256K1 curve parameters (base point G)
struct Secp256k1Params {
    g_x: [u8; 32],
    g_y: [u8; 32],
}

const SECP256K1: Secp256k1Params = Secp256k1Params {
    g_x: [
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8,
        0x17, 0x98,
    ],
    g_y: [
        0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08,
        0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10,
        0xD4, 0xB8,
    ],
};

/// Get the standard base point G of the secp256k1 curve
pub fn base_point_g() -> Point {
    Point::new_uncompressed(&SECP256K1.g_x, &SECP256K1.g_y)
        .expect("Standard base point must be valid")
}

/// Scalar multiplication with the base point: scalar * G
pub fn scalar_mult_base_g(scalar: &Scalar) -> Result<Point> {
    let g = base_point_g();
    g.mul(scalar)
}

/// Generate a cryptographically secure ECDH keypair
pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<(Scalar, Point)> {
    let mut scalar_bytes = [0u8; K256_SCALAR_SIZE];
    loop {
        rng.try_fill_bytes(&mut scalar_bytes)?;
        match Scalar::new(scalar_bytes) {
            Ok(private_key) => {
                let public_key = scalar_mult_base_g(&private_key)?;
                return Ok((private_key, public_key));
            }
            Err(_) => continue,
        }
    }
}

/// General scalar multiplication: compute scalar * point
pub fn scalar_mult(scalar: &Scalar, point: &Point) -> Result<Point> {
    if point.is_identity() {
        return Ok(Point::identity());
    }
    point.mul(scalar)
}

/// Key derivation function for ECDH shared secret using HKDF-SHA256
pub fn kdf_hkdf_sha256_for_ecdh_kem(
    ikm: &[u8],
    info: Option<&[u8]>,
) -> Result<[u8; K256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE]> {
    let hkdf_instance = <Hkdf<Sha256, 16> as KdfTrait>::new();

    let derived_key_vec =
        hkdf_instance.derive_key(ikm, None, info, K256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE)?;

    let mut output_array = [0u8; K256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE];
    if derived_key_vec.len() == K256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE {
        output_array.copy_from_slice(&derived_key_vec);
        Ok(output_array)
    } else {
        Err(Error::Length {
            context: "KDF output for ECDH K256",
            expected: K256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE,
            actual: derived_key_vec.len(),
        })
    }
}

#[cfg(test)]
mod tests;
