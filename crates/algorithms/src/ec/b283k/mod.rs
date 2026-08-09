//! Koblitz sect283k1 Elliptic Curve Primitives
//!
//! This module implements the sect283k1 binary elliptic curve operations.
//! The curve equation is y² + xy = x³ + 1 over the binary field GF(2^283).
//! - Field polynomial: x^283 + x^12 + x^7 + x^5 + 1
//! - The curve order n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE96E404282DD3232283E52623152F256011
//!
//! Operations use timing-aware source structure, but no blanket compiler- or
//! target-level constant-time guarantee is made.

mod constants;
mod field;
mod point;
mod scalar;

pub use constants::{
    B283K_FIELD_ELEMENT_SIZE, B283K_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE, B283K_POINT_COMPRESSED_SIZE,
    B283K_POINT_UNCOMPRESSED_SIZE, B283K_SCALAR_SIZE,
};
pub use field::FieldElement;
pub use point::{Point, PointFormat};
pub use scalar::Scalar;

use crate::error::{Error, Result};
use crate::hash::sha2::Sha384;
use crate::kdf::hkdf::Hkdf;
use crate::kdf::KeyDerivationFunction as KdfTrait;
use dcrypt_internal::random::{CryptoRng, RngCore};

/// SECT283K1 curve parameters (base point G)
struct Sect283k1Params {
    g_x: [u8; 36],
    g_y: [u8; 36],
}

const SECT283K1: Sect283k1Params = Sect283k1Params {
    // Correct g_x from SEC 2: 0503213F 78CA4488 3F1A3B81 62F188E5 53CD265F 23C1567A 16876913 B0C2AC24 58492836
    g_x: [
        0x05, 0x03, 0x21, 0x3F, 0x78, 0xCA, 0x44, 0x88, 0x3F, 0x1A, 0x3B, 0x81, 0x62, 0xF1, 0x88,
        0xE5, 0x53, 0xCD, 0x26, 0x5F, 0x23, 0xC1, 0x56, 0x7A, 0x16, 0x87, 0x69, 0x13, 0xB0, 0xC2,
        0xAC, 0x24, 0x58, 0x49, 0x28, 0x36,
    ],
    // Correct g_y from SEC 2: 01CCDA38 0F1C9E31 8D90F95D 07E5426F E87E45C0 E8184698 E4596236 4E341161 77DD2259
    g_y: [
        0x01, 0xCC, 0xDA, 0x38, 0x0F, 0x1C, 0x9E, 0x31, 0x8D, 0x90, 0xF9, 0x5D, 0x07, 0xE5, 0x42,
        0x6F, 0xE8, 0x7E, 0x45, 0xC0, 0xE8, 0x18, 0x46, 0x98, 0xE4, 0x59, 0x62, 0x36, 0x4E, 0x34,
        0x11, 0x61, 0x77, 0xDD, 0x22, 0x59,
    ],
};

/// Get the standard base point G of the sect283k1 curve
pub fn base_point_g() -> Point {
    Point::new_uncompressed(&SECT283K1.g_x, &SECT283K1.g_y)
        .expect("Standard base point must be valid")
}

/// Scalar multiplication with the base point: scalar * G
pub fn scalar_mult_base_g(scalar: &Scalar) -> Result<Point> {
    let g = base_point_g();
    g.mul(scalar)
}

/// Generate a cryptographically secure ECDH keypair
pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<(Scalar, Point)> {
    let mut scalar_bytes = [0u8; B283K_SCALAR_SIZE];
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

/// Key derivation function for ECDH shared secret using HKDF-SHA384
pub fn kdf_hkdf_sha384_for_ecdh_kem(
    ikm: &[u8],
    info: Option<&[u8]>,
) -> Result<[u8; B283K_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE]> {
    let hkdf_instance = <Hkdf<Sha384, 16> as KdfTrait>::new();

    let derived_key_vec =
        hkdf_instance.derive_key(ikm, None, info, B283K_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE)?;

    let mut output_array = [0u8; B283K_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE];
    if derived_key_vec.len() == B283K_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE {
        output_array.copy_from_slice(&derived_key_vec);
        Ok(output_array)
    } else {
        Err(Error::Length {
            context: "KDF output for ECDH B283k",
            expected: B283K_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE,
            actual: derived_key_vec.len(),
        })
    }
}

#[cfg(test)]
mod tests;
