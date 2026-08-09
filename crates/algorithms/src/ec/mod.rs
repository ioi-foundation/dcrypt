// File: crates/algorithms/src/ec/mod.rs
//! Elliptic Curve Primitives
//!
//! This module provides low-level elliptic-curve operations on several curves.
//! Individual implementations use timing-aware techniques, but the module has
//! no blanket compiler- or target-level constant-time guarantee and is not by
//! itself a complete protocol such as RFC 9180 HPKE.
//! The prime curves retained for v3 are P-224, P-256, P-384, P-521, and
//! secp256k1. P-192 and sect283k1 were removed: P-192 is legacy-only in
//! NIST SP 800-186, while the previous sect283k1 implementation used an
//! incorrect group order and did not validate subgroup membership.

pub mod bls12_381;
pub mod k256;
pub mod p224;
pub mod p256;
pub mod p384;
pub mod p521;

// Re-export types with consistent naming scheme.
// This corrects the original error which tried to export non-existent types like 'PointG1'.
pub use bls12_381::{
    pairing as bls12_381_pairing, Bls12_381Scalar, G1Projective as Bls12_381G1,
    G2Projective as Bls12_381G2, Gt as Bls12_381Gt,
};

pub use k256::{Point as K256Point, Scalar as K256Scalar};
pub use p224::{Point as P224Point, Scalar as P224Scalar};
pub use p256::{Point as P256Point, Scalar as P256Scalar};
pub use p384::{Point as P384Point, Scalar as P384Scalar};
pub use p521::{Point as P521Point, Scalar as P521Scalar};

/// Common trait for coordinate systems used in elliptic curve operations
pub trait CoordinateSystem {}

/// Affine coordinates (x,y)
pub struct Affine;
impl CoordinateSystem for Affine {}

/// Jacobian projective coordinates (X:Y:Z) where x = X/Z² and y = Y/Z³
pub struct Jacobian;
impl CoordinateSystem for Jacobian {}

#[cfg(test)]
mod scalar_storage_policy_tests {
    const SCALAR_SOURCES: [(&str, &str); 5] = [
        ("p224", include_str!("p224/scalar.rs")),
        ("p256", include_str!("p256/scalar.rs")),
        ("p384", include_str!("p384/scalar.rs")),
        ("p521", include_str!("p521/scalar.rs")),
        ("k256", include_str!("k256/scalar.rs")),
    ];

    #[test]
    fn retained_scalar_sources_keep_secret_storage_raii_protected() {
        for (curve, source) in SCALAR_SOURCES {
            assert!(
                source.contains("Self::from_secret_buffer(SecretBuffer::new(data))"),
                "{curve} must protect raw constructor input before validation"
            );
            assert!(
                source.contains("let mut protected = SecretBuffer::zeroed();")
                    && source.contains("protected.as_mut().copy_from_slice(bytes);"),
                "{curve} deserialization must copy directly into protected storage"
            );
            assert!(
                source.contains("pub fn serialize(&self) -> SecretBuffer<"),
                "{curve} serialization must return protected exact-size storage"
            );

            for forbidden in [
                "-> [u8;",
                "-> [u32;",
                ".to_be_bytes()",
                ".to_le_bytes()",
                "from_be_bytes([",
                "from_le_bytes([",
                "let original = *bytes",
                "bytes[i] = u8::conditional_select",
            ] {
                assert!(
                    !source.contains(forbidden),
                    "{curve} scalar source contains forbidden unprotected storage pattern: {forbidden}"
                );
            }

            for line in source.lines() {
                let line = line.trim_start();
                let raw_local_array = line.starts_with("let ")
                    && (line.contains(" = [")
                        || line.contains(": [u8;")
                        || line.contains(": [u32;"));
                assert!(
                    !raw_local_array,
                    "{curve} scalar source declares an unprotected local array: {line}"
                );
            }
        }

        for (curve, source) in SCALAR_SOURCES.into_iter().take(4) {
            assert!(
                source.contains("let mut protected = SecretBuffer::new(data);"),
                "{curve} reduction must protect raw input before arithmetic"
            );
            assert!(
                source.contains("Zeroizing::new([0u32;"),
                "{curve} limb scratch must use zeroize-on-drop storage"
            );
            assert!(
                source.contains("#[inline(never)]\n    fn select_secret_buffer("),
                "{curve} selection must retain its compiler-reviewed mask boundary"
            );
        }
    }
}
