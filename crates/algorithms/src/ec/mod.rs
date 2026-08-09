// File: crates/algorithms/src/ec/mod.rs
//! Elliptic Curve Primitives
//!
//! This module provides low-level elliptic-curve operations on several curves.
//! Individual implementations use timing-aware techniques, but the module has
//! no blanket compiler- or target-level constant-time guarantee and is not by
//! itself a complete protocol such as RFC 9180 HPKE.
//! This module now also includes support for Koblitz (secp256k1) and Binary (sect283k1) curves.

pub mod b283k;
pub mod bls12_381;
pub mod k256; // For secp256k1
pub mod p192;
pub mod p224;
pub mod p256;
pub mod p384;
pub mod p521; // For sect283k1

// Re-export types with consistent naming scheme.
// This corrects the original error which tried to export non-existent types like 'PointG1'.
pub use bls12_381::{
    pairing as bls12_381_pairing, Bls12_381Scalar, G1Projective as Bls12_381G1,
    G2Projective as Bls12_381G2, Gt as Bls12_381Gt,
};

pub use b283k::{Point as B283kPoint, Scalar as B283kScalar};
pub use k256::{Point as K256Point, Scalar as K256Scalar};
pub use p192::{Point as P192Point, Scalar as P192Scalar};
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
