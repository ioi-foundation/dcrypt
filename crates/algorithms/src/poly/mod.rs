// Path: crates/algorithms/src/poly/mod.rs
//! Generic Polynomial Engine
//!
//! This module provides foundational elements for polynomial arithmetic over rings,
//! designed to be reusable by various lattice-based cryptographic schemes.

#[cfg(feature = "alloc")]
extern crate alloc;

// FIX: Add the new fft module
pub mod fft;
pub mod ntt;
pub mod params;
pub mod polynomial;
pub mod sampling;
pub mod serialize;

/// Prelude for easy importing of common polynomial types and traits.
pub mod prelude {
    // FIX: Add fft and ifft to the prelude
    pub use super::fft::{fft, ifft};
    pub use super::ntt::{montgomery_reduce, InverseNttOperator, NttOperator};
    pub use super::params::{Modulus, NttModulus};
    pub use super::polynomial::{Polynomial, PolynomialNttExt};
    pub use super::sampling::{CbdSampler, UniformSampler};
    pub use super::serialize::{CoefficientPacker, CoefficientUnpacker};
}

// Helper functions or common constants might be added here later.
