//! Internal utility functions for the dcrypt library
//!
//! This crate provides low-level shared utilities. The dcrypt facade publicly
//! re-exports its caller-supplied RNG traits; other items are
//! implementation-oriented and have no separate stability promise.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(any(feature = "alloc", feature = "std"))]
extern crate alloc;

pub mod constant_time;
pub mod endian;
pub mod random;
pub mod zeroing;

pub use constant_time::*;
pub use endian::*;
pub use random::*;
pub use zeroing::*;

#[cfg(feature = "simd")]
pub mod simd {
    //! SIMD utility functions

    /// Check if SIMD is available
    pub fn is_available() -> bool {
        #[cfg(target_feature = "sse2")]
        {
            true
        }

        #[cfg(not(target_feature = "sse2"))]
        {
            false
        }
    }
}
