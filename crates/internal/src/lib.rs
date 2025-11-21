//! Internal utility functions for the dcrypt library
//!
//! This crate provides internal utilities and helpers that are used by
//! other dcrypt crates but are not part of the public API.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod constant_time;
pub mod endian;
pub mod zeroing;

pub use constant_time::*;
pub use endian::*;
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
