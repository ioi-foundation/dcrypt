//! Utility functions for the dcrypt library

pub mod constant_time;
pub mod endian;
pub mod zeroing;

pub use constant_time::*;
pub use endian::*;
pub use zeroing::*;

// Re-export the new error validation module for convenience
pub use crate::validate as validate_new;

#[cfg(feature = "simd")]
pub mod simd {
    //! SIMD utility functions

    /// Check if SIMD is available
    pub fn is_available() -> bool {
        #[cfg(target_feature = "sse2")]
        {
            return true;
        }

        #[cfg(not(target_feature = "sse2"))]
        {
            return false;
        }
    }
}