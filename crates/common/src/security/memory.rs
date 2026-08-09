//! Memory safety patterns and secure operations
//!
//! This module provides traits and utilities for ensuring memory safety
//! in cryptographic operations.

// Handle Box imports based on features
#[cfg(feature = "std")]
use std::boxed::Box;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc as rust_alloc;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use rust_alloc::boxed::Box;

/// Trait for types that can be securely compared
///
/// This trait provides constant-time comparison operations to prevent
/// timing attacks.
pub trait SecureCompare: Sized {
    /// Compare two values in constant time
    fn secure_eq(&self, other: &Self) -> bool;

    /// Compare two values and return a constant-time choice
    fn secure_cmp(&self, other: &Self) -> dcrypt_internal::constant_time::Choice;
}

impl<const N: usize> SecureCompare for [u8; N] {
    fn secure_eq(&self, other: &Self) -> bool {
        use dcrypt_internal::constant_time::ConstantTimeEq;
        bool::from(self.ct_eq(other))
    }

    fn secure_cmp(&self, other: &Self) -> dcrypt_internal::constant_time::Choice {
        use dcrypt_internal::constant_time::ConstantTimeEq;
        self.ct_eq(other)
    }
}

impl SecureCompare for &[u8] {
    fn secure_eq(&self, other: &Self) -> bool {
        use dcrypt_internal::constant_time::ConstantTimeEq;
        bool::from(self.ct_eq(other))
    }

    fn secure_cmp(&self, other: &Self) -> dcrypt_internal::constant_time::Choice {
        use dcrypt_internal::constant_time::ConstantTimeEq;
        self.ct_eq(other)
    }
}

/// Memory barrier utilities
pub mod barrier {
    use core::sync::atomic::{compiler_fence, fence, Ordering};

    /// Insert a compiler fence to prevent reordering
    #[inline(always)]
    pub fn compiler_fence_seq_cst() {
        compiler_fence(Ordering::SeqCst);
    }

    /// Insert a full memory fence
    #[inline(always)]
    pub fn memory_fence_seq_cst() {
        fence(Ordering::SeqCst);
    }

    /// Execute a closure with memory barriers before and after
    #[inline(always)]
    pub fn with_barriers<T, F: FnOnce() -> T>(f: F) -> T {
        compiler_fence_seq_cst();
        let result = f();
        compiler_fence_seq_cst();
        result
    }
}

/// Exact-size initialized storage helpers for sensitive values.
///
/// These helpers do not lock pages, alter allocator behavior, or claim to
/// protect memory from the operating system. Doing so would require native
/// interfaces that are outside dcrypt's implementation boundary.
#[cfg(feature = "alloc")]
pub mod alloc {
    use super::*;
    use dcrypt_internal::zeroing::Zeroize;

    #[cfg(all(not(feature = "std"), feature = "alloc"))]
    use super::rust_alloc::vec;

    /// Allocate an exact-size boxed slice of initialized values.
    pub fn zeroizing_box<T: Default + Zeroize + Clone>(size: usize) -> Box<[T]> {
        vec![T::default(); size].into_boxed_slice()
    }

    /// Clear every initialized element before releasing a boxed slice.
    pub fn clear_box<T: Zeroize>(mut data: Box<[T]>) {
        data.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_compare() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(a.secure_eq(&b));
        assert!(!a.secure_eq(&c));
    }

    #[test]
    fn test_memory_barriers() {
        use barrier::*;

        let result = with_barriers(|| {
            let mut x = 42;
            x += 1;
            x
        });

        assert_eq!(result, 43);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn exact_size_sensitive_storage_helpers_round_trip() {
        let mut data = alloc::zeroizing_box::<u8>(17);
        assert_eq!(data.len(), 17);
        data.fill(0x5a);
        alloc::clear_box(data);
    }
}
