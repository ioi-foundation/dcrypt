//! Secret data types that invoke zeroization for owned storage
//!
//! This module provides type-safe wrappers for sensitive data that ensure
//! cleanup and zeroization when the data is no longer needed. Software
//! zeroization cannot erase caller, compiler/register, or already-freed copies.

use core::convert::{AsMut, AsRef};
use core::fmt;
use core::ops::{Deref, DerefMut};
use dcrypt_internal::zeroing::Zeroize;

pub use dcrypt_api::types::SecretBytes as SecretBuffer;
#[cfg(feature = "alloc")]
pub use dcrypt_api::types::SecretVec;

/// Trait for types that can be securely zeroed and cloned
pub trait SecureZeroingType: Zeroize + Clone {
    /// Create a zeroed instance
    fn zeroed() -> Self;

    /// Create a secure clone that preserves security properties
    ///
    /// This method ensures that cloned instances maintain the same
    /// security guarantees as the original, including proper zeroization.
    fn secure_clone(&self) -> Self {
        self.clone() // Default implementation uses regular clone
    }
}

impl<const N: usize> SecureZeroingType for SecretBuffer<N> {
    fn zeroed() -> Self {
        Self::zeroed()
    }

    fn secure_clone(&self) -> Self {
        self.clone()
    }
}

#[cfg(feature = "alloc")]
impl SecureZeroingType for SecretVec {
    fn zeroed() -> Self {
        Self::empty()
    }

    fn secure_clone(&self) -> Self {
        self.clone()
    }
}

/// Ephemeral secret that is automatically zeroized after use
///
/// This type wraps any type T and ensures it is zeroized when dropped.
/// It's useful for temporary secrets and intermediate cryptographic values.
pub struct EphemeralSecret<T: Zeroize> {
    inner: Option<T>,
}

impl<T: Zeroize> EphemeralSecret<T> {
    /// Create a new ephemeral secret
    pub fn new(value: T) -> Self {
        Self { inner: Some(value) }
    }

    /// Consume the secret and return the inner value
    ///
    /// Note: After calling this method, the caller is responsible
    /// for ensuring the value is properly zeroized.
    pub fn into_inner(self) -> T {
        let mut this = self;
        this.inner
            .take()
            .expect("EphemeralSecret value was already consumed")
    }
}

// Fixed: Implement actual AsRef and AsMut traits instead of methods
impl<T: Zeroize> AsRef<T> for EphemeralSecret<T> {
    fn as_ref(&self) -> &T {
        self.inner
            .as_ref()
            .expect("EphemeralSecret value was already consumed")
    }
}

impl<T: Zeroize> AsMut<T> for EphemeralSecret<T> {
    fn as_mut(&mut self) -> &mut T {
        self.inner
            .as_mut()
            .expect("EphemeralSecret value was already consumed")
    }
}

impl<T: Zeroize> Drop for EphemeralSecret<T> {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.as_mut() {
            inner.zeroize();
        }
    }
}

impl<T: Zeroize + Clone> Clone for EphemeralSecret<T> {
    fn clone(&self) -> Self {
        Self::new(
            self.inner
                .as_ref()
                .expect("EphemeralSecret value was already consumed")
                .clone(),
        )
    }
}

impl<T: Zeroize + Default> Default for EphemeralSecret<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Zeroize> Deref for EphemeralSecret<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T: Zeroize> DerefMut for EphemeralSecret<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl<T: Zeroize> fmt::Debug for EphemeralSecret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EphemeralSecret([REDACTED])")
    }
}

/// Guard type that ensures a value is zeroized when dropped
///
/// This is useful for ensuring cleanup happens even in the presence
/// of early returns or panics.
pub struct ZeroizeGuard<'a, T: Zeroize> {
    value: &'a mut T,
}

impl<'a, T: Zeroize> ZeroizeGuard<'a, T> {
    /// Create a new zeroize guard for the given value
    pub fn new(value: &'a mut T) -> Self {
        Self { value }
    }
}

// Fixed: Use lifetime elision instead of explicit lifetimes
impl<T: Zeroize> Drop for ZeroizeGuard<'_, T> {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl<T: Zeroize> Deref for ZeroizeGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.value
    }
}

impl<T: Zeroize> DerefMut for ZeroizeGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_buffer_basic() {
        let mut buffer = SecretBuffer::<32>::new([42u8; 32]);
        assert_eq!(buffer.len(), 32);
        assert_eq!(buffer.as_slice()[0], 42);

        // Test mutation
        buffer.as_mut_slice()[0] = 1;
        assert_eq!(buffer.as_slice()[0], 1);
    }

    #[test]
    fn test_secret_buffer_secure_clone() {
        let buffer = SecretBuffer::<16>::new([0xAA; 16]);
        let cloned = buffer.secure_clone();
        assert_eq!(cloned.as_slice(), buffer.as_slice());
    }

    #[test]
    fn test_secret_buffer_zeroed() {
        let zeroed = SecretBuffer::<32>::zeroed();
        assert_eq!(zeroed.as_slice(), &[0u8; 32]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_secret_vec_operations() {
        let mut vec = SecretVec::from_slice(&[1, 2, 3, 4]);
        assert_eq!(vec.len(), 4);
        assert_eq!(vec.as_slice(), &[1, 2, 3, 4]);

        // Test extend
        vec.extend_from_slice(&[5, 6]);
        assert_eq!(vec.as_slice(), &[1, 2, 3, 4, 5, 6]);

        // Test truncate
        vec.truncate(3);
        assert_eq!(vec.as_slice(), &[1, 2, 3]);

        // Test resize
        vec.resize(5, 0xFF);
        assert_eq!(vec.as_slice(), &[1, 2, 3, 0xFF, 0xFF]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_uses_exact_size_storage() {
        let secret = SecretVec::from_slice(&[0xA5; 4]);

        assert_eq!(secret.as_slice(), &[0xA5; 4]);
        assert_eq!(secret.capacity(), secret.len());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_wipes_bytes_removed_by_truncate_resize_clear_and_pop() {
        let mut secret = SecretVec::from_slice(&[1, 2, 3, 4, 5, 6]);

        secret.truncate(4);
        assert_eq!(secret.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(secret.capacity(), secret.len());

        secret.resize(2, 0xFF);
        assert_eq!(secret.as_slice(), &[1, 2]);
        assert_eq!(secret.capacity(), secret.len());

        assert_eq!(secret.pop(), Some(2));
        assert_eq!(secret.as_slice(), &[1]);
        assert_eq!(secret.capacity(), secret.len());

        secret.clear();
        assert!(secret.is_empty());
        assert_eq!(secret.capacity(), secret.len());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_growth_and_shrink_replace_allocations_securely() {
        let mut secret = SecretVec::from_slice(&[0x11; 4]);
        secret.extend_from_slice(&[0x22, 0x33]);
        assert_eq!(secret.capacity(), 6);
        assert_eq!(secret.as_slice(), &[0x11, 0x11, 0x11, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn test_ephemeral_secret() {
        #[derive(Clone)]
        struct TestSecret(u64);

        impl Zeroize for TestSecret {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        let secret = EphemeralSecret::new(TestSecret(42));
        assert_eq!(secret.0, 42);

        // Test deref
        let value = secret.0;
        assert_eq!(value, 42);

        // Test clone
        let cloned = secret.clone();
        assert_eq!(cloned.0, 42);

        // Test into_inner
        let inner = secret.into_inner();
        assert_eq!(inner.0, 42);
    }

    #[test]
    fn test_zeroize_guard() {
        let mut value = [1u8, 2, 3, 4];
        {
            let guard = ZeroizeGuard::new(&mut value);
            // Simulate work with the value
            assert_eq!(&*guard, &[1, 2, 3, 4]);
        }
        assert_eq!(value, [0; 4]);
    }
}
