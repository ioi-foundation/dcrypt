//! Secret data types that invoke zeroization for owned storage
//!
//! This module provides type-safe wrappers for sensitive data that ensure
//! cleanup and zeroization when the data is no longer needed. Software
//! zeroization cannot erase caller, compiler/register, or already-freed copies.

use core::convert::{AsMut, AsRef};
use core::fmt;
use core::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Handle Vec import based on features
#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

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

/// Fixed-size secret buffer that guarantees zeroization
///
/// This type provides:
/// - Automatic zeroization on drop
/// - Secure cloning that preserves security properties
/// - Type-safe size guarantees at compile time
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBuffer<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecretBuffer<N> {
    /// Create a new secret buffer with the given data
    pub fn new(data: [u8; N]) -> Self {
        Self { data }
    }

    /// Create a zeroed secret buffer
    pub fn zeroed() -> Self {
        Self { data: [0u8; N] }
    }

    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        N
    }

    /// Check if the buffer is empty (always false for non-zero N)
    pub fn is_empty(&self) -> bool {
        N == 0
    }

    /// Get a reference to the inner data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the inner data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> SecureZeroingType for SecretBuffer<N> {
    fn zeroed() -> Self {
        Self::zeroed()
    }

    fn secure_clone(&self) -> Self {
        Self::new(self.data) // Fixed: removed .clone() since [u8; N] implements Copy
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBuffer<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> AsMut<[u8]> for SecretBuffer<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> fmt::Debug for SecretBuffer<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuffer<{}>([REDACTED])", N)
    }
}

/// Variable-size secret vector that wipes storage it owns
///
/// This type provides:
/// - Automatic zeroization on drop
/// - Secure cloning that preserves security properties
/// - Dynamic sizing with secure memory management
#[cfg(feature = "alloc")]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretVec {
    data: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl SecretVec {
    /// Create a new secret vector with the given data.
    ///
    /// The current allocation and its spare capacity become protected by this
    /// type. Allocations the caller freed before passing this `Vec` cannot be
    /// recovered or retroactively wiped.
    pub fn new(mut data: Vec<u8>) -> Self {
        // A Vec supplied by a caller may previously have been truncated. Wipe
        // its unused allocation before accepting responsibility for it.
        Self::zeroize_spare_capacity(&mut data);
        Self { data }
    }

    /// Create a secret vector from a slice
    pub fn from_slice(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }

    /// Create an empty secret vector
    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }

    /// Create a secret vector with the specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        let mut data = Vec::with_capacity(capacity);
        Self::zeroize_spare_capacity(&mut data);
        Self { data }
    }

    /// Get the length of the vector
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the vector is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get a reference to the inner data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the inner data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the allocation capacity.
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Extend the vector with additional data
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.ensure_additional_capacity(slice.len());
        self.data.extend_from_slice(slice);
    }

    /// Resize the vector to the specified length
    pub fn resize(&mut self, new_len: usize, value: u8) {
        if new_len <= self.data.len() {
            self.truncate(new_len);
            return;
        }

        self.ensure_additional_capacity(new_len - self.data.len());
        self.data.resize(new_len, value);
    }

    /// Truncate the vector to the specified length
    pub fn truncate(&mut self, len: usize) {
        if len >= self.data.len() {
            return;
        }

        self.data[len..].zeroize();
        self.data.truncate(len);
    }

    /// Remove all bytes while retaining a fully zeroed allocation.
    pub fn clear(&mut self) {
        self.data.zeroize();
    }

    /// Append one byte, securely replacing the allocation when it is full.
    pub fn push(&mut self, value: u8) {
        self.ensure_additional_capacity(1);
        self.data.push(value);
    }

    /// Remove and return the last byte, wiping its allocation slot first.
    pub fn pop(&mut self) -> Option<u8> {
        let value = self.data.last().copied()?;
        let new_len = self.data.len() - 1;
        self.data[new_len].zeroize();
        self.data.truncate(new_len);
        Some(value)
    }

    /// Reserve room for at least `additional` more bytes.
    ///
    /// Unlike `Vec::reserve`, this never asks the allocator to resize the live
    /// secret allocation. It copies into a new allocation and wipes the old
    /// allocation before releasing it.
    pub fn reserve(&mut self, additional: usize) {
        self.ensure_additional_capacity(additional);
    }

    /// Reduce capacity to the current length while wiping the old allocation.
    pub fn shrink_to_fit(&mut self) {
        if self.data.capacity() > self.data.len() {
            self.secure_reallocate(self.data.len());
        }
    }

    fn ensure_additional_capacity(&mut self, additional: usize) {
        let required = self
            .data
            .len()
            .checked_add(additional)
            .expect("SecretVec capacity overflow");

        if required > self.data.capacity() {
            self.secure_reallocate(required);
        }
    }

    fn secure_reallocate(&mut self, capacity: usize) {
        debug_assert!(capacity >= self.data.len());

        let mut replacement = Vec::with_capacity(capacity);
        replacement.extend_from_slice(&self.data);
        Self::zeroize_spare_capacity(&mut replacement);

        // zeroize() wipes both initialized elements and the entire spare
        // capacity before clearing the Vec. Only then is the allocation freed.
        self.data.zeroize();
        #[cfg(test)]
        assert!(Self::allocation_is_zeroed(&self.data));
        self.data = replacement;
    }

    fn zeroize_spare_capacity(data: &mut Vec<u8>) {
        data.spare_capacity_mut().zeroize();
    }

    #[cfg(test)]
    fn allocation_is_zeroed(data: &Vec<u8>) -> bool {
        // Callers use this only after Vec::zeroize(), which initializes the
        // entire allocation with zero bytes and sets len to zero.
        let allocation = unsafe { core::slice::from_raw_parts(data.as_ptr(), data.capacity()) };
        allocation.iter().all(|byte| *byte == 0)
    }
}

#[cfg(feature = "alloc")]
impl Clone for SecretVec {
    fn clone(&self) -> Self {
        Self::from_slice(&self.data)
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

#[cfg(feature = "alloc")]
impl AsRef<[u8]> for SecretVec {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(feature = "alloc")]
impl AsMut<[u8]> for SecretVec {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

#[cfg(feature = "alloc")]
impl From<Vec<u8>> for SecretVec {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

#[cfg(feature = "alloc")]
impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretVec(len={}, [REDACTED])", self.data.len())
    }
}

/// Ephemeral secret that is automatically zeroized after use
///
/// This type wraps any type T and ensures it is zeroized when dropped.
/// It's useful for temporary secrets and intermediate cryptographic values.
pub struct EphemeralSecret<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> EphemeralSecret<T> {
    /// Create a new ephemeral secret
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Consume the secret and return the inner value
    ///
    /// Note: After calling this method, the caller is responsible
    /// for ensuring the value is properly zeroized.
    pub fn into_inner(self) -> T {
        let this = core::mem::ManuallyDrop::new(self);
        unsafe { core::ptr::read(&this.inner) }
    }
}

// Fixed: Implement actual AsRef and AsMut traits instead of methods
impl<T: Zeroize> AsRef<T> for EphemeralSecret<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> AsMut<T> for EphemeralSecret<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Zeroize> Drop for EphemeralSecret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize + Clone> Clone for EphemeralSecret<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
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
        &self.inner
    }
}

impl<T: Zeroize> DerefMut for EphemeralSecret<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: Zeroize + fmt::Debug> fmt::Debug for EphemeralSecret<T> {
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

    #[cfg(all(not(feature = "std"), feature = "alloc"))]
    use alloc::vec;

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
    fn assert_secret_vec_spare_capacity_is_zero(vec: &SecretVec) {
        // SecretVec initializes every spare-capacity byte on construction and
        // after each operation that can change the allocation.
        let spare = unsafe {
            core::slice::from_raw_parts(
                vec.data.as_ptr().add(vec.data.len()),
                vec.data.capacity() - vec.data.len(),
            )
        };
        assert!(spare.iter().all(|byte| *byte == 0));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_wipes_preexisting_unused_capacity() {
        let mut raw = vec![0xA5; 64];
        raw.truncate(4);
        let secret = SecretVec::new(raw);

        assert_eq!(secret.as_slice(), &[0xA5; 4]);
        assert_secret_vec_spare_capacity_is_zero(&secret);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_wipes_bytes_removed_by_truncate_resize_clear_and_pop() {
        let mut secret = SecretVec::from_slice(&[1, 2, 3, 4, 5, 6]);

        secret.truncate(4);
        assert_eq!(secret.as_slice(), &[1, 2, 3, 4]);
        assert_secret_vec_spare_capacity_is_zero(&secret);

        secret.resize(2, 0xFF);
        assert_eq!(secret.as_slice(), &[1, 2]);
        assert_secret_vec_spare_capacity_is_zero(&secret);

        assert_eq!(secret.pop(), Some(2));
        assert_eq!(secret.as_slice(), &[1]);
        assert_secret_vec_spare_capacity_is_zero(&secret);

        secret.clear();
        assert!(secret.is_empty());
        assert_secret_vec_spare_capacity_is_zero(&secret);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn secret_vec_growth_and_shrink_replace_allocations_securely() {
        let mut raw = Vec::with_capacity(4);
        raw.extend_from_slice(&[0x11; 4]);
        let mut secret = SecretVec::new(raw);
        let initial_capacity = secret.capacity();

        // This exercises secure_reallocate; its test assertion observes the
        // old allocation after zeroization and before deallocation.
        secret.extend_from_slice(&[0x22, 0x33]);
        assert!(secret.capacity() > initial_capacity);
        assert_eq!(secret.as_slice(), &[0x11, 0x11, 0x11, 0x11, 0x22, 0x33]);
        assert_secret_vec_spare_capacity_is_zero(&secret);

        secret.reserve(32);
        assert!(secret.capacity() >= secret.len() + 32);
        assert_secret_vec_spare_capacity_is_zero(&secret);

        secret.shrink_to_fit();
        assert_eq!(secret.capacity(), secret.len());
        assert_eq!(secret.as_slice(), &[0x11, 0x11, 0x11, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn test_ephemeral_secret() {
        #[derive(Clone, Zeroize)]
        struct TestSecret(u64);

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
        let mut value = vec![1u8, 2, 3, 4];
        {
            let guard = ZeroizeGuard::new(&mut value);
            // Simulate work with the value
            assert_eq!(&**guard, &[1, 2, 3, 4]);
        }
        // Guard should have zeroized the value (which clears the Vec)
        assert!(value.is_empty());
    }
}
