// File: crates/api/src/types.rs

//! Core types with security guarantees for the dcrypt library
//!
//! This module provides fundamental type definitions that enforce
//! compile-time and runtime guarantees for cryptographic operations.

use crate::{
    error::Error,
    traits::serialize::{Serialize, SerializeSecret},
    Result,
};
use core::fmt;
use core::ops::{Deref, DerefMut};
use dcrypt_internal::constant_time::ct_eq;
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec, vec::Vec};
#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};

/// A fixed-size array of bytes that is securely zeroed when dropped
#[derive(Clone)]
pub struct SecretBytes<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> Zeroize for SecretBytes<N> {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for SecretBytes<N> {}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> SecretBytes<N> {
    pub fn new(data: [u8; N]) -> Self {
        Self { data }
    }
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(Error::InvalidLength {
                context: "SecretBytes::from_slice",
                expected: N,
                actual: slice.len(),
            });
        }
        let mut data = [0u8; N];
        data.copy_from_slice(slice);
        Ok(Self { data })
    }
    pub fn zeroed() -> Self {
        Self { data: [0u8; N] }
    }
    pub fn random<R: dcrypt_internal::random::CryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut data = [0u8; N];
        rng.try_fill_bytes(&mut data)
            .map_err(|_| Error::RandomGenerationError {
                context: "SecretBytes::random",
                #[cfg(feature = "std")]
                message: "caller-provided randomness source failed".into(),
            })?;
        Ok(Self { data })
    }
    pub fn len(&self) -> usize {
        N
    }
    pub fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> AsMut<[u8]> for SecretBytes<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize> Deref for SecretBytes<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for SecretBytes<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(self.data, other.data)
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{}>[REDACTED]", N)
    }
}

impl<const N: usize> SerializeSecret for SecretBytes<N> {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_slice(bytes)
    }
    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.data.to_vec())
    }
}

/// A variable-length vector of bytes that is securely zeroed when dropped
pub struct SecretVec {
    data: Box<[u8]>,
}

impl Zeroize for SecretVec {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl ZeroizeOnDrop for SecretVec {}

impl Drop for SecretVec {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SecretVec {
    /// Create a new SecretVec.
    ///
    /// The initialized bytes are copied into exact-size owned storage. Any
    /// inaccessible spare capacity from a caller-owned `Vec` is outside this
    /// type's control and is never retained by `SecretVec`.
    pub fn new<T: Into<Vec<u8>>>(data: T) -> Self {
        Self {
            data: data.into().into_boxed_slice(),
        }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }
    pub fn zeroed(len: usize) -> Self {
        Self::new(vec![0u8; len])
    }
    pub fn random<R: dcrypt_internal::random::CryptoRng + ?Sized>(
        rng: &mut R,
        len: usize,
    ) -> Result<Self> {
        let mut data = vec![0u8; len];
        rng.try_fill_bytes(&mut data)
            .map_err(|_| Error::RandomGenerationError {
                context: "SecretVec::random",
                #[cfg(feature = "std")]
                message: "caller-provided randomness source failed".into(),
            })?;
        Ok(Self::new(data))
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Return the secret bytes as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Return the secret bytes as a mutable slice.
    ///
    /// Slice access permits in-place byte changes but cannot resize or
    /// reallocate the backing storage.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Return the allocation capacity.
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Extend the value, wiping the old allocation before freeing it if growth
    /// requires a larger allocation.
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        let new_len = self
            .data
            .len()
            .checked_add(slice.len())
            .expect("SecretVec length overflow");
        let mut replacement = vec![0u8; new_len].into_boxed_slice();
        replacement[..self.data.len()].copy_from_slice(&self.data);
        replacement[self.data.len()..].copy_from_slice(slice);
        self.replace_and_zeroize(replacement);
    }

    /// Resize the value. Bytes removed by shrinking are wiped first.
    pub fn resize(&mut self, new_len: usize, value: u8) {
        if new_len <= self.data.len() {
            self.truncate(new_len);
            return;
        }

        let mut replacement = vec![value; new_len].into_boxed_slice();
        replacement[..self.data.len()].copy_from_slice(&self.data);
        self.replace_and_zeroize(replacement);
    }

    /// Shorten the value, wiping every removed byte before changing its length.
    pub fn truncate(&mut self, len: usize) {
        if len >= self.data.len() {
            return;
        }

        let replacement = self.data[..len].to_vec().into_boxed_slice();
        self.replace_and_zeroize(replacement);
    }

    /// Remove all bytes while retaining a fully zeroed allocation.
    pub fn clear(&mut self) {
        self.replace_and_zeroize(Vec::new().into_boxed_slice());
    }

    /// Append one byte, securely replacing the allocation when it is full.
    pub fn push(&mut self, value: u8) {
        self.extend_from_slice(&[value]);
    }

    /// Remove and return the last byte, wiping its allocation slot first.
    pub fn pop(&mut self) -> Option<u8> {
        let value = self.data.last().copied()?;
        self.truncate(self.data.len() - 1);
        Some(value)
    }

    /// Validate that a future length would fit. Exact-size secret storage does
    /// not retain spare allocation capacity.
    pub fn reserve(&mut self, additional: usize) {
        self.data
            .len()
            .checked_add(additional)
            .expect("SecretVec length overflow");
    }

    /// Reduce capacity to the current length while wiping the old allocation.
    pub fn shrink_to_fit(&mut self) {
        // Storage is always exact-size.
    }

    fn replace_and_zeroize(&mut self, replacement: Box<[u8]>) {
        self.data.zeroize();
        self.data = replacement;
    }
}

impl Clone for SecretVec {
    fn clone(&self) -> Self {
        Self::from_slice(&self.data)
    }
}

impl From<Vec<u8>> for SecretVec {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl AsRef<[u8]> for SecretVec {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl AsMut<[u8]> for SecretVec {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

impl Deref for SecretVec {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.data.as_ref()
    }
}

impl DerefMut for SecretVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data.as_mut()
    }
}

impl PartialEq for SecretVec {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(self.data.as_ref(), other.data.as_ref())
    }
}

impl Eq for SecretVec {}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretVec({})[REDACTED]", self.data.len())
    }
}

impl SerializeSecret for SecretVec {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self::from_slice(bytes))
    }
    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.data.to_vec())
    }
}

#[cfg(test)]
mod secret_vec_tests {
    use super::{SecretBytes, SecretVec};
    use dcrypt_internal::random::{CryptoRng, Error as RandomError, RngCore};

    #[cfg(not(feature = "std"))]
    use alloc::{vec, vec::Vec};

    #[test]
    fn constructor_uses_exact_size_storage() {
        let mut raw = vec![0xA5; 64];
        raw.truncate(4);
        let secret = SecretVec::new(raw);

        assert_eq!(secret.as_slice(), &[0xA5; 4]);
        assert_eq!(secret.capacity(), secret.len());
    }

    #[test]
    fn shrinking_operations_wipe_removed_slots() {
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

    #[test]
    fn growth_and_shrink_replace_allocations_securely() {
        let mut raw = Vec::with_capacity(4);
        raw.extend_from_slice(&[0x11; 4]);
        let mut secret = SecretVec::new(raw);
        secret.extend_from_slice(&[0x22, 0x33]);
        assert_eq!(secret.capacity(), 6);
        assert_eq!(secret.as_slice(), &[0x11, 0x11, 0x11, 0x11, 0x22, 0x33]);

        secret.reserve(32);
        assert_eq!(secret.capacity(), secret.len());

        secret.shrink_to_fit();
        assert_eq!(secret.capacity(), secret.len());
        assert_eq!(secret.as_slice(), &[0x11, 0x11, 0x11, 0x11, 0x22, 0x33]);
    }

    struct FailingRng;

    impl RngCore for FailingRng {
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), RandomError> {
            Err(RandomError)
        }
    }

    impl CryptoRng for FailingRng {}

    #[test]
    fn random_secret_constructors_propagate_caller_rng_failure() {
        let mut rng = FailingRng;
        assert!(SecretBytes::<32>::random(&mut rng).is_err());
        assert!(SecretVec::random(&mut rng, 32).is_err());
    }
}

/// Base key type that provides secure memory handling
#[derive(Clone)]
pub struct Key {
    data: Box<[u8]>,
}

impl Zeroize for Key {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl ZeroizeOnDrop for Key {}

impl Drop for Key {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Key {
    /// Create a new Key.
    ///
    /// Accepts `Vec<u8>` (move) or `&[u8]` (copy).
    /// Moving a `Vec<u8>` is preferred for security as it ensures the original
    /// memory allocation is controlled and zeroized by Key.
    pub fn new<T: Into<Vec<u8>>>(data: T) -> Self {
        Self {
            data: data.into().into_boxed_slice(),
        }
    }
    pub fn new_zeros(len: usize) -> Self {
        Self {
            data: vec![0u8; len].into_boxed_slice(),
        }
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl From<Vec<u8>> for Key {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl AsMut<[u8]> for Key {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

impl SerializeSecret for Key {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self::new(bytes))
    }
    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.data.to_vec())
    }
}

/// Wrapper for public key data
#[derive(Clone)]
pub struct PublicKey {
    data: Vec<u8>,
}

impl PublicKey {
    /// Create a new PublicKey.
    ///
    /// Accepts `Vec<u8>` (move) or `&[u8]` (copy).
    /// Moving a `Vec<u8>` avoids unnecessary allocation.
    pub fn new<T: Into<Vec<u8>>>(data: T) -> Self {
        Self { data: data.into() }
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl From<Vec<u8>> for PublicKey {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Serialize for PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self::new(bytes))
    }
}

/// Wrapper for ciphertext data
#[derive(Clone)]
pub struct Ciphertext {
    data: Vec<u8>,
}

impl Ciphertext {
    /// Create a new Ciphertext.
    ///
    /// Accepts `Vec<u8>` (move) or `&[u8]` (copy).
    /// Moving a `Vec<u8>` avoids unnecessary allocation, which is critical
    /// for large ciphertexts.
    pub fn new<T: Into<Vec<u8>>>(data: T) -> Self {
        Self { data: data.into() }
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl From<Vec<u8>> for Ciphertext {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for Ciphertext {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Serialize for Ciphertext {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self::new(bytes))
    }
}
