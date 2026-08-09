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
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{vec, vec::Vec};
#[cfg(feature = "std")]
use std::vec::Vec;

/// A fixed-size array of bytes that is securely zeroed when dropped
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize> {
    data: [u8; N],
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
    pub fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        let mut data = [0u8; N];
        rng.fill_bytes(&mut data);
        Self { data }
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
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretVec {
    data: Vec<u8>,
}

impl SecretVec {
    /// Create a new SecretVec.
    ///
    /// Accepts `Vec<u8>` (move) or `&[u8]` (copy).
    /// Moving a `Vec<u8>` is preferred for security as it ensures the original
    /// memory allocation is controlled and zeroized by SecretVec.
    /// Allocations the caller freed before passing the current `Vec` cannot be
    /// recovered or retroactively wiped.
    pub fn new<T: Into<Vec<u8>>>(data: T) -> Self {
        let mut data = data.into();
        // A caller-owned Vec may previously have been truncated. Wipe its
        // unused allocation before accepting responsibility for it.
        Self::zeroize_spare_capacity(&mut data);
        Self { data }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }
    pub fn zeroed(len: usize) -> Self {
        Self::new(vec![0u8; len])
    }
    pub fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R, len: usize) -> Self {
        let mut data = vec![0u8; len];
        rng.fill_bytes(&mut data);
        Self::new(data)
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
        self.data.capacity()
    }

    /// Extend the value, wiping the old allocation before freeing it if growth
    /// requires a larger allocation.
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.ensure_additional_capacity(slice.len());
        self.data.extend_from_slice(slice);
    }

    /// Resize the value. Bytes removed by shrinking are wiped first.
    pub fn resize(&mut self, new_len: usize, value: u8) {
        if new_len <= self.data.len() {
            self.truncate(new_len);
            return;
        }

        self.ensure_additional_capacity(new_len - self.data.len());
        self.data.resize(new_len, value);
    }

    /// Shorten the value, wiping every removed byte before changing its length.
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

    /// Reserve room for at least `additional` more bytes without resizing the
    /// live secret allocation in place.
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

        // Vec::zeroize wipes both its initialized bytes and its entire spare
        // capacity. Free the allocation only after that wipe is complete.
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
        &self.data
    }
}

impl AsMut<[u8]> for SecretVec {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Deref for SecretVec {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for SecretVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl PartialEq for SecretVec {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.data, &other.data)
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
        Zeroizing::new(self.data.clone())
    }
}

#[cfg(test)]
mod secret_vec_tests {
    use super::SecretVec;

    #[cfg(all(not(feature = "std"), feature = "alloc"))]
    use alloc::{vec, vec::Vec};

    fn assert_spare_capacity_is_zero(secret: &SecretVec) {
        // SecretVec initializes every byte of spare capacity. Reading this
        // range is therefore valid even though Vec does not expose it as an
        // initialized slice.
        let spare = unsafe {
            core::slice::from_raw_parts(
                secret.data.as_ptr().add(secret.data.len()),
                secret.data.capacity() - secret.data.len(),
            )
        };
        assert!(spare.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn constructor_wipes_preexisting_unused_capacity() {
        let mut raw = vec![0xA5; 64];
        raw.truncate(4);
        let secret = SecretVec::new(raw);

        assert_eq!(secret.as_slice(), &[0xA5; 4]);
        assert_spare_capacity_is_zero(&secret);
    }

    #[test]
    fn shrinking_operations_wipe_removed_slots() {
        let mut secret = SecretVec::from_slice(&[1, 2, 3, 4, 5, 6]);

        secret.truncate(4);
        assert_eq!(secret.as_slice(), &[1, 2, 3, 4]);
        assert_spare_capacity_is_zero(&secret);

        secret.resize(2, 0xFF);
        assert_eq!(secret.as_slice(), &[1, 2]);
        assert_spare_capacity_is_zero(&secret);

        assert_eq!(secret.pop(), Some(2));
        assert_eq!(secret.as_slice(), &[1]);
        assert_spare_capacity_is_zero(&secret);

        secret.clear();
        assert!(secret.is_empty());
        assert_spare_capacity_is_zero(&secret);
    }

    #[test]
    fn growth_and_shrink_replace_allocations_securely() {
        let mut raw = Vec::with_capacity(4);
        raw.extend_from_slice(&[0x11; 4]);
        let mut secret = SecretVec::new(raw);
        let initial_capacity = secret.capacity();

        // secure_reallocate contains a test assertion that observes the old
        // allocation after zeroization and immediately before deallocation.
        secret.extend_from_slice(&[0x22, 0x33]);
        assert!(secret.capacity() > initial_capacity);
        assert_eq!(secret.as_slice(), &[0x11, 0x11, 0x11, 0x11, 0x22, 0x33]);
        assert_spare_capacity_is_zero(&secret);

        secret.reserve(32);
        assert!(secret.capacity() >= secret.len() + 32);
        assert_spare_capacity_is_zero(&secret);

        secret.shrink_to_fit();
        assert_eq!(secret.capacity(), secret.len());
        assert_eq!(secret.as_slice(), &[0x11, 0x11, 0x11, 0x11, 0x22, 0x33]);
    }
}

/// Base key type that provides secure memory handling
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key {
    data: Vec<u8>,
}

impl Key {
    /// Create a new Key.
    ///
    /// Accepts `Vec<u8>` (move) or `&[u8]` (copy).
    /// Moving a `Vec<u8>` is preferred for security as it ensures the original
    /// memory allocation is controlled and zeroized by Key.
    pub fn new<T: Into<Vec<u8>>>(data: T) -> Self {
        Self { data: data.into() }
    }
    pub fn new_zeros(len: usize) -> Self {
        Self {
            data: vec![0u8; len],
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
        &self.data
    }
}

impl AsMut<[u8]> for Key {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl SerializeSecret for Key {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self::new(bytes))
    }
    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.data.clone())
    }
}

/// Wrapper for public key data
#[derive(Clone, Zeroize)]
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
