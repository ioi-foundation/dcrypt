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
use alloc::vec::Vec;
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
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretVec {
    data: Vec<u8>,
}

impl SecretVec {
    /// Create a new SecretVec.
    ///
    /// Accepts `Vec<u8>` (move) or `&[u8]` (copy).
    /// Moving a Vec<u8> is preferred for security as it ensures the original
    /// memory allocation is controlled and zeroized by SecretVec.
    pub fn new<T: Into<Vec<u8>>>(data: T) -> Self {
        Self { data: data.into() }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            data: slice.to_vec(),
        }
    }
    pub fn zeroed(len: usize) -> Self {
        Self {
            data: vec![0u8; len],
        }
    }
    pub fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R, len: usize) -> Self {
        let mut data = vec![0u8; len];
        rng.fill_bytes(&mut data);
        Self { data }
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
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
    type Target = Vec<u8>;
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

/// Base key type that provides secure memory handling
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key {
    data: Vec<u8>,
}

impl Key {
    /// Create a new Key.
    ///
    /// Accepts `Vec<u8>` (move) or `&[u8]` (copy).
    /// Moving a Vec<u8> is preferred for security as it ensures the original
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
    /// Moving a Vec<u8> avoids unnecessary allocation.
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
    /// Moving a Vec<u8> avoids unnecessary allocation, which is critical
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
