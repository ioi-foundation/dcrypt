//! Type-safe key implementations with algorithm binding
//!
//! Provides key types with compile-time guarantees about their
//! usage and appropriate security properties.

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;

use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use dcrypt_internal::constant_time::ConstantTimeEq;
use dcrypt_internal::random::{try_fill_bytes_zeroing_on_error, CryptoRng, RngCore};
use dcrypt_internal::zeroing::{
    zeroizing_bytes_from_slice, Zeroize, ZeroizeOnDrop, ZeroizingBytes,
};

use crate::error::{validate, Result};
use crate::types::sealed::Sealed;
use crate::types::{
    ByteSerializable, ConstantTimeEq as LocalConstantEq, FixedSize, RandomGeneration,
    SecureZeroingType,
};
use crate::types::{ValidKeySize, ValidPublicKeySize, ValidSecretKeySize};

// Import security types from dcrypt-core
use dcrypt_common::security::SecretBuffer;

// Add these imports to fix the "cannot find type" errors
use crate::types::algorithms::{
    Aes128, Aes256, ChaCha20, ChaCha20Poly1305, Ed25519, P256, P384, P521, X25519,
};

/// Marker trait for symmetric algorithms
pub trait SymmetricAlgorithm {
    /// Key size in bytes
    const KEY_SIZE: usize;

    /// Block size in bytes (if applicable)
    const BLOCK_SIZE: usize;

    /// Algorithm identifier
    const ALGORITHM_ID: &'static str;

    /// Algorithm name
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// Marker trait for asymmetric algorithms
pub trait AsymmetricAlgorithm {
    /// Public key size in bytes
    const PUBLIC_KEY_SIZE: usize;

    /// Secret key size in bytes
    const SECRET_KEY_SIZE: usize;

    /// Algorithm identifier
    const ALGORITHM_ID: &'static str;

    /// Algorithm name
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// A key for a specific symmetric algorithm with fixed size
#[derive(Clone)]
pub struct SymmetricKey<A: SymmetricAlgorithm, const N: usize> {
    data: SecretBuffer<N>,
    _algorithm: PhantomData<A>,
}

impl<A: SymmetricAlgorithm, const N: usize> Zeroize for SymmetricKey<A, N> {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl<A: SymmetricAlgorithm, const N: usize> Drop for SymmetricKey<A, N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<A: SymmetricAlgorithm, const N: usize> ZeroizeOnDrop for SymmetricKey<A, N> {}

// Mark types as sealed to prevent external implementations
impl<A: SymmetricAlgorithm, const N: usize> Sealed for SymmetricKey<A, N> {}

// Individual implementations for specific algorithm and size combinations
impl ValidKeySize<Aes128, 16> for SymmetricKey<Aes128, 16> {}
impl ValidKeySize<Aes256, 32> for SymmetricKey<Aes256, 32> {}
impl ValidKeySize<ChaCha20, 32> for SymmetricKey<ChaCha20, 32> {}
impl ValidKeySize<ChaCha20Poly1305, 32> for SymmetricKey<ChaCha20Poly1305, 32> {}

impl<A: SymmetricAlgorithm, const N: usize> SymmetricKey<A, N>
where
    Self: ValidKeySize<A, N>,
{
    /// Create a new key from an existing array
    pub fn new(data: [u8; N]) -> Self {
        Self {
            data: SecretBuffer::new(data),
            _algorithm: PhantomData,
        }
    }

    /// Create from a slice, if it has the correct length
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        validate::length("SymmetricKey::from_slice", bytes.len(), N)?;

        let mut data = SecretBuffer::<N>::zeroed();
        data.as_mut().copy_from_slice(bytes);

        Ok(Self {
            data,
            _algorithm: PhantomData,
        })
    }

    /// Create a zeroed key (not recommended for cryptographic use)
    pub fn zeroed() -> Self {
        Self {
            data: SecretBuffer::zeroed(),
            _algorithm: PhantomData,
        }
    }

    /// Get the algorithm name
    pub fn algorithm_name() -> String {
        A::name()
    }

    /// Get the key size in bytes
    pub fn key_size() -> usize {
        N
    }
}

impl<A: SymmetricAlgorithm, const N: usize> AsRef<[u8]> for SymmetricKey<A, N> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<A: SymmetricAlgorithm, const N: usize> AsMut<[u8]> for SymmetricKey<A, N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

impl<A: SymmetricAlgorithm, const N: usize> Deref for SymmetricKey<A, N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data.as_ref()
    }
}

impl<A: SymmetricAlgorithm, const N: usize> DerefMut for SymmetricKey<A, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data.as_mut()
    }
}

impl<A: SymmetricAlgorithm, const N: usize> PartialEq for SymmetricKey<A, N> {
    fn eq(&self, other: &Self) -> bool {
        // Use the workspace-owned constant-time equality trait directly.
        self.data.as_ref().ct_eq(other.data.as_ref()).into()
    }
}

impl<A: SymmetricAlgorithm, const N: usize> Eq for SymmetricKey<A, N> {}

impl<A: SymmetricAlgorithm, const N: usize> fmt::Debug for SymmetricKey<A, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SymmetricKey<{}>[REDACTED]", A::name())
    }
}

impl<A: SymmetricAlgorithm, const N: usize> LocalConstantEq for SymmetricKey<A, N> {
    fn ct_eq(&self, other: &Self) -> bool {
        // Use the workspace-owned constant-time equality trait for the data.
        self.data.as_ref().ct_eq(other.data.as_ref()).into()
    }
}

impl<A: SymmetricAlgorithm, const N: usize> RandomGeneration for SymmetricKey<A, N> {
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut data = SecretBuffer::<N>::zeroed();
        try_fill_bytes_zeroing_on_error(rng, data.as_mut())?;
        Ok(Self {
            data,
            _algorithm: PhantomData,
        })
    }
}

impl<A: SymmetricAlgorithm + Clone, const N: usize> SecureZeroingType for SymmetricKey<A, N> {
    fn zeroed() -> Self {
        Self {
            data: SecretBuffer::zeroed(),
            _algorithm: PhantomData,
        }
    }

    fn secure_clone(&self) -> Self {
        Self {
            data: self.data.secure_clone(),
            _algorithm: PhantomData,
        }
    }
}

impl<A: SymmetricAlgorithm, const N: usize> FixedSize for SymmetricKey<A, N> {
    fn size() -> usize {
        N
    }
}

// Implement ByteSerializable only for specific valid combinations
impl ByteSerializable for SymmetricKey<Aes128, 16> {
    type Bytes = ZeroizingBytes;

    fn to_bytes(&self) -> ZeroizingBytes {
        zeroizing_bytes_from_slice(self.data.as_ref())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl ByteSerializable for SymmetricKey<Aes256, 32> {
    type Bytes = ZeroizingBytes;

    fn to_bytes(&self) -> ZeroizingBytes {
        zeroizing_bytes_from_slice(self.data.as_ref())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl ByteSerializable for SymmetricKey<ChaCha20, 32> {
    type Bytes = ZeroizingBytes;

    fn to_bytes(&self) -> ZeroizingBytes {
        zeroizing_bytes_from_slice(self.data.as_ref())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl ByteSerializable for SymmetricKey<ChaCha20Poly1305, 32> {
    type Bytes = ZeroizingBytes;

    fn to_bytes(&self) -> ZeroizingBytes {
        zeroizing_bytes_from_slice(self.data.as_ref())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

/// A secret key for a specific asymmetric algorithm
#[derive(Clone)]
pub struct AsymmetricSecretKey<A: AsymmetricAlgorithm, const N: usize> {
    data: SecretBuffer<N>,
    _algorithm: PhantomData<A>,
}

impl<A: AsymmetricAlgorithm, const N: usize> Zeroize for AsymmetricSecretKey<A, N> {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> Drop for AsymmetricSecretKey<A, N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> ZeroizeOnDrop for AsymmetricSecretKey<A, N> {}

// Mark types as sealed to prevent external implementations
impl<A: AsymmetricAlgorithm, const N: usize> Sealed for AsymmetricSecretKey<A, N> {}

// Individual implementations for specific algorithm and size combinations
impl ValidSecretKeySize<Ed25519, 32> for AsymmetricSecretKey<Ed25519, 32> {}
impl ValidSecretKeySize<X25519, 32> for AsymmetricSecretKey<X25519, 32> {}
impl ValidSecretKeySize<P256, 32> for AsymmetricSecretKey<P256, 32> {} // Added for P-256
impl ValidSecretKeySize<P384, 48> for AsymmetricSecretKey<P384, 48> {} // Added for P-384
impl ValidSecretKeySize<P521, 66> for AsymmetricSecretKey<P521, 66> {} // P-521

impl<A: AsymmetricAlgorithm, const N: usize> AsymmetricSecretKey<A, N>
where
    Self: ValidSecretKeySize<A, N>,
{
    /// Create a new key from an existing array
    pub fn new(data: [u8; N]) -> Self {
        Self {
            data: SecretBuffer::new(data),
            _algorithm: PhantomData,
        }
    }

    /// Create from a slice, if it has the correct length
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        validate::length("AsymmetricSecretKey::from_slice", bytes.len(), N)?;

        let mut data = SecretBuffer::<N>::zeroed();
        data.as_mut().copy_from_slice(bytes);

        Ok(Self {
            data,
            _algorithm: PhantomData,
        })
    }

    /// Create a zeroed key (not recommended for cryptographic use)
    pub fn zeroed() -> Self {
        Self {
            data: SecretBuffer::zeroed(),
            _algorithm: PhantomData,
        }
    }

    /// Get the algorithm name
    pub fn algorithm_name() -> String {
        A::name()
    }

    /// Get the key size in bytes
    pub fn key_size() -> usize {
        N
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> AsRef<[u8]> for AsymmetricSecretKey<A, N> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> AsMut<[u8]> for AsymmetricSecretKey<A, N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> Deref for AsymmetricSecretKey<A, N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data.as_ref()
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> DerefMut for AsymmetricSecretKey<A, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data.as_mut()
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> PartialEq for AsymmetricSecretKey<A, N> {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison for secret keys
        self.data.as_ref().ct_eq(other.data.as_ref()).into()
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> Eq for AsymmetricSecretKey<A, N> {}

impl<A: AsymmetricAlgorithm, const N: usize> fmt::Debug for AsymmetricSecretKey<A, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AsymmetricSecretKey<{}>[REDACTED]", A::name())
    }
}

impl<A: AsymmetricAlgorithm + Clone, const N: usize> SecureZeroingType
    for AsymmetricSecretKey<A, N>
{
    fn zeroed() -> Self {
        Self {
            data: SecretBuffer::zeroed(),
            _algorithm: PhantomData,
        }
    }

    fn secure_clone(&self) -> Self {
        Self {
            data: self.data.secure_clone(),
            _algorithm: PhantomData,
        }
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> FixedSize for AsymmetricSecretKey<A, N> {
    fn size() -> usize {
        N
    }
}

// Implement ByteSerializable only for specific valid combinations
impl ByteSerializable for AsymmetricSecretKey<Ed25519, 32> {
    type Bytes = ZeroizingBytes;

    fn to_bytes(&self) -> ZeroizingBytes {
        zeroizing_bytes_from_slice(self.data.as_ref())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl ByteSerializable for AsymmetricSecretKey<X25519, 32> {
    type Bytes = ZeroizingBytes;

    fn to_bytes(&self) -> ZeroizingBytes {
        zeroizing_bytes_from_slice(self.data.as_ref())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl ByteSerializable for AsymmetricSecretKey<P256, 32> {
    type Bytes = ZeroizingBytes;

    // Added for P-256
    fn to_bytes(&self) -> ZeroizingBytes {
        zeroizing_bytes_from_slice(self.data.as_ref())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl ByteSerializable for AsymmetricSecretKey<P384, 48> {
    type Bytes = ZeroizingBytes;

    // Added for P-384
    fn to_bytes(&self) -> ZeroizingBytes {
        zeroizing_bytes_from_slice(self.data.as_ref())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl ByteSerializable for AsymmetricSecretKey<P521, 66> {
    type Bytes = ZeroizingBytes;

    // P-521
    fn to_bytes(&self) -> ZeroizingBytes {
        zeroizing_bytes_from_slice(self.data.as_ref())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

/// A public key for a specific asymmetric algorithm
///
/// Note: Public keys don't need SecretBuffer since they're not secret
#[derive(Clone)]
pub struct AsymmetricPublicKey<A: AsymmetricAlgorithm, const N: usize> {
    data: [u8; N],
    _algorithm: PhantomData<A>,
}

// Mark types as sealed to prevent external implementations
impl<A: AsymmetricAlgorithm, const N: usize> Sealed for AsymmetricPublicKey<A, N> {}

// Individual implementations for specific algorithm and size combinations
impl ValidPublicKeySize<Ed25519, 32> for AsymmetricPublicKey<Ed25519, 32> {}
impl ValidPublicKeySize<X25519, 32> for AsymmetricPublicKey<X25519, 32> {}
impl ValidPublicKeySize<P256, 65> for AsymmetricPublicKey<P256, 65> {} // Added for P-256 (uncompressed)
impl ValidPublicKeySize<P256, 33> for AsymmetricPublicKey<P256, 33> {} // Added for P-256 (compressed)
impl ValidPublicKeySize<P384, 97> for AsymmetricPublicKey<P384, 97> {} // Added for P-384 (uncompressed)
impl ValidPublicKeySize<P384, 49> for AsymmetricPublicKey<P384, 49> {} // Added for P-384 (compressed)
impl ValidPublicKeySize<P521, 133> for AsymmetricPublicKey<P521, 133> {} // P-521 (uncompressed)
impl ValidPublicKeySize<P521, 67> for AsymmetricPublicKey<P521, 67> {} // Added for P-521 (compressed)

impl<A: AsymmetricAlgorithm, const N: usize> AsymmetricPublicKey<A, N>
where
    Self: ValidPublicKeySize<A, N>,
{
    /// Create a new key from an existing array
    pub fn new(data: [u8; N]) -> Self {
        Self {
            data,
            _algorithm: PhantomData,
        }
    }

    /// Create from a slice, if it has the correct length
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        validate::length("AsymmetricPublicKey::from_slice", bytes.len(), N)?;

        let mut data = [0u8; N];
        data.copy_from_slice(bytes);

        Ok(Self {
            data,
            _algorithm: PhantomData,
        })
    }

    /// Get the algorithm name
    pub fn algorithm_name() -> String {
        A::name()
    }

    /// Get the key size in bytes
    pub fn key_size() -> usize {
        N
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> AsRef<[u8]> for AsymmetricPublicKey<A, N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> AsMut<[u8]> for AsymmetricPublicKey<A, N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> fmt::Debug for AsymmetricPublicKey<A, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AsymmetricPublicKey<{}>({:?})",
            A::name(),
            &self.data[..]
        )
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> PartialEq for AsymmetricPublicKey<A, N> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data // Public keys can use direct comparison
    }
}

impl<A: AsymmetricAlgorithm, const N: usize> Eq for AsymmetricPublicKey<A, N> {}

impl<A: AsymmetricAlgorithm, const N: usize> FixedSize for AsymmetricPublicKey<A, N> {
    fn size() -> usize {
        N
    }
}

// Implement ByteSerializable only for specific valid combinations
impl ByteSerializable for AsymmetricPublicKey<Ed25519, 32> {
    type Bytes = Vec<u8>;

    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl ByteSerializable for AsymmetricPublicKey<X25519, 32> {
    type Bytes = Vec<u8>;

    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl ByteSerializable for AsymmetricPublicKey<P256, 65> {
    type Bytes = Vec<u8>;

    // Added for P-256 uncompressed
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl ByteSerializable for AsymmetricPublicKey<P256, 33> {
    type Bytes = Vec<u8>;

    // Added for P-256 compressed
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl ByteSerializable for AsymmetricPublicKey<P384, 97> {
    type Bytes = Vec<u8>;

    // Added for P-384 uncompressed
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl ByteSerializable for AsymmetricPublicKey<P384, 49> {
    type Bytes = Vec<u8>;

    // Added for P-384 compressed
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl ByteSerializable for AsymmetricPublicKey<P521, 133> {
    type Bytes = Vec<u8>;

    // P-521 uncompressed
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl ByteSerializable for AsymmetricPublicKey<P521, 67> {
    type Bytes = Vec<u8>;

    // Added for P-521 compressed
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}
