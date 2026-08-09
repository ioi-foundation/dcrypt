//! Key Derivation Functions with operation pattern and type-level guarantees
//!
//! This module provides implementations of key derivation functions (KDFs)
//! with improved type safety and ergonomic APIs.
//!
/// ## Example usage
///
/// ```
/// # use dcrypt_internal::random::ChaCha20Rng;
/// use dcrypt_algorithms::kdf::{TypedHkdf, KeyDerivationFunction, KdfOperation};
/// use dcrypt_algorithms::hash::Sha256;
///
/// // Create KDF instance
/// let kdf = TypedHkdf::<Sha256>::new();
///
/// // Generate a random salt
/// let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
/// let salt = TypedHkdf::<Sha256>::generate_salt(&mut rng).unwrap();
///
/// // Traditional API
/// let key1 = kdf.derive_key(
///     b"password123",
///     Some(salt.as_ref()),
///     Some(b"context info"),
///     32
/// ).unwrap();
///
/// // Operation pattern API
/// let key2 = kdf.builder()
///     .with_ikm(b"password123")
///     .with_salt(salt.as_ref())
///     .with_info(b"context info")
///     .with_output_length(32)
///     .derive().unwrap();
///
/// // Derive to fixed-size array
/// let key3: dcrypt_internal::zeroing::Zeroizing<[u8; 32]> = kdf.builder()
///     .with_ikm(b"password123")
///     .with_salt(salt.as_ref())
///     .with_info(b"context info")
///     .derive_array().unwrap();
///
/// assert_eq!(key1, key2);
/// assert_eq!(&key1[..], &key3[..]);
/// ```
// Conditional imports for no_std
#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;

#[cfg(feature = "std")]
use std::time::Duration;

#[cfg(not(feature = "std"))]
use core::time::Duration;

use ::core::marker::PhantomData;
use dcrypt_internal::random::{CryptoRng, RngCore};
#[cfg(feature = "alloc")]
use dcrypt_internal::zeroing::{Zeroizing, ZeroizingBytes};

// Import the new error types
use crate::error::{Error, Result};
use crate::hash::HashFunction;
use crate::types::Salt;
use dcrypt_internal::zeroing::Zeroize;

pub mod common;
pub mod params;

#[cfg(feature = "alloc")]
pub mod hkdf;

#[cfg(feature = "alloc")]
pub mod pbkdf2;

#[cfg(feature = "alloc")]
pub mod argon2;

pub use common::SecurityLevel;
pub use params::{ParamProvider, PasswordHash};

// Re-exports for convenience
#[cfg(feature = "alloc")]
pub use hkdf::Hkdf;

#[cfg(feature = "alloc")]
pub use pbkdf2::{Pbkdf2, Pbkdf2Params};

#[cfg(feature = "alloc")]
pub use argon2::{Algorithm as Argon2Type, Argon2, Params as Argon2Params};

/// Marker trait for KDF algorithms
pub trait KdfAlgorithm {
    /// Minimum salt size in bytes
    const MIN_SALT_SIZE: usize;

    /// Default output size in bytes
    const DEFAULT_OUTPUT_SIZE: usize;

    /// Static algorithm identifier for compile-time checking
    const ALGORITHM_ID: &'static str;

    /// Returns the KDF algorithm name
    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }

    /// Security level provided by this KDF
    fn security_level() -> SecurityLevel;
}

/// Operation for KDF operations with improved type safety
pub trait KdfOperation<'a, A: KdfAlgorithm, T = ZeroizingBytes>: Sized {
    /// Set the input keying material
    fn with_ikm(self, ikm: &'a [u8]) -> Self;

    /// Set the salt
    fn with_salt(self, salt: &'a [u8]) -> Self;

    /// Set the info/context data
    fn with_info(self, info: &'a [u8]) -> Self;

    /// Set the desired output length
    fn with_output_length(self, length: usize) -> Self;

    /// Execute the key derivation
    fn derive(self) -> Result<T>;

    /// Execute the key derivation into a fixed-size array
    fn derive_array<const N: usize>(self) -> Result<Zeroizing<[u8; N]>>;
}

/// Common trait for all key derivation functions
pub trait KeyDerivationFunction {
    /// The algorithm this KDF implements
    type Algorithm: KdfAlgorithm;

    /// Salt type with appropriate validation
    type Salt: AsRef<[u8]> + AsMut<[u8]> + Clone;

    /// Creates a new instance of the KDF with default parameters
    fn new() -> Self;

    /// Derives a key using the KDF parameters
    ///
    /// # Arguments
    /// * `input` - Input keying material
    /// * `salt` - Optional salt value
    /// * `info` - Optional context and application-specific information
    /// * `length` - Length of the output key in bytes
    ///
    /// # Returns
    /// The derived key in exact-size, zeroizing storage.
    #[cfg(feature = "alloc")]
    fn derive_key(
        &self,
        input: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        length: usize,
    ) -> Result<ZeroizingBytes>;

    /// Creates a builder for fluent API usage - FIXED: Elided lifetime
    fn builder(&self) -> impl KdfOperation<'_, Self::Algorithm>
    where
        Self: Sized;

    /// Returns the security level of the KDF in bits
    fn security_level() -> SecurityLevel {
        Self::Algorithm::security_level()
    }

    /// Generate a random salt with appropriate size
    fn generate_salt<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Salt>;
}

/// Type-level constants for HKDF algorithm
pub enum HkdfAlgorithm<H: HashFunction> {
    /// Phantom field for the hash function
    _Hash(PhantomData<H>),
}

impl<H: HashFunction> KdfAlgorithm for HkdfAlgorithm<H> {
    const MIN_SALT_SIZE: usize = 16;
    const DEFAULT_OUTPUT_SIZE: usize = 32;
    const ALGORITHM_ID: &'static str = "HKDF";

    fn name() -> String {
        format!("{}-{}", Self::ALGORITHM_ID, H::name())
    }

    fn security_level() -> SecurityLevel {
        match H::output_size() * 8 {
            bits if bits >= 512 => SecurityLevel::L256,
            bits if bits >= 384 => SecurityLevel::L192,
            bits if bits >= 256 => SecurityLevel::L128,
            bits => SecurityLevel::Custom(bits as u32 / 2),
        }
    }
}

/// Enhanced HKDF implementation with type-level guarantees
#[cfg(feature = "alloc")]
pub struct TypedHkdf<H: HashFunction + Clone> {
    inner: hkdf::Hkdf<H, 16>, // Use default size of 16
    _phantom: PhantomData<H>,
}

#[cfg(feature = "alloc")]
impl<H: HashFunction + Clone> KeyDerivationFunction for TypedHkdf<H> {
    type Algorithm = HkdfAlgorithm<H>;
    type Salt = Salt<16>; // Updated to use generic Salt with size

    fn new() -> Self {
        Self {
            inner: hkdf::Hkdf::<H, 16>::new(),
            _phantom: PhantomData,
        }
    }

    #[cfg(feature = "alloc")]
    fn derive_key(
        &self,
        input: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        length: usize,
    ) -> Result<ZeroizingBytes> {
        self.inner.derive_key(input, salt, info, length)
    }

    // FIXED: Elided lifetime
    fn builder(&self) -> impl KdfOperation<'_, Self::Algorithm> {
        HKdfOperation {
            kdf: self,
            ikm: None,
            salt: None,
            info: None,
            length: Self::Algorithm::DEFAULT_OUTPUT_SIZE,
        }
    }

    // FIXED: Removed unnecessary let binding
    fn generate_salt<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Salt> {
        Salt::random_with_size(rng, Self::Algorithm::MIN_SALT_SIZE)
    }
}

/// HKDF builder implementation
#[cfg(feature = "alloc")]
pub struct HKdfOperation<'a, H: HashFunction + Clone> {
    kdf: &'a TypedHkdf<H>,
    ikm: Option<&'a [u8]>,
    salt: Option<&'a [u8]>,
    info: Option<&'a [u8]>,
    length: usize,
}

#[cfg(feature = "alloc")]
impl<'a, H: HashFunction + Clone> KdfOperation<'a, HkdfAlgorithm<H>> for HKdfOperation<'a, H> {
    fn with_ikm(mut self, ikm: &'a [u8]) -> Self {
        self.ikm = Some(ikm);
        self
    }

    fn with_salt(mut self, salt: &'a [u8]) -> Self {
        self.salt = Some(salt);
        self
    }

    fn with_info(mut self, info: &'a [u8]) -> Self {
        self.info = Some(info);
        self
    }

    fn with_output_length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }

    fn derive(self) -> Result<ZeroizingBytes> {
        let ikm = self
            .ikm
            .ok_or_else(|| Error::param("ikm", "Input keying material is required"))?;

        self.kdf.derive_key(ikm, self.salt, self.info, self.length)
    }

    fn derive_array<const N: usize>(self) -> Result<Zeroizing<[u8; N]>> {
        // Ensure the requested size matches
        if self.length != N {
            return Err(Error::Length {
                context: "HKDF output",
                expected: N,
                actual: self.length,
            });
        }

        let vec = self.derive()?;

        // Convert to fixed-size array
        let mut array = Zeroizing::new([0u8; N]);
        array.copy_from_slice(&vec);
        Ok(array)
    }
}

/// Type-level constants for PBKDF2 algorithm
pub enum Pbkdf2Algorithm<H: HashFunction> {
    /// Phantom field for the hash function
    _Hash(PhantomData<H>),
}

impl<H: HashFunction> KdfAlgorithm for Pbkdf2Algorithm<H> {
    const MIN_SALT_SIZE: usize = 16;
    const DEFAULT_OUTPUT_SIZE: usize = 32;
    const ALGORITHM_ID: &'static str = "PBKDF2";

    fn name() -> String {
        format!("{}-{}", Self::ALGORITHM_ID, H::name())
    }

    fn security_level() -> SecurityLevel {
        // PBKDF2 security depends on iterations and hash size
        match H::output_size() * 8 {
            bits if bits >= 512 => SecurityLevel::L128, // Conservative estimate
            bits if bits >= 384 => SecurityLevel::L128,
            bits if bits >= 256 => SecurityLevel::L128,
            bits => SecurityLevel::Custom(bits as u32 / 2),
        }
    }
}

/// Enhanced PBKDF2 implementation with type-level guarantees
#[cfg(feature = "alloc")]
pub struct TypedPbkdf2<H: HashFunction + Clone> {
    inner: pbkdf2::Pbkdf2<H, 16>, // Use default size of 16
    _phantom: PhantomData<H>,
}

#[cfg(feature = "alloc")]
impl<H: HashFunction + Clone> KeyDerivationFunction for TypedPbkdf2<H> {
    type Algorithm = Pbkdf2Algorithm<H>;
    type Salt = Salt<16>; // Updated to use generic Salt with size

    fn new() -> Self {
        Self {
            inner: pbkdf2::Pbkdf2::<H, 16>::new(),
            _phantom: PhantomData,
        }
    }

    #[cfg(feature = "alloc")]
    fn derive_key(
        &self,
        input: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        length: usize,
    ) -> Result<ZeroizingBytes> {
        self.inner.derive_key(input, salt, info, length)
    }

    // FIXED: Elided lifetime
    fn builder(&self) -> impl KdfOperation<'_, Self::Algorithm> {
        Pbkdf2Builder {
            kdf: self,
            password: None,
            salt: None,
            iterations: 600_000, // OWASP recommended minimum
            length: Self::Algorithm::DEFAULT_OUTPUT_SIZE,
        }
    }

    // FIXED: Removed unnecessary let binding
    fn generate_salt<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Salt> {
        Salt::random_with_size(rng, Self::Algorithm::MIN_SALT_SIZE)
    }
}

/// PBKDF2 builder implementation
#[cfg(feature = "alloc")]
pub struct Pbkdf2Builder<'a, H: HashFunction + Clone> {
    kdf: &'a TypedPbkdf2<H>,
    password: Option<&'a [u8]>,
    salt: Option<&'a [u8]>,
    iterations: u32,
    length: usize,
}

// FIXED: Elided lifetime in impl block
#[cfg(feature = "alloc")]
impl<H: HashFunction + Clone> Pbkdf2Builder<'_, H> {
    /// Set the number of iterations
    pub fn with_iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }
}

#[cfg(feature = "alloc")]
impl<'a, H: HashFunction + Clone> KdfOperation<'a, Pbkdf2Algorithm<H>> for Pbkdf2Builder<'a, H> {
    fn with_ikm(mut self, password: &'a [u8]) -> Self {
        self.password = Some(password);
        self
    }

    fn with_salt(mut self, salt: &'a [u8]) -> Self {
        self.salt = Some(salt);
        self
    }

    fn with_info(self, _info: &'a [u8]) -> Self {
        // PBKDF2 doesn't use info, but we implement for API compatibility
        self
    }

    fn with_output_length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }

    fn derive(self) -> Result<ZeroizingBytes> {
        let password = self
            .password
            .ok_or_else(|| Error::param("password", "Password is required"))?;
        let salt = self
            .salt
            .ok_or_else(|| Error::param("salt", "Salt is required"))?;

        // Adjust inner Pbkdf2Params
        let mut params = self.kdf.inner.params().clone();
        params.iterations = self.iterations;
        params.key_length = self.length;

        // Use inner implementation
        let mut kdf = self.kdf.inner.clone();
        kdf.set_params(params);

        kdf.derive_key(password, Some(salt), None, self.length)
    }

    fn derive_array<const N: usize>(self) -> Result<Zeroizing<[u8; N]>> {
        // Ensure the requested size matches
        if self.length != N {
            return Err(Error::Length {
                context: "PBKDF2 output",
                expected: N,
                actual: self.length,
            });
        }

        let vec = self.derive()?;

        // Convert to fixed-size array
        let mut array = Zeroizing::new([0u8; N]);
        array.copy_from_slice(&vec);
        Ok(array)
    }
}

/// Trait for password hashing functions with type-level guarantees
pub trait PasswordHashFunction: KeyDerivationFunction + ParamProvider {
    /// Password type with zeroizing
    type Password: AsRef<[u8]> + AsMut<[u8]> + Clone + Zeroize;

    /// Hashes a password with the configured parameters
    fn hash_password(&self, password: &Self::Password) -> Result<PasswordHash>;

    /// Verifies a password against a hash
    fn verify(&self, password: &Self::Password, hash: &PasswordHash) -> Result<bool>;

    /// Benchmarks the current parameters on this system
    fn benchmark(&self) -> Duration;

    /// Recommends parameters based on a target duration
    fn recommended_params(target_duration: Duration) -> Self::Params;
}
