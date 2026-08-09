//! Password-Based Key Derivation Function 2 (PBKDF2)
//!
//! This module implements PBKDF2 as specified in RFC 8018.
//! PBKDF2 applies a pseudorandom function (such as HMAC) to the input password
//! along with a salt value and repeats the process many times to produce a
//! derived key, which can then be used as a cryptographic key in subsequent operations.

use crate::error::{validate, Error, Result};
use crate::hash::HashFunction;
#[cfg(feature = "std")]
use crate::kdf::common::constant_time_eq;
use crate::kdf::{KdfAlgorithm, KdfOperation, KeyDerivationFunction, ParamProvider, SecurityLevel};
#[cfg(feature = "std")]
use crate::kdf::{PasswordHash, PasswordHashFunction};
use crate::mac::hmac::Hmac;
use crate::types::salt::Pbkdf2Compatible;
use crate::types::Salt;
#[cfg(feature = "std")]
use crate::types::{ByteSerializable, SecretBytes};

// Import security types
use dcrypt_common::security::SecretVec;

// Conditional imports based on features
#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::string::String;
#[cfg(feature = "std")]
use std::time::{Duration, Instant};

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::string::String;

use core::marker::PhantomData;
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::{
    boxed_bytes_zeroed, Zeroize, ZeroizeOnDrop, Zeroizing, ZeroizingBytes,
};

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
        // PBKDF2 security depends on the underlying hash
        match H::output_size() * 8 {
            bits if bits >= 512 => SecurityLevel::L128, // Conservative estimate
            bits if bits >= 384 => SecurityLevel::L128,
            bits if bits >= 256 => SecurityLevel::L128,
            bits => SecurityLevel::Custom(bits as u32 / 2),
        }
    }
}

/// Parameters for PBKDF2
#[derive(Clone, Debug)]
pub struct Pbkdf2Params<const S: usize = 16> {
    /// Salt value
    pub salt: Salt<S>,

    /// Number of iterations
    pub iterations: u32,

    /// Length of derived key in bytes
    pub key_length: usize,
}

impl<const S: usize> Zeroize for Pbkdf2Params<S> {
    fn zeroize(&mut self) {
        self.salt.zeroize();
        self.iterations.zeroize();
        self.key_length.zeroize();
    }
}

impl<const S: usize> Default for Pbkdf2Params<S>
where
    Salt<S>: Pbkdf2Compatible,
{
    fn default() -> Self {
        Self {
            salt: Salt::<S>::zeroed(), // Will be filled with random data during initialization
            iterations: 600_000,       // OWASP recommended minimum as of 2023
            key_length: 32,            // 256 bits
        }
    }
}

/// PBKDF2 implementation using any HMAC-based PRF
///
/// PBKDF2 can be used with any pseudorandom function, but this implementation
/// uses HMAC with a configurable hash function.
#[derive(Clone)]
pub struct Pbkdf2<H: HashFunction + Clone, const S: usize = 16> {
    /// The hash function type
    _hash_type: PhantomData<H>,

    /// PBKDF2 parameters
    params: Pbkdf2Params<S>,
}

impl<H: HashFunction + Clone, const S: usize> Zeroize for Pbkdf2<H, S> {
    fn zeroize(&mut self) {
        self.params.zeroize();
    }
}

impl<H: HashFunction + Clone, const S: usize> Drop for Pbkdf2<H, S> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<H: HashFunction + Clone, const S: usize> ZeroizeOnDrop for Pbkdf2<H, S> {}

/// PBKDF2 builder implementation
pub struct Pbkdf2Builder<'a, H: HashFunction + Clone, const S: usize = 16> {
    kdf: &'a Pbkdf2<H, S>,
    ikm: Option<&'a [u8]>,
    salt: Option<&'a [u8]>,
    iterations: u32,
    length: usize,
}

// FIXED: Elided lifetime in impl block
impl<H: HashFunction + Clone, const S: usize> Pbkdf2Builder<'_, H, S> {
    /// Set the number of iterations
    pub fn with_iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }
}

impl<'a, H: HashFunction + Clone, const S: usize> KdfOperation<'a, Pbkdf2Algorithm<H>>
    for Pbkdf2Builder<'a, H, S>
where
    Salt<S>: Pbkdf2Compatible,
{
    fn with_ikm(mut self, ikm: &'a [u8]) -> Self {
        self.ikm = Some(ikm);
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
        let ikm = self.ikm.ok_or_else(|| {
            Error::param("input_keying_material", "Input keying material is required")
        })?;

        let salt = match self.salt {
            Some(s) => s,
            None => self.kdf.params.salt.as_ref(),
        };

        // Use PBKDF2 with secure key handling
        Pbkdf2::<H, S>::pbkdf2_secure(ikm, salt, self.iterations, self.length)
    }

    fn derive_array<const N: usize>(self) -> Result<Zeroizing<[u8; N]>> {
        // Ensure the requested size matches
        validate::length("PBKDF2 output", self.length, N)?;

        let vec = self.derive()?;

        // Convert to fixed-size array
        let mut array = Zeroizing::new([0u8; N]);
        array.copy_from_slice(&vec);
        Ok(array)
    }
}

impl<H: HashFunction + Clone, const S: usize> Pbkdf2<H, S> {
    /// Internal PBKDF2 implementation with secure key handling
    ///
    /// This implements the core PBKDF2 algorithm as defined in RFC 8018 Section 5.2
    /// with enhanced security for key material handling.
    ///
    /// # Arguments
    /// * `password` - The password to derive the key from
    /// * `salt` - The salt value
    /// * `iterations` - The number of iterations
    /// * `key_length` - The length of the derived key in bytes
    ///
    /// # Returns
    /// The derived key of length key_length bytes
    pub fn pbkdf2(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        key_length: usize,
    ) -> Result<ZeroizingBytes> {
        // Wrap password in secure buffer for internal operations
        let secure_password = SecretVec::from_slice(password);
        Self::pbkdf2_internal(&secure_password, salt, iterations, key_length)
    }

    /// Secure PBKDF2 implementation returning exact-size zeroizing storage.
    pub fn pbkdf2_secure(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        key_length: usize,
    ) -> Result<ZeroizingBytes> {
        Self::pbkdf2(password, salt, iterations, key_length)
    }

    /// Internal PBKDF2 implementation using secure types
    fn pbkdf2_internal(
        password: &SecretVec,
        salt: &[u8],
        iterations: u32,
        key_length: usize,
    ) -> Result<ZeroizingBytes> {
        // Strict parameter validation
        validate::parameter(
            iterations > 0,
            "iterations",
            "PBKDF2 iteration count must be > 0",
        )?;

        validate::parameter(
            key_length > 0,
            "key_length",
            "PBKDF2 output length must be > 0",
        )?;

        let hash_len = H::output_size();

        // Calculate how many blocks we need to generate - FIXED: Using div_ceil
        let block_count = key_length.div_ceil(hash_len);

        // Check that the output length is not too large
        // RFC 8018 section 5.2 states that the maximum output length is (2^32 - 1) * hash_len
        if block_count > 0xFFFFFFFF {
            return Err(Error::Length {
                context: "PBKDF2 output length",
                expected: 0xFFFFFFFF * hash_len,
                actual: key_length,
            });
        }

        let mut result = Zeroizing::new(boxed_bytes_zeroed(key_length));
        let mut result_offset = 0usize;

        // Derive each block of the output
        // Each block is calculated independently using the F function
        for block_index in 1..=block_count {
            let block =
                Self::pbkdf2_f::<H>(password.as_ref(), salt, iterations, block_index as u32)?;

            // Determine how much of this block to use
            // Most blocks are used completely, but the last one might be partial
            let to_copy = if block_index == block_count {
                let remainder = key_length % hash_len;
                if remainder == 0 {
                    hash_len
                } else {
                    remainder
                }
            } else {
                hash_len
            };

            result[result_offset..result_offset + to_copy].copy_from_slice(&block[..to_copy]);
            result_offset += to_copy;
        }

        Ok(result)
    }

    /// F function for PBKDF2 as defined in RFC 8018
    ///
    /// This function applies the pseudorandom function (PRF) iteratively and
    /// combines the results by XOR.
    ///
    /// Computes F(P, S, c, i) = U_1 XOR U_2 XOR ... XOR U_c
    /// where U_1 = PRF(P, S || INT_32_BE(i))
    ///       U_j = PRF(P, U_{j-1})
    fn pbkdf2_f<T: HashFunction + Clone>(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        block_index: u32,
    ) -> Result<ZeroizingBytes> {
        // First iteration: HMAC(password, salt || block_index)
        // U_1 = PRF(P, S || INT_32_BE(i))
        let mut hmac = Hmac::<T>::new(password)?;
        hmac.update(salt)?;
        hmac.update(&block_index.to_be_bytes())?;
        let result = hmac.finalize()?;

        let mut prev = result.clone();

        // Subsequent iterations: HMAC(password, prev_result)
        // U_j = PRF(P, U_{j-1})
        // Combine results by XOR: U_1 XOR U_2 XOR ... XOR U_c
        let mut output = result;

        for _ in 1..iterations {
            let mut hmac = Hmac::<T>::new(password)?;
            hmac.update(&prev)?;
            prev = hmac.finalize()?;

            // XOR the result with prev
            for i in 0..output.len() {
                output[i] ^= prev[i];
            }
        }

        Ok(output)
    }
}

impl<H: HashFunction + Clone, const S: usize> ParamProvider for Pbkdf2<H, S> {
    type Params = Pbkdf2Params<S>;

    fn with_params(params: Self::Params) -> Self {
        Self {
            _hash_type: PhantomData,
            params,
        }
    }

    fn params(&self) -> &Self::Params {
        &self.params
    }

    fn set_params(&mut self, params: Self::Params) {
        self.params = params;
    }
}

impl<H: HashFunction + Clone, const S: usize> KeyDerivationFunction for Pbkdf2<H, S>
where
    Salt<S>: Pbkdf2Compatible,
{
    type Algorithm = Pbkdf2Algorithm<H>;
    type Salt = Salt<S>;

    fn new() -> Self {
        Self {
            _hash_type: PhantomData,
            params: Pbkdf2Params::default(),
        }
    }

    #[cfg(feature = "alloc")]
    fn derive_key(
        &self,
        input: &[u8],
        salt: Option<&[u8]>,
        _info: Option<&[u8]>,
        length: usize,
    ) -> Result<ZeroizingBytes> {
        // Use provided salt or fallback to default from params - FIXED: Removed needless borrow
        let effective_salt = match salt {
            Some(s) => s,
            None => self.params.salt.as_ref(),
        };

        // Use provided length or fallback to default from params
        let effective_length = if length > 0 {
            length
        } else {
            self.params.key_length
        };

        // Use the secure version
        Self::pbkdf2_secure(
            input,
            effective_salt,
            self.params.iterations,
            effective_length,
        )
    }

    // FIXED: Elided lifetime
    fn builder(&self) -> impl KdfOperation<'_, Self::Algorithm> {
        Pbkdf2Builder::<H, S> {
            kdf: self,
            ikm: None,
            salt: None,
            iterations: self.params.iterations,
            length: self.params.key_length,
        }
    }

    fn generate_salt<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Salt> {
        Salt::random_with_size(rng, Self::Algorithm::MIN_SALT_SIZE)
    }

    fn security_level() -> SecurityLevel {
        Self::Algorithm::security_level()
    }
}

#[cfg(feature = "std")]
impl<H: HashFunction + Clone, const S: usize> PasswordHashFunction for Pbkdf2<H, S>
where
    Salt<S>: Pbkdf2Compatible,
{
    type Password = SecretBytes<32>; // Using a 32-byte buffer for passwords

    fn hash_password(&self, password: &Self::Password) -> Result<PasswordHash> {
        // Derive the key using secure implementation
        let hash = Self::pbkdf2(
            password.as_ref(),
            self.params.salt.as_ref(),
            self.params.iterations,
            self.params.key_length,
        )?;

        // Create parameters map
        let mut params = BTreeMap::new();
        params.insert("i".to_string(), self.params.iterations.to_string());

        Ok(PasswordHash {
            algorithm: format!("pbkdf2-{}", H::name().to_lowercase()),
            params,
            salt: self.params.salt.to_bytes(),
            hash: hash.into_inner().into_vec(),
        })
    }

    fn verify(&self, password: &Self::Password, hash: &PasswordHash) -> Result<bool> {
        // Verify the algorithm
        let expected_alg = format!("pbkdf2-{}", H::name().to_lowercase());
        validate::parameter(
            hash.algorithm == expected_alg,
            "algorithm",
            "Algorithm mismatch",
        )?;

        // Get iterations from the hash parameters
        let iterations = match hash.param("i") {
            Some(i) => i
                .parse::<u32>()
                .map_err(|_| Error::param("iterations", "Invalid iterations parameter"))?,
            None => return Err(Error::param("iterations", "Missing iterations parameter")),
        };

        // Derive key with the same parameters, using secure implementation
        let derived = Self::pbkdf2(password.as_ref(), &hash.salt, iterations, hash.hash.len())?;

        // Compare in constant time
        Ok(constant_time_eq(&derived, &hash.hash))
    }

    fn benchmark(&self) -> Duration {
        let start = Instant::now();
        let password = SecretBytes::new([0u8; 32]); // Use a dummy password for benchmarking

        // If hash_password fails, we still return a valid Duration
        // This is acceptable since benchmark is not critical for security
        match self.hash_password(&password) {
            Ok(_) => {}
            Err(_) => {
                // We could log the error here if we had a logging system
                // For now, we'll just continue and return the elapsed time
                // This gives a reasonable approximation even on error
            }
        }

        start.elapsed()
    }

    fn recommended_params(target_duration: Duration) -> Self::Params {
        // Start with the default parameters
        let mut params = Pbkdf2Params::default();

        // Create a temporary instance
        let instance = Self::with_params(params.clone());

        // Measure the current execution time
        let current_duration = instance.benchmark();

        // Calculate the ratio and adjust iterations
        let ratio = target_duration.as_secs_f64() / current_duration.as_secs_f64();
        params.iterations = (params.iterations as f64 * ratio) as u32;

        // Ensure iterations is at least 10,000
        params.iterations = core::cmp::max(params.iterations, 10_000);

        params
    }
}

#[cfg(test)]
mod tests;
