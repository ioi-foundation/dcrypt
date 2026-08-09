//! HMAC-based Key Derivation Function (HKDF)
//!
//! This module implements HKDF as defined in RFC 5869.
//! HKDF is designed to take input keying material (IKM) that is not necessarily
//! uniform and produce output keying material (OKM) suitable for use in cryptographic
//! contexts.

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;

use crate::error::{validate, Error, Result};
use crate::hash::HashFunction;
use crate::kdf::{KdfAlgorithm, KdfOperation, KeyDerivationFunction, ParamProvider, SecurityLevel};
use crate::mac::hmac::Hmac;
use crate::types::salt::HkdfCompatible;
use crate::types::Salt;

// Import security types from dcrypt-core
use dcrypt_common::security::{EphemeralSecret, SecureZeroingType};

use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::marker::PhantomData;

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

/// Parameters for HKDF
#[derive(Clone, Debug)]
pub struct HkdfParams<const S: usize = 16> {
    /// Optional default salt (can be overridden in derive_key)
    pub salt: Option<Salt<S>>,
    /// Optional default info (context, can be overridden in derive_key)
    pub info: Option<Zeroizing<Vec<u8>>>,
}

impl<const S: usize> Zeroize for HkdfParams<S> {
    fn zeroize(&mut self) {
        self.salt.zeroize();
        self.info.zeroize();
    }
}

impl<const S: usize> Default for HkdfParams<S> {
    fn default() -> Self {
        Self {
            salt: None,
            info: None,
        }
    }
}

/// HKDF implementation using any hash function
#[derive(Clone)]
pub struct Hkdf<H: HashFunction, const S: usize = 16> {
    _hash_type: PhantomData<H>,
    params: HkdfParams<S>,
}

impl<H: HashFunction, const S: usize> Zeroize for Hkdf<H, S> {
    fn zeroize(&mut self) {
        self.params.zeroize();
    }
}

impl<H: HashFunction, const S: usize> Drop for Hkdf<H, S> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<H: HashFunction, const S: usize> ZeroizeOnDrop for Hkdf<H, S> {}

/// Operation for HKDF operations
pub struct HkdfOperation<'a, H: HashFunction, const S: usize = 16> {
    #[allow(dead_code)] // Kept for potential future use and API consistency
    kdf: &'a Hkdf<H, S>,
    ikm: Option<&'a [u8]>,
    salt: Option<&'a [u8]>,
    info: Option<&'a [u8]>,
    length: usize,
}

impl<'a, H: HashFunction + Clone, const S: usize> KdfOperation<'a, HkdfAlgorithm<H>>
    for HkdfOperation<'a, H, S>
where
    Salt<S>: HkdfCompatible,
{
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

    fn derive(self) -> Result<Vec<u8>> {
        let ikm = self
            .ikm
            .ok_or_else(|| Error::param("ikm", "Input keying material is required"))?;

        let salt_bytes = self.salt;
        let info_bytes = self.info;

        // Fix: Convert Zeroizing<Vec<u8>> to Vec<u8>
        Hkdf::<H, S>::derive(salt_bytes, ikm, info_bytes, self.length).map(|result| result.to_vec())
    }

    fn derive_array<const N: usize>(self) -> Result<[u8; N]> {
        // Ensure the requested size matches
        validate::length("HKDF output", self.length, N)?;

        let vec = self.derive()?;

        // Convert to fixed-size array
        let mut array = [0u8; N];
        array.copy_from_slice(&vec);
        Ok(array)
    }
}

impl<H: HashFunction + Clone, const S: usize> Hkdf<H, S>
where
    Salt<S>: HkdfCompatible,
{
    /// HKDF-Extract
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        // Convert salt to owned Vec to wrap in EphemeralSecret
        let salt_vec = salt.unwrap_or(&[]).to_vec();
        let secure_salt = EphemeralSecret::new(salt_vec);

        // Use HMAC with secure salt
        let result = Hmac::<H>::mac(&secure_salt, ikm)?;
        Ok(Zeroizing::new(result))
    }

    /// HKDF-Expand
    pub fn expand(prk: &[u8], info: Option<&[u8]>, length: usize) -> Result<Zeroizing<Vec<u8>>> {
        let hash_len = H::output_size();
        let max_len = 255 * hash_len;

        // Specified max-length check (length is public)
        validate::max_length("HKDF-Expand output", length, max_len)?;

        // PRK length check (must be at least one hash block)
        validate::min_length("PRK for HKDF-Expand", prk.len(), hash_len)?;

        // Number of blocks needed - FIXED: Using div_ceil
        let n = length.div_ceil(hash_len);

        // Pre-allocate OKM buffer and temporary block buffer
        let mut okm = Zeroizing::new(vec![0u8; n * hash_len]);
        let mut t_buf = Zeroizing::new(vec![0u8; hash_len]);
        let info_bytes = info.unwrap_or(&[]);

        // Convert PRK to owned Vec to wrap in EphemeralSecret
        let prk_vec = prk.to_vec();
        let secure_prk = EphemeralSecret::new(prk_vec);

        for i in 1..=n {
            let mut hmac = Hmac::<H>::new(&secure_prk)?;
            if i > 1 {
                // feed previous block for iterations > 1
                hmac.update(&t_buf)?;
            }
            hmac.update(info_bytes)?;
            hmac.update(&[i as u8])?;
            let block = hmac.finalize()?;
            t_buf.copy_from_slice(&block);
            let start = (i - 1) * hash_len;
            okm[start..start + hash_len].copy_from_slice(&t_buf);
        }

        okm.truncate(length);
        Ok(okm)
    }

    /// Full HKDF (Extract + Expand) with warm-up
    pub fn derive(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: Option<&[u8]>,
        length: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let _ = Hmac::<H>::new(&[])?; // warm-up

        // Extract phase - produces PRK
        let prk = Self::extract(salt, ikm)?;

        // Expand phase - uses PRK to generate OKM
        Self::expand(&prk, info, length)
    }
}

impl<H: HashFunction, const S: usize> ParamProvider for Hkdf<H, S>
where
    Salt<S>: HkdfCompatible,
{
    type Params = HkdfParams<S>;
    fn with_params(params: Self::Params) -> Self {
        Hkdf {
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

impl<H: HashFunction + Clone, const S: usize> KeyDerivationFunction for Hkdf<H, S>
where
    Salt<S>: HkdfCompatible,
{
    type Algorithm = HkdfAlgorithm<H>;
    type Salt = Salt<S>;

    fn new() -> Self {
        Hkdf {
            _hash_type: PhantomData,
            params: HkdfParams::default(),
        }
    }

    fn derive_key(
        &self,
        input: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        length: usize,
    ) -> Result<Vec<u8>> {
        let effective_salt = salt.or_else(|| self.params.salt.as_ref().map(|s| s.as_ref()));
        let effective_info = info.or_else(|| self.params.info.as_ref().map(|i| i.as_slice()));
        let result = Self::derive(effective_salt, input, effective_info, length)?;
        Ok(result.to_vec())
    }

    // FIXED: Elided lifetime
    fn builder(&self) -> impl KdfOperation<'_, Self::Algorithm> {
        HkdfOperation::<H, S> {
            kdf: self,
            ikm: None,
            salt: None,
            info: None,
            length: Self::Algorithm::DEFAULT_OUTPUT_SIZE,
        }
    }

    fn generate_salt<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Salt> {
        Salt::random_with_size(rng, Self::Algorithm::MIN_SALT_SIZE)
    }

    // Changed from instance method to static method
    fn security_level() -> SecurityLevel {
        match H::output_size() * 8 {
            bits if bits >= 512 => SecurityLevel::L256,
            bits if bits >= 384 => SecurityLevel::L192,
            bits if bits >= 256 => SecurityLevel::L128,
            bits => SecurityLevel::Custom(bits as u32 / 2),
        }
    }
}

impl<H: HashFunction + Clone, const S: usize> SecureZeroingType for Hkdf<H, S>
where
    Salt<S>: HkdfCompatible,
{
    fn zeroed() -> Self {
        Self {
            _hash_type: PhantomData,
            params: HkdfParams::default(),
        }
    }

    fn secure_clone(&self) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod tests;
