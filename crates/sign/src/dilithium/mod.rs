// File: crates/sign/src/pq/dilithium/mod.rs
//! Dilithium Digital Signature Algorithm (as per FIPS 204)
//!
//! This module provides high-level implementations for Dilithium2, Dilithium3, and Dilithium5,
//! which are lattice-based digital signature schemes standardized by NIST.
//!
//! The core cryptographic logic relies on polynomial arithmetic over rings, specific sampling
//! distributions (Centered Binomial Distribution, uniform bounded for `y`, sparse ternary for `c`),
//! and cryptographic hash functions (SHA3, SHAKE) provided by the `dcrypt-algorithms` crate.
//! The security of Dilithium is based on the hardness of the Module Learning With Errors (MLWE)
//! and Module Short Integer Solution (MSIS) problems over polynomial rings.
//!
//! The signing process employs the Fiat-Shamir with Aborts paradigm to achieve security
//! against chosen message attacks.
//!
//! This module defines the public API for Dilithium, conforming to the `dcrypt-api::Signature` trait.
//! Detailed implementations of internal operations are found in submodules:
//! - `polyvec.rs`: Defines `PolyVecL`, `PolyVecK` and Dilithium-specific polynomial vector operations.
//! - `arithmetic.rs`: Implements crucial arithmetic functions like `Power2Round`, `Decompose`,
//!   `MakeHint`, `UseHint`, and coefficient norm checking.
//! - `sampling.rs`: Implements Dilithium-specific sampling procedures for secret polynomials,
//!   the masking vector `y`, and the challenge polynomial `c`.
//! - `encoding.rs`: Handles the precise serialization and deserialization formats for public keys,
//!   secret keys, and signatures as specified by FIPS 204.
//! - `sign.rs`: Contains the core `keypair_internal`, `sign_internal`, and `verify_internal` logic.

use crate::error::Error as SignError;
use core::marker::PhantomData;
use dcrypt_api::{Result as ApiResult, Signature as SignatureTrait};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Internal modules for Dilithium logic
mod arithmetic;
mod encoding;
mod polyvec;
mod sampling;
mod sign;

// Import what we need for public key reconstruction
use arithmetic::power2round_polyvec;
use polyvec::{expand_matrix_a, matrix_polyvecl_mul};

// Make encoding functions accessible for serialization
use encoding::{unpack_public_key, unpack_secret_key, unpack_signature};

// Re-export from params crate for easy access to DilithiumNParams structs.
// These structs from `dcrypt-params` hold the specific numerical parameters (K, L, eta, gamma1, etc.)
// that define each Dilithium security level.
use dcrypt_params::pqc::dilithium::{
    Dilithium2Params, Dilithium3Params, Dilithium5Params, DilithiumSchemeParams,
};

// --- Public Key, Secret Key, Signature Data Wrapper Structs ---
// These structs wrap byte vectors (`Vec<u8>`) that store the serialized representations
// of the cryptographic objects. They provide a type-safe interface at the API boundary.

/// Dilithium Public Key.
///
/// Stores the packed representation of `(rho, t1)`.
/// - `rho`: A 32-byte seed used to deterministically generate the matrix A.
/// - `t1`: A vector of K polynomials, where each coefficient is the high-order bits
///   of `t_i = (A*s1)_i + (s2)_i`. Packed according to `P::D_PARAM` bits.
#[derive(Clone, Debug, Zeroize)]
pub struct DilithiumPublicKey(pub(crate) Vec<u8>);

/// Dilithium Secret Key.
///
/// Stores the FIPS 204 compliant packed representation of `(rho, K, tr, s1, s2, t0)`.
/// This implementation follows the standard FIPS 204 format exclusively.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct DilithiumSecretKey(Vec<u8>);

/// Dilithium Signature Data.
///
/// Stores the packed representation of `(c_tilde, z, h)`.
/// - `c_tilde`: A short seed from which the challenge polynomial `c` is derived.
/// - `z`: A vector of L polynomials, `z = y + c*s1`.
/// - `h`: A hint vector indicating which coefficients required correction during verification.
#[derive(Clone, Debug)]
pub struct DilithiumSignatureData(pub(crate) Vec<u8>);

// AsRef/AsMut implementations allow access to the raw byte data.
impl AsRef<[u8]> for DilithiumPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for DilithiumPublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl AsRef<[u8]> for DilithiumSignatureData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for DilithiumSignatureData {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

// --- DilithiumSecretKey Implementation ---

impl AsRef<[u8]> for DilithiumSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// NOTE: AsMut<[u8]> implementation removed for security reasons.
// Use from_bytes() and to_bytes() for safe secret key manipulation.

impl DilithiumSecretKey {
    /// Create from FIPS 204 format bytes
    ///
    /// The secret key must be in the standard FIPS 204 format which includes
    /// the tr component and appropriate padding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        // Validate that the size matches one of the standard FIPS 204 sizes
        match bytes.len() {
            2560 => {} // Dilithium2 FIPS 204 format
            4032 => {} // Dilithium3 FIPS 204 format
            4896 => {} // Dilithium5 FIPS 204 format
            _ => {
                return Err(SignError::Deserialization(format!(
                    "Invalid FIPS 204 secret key size: {} bytes",
                    bytes.len()
                )))
            }
        };

        // Basic validation by attempting to unpack
        match bytes.len() {
            2560 => {
                let _ = unpack_secret_key::<Dilithium2Params>(bytes)?;
            }
            4032 => {
                let _ = unpack_secret_key::<Dilithium3Params>(bytes)?;
            }
            4896 => {
                let _ = unpack_secret_key::<Dilithium5Params>(bytes)?;
            }
            _ => unreachable!(),
        }

        Ok(Self(bytes.to_vec()))
    }

    /// Get the serialized bytes of this secret key (FIPS 204 format)
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Extract the public key from this secret key
    pub fn public_key(&self) -> Result<DilithiumPublicKey, SignError> {
        match self.0.len() {
            2560 => {
                let (rho, _, _, s1, s2, _) = unpack_secret_key::<Dilithium2Params>(&self.0)?;
                let pk_bytes = reconstruct_public_key::<Dilithium2Params>(&rho, &s1, &s2)?;
                Ok(DilithiumPublicKey(pk_bytes))
            }
            4032 => {
                let (rho, _, _, s1, s2, _) = unpack_secret_key::<Dilithium3Params>(&self.0)?;
                let pk_bytes = reconstruct_public_key::<Dilithium3Params>(&rho, &s1, &s2)?;
                Ok(DilithiumPublicKey(pk_bytes))
            }
            4896 => {
                let (rho, _, _, s1, s2, _) = unpack_secret_key::<Dilithium5Params>(&self.0)?;
                let pk_bytes = reconstruct_public_key::<Dilithium5Params>(&rho, &s1, &s2)?;
                Ok(DilithiumPublicKey(pk_bytes))
            }
            _ => unreachable!(),
        }
    }
}

// Helper function to reconstruct public key from secret key components
fn reconstruct_public_key<P: DilithiumSchemeParams>(
    rho: &[u8; 32],
    s1: &polyvec::PolyVecL<P>,
    s2: &polyvec::PolyVecK<P>,
) -> Result<Vec<u8>, SignError> {
    // Expand matrix A from rho
    let matrix_a = expand_matrix_a::<P>(rho)?;

    // Convert to NTT domain
    let mut matrix_a_hat = Vec::with_capacity(P::K_DIM);
    for row in matrix_a {
        let mut row_ntt = row;
        row_ntt.ntt_inplace().map_err(SignError::from_algo)?;
        matrix_a_hat.push(row_ntt);
    }

    let mut s1_hat = s1.clone();
    s1_hat.ntt_inplace().map_err(SignError::from_algo)?;

    let mut s2_hat = s2.clone();
    s2_hat.ntt_inplace().map_err(SignError::from_algo)?;

    // t = As1 + s2
    let mut t_hat = matrix_polyvecl_mul(&matrix_a_hat, &s1_hat);
    t_hat = t_hat.add(&s2_hat);

    // Convert back to standard domain
    let mut t = t_hat;
    t.inv_ntt_inplace().map_err(SignError::from_algo)?;

    // Get t1 using Power2Round
    let (_, t1) = power2round_polyvec(&t, P::D_PARAM);

    // Pack public key
    encoding::pack_public_key::<P>(rho, &t1)
}

// --- Serialization/Deserialization Methods ---

impl DilithiumPublicKey {
    /// Deserialize a public key from bytes with full validation
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        // Determine parameter set from key size and validate
        match bytes.len() {
            n if n == Dilithium2Params::PUBLIC_KEY_BYTES => {
                let _ = unpack_public_key::<Dilithium2Params>(bytes)?;
            }
            n if n == Dilithium3Params::PUBLIC_KEY_BYTES => {
                let _ = unpack_public_key::<Dilithium3Params>(bytes)?;
            }
            n if n == Dilithium5Params::PUBLIC_KEY_BYTES => {
                let _ = unpack_public_key::<Dilithium5Params>(bytes)?;
            }
            _ => {
                return Err(SignError::Deserialization(format!(
                    "Invalid public key size: {} bytes",
                    bytes.len()
                )))
            }
        }

        Ok(Self(bytes.to_vec()))
    }

    /// Get the serialized bytes of this public key
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl DilithiumSignatureData {
    /// Deserialize a signature from bytes with full validation
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        // Determine parameter set from signature size and validate
        match bytes.len() {
            n if n == Dilithium2Params::SIGNATURE_SIZE => {
                let _ = unpack_signature::<Dilithium2Params>(bytes)?;
            }
            n if n == Dilithium3Params::SIGNATURE_SIZE => {
                let _ = unpack_signature::<Dilithium3Params>(bytes)?;
            }
            n if n == Dilithium5Params::SIGNATURE_SIZE => {
                let _ = unpack_signature::<Dilithium5Params>(bytes)?;
            }
            _ => {
                return Err(SignError::Deserialization(format!(
                    "Invalid signature size: {} bytes",
                    bytes.len()
                )))
            }
        }

        Ok(Self(bytes.to_vec()))
    }

    /// Get the serialized bytes of this signature
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Generic Dilithium signature structure parameterized by `P: DilithiumSchemeParams`.
pub struct Dilithium<P: DilithiumSchemeParams + 'static> {
    _params: PhantomData<P>,
}

// --- Implement api::Signature for Dilithium<P> ---
impl<P: DilithiumSchemeParams + Send + Sync + 'static> SignatureTrait for Dilithium<P> {
    type PublicKey = DilithiumPublicKey;
    type SecretKey = DilithiumSecretKey;
    type SignatureData = DilithiumSignatureData;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        P::NAME
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (pk_bytes, sk_bytes) =
            sign::keypair_internal::<P, R>(rng).map_err(dcrypt_api::Error::from)?;
        let sk = DilithiumSecretKey::from_bytes(&sk_bytes).map_err(dcrypt_api::Error::from)?;
        Ok((DilithiumPublicKey(pk_bytes), sk))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }
    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn sign(message: &[u8], secret_key: &Self::SecretKey) -> ApiResult<Self::SignatureData> {
        let mut rng = rand::rngs::OsRng;
        let sig_bytes = sign::sign_internal::<P, _>(message, &secret_key.0, &mut rng)
            .map_err(dcrypt_api::Error::from)?;
        Ok(DilithiumSignatureData(sig_bytes))
    }

    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> ApiResult<()> {
        sign::verify_internal::<P>(message, &signature.0, &public_key.0)
            .map_err(dcrypt_api::Error::from)
    }
}

// Concrete types for different Dilithium levels
pub type Dilithium2 = Dilithium<Dilithium2Params>;
pub type Dilithium3 = Dilithium<Dilithium3Params>;
pub type Dilithium5 = Dilithium<Dilithium5Params>;

#[cfg(test)]
mod tests;
