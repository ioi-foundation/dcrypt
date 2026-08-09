// crates/kem/src/kyber/kem.rs

//! Core Kyber KEM logic using the `api::Kem` trait.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::Error as KemError; // KEM-specific errors
use core::marker::PhantomData;
use dcrypt_algorithms::error::Error as AlgoError;
use dcrypt_api::{
    error::Error as ApiError,
    traits::serialize::{Serialize, SerializeSecret},
    Kem as KemTrait, Key as ApiKey, Result as ApiResult,
};
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::Zeroizing;

use super::ind_cca::{kem_decaps, kem_encaps, kem_keygen};
use super::params::KyberParams; // IND-CCA2 scheme components

/// Kyber Public Key (byte representation).
///
/// # Security Note
/// No direct byte access is provided. Use explicit methods for serialization.
#[derive(Clone, Debug)]
pub struct KyberPublicKey(Vec<u8>);

impl_zeroize_tuple!(KyberPublicKey);

impl KyberPublicKey {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Ok(Self(bytes.to_vec()))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl Serialize for KyberPublicKey {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

/// Kyber Secret Key (byte representation).
///
/// # Security Note
/// - Implements Zeroize for secure cleanup
/// - No direct byte access through traits
/// - All access must be explicit and auditable
#[derive(Clone, Debug)]
pub struct KyberSecretKey(Vec<u8>);

impl_zeroize_on_drop_tuple!(KyberSecretKey);

impl KyberSecretKey {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Ok(Self(bytes.to_vec()))
    }
    pub fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.clone())
    }
}

impl SerializeSecret for KyberSecretKey {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        self.to_bytes_zeroizing()
    }
}

/// Kyber Ciphertext (byte representation).
///
/// # Security Note
/// No direct byte access prevents tampering.
#[derive(Clone, Debug)]
pub struct KyberCiphertext(Vec<u8>);

impl KyberCiphertext {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Ok(Self(bytes.to_vec()))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl Serialize for KyberCiphertext {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

/// Kyber Shared Secret.
///
/// # Security Note
/// - Implements Zeroize for secure cleanup
/// - No direct byte access through traits
/// - Should be used immediately for key derivation
#[derive(Clone)]
pub struct KyberSharedSecret(ApiKey);

impl_zeroize_on_drop_tuple!(KyberSharedSecret);

impl KyberSharedSecret {
    pub fn new(key: ApiKey) -> Self {
        Self(key)
    }
    pub fn to_key(&self) -> ApiKey {
        self.0.clone()
    }
    pub fn len(&self) -> usize {
        self.0.as_ref().len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
    pub fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

impl SerializeSecret for KyberSharedSecret {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Ok(Self(ApiKey::new(bytes)))
    }
    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        self.to_bytes_zeroizing()
    }
}

impl core::fmt::Debug for KyberSharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KyberSharedSecret")
            .field("length", &self.len())
            .finish()
    }
}

/// Generic Kyber KEM structure parameterized by KyberParams.
pub struct KyberKem<P: KyberParams> {
    _params: PhantomData<P>,
}

impl<P: KyberParams> KemTrait for KyberKem<P> {
    type PublicKey = KyberPublicKey;
    type SecretKey = KyberSecretKey;
    type SharedSecret = KyberSharedSecret;
    type Ciphertext = KyberCiphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        P::NAME
    }

    fn keypair<R: RngCore + CryptoRng>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (pk_bytes, sk_bytes) =
            kem_keygen::<P, R>(rng).map_err(|algo_err| ApiError::from(KemError::from(algo_err)))?;
        Ok((KyberPublicKey::new(pk_bytes), KyberSecretKey::new(sk_bytes)))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn encapsulate<R: RngCore + CryptoRng>(
        rng: &mut R,
        public_key: &Self::PublicKey,
    ) -> ApiResult<(Self::Ciphertext, Self::SharedSecret)> {
        if public_key.as_bytes().len() != P::PUBLIC_KEY_BYTES {
            return Err(ApiError::InvalidKey {
                context: "Kyber public key",
                #[cfg(feature = "std")]
                message: format!(
                    "Incorrect length: expected {}, got {}",
                    P::PUBLIC_KEY_BYTES,
                    public_key.as_bytes().len()
                ),
            });
        }

        let (ct_bytes, ss_bytes_fixed) = kem_encaps::<P, R>(&public_key.0, rng)
            .map_err(|algo_err| ApiError::from(KemError::from(algo_err)))?;

        Ok((
            KyberCiphertext::new(ct_bytes),
            KyberSharedSecret::new(ApiKey::new(ss_bytes_fixed.as_ref())),
        ))
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        if secret_key.as_bytes().len() != P::SECRET_KEY_BYTES {
            return Err(ApiError::InvalidKey {
                context: "Kyber secret key",
                #[cfg(feature = "std")]
                message: format!(
                    "Incorrect length: expected {}, got {}",
                    P::SECRET_KEY_BYTES,
                    secret_key.as_bytes().len()
                ),
            });
        }
        if ciphertext.as_bytes().len() != P::CIPHERTEXT_BYTES {
            return Err(ApiError::InvalidCiphertext {
                context: "Kyber ciphertext",
                #[cfg(feature = "std")]
                message: format!(
                    "Incorrect length: expected {}, got {}",
                    P::CIPHERTEXT_BYTES,
                    ciphertext.as_bytes().len()
                ),
            });
        }

        let ss_bytes_fixed =
            kem_decaps::<P>(&secret_key.0, &ciphertext.0).map_err(|algo_err| match algo_err {
                AlgoError::Processing { .. } => ApiError::DecryptionFailed {
                    context: P::NAME,
                    #[cfg(feature = "std")]
                    message: "Decapsulation failed".into(),
                },
                _ => ApiError::from(KemError::from(algo_err)),
            })?;

        Ok(KyberSharedSecret::new(ApiKey::new(ss_bytes_fixed.as_ref())))
    }
}
