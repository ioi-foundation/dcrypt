// File: crates/kem/src/ecdh/k256/mod.rs
//! ECDH-KEM with secp256k1 (K-256)
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the secp256k1 curve.
//! This is a dcrypt-specific ECDH-plus-HKDF construction, not RFC 9180 HPKE.
//! Invalid inputs return errors. No blanket constant-time or IND-CCA claim is
//! made; arithmetic behavior depends on the backend, compiler, and target.
//!
//! This implementation uses compressed point format for optimal bandwidth efficiency.
//!
//! Public points are validated and the shared point is processed with
//! HKDF-SHA256. Protocols needing HPKE or implicit rejection must use a vetted
//! implementation of that construction instead.

use super::concat_kdf_ikm;
use crate::error::Error as KemError;
use alloc::vec::Vec;
use dcrypt_algorithms::ec::k256 as ec_k256;
use dcrypt_api::{
    error::Error as ApiError,
    traits::serialize::{Serialize, SerializeSecret},
    Kem, Key as ApiKey, Result as ApiResult, ZeroizingBytes,
};
use dcrypt_common::security::SecretBuffer;
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::Zeroizing;

const KDF_INFO: &[u8] = b"dcrypt-v3/ECDH-K256-KEM/shared-secret";

/// ECDH KEM with secp256k1 curve
pub struct EcdhK256;

/// Public key for ECDH-K256 KEM (compressed EC point)
#[derive(Clone)]
pub struct EcdhK256PublicKey([u8; ec_k256::K256_POINT_COMPRESSED_SIZE]);

impl_zeroize_tuple!(EcdhK256PublicKey);

impl AsRef<[u8]> for EcdhK256PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for EcdhK256PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Secret key for ECDH-K256 KEM (scalar value)
#[derive(Clone)]
pub struct EcdhK256SecretKey(SecretBuffer<{ ec_k256::K256_SCALAR_SIZE }>);

impl_zeroize_on_drop_tuple!(EcdhK256SecretKey);

impl AsRef<[u8]> for EcdhK256SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Shared secret from ECDH-K256 KEM
#[derive(Clone)]
pub struct EcdhK256SharedSecret(ApiKey);

impl_zeroize_on_drop_tuple!(EcdhK256SharedSecret);

impl AsRef<[u8]> for EcdhK256SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Ciphertext for ECDH-K256 KEM (compressed ephemeral public key)
#[derive(Clone)]
pub struct EcdhK256Ciphertext([u8; ec_k256::K256_POINT_COMPRESSED_SIZE]);

impl AsRef<[u8]> for EcdhK256Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for EcdhK256Ciphertext {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

// --- Public key methods ---
impl EcdhK256PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ec_k256::K256_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhK256PublicKey::from_bytes",
                expected: ec_k256::K256_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        let point = ec_k256::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "EcdhK256PublicKey::from_bytes",
                #[cfg(feature = "std")]
                message: "Public key cannot be the identity point".to_string(),
            });
        }
        let mut key_bytes = [0u8; ec_k256::K256_POINT_COMPRESSED_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self(key_bytes))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Serialize for EcdhK256PublicKey {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

// --- Secret key methods ---
impl EcdhK256SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ec_k256::K256_SCALAR_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhK256SecretKey::from_bytes",
                expected: ec_k256::K256_SCALAR_SIZE,
                actual: bytes.len(),
            });
        }
        let mut buffer_bytes = [0u8; ec_k256::K256_SCALAR_SIZE];
        buffer_bytes.copy_from_slice(bytes);
        let buffer = SecretBuffer::new(buffer_bytes);
        let scalar = ec_k256::Scalar::from_secret_buffer(buffer.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        drop(scalar);
        Ok(Self(buffer))
    }
    pub fn to_bytes(&self) -> ZeroizingBytes {
        self.0.to_bytes_zeroizing_boxed()
    }
}

impl SerializeSecret for EcdhK256SecretKey {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes_zeroizing(&self) -> ZeroizingBytes {
        self.to_bytes()
    }
}

// --- Shared secret methods ---
impl EcdhK256SharedSecret {
    pub fn to_bytes(&self) -> ZeroizingBytes {
        self.0.to_bytes_zeroizing_boxed()
    }
    pub fn to_bytes_zeroizing(&self) -> ZeroizingBytes {
        self.to_bytes()
    }
}

impl SerializeSecret for EcdhK256SharedSecret {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ec_k256::K256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhK256SharedSecret::from_bytes",
                expected: ec_k256::K256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(ApiKey::new(bytes)))
    }
    fn to_bytes_zeroizing(&self) -> ZeroizingBytes {
        self.to_bytes_zeroizing()
    }
}

// --- Ciphertext methods ---
impl EcdhK256Ciphertext {
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ec_k256::K256_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhK256Ciphertext::from_bytes",
                expected: ec_k256::K256_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        let point = ec_k256::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "EcdhK256Ciphertext::from_bytes",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }
        let mut ct_bytes = [0u8; ec_k256::K256_POINT_COMPRESSED_SIZE];
        ct_bytes.copy_from_slice(bytes);
        Ok(Self(ct_bytes))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Serialize for EcdhK256Ciphertext {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl Kem for EcdhK256 {
    type PublicKey = EcdhK256PublicKey;
    type SecretKey = EcdhK256SecretKey;
    type SharedSecret = EcdhK256SharedSecret;
    type Ciphertext = EcdhK256Ciphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-K256"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (sk_scalar, pk_point) =
            ec_k256::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;
        let public_key = EcdhK256PublicKey(pk_point.serialize_compressed());
        let secret_key = EcdhK256SecretKey(sk_scalar.as_secret_buffer().clone());
        Ok((public_key, secret_key))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn encapsulate<R: CryptoRng + RngCore>(
        rng: &mut R,
        public_key_recipient: &Self::PublicKey,
    ) -> ApiResult<(Self::Ciphertext, Self::SharedSecret)> {
        let pk_r_point = ec_k256::Point::deserialize_compressed(&public_key_recipient.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if pk_r_point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "ECDH-K256 encapsulate",
                #[cfg(feature = "std")]
                message: "Recipient public key cannot be the identity point".to_string(),
            });
        }
        let (ephemeral_scalar, ephemeral_point) =
            ec_k256::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;
        let ciphertext = EcdhK256Ciphertext(ephemeral_point.serialize_compressed());
        let shared_point = ec_k256::scalar_mult(&ephemeral_scalar, &pk_r_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-K256 encapsulate",
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }
        let x_coord_bytes = Zeroizing::new(shared_point.x_coordinate_bytes());
        let kdf_ikm = concat_kdf_ikm(
            x_coord_bytes.as_ref(),
            &ephemeral_point.serialize_compressed(),
            &public_key_recipient.0,
        );
        let ss_bytes = Zeroizing::new(
            ec_k256::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, Some(KDF_INFO))
                .map_err(|e| ApiError::from(KemError::from(e)))?,
        );
        let shared_secret = EcdhK256SharedSecret(ApiKey::new(&ss_bytes[..]));
        drop(ephemeral_scalar);
        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(
        secret_key_recipient: &Self::SecretKey,
        ciphertext_ephemeral_pk: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        let sk_r_scalar = ec_k256::Scalar::from_secret_buffer(secret_key_recipient.0.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        let q_e_point = ec_k256::Point::deserialize_compressed(&ciphertext_ephemeral_pk.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if q_e_point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "ECDH-K256 decapsulate",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }
        let shared_point = ec_k256::scalar_mult(&sk_r_scalar, &q_e_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-K256 decapsulate",
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }
        let x_coord_bytes = Zeroizing::new(shared_point.x_coordinate_bytes());
        let q_r_point = ec_k256::scalar_mult_base_g(&sk_r_scalar)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        let kdf_ikm = concat_kdf_ikm(
            x_coord_bytes.as_ref(),
            &ciphertext_ephemeral_pk.0,
            &q_r_point.serialize_compressed(),
        );
        let ss_bytes = Zeroizing::new(
            ec_k256::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, Some(KDF_INFO))
                .map_err(|e| ApiError::from(KemError::from(e)))?,
        );
        let shared_secret = EcdhK256SharedSecret(ApiKey::new(&ss_bytes[..]));
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests;
