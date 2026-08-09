// File: crates/kem/src/ecdh/p521/mod.rs
//! ECDH-KEM with NIST P-521
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the NIST P-521 curve.
//! This is a dcrypt-specific ECDH-plus-HKDF construction, not RFC 9180 HPKE.
//! Invalid inputs return errors. No blanket constant-time or IND-CCA claim is
//! made; arithmetic behavior depends on the backend, compiler, and target.
//!
//! This implementation uses compressed point format for optimal bandwidth efficiency.
//!
//! Public points are validated and the shared point is processed with
//! HKDF-SHA512. Protocols needing HPKE or implicit rejection must use a vetted
//! implementation of that construction instead.

use super::concat_kdf_ikm;
use crate::error::Error as KemError;
use alloc::vec::Vec;
use dcrypt_algorithms::ec::p521 as ec_p521;
use dcrypt_api::{
    error::Error as ApiError,
    traits::serialize::{Serialize, SerializeSecret},
    Kem, Key as ApiKey, Result as ApiResult, ZeroizingBytes,
};
use dcrypt_common::security::SecretBuffer;
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::Zeroizing;

const KDF_INFO: &[u8] = b"dcrypt-v3/ECDH-P521-KEM/shared-secret";

/// ECDH KEM with P-521 curve
pub struct EcdhP521;

/// Public key for ECDH-P521 KEM (compressed EC point)
#[derive(Clone)]
pub struct EcdhP521PublicKey([u8; ec_p521::P521_POINT_COMPRESSED_SIZE]);

impl_zeroize_tuple!(EcdhP521PublicKey);

impl AsRef<[u8]> for EcdhP521PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for EcdhP521PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Secret key for ECDH-P521 KEM (scalar value)
#[derive(Clone)]
pub struct EcdhP521SecretKey(SecretBuffer<{ ec_p521::P521_SCALAR_SIZE }>);

impl_zeroize_on_drop_tuple!(EcdhP521SecretKey);

impl AsRef<[u8]> for EcdhP521SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Shared secret from ECDH-P521 KEM
#[derive(Clone)]
pub struct EcdhP521SharedSecret(ApiKey);

impl_zeroize_on_drop_tuple!(EcdhP521SharedSecret);

impl AsRef<[u8]> for EcdhP521SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Ciphertext for ECDH-P521 KEM (compressed ephemeral public key)
#[derive(Clone)]
pub struct EcdhP521Ciphertext([u8; ec_p521::P521_POINT_COMPRESSED_SIZE]);

impl AsRef<[u8]> for EcdhP521Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for EcdhP521Ciphertext {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

// --- Public key methods ---
impl EcdhP521PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ec_p521::P521_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP521PublicKey::from_bytes",
                expected: ec_p521::P521_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        let point = ec_p521::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "EcdhP521PublicKey::from_bytes",
                #[cfg(feature = "std")]
                message: "Public key cannot be the identity point".to_string(),
            });
        }
        let mut key_bytes = [0u8; ec_p521::P521_POINT_COMPRESSED_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self(key_bytes))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Serialize for EcdhP521PublicKey {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

// --- Secret key methods ---
impl EcdhP521SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ec_p521::P521_SCALAR_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP521SecretKey::from_bytes",
                expected: ec_p521::P521_SCALAR_SIZE,
                actual: bytes.len(),
            });
        }
        let mut buffer_bytes = [0u8; ec_p521::P521_SCALAR_SIZE];
        buffer_bytes.copy_from_slice(bytes);
        let buffer = SecretBuffer::new(buffer_bytes);
        let scalar = ec_p521::Scalar::from_secret_buffer(buffer.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        drop(scalar);
        Ok(Self(buffer))
    }
    pub fn to_bytes(&self) -> ZeroizingBytes {
        self.0.to_bytes_zeroizing_boxed()
    }
}

impl SerializeSecret for EcdhP521SecretKey {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes_zeroizing(&self) -> ZeroizingBytes {
        self.to_bytes()
    }
}

// --- Shared secret methods ---
impl EcdhP521SharedSecret {
    pub fn to_bytes(&self) -> ZeroizingBytes {
        self.0.to_bytes_zeroizing_boxed()
    }
}

impl SerializeSecret for EcdhP521SharedSecret {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ec_p521::P521_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP521SharedSecret::from_bytes",
                expected: ec_p521::P521_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Self(ApiKey::new(bytes)))
    }
    fn to_bytes_zeroizing(&self) -> ZeroizingBytes {
        self.to_bytes()
    }
}

// --- Ciphertext methods ---
impl EcdhP521Ciphertext {
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ec_p521::P521_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP521Ciphertext::from_bytes",
                expected: ec_p521::P521_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        let point = ec_p521::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "EcdhP521Ciphertext::from_bytes",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }
        let mut ct_bytes = [0u8; ec_p521::P521_POINT_COMPRESSED_SIZE];
        ct_bytes.copy_from_slice(bytes);
        Ok(Self(ct_bytes))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Serialize for EcdhP521Ciphertext {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl Kem for EcdhP521 {
    type PublicKey = EcdhP521PublicKey;
    type SecretKey = EcdhP521SecretKey;
    type SharedSecret = EcdhP521SharedSecret;
    type Ciphertext = EcdhP521Ciphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-P521"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (sk_scalar, pk_point) =
            ec_p521::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;
        let public_key = EcdhP521PublicKey(pk_point.serialize_compressed());
        let secret_key = EcdhP521SecretKey(sk_scalar.as_secret_buffer().clone());
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
        let pk_r_point = ec_p521::Point::deserialize_compressed(&public_key_recipient.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if pk_r_point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "ECDH-P521 encapsulate",
                #[cfg(feature = "std")]
                message: "Recipient public key cannot be the identity point".to_string(),
            });
        }
        let (ephemeral_scalar, ephemeral_point) =
            ec_p521::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;
        let ciphertext = EcdhP521Ciphertext(ephemeral_point.serialize_compressed());
        let shared_point = ec_p521::scalar_mult(&ephemeral_scalar, &pk_r_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-P521 encapsulate",
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
        let ss_bytes = ec_p521::kdf_hkdf_sha512_for_ecdh_kem(&kdf_ikm, Some(KDF_INFO))
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        let shared_secret = EcdhP521SharedSecret(ApiKey::new(&ss_bytes[..]));
        drop(ephemeral_scalar);
        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(
        secret_key_recipient: &Self::SecretKey,
        ciphertext_ephemeral_pk: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        let scalar_result = ec_p521::Scalar::from_secret_buffer(secret_key_recipient.0.clone());
        let sk_r_scalar = match scalar_result {
            Ok(scalar) => scalar,
            Err(e) => return Err(ApiError::from(KemError::from(e))),
        };
        let q_e_point = ec_p521::Point::deserialize_compressed(&ciphertext_ephemeral_pk.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if q_e_point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "ECDH-P521 decapsulate",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }
        let shared_point = ec_p521::scalar_mult(&sk_r_scalar, &q_e_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-P521 decapsulate",
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }
        let x_coord_bytes = Zeroizing::new(shared_point.x_coordinate_bytes());
        let q_r_point = ec_p521::scalar_mult_base_g(&sk_r_scalar)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        let kdf_ikm = concat_kdf_ikm(
            x_coord_bytes.as_ref(),
            &ciphertext_ephemeral_pk.0,
            &q_r_point.serialize_compressed(),
        );
        let ss_bytes = ec_p521::kdf_hkdf_sha512_for_ecdh_kem(&kdf_ikm, Some(KDF_INFO))
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        let shared_secret = EcdhP521SharedSecret(ApiKey::new(&ss_bytes[..]));
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests;
