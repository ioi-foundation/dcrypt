// File: crates/kem/src/ecdh/p192/mod.rs
//! ECDH-KEM with NIST P-192
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the NIST P-192 curve.
//! The implementation is secure against timing attacks and follows best practices
//! for key derivation according to RFC 9180 (HPKE).
//! This implementation uses compressed point format.
//!
//! # Security Features
//!
//! - No direct byte access to keys (prevents tampering and leakage)
//! - Constant-time operations where applicable
//! - Proper validation of curve points
//! - Secure key derivation using HKDF-SHA256

use crate::error::Error as KemError;
use dcrypt_algorithms::ec::p192 as ec;
use dcrypt_api::{
    error::Error as ApiError,
    traits::serialize::{Serialize, SerializeSecret},
    Kem, Key as ApiKey, Result as ApiResult,
};
use dcrypt_common::security::SecretBuffer;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// ECDH KEM with P-192 curve
pub struct EcdhP192;

/// Public key for ECDH-P192 KEM (compressed EC point)
///
/// # Security Note
/// This type provides no direct byte access. Use the `to_bytes()` method
/// for serialization and `from_bytes()` for deserialization.
#[derive(Clone, Zeroize)]
pub struct EcdhP192PublicKey([u8; ec::P192_POINT_COMPRESSED_SIZE]);

/// Secret key for ECDH-P192 KEM (scalar value)
///
/// # Security Note
/// This type provides no direct byte access to prevent key exposure.
/// Use the `to_bytes()` method which returns a `Zeroizing` wrapper.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhP192SecretKey(SecretBuffer<{ ec::P192_SCALAR_SIZE }>);

/// Shared secret from ECDH-P192 KEM
///
/// # Security Note
/// This type provides no direct byte access to prevent secret leakage.
/// Convert to application keys immediately after generation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhP192SharedSecret(ApiKey);

/// Ciphertext for ECDH-P192 KEM (compressed ephemeral public key)
///
/// # Security Note
/// This type provides no direct byte access to prevent tampering.
#[derive(Clone)]
pub struct EcdhP192Ciphertext([u8; ec::P192_POINT_COMPRESSED_SIZE]);

// --- Public key methods ---
impl EcdhP192PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ec::P192_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP192PublicKey::from_bytes",
                expected: ec::P192_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        let point = ec::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "EcdhP192PublicKey::from_bytes",
                #[cfg(feature = "std")]
                message: "Public key cannot be the identity point".to_string(),
            });
        }
        let mut key_bytes = [0u8; ec::P192_POINT_COMPRESSED_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self(key_bytes))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Serialize for EcdhP192PublicKey {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

// --- Secret key methods ---
impl EcdhP192SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ec::P192_SCALAR_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP192SecretKey::from_bytes",
                expected: ec::P192_SCALAR_SIZE,
                actual: bytes.len(),
            });
        }
        let mut buffer_bytes = [0u8; ec::P192_SCALAR_SIZE];
        buffer_bytes.copy_from_slice(bytes);
        let buffer = SecretBuffer::new(buffer_bytes);
        let scalar = ec::Scalar::from_secret_buffer(buffer.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        drop(scalar);
        Ok(Self(buffer))
    }
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

impl SerializeSecret for EcdhP192SecretKey {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        self.to_bytes()
    }
}

// --- Shared secret methods ---
impl EcdhP192SharedSecret {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
    pub fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

impl SerializeSecret for EcdhP192SharedSecret {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Ok(Self(ApiKey::new(bytes)))
    }
    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        self.to_bytes_zeroizing()
    }
}

// --- Ciphertext methods ---
impl EcdhP192Ciphertext {
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ec::P192_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP192Ciphertext::from_bytes",
                expected: ec::P192_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        let point = ec::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "EcdhP192Ciphertext::from_bytes",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }
        let mut ct_bytes = [0u8; ec::P192_POINT_COMPRESSED_SIZE];
        ct_bytes.copy_from_slice(bytes);
        Ok(Self(ct_bytes))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Serialize for EcdhP192Ciphertext {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

// No AsRef or AsMut implementations - this prevents direct byte access

impl Kem for EcdhP192 {
    type PublicKey = EcdhP192PublicKey;
    type SecretKey = EcdhP192SecretKey;
    type SharedSecret = EcdhP192SharedSecret;
    type Ciphertext = EcdhP192Ciphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-P192"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (sk_scalar, pk_point) =
            ec::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;
        let public_key = EcdhP192PublicKey(pk_point.serialize_compressed());
        let secret_key = EcdhP192SecretKey(sk_scalar.as_secret_buffer().clone());
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
        let pk_r_point = ec::Point::deserialize_compressed(&public_key_recipient.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if pk_r_point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "ECDH-P192 encapsulate",
                #[cfg(feature = "std")]
                message: "Recipient public key is identity".to_string(),
            });
        }

        let (ephemeral_scalar, ephemeral_point) =
            ec::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;
        let ciphertext = EcdhP192Ciphertext(ephemeral_point.serialize_compressed());

        let shared_point = ec::scalar_mult(&ephemeral_scalar, &pk_r_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-P192 encapsulate",
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }
        let x_coord_bytes = shared_point.x_coordinate_bytes();

        let mut kdf_ikm =
            Vec::with_capacity(ec::P192_FIELD_ELEMENT_SIZE + 2 * ec::P192_POINT_COMPRESSED_SIZE);
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ephemeral_point.serialize_compressed());
        kdf_ikm.extend_from_slice(&public_key_recipient.0);

        let ss_bytes = ec::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, Some(&b"ECDH-P192-KEM"[..]))
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        let shared_secret = EcdhP192SharedSecret(ApiKey::new(&ss_bytes));
        drop(ephemeral_scalar);
        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(
        secret_key_recipient: &Self::SecretKey,
        ciphertext_ephemeral_pk: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        let sk_r_scalar = ec::Scalar::from_secret_buffer(secret_key_recipient.0.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        let q_e_point = ec::Point::deserialize_compressed(&ciphertext_ephemeral_pk.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if q_e_point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "ECDH-P192 decapsulate",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }

        let shared_point = ec::scalar_mult(&sk_r_scalar, &q_e_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-P192 decapsulate",
                #[cfg(feature = "std")]
                message: "Shared point is the identity".to_string(),
            });
        }
        let x_coord_bytes = shared_point.x_coordinate_bytes();
        let q_r_point =
            ec::scalar_mult_base_g(&sk_r_scalar).map_err(|e| ApiError::from(KemError::from(e)))?;

        let mut kdf_ikm =
            Vec::with_capacity(ec::P192_FIELD_ELEMENT_SIZE + 2 * ec::P192_POINT_COMPRESSED_SIZE);
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ciphertext_ephemeral_pk.0);
        kdf_ikm.extend_from_slice(&q_r_point.serialize_compressed());

        let ss_bytes = ec::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, Some(&b"ECDH-P192-KEM"[..]))
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        Ok(EcdhP192SharedSecret(ApiKey::new(&ss_bytes)))
    }
}

#[cfg(test)]
mod tests;
