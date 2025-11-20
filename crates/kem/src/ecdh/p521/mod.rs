// File: crates/kem/src/ecdh/p521/mod.rs
//! ECDH-KEM with NIST P-521
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the NIST P-521 curve.
//! The implementation is secure against timing attacks and follows best practices
//! for key derivation according to RFC 9180 (HPKE).
//!
//! This implementation uses compressed point format for optimal bandwidth efficiency.
//!
//! # Security Features
//!
//! - No direct byte access to keys (prevents tampering and exposure)
//! - Constant-time operations
//! - Proper validation of curve points
//! - Secure key derivation using HKDF-SHA512

use crate::error::Error as KemError;
use dcrypt_algorithms::ec::p521 as ec_p521;
use dcrypt_api::{
    error::Error as ApiError,
    traits::serialize::{Serialize, SerializeSecret},
    Kem, Key as ApiKey, Result as ApiResult,
};
use dcrypt_common::security::SecretBuffer;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// ECDH KEM with P-521 curve
pub struct EcdhP521;

/// Public key for ECDH-P521 KEM (compressed EC point)
#[derive(Clone, Zeroize)]
pub struct EcdhP521PublicKey([u8; ec_p521::P521_POINT_COMPRESSED_SIZE]);

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
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhP521SecretKey(SecretBuffer<{ ec_p521::P521_SCALAR_SIZE }>);

impl AsRef<[u8]> for EcdhP521SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Shared secret from ECDH-P521 KEM
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdhP521SharedSecret(ApiKey);

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
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

impl SerializeSecret for EcdhP521SecretKey {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        self.to_bytes()
    }
}

// --- Shared secret methods ---
impl EcdhP521SharedSecret {
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

impl SerializeSecret for EcdhP521SharedSecret {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Ok(Self(ApiKey::new(bytes)))
    }
    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
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
        let x_coord_bytes = shared_point.x_coordinate_bytes();
        let mut kdf_ikm = Vec::with_capacity(
            ec_p521::P521_FIELD_ELEMENT_SIZE + 2 * ec_p521::P521_POINT_COMPRESSED_SIZE,
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ephemeral_point.serialize_compressed());
        kdf_ikm.extend_from_slice(&public_key_recipient.0);
        let info: Option<&[u8]> = Some(b"ECDH-P521-KEM");
        let ss_bytes = ec_p521::kdf_hkdf_sha512_for_ecdh_kem(&kdf_ikm, info)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        let shared_secret = EcdhP521SharedSecret(ApiKey::new(&ss_bytes));
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
        let x_coord_bytes = shared_point.x_coordinate_bytes();
        let q_r_point = ec_p521::scalar_mult_base_g(&sk_r_scalar)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        let mut kdf_ikm = Vec::with_capacity(
            ec_p521::P521_FIELD_ELEMENT_SIZE + 2 * ec_p521::P521_POINT_COMPRESSED_SIZE,
        );
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ciphertext_ephemeral_pk.0);
        kdf_ikm.extend_from_slice(&q_r_point.serialize_compressed());
        let info: Option<&[u8]> = Some(b"ECDH-P521-KEM");
        let ss_bytes = ec_p521::kdf_hkdf_sha512_for_ecdh_kem(&kdf_ikm, info)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        let shared_secret = EcdhP521SharedSecret(ApiKey::new(&ss_bytes));
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests;