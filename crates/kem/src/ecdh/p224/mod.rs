// File: crates/kem/src/ecdh/p224/mod.rs
//! ECDH-KEM with NIST P-224
//!
//! This module provides a Key Encapsulation Mechanism (KEM) based on the
//! Elliptic Curve Diffie-Hellman (ECDH) protocol using the NIST P-224 curve.
//! Uses HKDF-SHA256 for key derivation and compressed points for ciphertexts.
//! Includes authentication via HMAC-SHA256 tags to ensure key confirmation.
//!
//! The construction validates public points and adds an HMAC-SHA256
//! key-confirmation tag. This is not RFC 9180 HPKE and makes no blanket
//! constant-time or IND-CCA claim.

use crate::error::Error as KemError;
use dcrypt_algorithms::ec::p224 as ec; // Use P-224 algorithms
use dcrypt_algorithms::hash::sha2::Sha256;
use dcrypt_algorithms::mac::hmac::Hmac;
use dcrypt_api::{
    error::Error as ApiError,
    traits::serialize::{Serialize, SerializeSecret},
    Kem, Key as ApiKey, Result as ApiResult,
};
use dcrypt_common::security::SecretBuffer;
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// ECDH KEM with P-224 curve
pub struct EcdhP224;

/// Public key for ECDH-P224 KEM (compressed EC point)
#[derive(Clone)]
pub struct EcdhP224PublicKey([u8; ec::P224_POINT_COMPRESSED_SIZE]);

impl_zeroize_tuple!(EcdhP224PublicKey);

/// Secret key for ECDH-P224 KEM (scalar value)
#[derive(Clone)]
pub struct EcdhP224SecretKey(SecretBuffer<{ ec::P224_SCALAR_SIZE }>);

impl_zeroize_on_drop_tuple!(EcdhP224SecretKey);

/// Shared secret from ECDH-P224 KEM
#[derive(Clone)]
pub struct EcdhP224SharedSecret(ApiKey);

impl_zeroize_on_drop_tuple!(EcdhP224SharedSecret);

/// Ciphertext for ECDH-P224 KEM (compressed ephemeral public key + authentication tag)
#[derive(Clone)]
pub struct EcdhP224Ciphertext([u8; ec::P224_CIPHERTEXT_SIZE]);

// --- Public key methods ---
impl EcdhP224PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ec::P224_POINT_COMPRESSED_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP224PublicKey::from_bytes",
                expected: ec::P224_POINT_COMPRESSED_SIZE,
                actual: bytes.len(),
            });
        }
        let point = ec::Point::deserialize_compressed(bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "EcdhP224PublicKey::from_bytes",
                #[cfg(feature = "std")]
                message: "Public key cannot be the identity point".to_string(),
            });
        }
        let mut key_bytes = [0u8; ec::P224_POINT_COMPRESSED_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self(key_bytes))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn validate(&self) -> ApiResult<()> {
        let point = ec::Point::deserialize_compressed(&self.0)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "validate_public_key",
                #[cfg(feature = "std")]
                message: "Public key is the identity point".to_string(),
            });
        }
        Ok(())
    }
}

impl Serialize for EcdhP224PublicKey {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

// --- Secret key methods ---
impl EcdhP224SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ec::P224_SCALAR_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP224SecretKey::from_bytes",
                expected: ec::P224_SCALAR_SIZE,
                actual: bytes.len(),
            });
        }
        let mut buffer_bytes = [0u8; ec::P224_SCALAR_SIZE];
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
    pub fn validate(&self) -> ApiResult<()> {
        let _ = ec::Scalar::from_secret_buffer(self.0.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        Ok(())
    }
}

impl SerializeSecret for EcdhP224SecretKey {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        self.to_bytes()
    }
}

// --- Shared secret methods ---
impl EcdhP224SharedSecret {
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_ref().to_vec())
    }
}

impl SerializeSecret for EcdhP224SharedSecret {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Ok(Self(ApiKey::new(bytes)))
    }
    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        self.to_bytes()
    }
}

// --- Ciphertext methods ---
impl EcdhP224Ciphertext {
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != ec::P224_CIPHERTEXT_SIZE {
            return Err(ApiError::InvalidLength {
                context: "EcdhP224Ciphertext::from_bytes",
                expected: ec::P224_CIPHERTEXT_SIZE,
                actual: bytes.len(),
            });
        }
        let pk_bytes = &bytes[..ec::P224_POINT_COMPRESSED_SIZE];
        let point = ec::Point::deserialize_compressed(pk_bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "EcdhP224Ciphertext::from_bytes",
                #[cfg(feature = "std")]
                message: "Ephemeral public key cannot be the identity point".to_string(),
            });
        }
        let mut ct_bytes = [0u8; ec::P224_CIPHERTEXT_SIZE];
        ct_bytes.copy_from_slice(bytes);
        Ok(Self(ct_bytes))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    pub fn validate(&self) -> ApiResult<()> {
        let pk_bytes = &self.0[..ec::P224_POINT_COMPRESSED_SIZE];
        let point = ec::Point::deserialize_compressed(pk_bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "validate_ciphertext",
                #[cfg(feature = "std")]
                message: "Ciphertext contains identity point".to_string(),
            });
        }
        Ok(())
    }
}

impl Serialize for EcdhP224Ciphertext {
    fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        Self::from_bytes(bytes)
    }
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

/// Calculate authentication tag for key confirmation
///
/// Uses truncated HMAC-SHA256 to create a 16-byte tag that proves
/// the sender and receiver computed the same shared secret.
fn calc_auth_tag(shared_secret: &[u8]) -> Result<[u8; ec::P224_TAG_SIZE], KemError> {
    // Create HMAC-SHA256 instance with fixed key
    let mut hmac = Hmac::<Sha256>::new(b"ECDH-P224-KEM tag").map_err(KemError::from)?;

    // Update with shared secret
    hmac.update(shared_secret).map_err(KemError::from)?;

    // Finalize and get tag (SHA256 produces 32-byte tags)
    let tag_vec: Vec<u8> = hmac.finalize().map_err(KemError::from)?;

    // Truncate to P224_TAG_SIZE bytes
    let mut truncated = [0u8; ec::P224_TAG_SIZE];
    truncated.copy_from_slice(&tag_vec[..ec::P224_TAG_SIZE]);
    Ok(truncated)
}

impl Kem for EcdhP224 {
    type PublicKey = EcdhP224PublicKey;
    type SecretKey = EcdhP224SecretKey;
    type SharedSecret = EcdhP224SharedSecret;
    type Ciphertext = EcdhP224Ciphertext;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDH-P224"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (sk_scalar, pk_point) =
            ec::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;
        let public_key = EcdhP224PublicKey(pk_point.serialize_compressed());
        let secret_key = EcdhP224SecretKey(sk_scalar.as_secret_buffer().clone());
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
                context: "ECDH-P224 encapsulate",
                #[cfg(feature = "std")]
                message: "Recipient public key is identity".to_string(),
            });
        }

        let (ephemeral_scalar, ephemeral_point) =
            ec::generate_keypair(rng).map_err(|e| ApiError::from(KemError::from(e)))?;
        let ephemeral_pk_compressed = ephemeral_point.serialize_compressed();

        let shared_point = ec::scalar_mult(&ephemeral_scalar, &pk_r_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-P224 encapsulate",
                #[cfg(feature = "std")]
                message: "Shared point is identity".to_string(),
            });
        }
        let x_coord_bytes = shared_point.x_coordinate_bytes();

        let mut kdf_ikm =
            Vec::with_capacity(ec::P224_FIELD_ELEMENT_SIZE + 2 * ec::P224_POINT_COMPRESSED_SIZE);
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(&ephemeral_pk_compressed);
        kdf_ikm.extend_from_slice(&public_key_recipient.0);

        let ss_bytes = ec::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, Some(&b"ECDH-P224-KEM"[..]))
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        let shared_secret = EcdhP224SharedSecret(ApiKey::new(&ss_bytes));

        // Create authenticated ciphertext: ephemeral_pk || tag
        let mut ct_bytes = [0u8; ec::P224_CIPHERTEXT_SIZE];
        ct_bytes[..ec::P224_POINT_COMPRESSED_SIZE].copy_from_slice(&ephemeral_pk_compressed);
        let tag = calc_auth_tag(&ss_bytes).map_err(ApiError::from)?;
        ct_bytes[ec::P224_POINT_COMPRESSED_SIZE..].copy_from_slice(&tag);
        let ciphertext = EcdhP224Ciphertext(ct_bytes);

        drop(ephemeral_scalar);
        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(
        secret_key_recipient: &Self::SecretKey,
        ciphertext_ephemeral_pk: &Self::Ciphertext,
    ) -> ApiResult<Self::SharedSecret> {
        // Split ciphertext into ephemeral public key and tag
        let (pk_bytes, tag_bytes) = ciphertext_ephemeral_pk
            .0
            .split_at(ec::P224_POINT_COMPRESSED_SIZE);

        // Convert tag bytes to array for comparison
        let mut received_tag = [0u8; ec::P224_TAG_SIZE];
        received_tag.copy_from_slice(tag_bytes);

        let sk_r_scalar = ec::Scalar::from_secret_buffer(secret_key_recipient.0.clone())
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        let q_e_point = ec::Point::deserialize_compressed(pk_bytes)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if q_e_point.is_identity() {
            return Err(ApiError::InvalidCiphertext {
                context: "ECDH-P224 decapsulate",
                #[cfg(feature = "std")]
                message: "Ephemeral PK is identity".to_string(),
            });
        }

        let shared_point = ec::scalar_mult(&sk_r_scalar, &q_e_point)
            .map_err(|e| ApiError::from(KemError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-P224 decapsulate",
                #[cfg(feature = "std")]
                message: "Shared point is identity".to_string(),
            });
        }
        let x_coord_bytes = shared_point.x_coordinate_bytes();
        let q_r_point =
            ec::scalar_mult_base_g(&sk_r_scalar).map_err(|e| ApiError::from(KemError::from(e)))?;

        let mut kdf_ikm =
            Vec::with_capacity(ec::P224_FIELD_ELEMENT_SIZE + 2 * ec::P224_POINT_COMPRESSED_SIZE);
        kdf_ikm.extend_from_slice(&x_coord_bytes);
        kdf_ikm.extend_from_slice(pk_bytes); // Use only the PK part, not the full ciphertext
        kdf_ikm.extend_from_slice(&q_r_point.serialize_compressed());

        let ss_bytes = ec::kdf_hkdf_sha256_for_ecdh_kem(&kdf_ikm, Some(&b"ECDH-P224-KEM"[..]))
            .map_err(|e| ApiError::from(KemError::from(e)))?;

        // Verify authentication tag
        let expected_tag = calc_auth_tag(&ss_bytes).map_err(ApiError::from)?;

        // Constant-time comparison of tags (array to array)
        use dcrypt_common::security::SecureCompare;
        if !received_tag.secure_eq(&expected_tag) {
            return Err(ApiError::DecryptionFailed {
                context: "ECDH-P224 decapsulate",
                #[cfg(feature = "std")]
                message: "Authentication tag mismatch".to_string(),
            });
        }

        Ok(EcdhP224SharedSecret(ApiKey::new(&ss_bytes)))
    }
}

#[cfg(test)]
mod tests;
