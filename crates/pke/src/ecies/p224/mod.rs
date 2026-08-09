//! ECIES implementation for NIST P-224.
use dcrypt_algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt_algorithms::ec::p224 as ec; // Use P-224 algorithms
use dcrypt_algorithms::types::Nonce;
use dcrypt_api::error::Error as ApiError;
use dcrypt_api::traits::symmetric::{DecryptOperation, EncryptOperation};
use dcrypt_api::traits::Pke;
use dcrypt_api::traits::SymmetricCipher as ApiSymmetricCipherTrait;
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::Zeroize;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{format, vec::Vec};
#[cfg(feature = "std")]
use std::{format, vec::Vec};

use super::{
    derive_symmetric_key_hkdf_sha256, // P-224 uses HKDF-SHA256 KDF
    EciesCiphertextComponents,
    CHACHA20POLY1305_KEY_LEN,
    CHACHA20POLY1305_NONCE_LEN,
};
use crate::error::Error as PkeError;

/// Public key for ECIES P-224. Stores serialized uncompressed point.
#[derive(Clone, Debug)]
pub struct EciesP224PublicKey([u8; ec::P224_POINT_UNCOMPRESSED_SIZE]);

impl AsRef<[u8]> for EciesP224PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Secret key for ECIES P-224. Stores serialized scalar.
#[derive(Clone)]
pub struct EciesP224SecretKey([u8; ec::P224_SCALAR_SIZE]);

impl_zeroize_on_drop_tuple!(EciesP224SecretKey);

impl AsRef<[u8]> for EciesP224SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct EciesP224;

impl Pke for EciesP224 {
    type PublicKey = EciesP224PublicKey;
    type SecretKey = EciesP224SecretKey;
    type Ciphertext = Vec<u8>; // Serialized EciesCiphertextComponents

    fn name() -> &'static str {
        "ECIES-P224-HKDF-SHA256-ChaCha20Poly1305"
    }

    fn keypair<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> dcrypt_api::error::Result<(Self::PublicKey, Self::SecretKey)> {
        let (sk_scalar, pk_point) =
            ec::generate_keypair(rng).map_err(|e| ApiError::from(PkeError::from(e)))?;
        Ok((
            EciesP224PublicKey(pk_point.serialize_uncompressed()),
            EciesP224SecretKey(sk_scalar.serialize()),
        ))
    }

    fn encrypt<R: RngCore + CryptoRng>(
        pk_recipient: &Self::PublicKey,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        rng: &mut R,
    ) -> dcrypt_api::error::Result<Self::Ciphertext> {
        let pk_recipient_point = ec::Point::deserialize_uncompressed(&pk_recipient.0)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;
        if pk_recipient_point.is_identity() {
            return Err(ApiError::from(PkeError::EncryptionFailed(
                "Recipient PK is point at infinity",
            )));
        }

        let (ephemeral_sk_scalar, ephemeral_pk_point) =
            ec::generate_keypair(rng).map_err(|e| ApiError::from(PkeError::from(e)))?;
        let r_bytes_uncompressed = ephemeral_pk_point.serialize_uncompressed();

        let shared_point = ec::scalar_mult(&ephemeral_sk_scalar, &pk_recipient_point)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::from(PkeError::EncryptionFailed(
                "ECDH resulted in point at infinity",
            )));
        }
        let mut z_bytes = shared_point.x_coordinate_bytes();

        let info_str = format!("{}-KeyMaterial", Self::name());
        let mut derived_key_material = derive_symmetric_key_hkdf_sha256(
            &z_bytes,
            &r_bytes_uncompressed, // Salt for KDF
            CHACHA20POLY1305_KEY_LEN,
            Some(info_str.as_bytes()),
        )
        .map_err(ApiError::from)?;

        let mut encryption_key_arr = [0u8; CHACHA20POLY1305_KEY_LEN];
        encryption_key_arr.copy_from_slice(&derived_key_material);

        drop(ephemeral_sk_scalar);
        z_bytes.zeroize();
        derived_key_material.zeroize();

        let aead_cipher_impl = ChaCha20Poly1305::new(&encryption_key_arr);
        encryption_key_arr.zeroize();
        let aead_nonce = Nonce::<CHACHA20POLY1305_NONCE_LEN>::random(rng)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;

        let aead_ciphertext_api_obj =
            <ChaCha20Poly1305 as ApiSymmetricCipherTrait>::encrypt(&aead_cipher_impl)
                .with_nonce(&aead_nonce)
                .with_aad(aad.unwrap_or_default())
                .encrypt(plaintext)?;

        let ecies_components = EciesCiphertextComponents {
            ephemeral_public_key: r_bytes_uncompressed.to_vec(),
            aead_nonce: aead_nonce.as_ref().to_vec(),
            aead_ciphertext_tag: aead_ciphertext_api_obj.as_ref().to_vec(),
        };
        ecies_components.serialize().map_err(ApiError::from)
    }

    fn decrypt(
        sk_recipient: &Self::SecretKey,
        ciphertext_bytes: &Self::Ciphertext,
        aad: Option<&[u8]>,
    ) -> dcrypt_api::error::Result<Vec<u8>> {
        // OPTIMIZATION: Destructure components to move vectors
        let EciesCiphertextComponents {
            ephemeral_public_key,
            aead_nonce,
            aead_ciphertext_tag,
        } = EciesCiphertextComponents::deserialize(ciphertext_bytes).map_err(ApiError::from)?;

        let r_point = ec::Point::deserialize_uncompressed(&ephemeral_public_key)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;
        if r_point.is_identity() {
            return Err(ApiError::from(PkeError::DecryptionFailed(
                "Ephemeral PK is point at infinity",
            )));
        }

        let sk_recipient_scalar = ec::Scalar::deserialize(&sk_recipient.0)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;

        let shared_point = ec::scalar_mult(&sk_recipient_scalar, &r_point)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;
        if shared_point.is_identity() {
            return Err(ApiError::from(PkeError::DecryptionFailed(
                "ECDH resulted in point at infinity",
            )));
        }
        let mut z_bytes = shared_point.x_coordinate_bytes();

        let info_str = format!("{}-KeyMaterial", Self::name());
        let mut derived_key_material = derive_symmetric_key_hkdf_sha256(
            &z_bytes,
            &ephemeral_public_key, // Salt for KDF
            CHACHA20POLY1305_KEY_LEN,
            Some(info_str.as_bytes()),
        )
        .map_err(ApiError::from)?;

        let mut encryption_key_arr = [0u8; CHACHA20POLY1305_KEY_LEN];
        encryption_key_arr.copy_from_slice(&derived_key_material);

        z_bytes.zeroize();
        derived_key_material.zeroize();

        let aead_nonce_obj = Nonce::<CHACHA20POLY1305_NONCE_LEN>::from_slice(&aead_nonce)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;

        let aead_cipher_impl = ChaCha20Poly1305::new(&encryption_key_arr);
        encryption_key_arr.zeroize();

        // Zero-copy optimization: Move the vector into Ciphertext
        let aead_ct_api_obj = dcrypt_api::Ciphertext::new(aead_ciphertext_tag);

        let plaintext = <ChaCha20Poly1305 as ApiSymmetricCipherTrait>::decrypt(&aead_cipher_impl)
            .with_nonce(&aead_nonce_obj)
            .with_aad(aad.unwrap_or_default())
            .decrypt(&aead_ct_api_obj)
            .map_err(|_| {
                ApiError::from(PkeError::DecryptionFailed("AEAD authentication failed"))
            })?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests;
