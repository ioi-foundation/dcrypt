//! ECIES implementation for NIST P-384.
use dcrypt_algorithms::aead::gcm::Gcm;
use dcrypt_algorithms::block::aes::Aes256;
use dcrypt_algorithms::block::BlockCipher;
use dcrypt_algorithms::ec::p384 as ec;
use dcrypt_algorithms::types::{Nonce, SecretBytes as AlgoSecretBytes};
use dcrypt_api::error::Error as ApiError;
use dcrypt_api::traits::Pke;
// Removed unused import: use dcrypt_api::SymmetricCipher as ApiSymmetricCipherTrait;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::format;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

use super::{
    derive_symmetric_key_hkdf_sha384, EciesCiphertextComponents, AES256GCM_KEY_LEN,
    AES256GCM_NONCE_LEN,
};
use crate::error::Error as PkeError;

/// Public key for ECIES P-384. Stores serialized uncompressed point.
#[derive(Clone, Debug)]
pub struct EciesP384PublicKey([u8; ec::P384_POINT_UNCOMPRESSED_SIZE]);

impl AsRef<[u8]> for EciesP384PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Secret key for ECIES P-384. Stores serialized scalar.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EciesP384SecretKey([u8; ec::P384_SCALAR_SIZE]);

impl AsRef<[u8]> for EciesP384SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct EciesP384;

impl Pke for EciesP384 {
    type PublicKey = EciesP384PublicKey;
    type SecretKey = EciesP384SecretKey;
    type Ciphertext = Vec<u8>;

    fn name() -> &'static str {
        "ECIES-P384-HKDF-SHA384-AES256GCM"
    }

    fn keypair<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> dcrypt_api::error::Result<(Self::PublicKey, Self::SecretKey)> {
        let (sk_scalar, pk_point) =
            ec::generate_keypair(rng).map_err(|e| ApiError::from(PkeError::from(e)))?;
        Ok((
            EciesP384PublicKey(pk_point.serialize_uncompressed()),
            EciesP384SecretKey(sk_scalar.serialize()),
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
        let mut derived_key_material = derive_symmetric_key_hkdf_sha384(
            &z_bytes,
            &r_bytes_uncompressed,
            AES256GCM_KEY_LEN,
            Some(info_str.as_bytes()),
        )
        .map_err(ApiError::from)?;

        let mut encryption_key_arr_aes = [0u8; AES256GCM_KEY_LEN];
        encryption_key_arr_aes.copy_from_slice(&derived_key_material);

        drop(ephemeral_sk_scalar);
        z_bytes.zeroize();
        derived_key_material.zeroize();

        let aes_core_key = AlgoSecretBytes::<AES256GCM_KEY_LEN>::new(encryption_key_arr_aes);
        let aes_core = Aes256::new(&aes_core_key);
        let aead_nonce = Nonce::<AES256GCM_NONCE_LEN>::random(rng);

        let gcm_cipher_impl = Gcm::<Aes256>::new(aes_core, &aead_nonce)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;

        let aead_ciphertext_and_tag_vec = gcm_cipher_impl
            .internal_encrypt(plaintext, aad)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;

        let ecies_components = EciesCiphertextComponents {
            ephemeral_public_key: r_bytes_uncompressed.to_vec(),
            aead_nonce: aead_nonce.as_ref().to_vec(),
            aead_ciphertext_tag: aead_ciphertext_and_tag_vec,
        };

        Ok(ecies_components.serialize())
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
        let mut derived_key_material = derive_symmetric_key_hkdf_sha384(
            &z_bytes,
            &ephemeral_public_key,
            AES256GCM_KEY_LEN,
            Some(info_str.as_bytes()),
        )
        .map_err(ApiError::from)?;

        let mut encryption_key_arr_aes = [0u8; AES256GCM_KEY_LEN];
        encryption_key_arr_aes.copy_from_slice(&derived_key_material);

        z_bytes.zeroize();
        derived_key_material.zeroize();

        let aead_nonce = Nonce::<AES256GCM_NONCE_LEN>::from_slice(&aead_nonce)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;

        let aes_core_key = AlgoSecretBytes::<AES256GCM_KEY_LEN>::new(encryption_key_arr_aes);
        let aes_core = Aes256::new(&aes_core_key);
        let gcm_cipher_impl = Gcm::<Aes256>::new(aes_core, &aead_nonce)
            .map_err(|e| ApiError::from(PkeError::from(e)))?;

        let plaintext = gcm_cipher_impl
            .internal_decrypt(&aead_ciphertext_tag, aad)
            .map_err(|_| {
                ApiError::from(PkeError::DecryptionFailed("AEAD authentication failed"))
            })?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests;