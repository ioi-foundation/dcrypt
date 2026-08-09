//! Elliptic Curve Integrated Encryption Scheme (ECIES) generic components.

use crate::error::{Error as PkeError, Result as PkeResult};
use dcrypt_algorithms::hash::sha2::{Sha256, Sha384, Sha512}; // Added Sha512
use dcrypt_algorithms::kdf::hkdf::Hkdf;
use dcrypt_algorithms::kdf::KeyDerivationFunction; // Use PKE specific Result/Error
use dcrypt_api::error::Error as ApiError;
use dcrypt_internal::zeroing::Zeroizing;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// Declare submodules
pub mod p224;
pub mod p256;
pub mod p384;
pub mod p521;

// Re-export the main structs
pub use p224::EciesP224;
pub use p256::EciesP256;
pub use p384::EciesP384;
pub use p521::EciesP521;

// --- Constants and Helper Structs/Functions (moved from individual files if generic enough, or keep here) ---

// Key lengths for AEADs
pub(crate) const CHACHA20POLY1305_KEY_LEN: usize = 32;
pub(crate) const AES256GCM_KEY_LEN: usize = 32;

// Nonce lengths for AEADs
pub(crate) const CHACHA20POLY1305_NONCE_LEN: usize = 12;
pub(crate) const AES256GCM_NONCE_LEN: usize = 12;
pub(crate) const AEAD_TAG_LEN: usize = 16;
const KDF_SALT: &[u8] = b"dcrypt-v3/ECIES/extract";

pub(crate) fn invalid_recipient_public_key() -> ApiError {
    ApiError::InvalidKey {
        context: "ECIES recipient public key",
        #[cfg(feature = "std")]
        message: "recipient public key is not a canonical non-identity curve point".to_string(),
    }
}

pub(crate) fn invalid_ephemeral_public_key() -> ApiError {
    ApiError::InvalidCiphertext {
        context: "ECIES ephemeral public key",
        #[cfg(feature = "std")]
        message: "ephemeral public key is not a canonical non-identity curve point".to_string(),
    }
}

fn kdf_transcript(
    shared_secret_z: &[u8],
    ephemeral_pk_bytes: &[u8],
    recipient_pk_bytes: &[u8],
) -> PkeResult<Zeroizing<Vec<u8>>> {
    let total_len = shared_secret_z
        .len()
        .checked_add(ephemeral_pk_bytes.len())
        .and_then(|len| len.checked_add(recipient_pk_bytes.len()))
        .ok_or(PkeError::SerializationError(
            "ECIES KDF transcript length overflows the platform address space",
        ))?;
    let mut transcript = Zeroizing::new(Vec::new());
    transcript
        .try_reserve_exact(total_len)
        .map_err(|_| PkeError::SerializationError("unable to allocate ECIES KDF transcript"))?;
    transcript.extend_from_slice(shared_secret_z);
    transcript.extend_from_slice(ephemeral_pk_bytes);
    transcript.extend_from_slice(recipient_pk_bytes);
    Ok(transcript)
}

/// Derives symmetric key from an ECDH shared secret using HKDF-SHA256.
pub(crate) fn derive_symmetric_key_hkdf_sha256(
    shared_secret_z: &[u8],
    ephemeral_pk_bytes: &[u8],
    recipient_pk_bytes: &[u8],
    key_output_len: usize,
    info: &[u8],
) -> PkeResult<Zeroizing<Vec<u8>>> {
    let transcript = kdf_transcript(shared_secret_z, ephemeral_pk_bytes, recipient_pk_bytes)?;
    let kdf = Hkdf::<Sha256>::new();
    let key = kdf
        .derive_key(&transcript, Some(KDF_SALT), Some(info), key_output_len)
        .map_err(PkeError::from)?;
    Ok(Zeroizing::new(key))
}

/// Derives symmetric key from an ECDH shared secret using HKDF-SHA384.
pub(crate) fn derive_symmetric_key_hkdf_sha384(
    shared_secret_z: &[u8],
    ephemeral_pk_bytes: &[u8],
    recipient_pk_bytes: &[u8],
    key_output_len: usize,
    info: &[u8],
) -> PkeResult<Zeroizing<Vec<u8>>> {
    let transcript = kdf_transcript(shared_secret_z, ephemeral_pk_bytes, recipient_pk_bytes)?;
    let kdf = Hkdf::<Sha384>::new();
    let key = kdf
        .derive_key(&transcript, Some(KDF_SALT), Some(info), key_output_len)
        .map_err(PkeError::from)?;
    Ok(Zeroizing::new(key))
}

/// Derives symmetric key from an ECDH shared secret using HKDF-SHA512.
pub(crate) fn derive_symmetric_key_hkdf_sha512(
    shared_secret_z: &[u8],
    ephemeral_pk_bytes: &[u8],
    recipient_pk_bytes: &[u8],
    key_output_len: usize,
    info: &[u8],
) -> PkeResult<Zeroizing<Vec<u8>>> {
    let transcript = kdf_transcript(shared_secret_z, ephemeral_pk_bytes, recipient_pk_bytes)?;
    let kdf = Hkdf::<Sha512>::new();
    let key = kdf
        .derive_key(&transcript, Some(KDF_SALT), Some(info), key_output_len)
        .map_err(PkeError::from)?;
    Ok(Zeroizing::new(key))
}

/// Internal structure for ECIES ciphertext components.
/// Format on wire: R_len (1 byte) || R || N_len (1 byte) || N || CT_len (4 bytes) || (C||T)
#[derive(Clone, Debug)]
pub(crate) struct EciesCiphertextComponents {
    pub ephemeral_public_key: Vec<u8>, // R
    pub aead_nonce: Vec<u8>,           // N
    pub aead_ciphertext_tag: Vec<u8>,  // C || T (AEAD output)
}

impl EciesCiphertextComponents {
    pub fn serialize(&self) -> PkeResult<Vec<u8>> {
        let r_len = self.ephemeral_public_key.len();
        let n_len = self.aead_nonce.len();
        let ct_t_len = self.aead_ciphertext_tag.len();

        if r_len > u8::MAX as usize {
            return Err(PkeError::SerializationError(
                "ephemeral public key exceeds the wire-format limit",
            ));
        }
        if n_len > u8::MAX as usize {
            return Err(PkeError::SerializationError(
                "AEAD nonce exceeds the wire-format limit",
            ));
        }
        if ct_t_len > u32::MAX as usize {
            return Err(PkeError::SerializationError(
                "AEAD payload exceeds the wire-format limit",
            ));
        }

        let total_len = 1usize
            .checked_add(r_len)
            .and_then(|len| len.checked_add(1))
            .and_then(|len| len.checked_add(n_len))
            .and_then(|len| len.checked_add(4))
            .and_then(|len| len.checked_add(ct_t_len))
            .ok_or(PkeError::SerializationError(
                "ECIES ciphertext length overflows the platform address space",
            ))?;
        let mut serialized = Vec::new();
        serialized
            .try_reserve_exact(total_len)
            .map_err(|_| PkeError::SerializationError("unable to allocate ECIES ciphertext"))?;

        serialized.push(r_len as u8);
        serialized.extend_from_slice(&self.ephemeral_public_key);

        serialized.push(n_len as u8);
        serialized.extend_from_slice(&self.aead_nonce);

        serialized.extend_from_slice(&(ct_t_len as u32).to_be_bytes());
        serialized.extend_from_slice(&self.aead_ciphertext_tag);
        Ok(serialized)
    }

    pub fn deserialize(bytes: &[u8]) -> PkeResult<Self> {
        if bytes.is_empty() {
            return Err(PkeError::InvalidCiphertextFormat(
                "empty input for deserialization",
            ));
        }
        let mut current_pos = 0;

        if bytes.len() < current_pos + 1 {
            return Err(PkeError::InvalidCiphertextFormat("R length truncated"));
        }
        let r_len = bytes[current_pos] as usize;
        current_pos += 1;
        let r_end = current_pos
            .checked_add(r_len)
            .ok_or(PkeError::InvalidCiphertextFormat(
                "R length overflows the platform address space",
            ))?;
        if bytes.len() < r_end {
            return Err(PkeError::InvalidCiphertextFormat("R data truncated"));
        }
        let r_start = current_pos;
        current_pos = r_end;

        if bytes.len() < current_pos + 1 {
            return Err(PkeError::InvalidCiphertextFormat("Nonce length truncated"));
        }
        let n_len = bytes[current_pos] as usize;
        current_pos += 1;
        let nonce_end = current_pos
            .checked_add(n_len)
            .ok_or(PkeError::InvalidCiphertextFormat(
                "nonce length overflows the platform address space",
            ))?;
        if bytes.len() < nonce_end {
            return Err(PkeError::InvalidCiphertextFormat("Nonce data truncated"));
        }
        let nonce_start = current_pos;
        current_pos = nonce_end;

        if bytes.len() < current_pos + 4 {
            return Err(PkeError::InvalidCiphertextFormat(
                "AEAD payload length truncated",
            ));
        }
        let ct_t_len = u32::from_be_bytes(
            bytes[current_pos..current_pos + 4]
                .try_into()
                .map_err(|_| {
                    PkeError::InvalidCiphertextFormat("Failed to read AEAD payload length")
                })?,
        ) as usize;
        current_pos += 4;

        let payload_end =
            current_pos
                .checked_add(ct_t_len)
                .ok_or(PkeError::InvalidCiphertextFormat(
                    "AEAD payload length overflows the platform address space",
                ))?;
        if bytes.len() < payload_end {
            return Err(PkeError::InvalidCiphertextFormat(
                "AEAD payload data truncated",
            ));
        }
        if payload_end != bytes.len() {
            return Err(PkeError::InvalidCiphertextFormat(
                "trailing data after deserialization",
            ));
        }

        // Perform no allocation until every declared length and the exact
        // frame boundary have been validated. Malformed input can therefore
        // allocate at most the caller-provided frame once it is accepted.
        let ephemeral_public_key = bytes[r_start..r_end].to_vec();
        let aead_nonce = bytes[nonce_start..nonce_end].to_vec();
        let aead_ciphertext_tag = bytes[current_pos..payload_end].to_vec();

        Ok(Self {
            ephemeral_public_key,
            aead_nonce,
            aead_ciphertext_tag,
        })
    }
}

#[cfg(test)]
mod framing_tests {
    use super::EciesCiphertextComponents;

    #[test]
    fn framing_roundtrip_is_exact() {
        let components = EciesCiphertextComponents {
            ephemeral_public_key: vec![4, 1, 2, 3],
            aead_nonce: vec![5; 12],
            aead_ciphertext_tag: vec![6; 31],
        };
        let encoded = components.serialize().unwrap();
        let decoded = EciesCiphertextComponents::deserialize(&encoded).unwrap();
        assert_eq!(
            decoded.ephemeral_public_key,
            components.ephemeral_public_key
        );
        assert_eq!(decoded.aead_nonce, components.aead_nonce);
        assert_eq!(decoded.aead_ciphertext_tag, components.aead_ciphertext_tag);
    }

    #[test]
    fn serializer_rejects_unrepresentable_component_lengths() {
        let oversized_key = EciesCiphertextComponents {
            ephemeral_public_key: vec![0; u8::MAX as usize + 1],
            aead_nonce: Vec::new(),
            aead_ciphertext_tag: Vec::new(),
        };
        assert!(oversized_key.serialize().is_err());

        let oversized_nonce = EciesCiphertextComponents {
            ephemeral_public_key: Vec::new(),
            aead_nonce: vec![0; u8::MAX as usize + 1],
            aead_ciphertext_tag: Vec::new(),
        };
        assert!(oversized_nonce.serialize().is_err());
    }

    #[test]
    fn decoder_rejects_truncation_and_trailing_data() {
        let truncated_payload = [0, 0, 0, 0, 0, 1];
        assert!(EciesCiphertextComponents::deserialize(&truncated_payload).is_err());

        let trailing_data = [0, 0, 0, 0, 0, 0, 1];
        assert!(EciesCiphertextComponents::deserialize(&trailing_data).is_err());

        let maximum_declared_payload = [0, 0, 0xff, 0xff, 0xff, 0xff];
        assert!(EciesCiphertextComponents::deserialize(&maximum_declared_payload).is_err());

        let mut maximum_key_then_truncated = vec![u8::MAX];
        maximum_key_then_truncated.extend_from_slice(&[0; u8::MAX as usize]);
        assert!(EciesCiphertextComponents::deserialize(&maximum_key_then_truncated).is_err());
    }
}
