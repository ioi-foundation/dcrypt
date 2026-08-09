//! Elliptic Curve Integrated Encryption Scheme (ECIES) generic components.

use crate::error::{Error as PkeError, Result as PkeResult};
use dcrypt_algorithms::hash::sha2::{Sha256, Sha384, Sha512}; // Added Sha512
use dcrypt_algorithms::kdf::hkdf::Hkdf;
use dcrypt_algorithms::kdf::KeyDerivationFunction; // Use PKE specific Result/Error

// Ensure Vec, String, format are available for no_std + alloc
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::format;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::string::String;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

// Declare submodules
pub mod p192; // Added P-192 module
pub mod p224;
pub mod p256;
pub mod p384;
pub mod p521;

// Re-export the main structs
pub use p192::EciesP192; // Added P-192 export
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

/// Derives symmetric key from an ECDH shared secret using HKDF-SHA256.
pub(crate) fn derive_symmetric_key_hkdf_sha256(
    shared_secret_z: &[u8],    // x-coordinate of shared point
    ephemeral_pk_bytes: &[u8], // Ephemeral public key R (salt for HKDF)
    key_output_len: usize,     // Length of the symmetric key to derive
    info: Option<&[u8]>,
) -> PkeResult<Vec<u8>> {
    let kdf = Hkdf::<Sha256>::new();
    kdf.derive_key(
        shared_secret_z,
        Some(ephemeral_pk_bytes),
        info,
        key_output_len,
    )
    .map_err(PkeError::from)
}

/// Derives symmetric key from an ECDH shared secret using HKDF-SHA384.
pub(crate) fn derive_symmetric_key_hkdf_sha384(
    shared_secret_z: &[u8],
    ephemeral_pk_bytes: &[u8],
    key_output_len: usize,
    info: Option<&[u8]>,
) -> PkeResult<Vec<u8>> {
    let kdf = Hkdf::<Sha384>::new();
    kdf.derive_key(
        shared_secret_z,
        Some(ephemeral_pk_bytes),
        info,
        key_output_len,
    )
    .map_err(PkeError::from)
}

/// Derives symmetric key from an ECDH shared secret using HKDF-SHA512.
pub(crate) fn derive_symmetric_key_hkdf_sha512(
    shared_secret_z: &[u8],
    ephemeral_pk_bytes: &[u8],
    key_output_len: usize,
    info: Option<&[u8]>,
) -> PkeResult<Vec<u8>> {
    let kdf = Hkdf::<Sha512>::new();
    kdf.derive_key(
        shared_secret_z,
        Some(ephemeral_pk_bytes),
        info,
        key_output_len,
    )
    .map_err(PkeError::from)
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
        let ephemeral_public_key = bytes[current_pos..r_end].to_vec();
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
        let aead_nonce = bytes[current_pos..nonce_end].to_vec();
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
        let aead_ciphertext_tag = bytes[current_pos..payload_end].to_vec();
        current_pos = payload_end;

        if current_pos != bytes.len() {
            return Err(PkeError::InvalidCiphertextFormat(
                "trailing data after deserialization",
            ));
        }

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
    }
}
