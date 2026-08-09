// File: crates/hybrid/src/sign/ecdsa_ml_dsa.rs
//! ECDSA P-384 + ML-DSA-65 hybrid signature scheme.
//!
//! Version 2 uses final FIPS 204 encodings. The historical version-1 framing,
//! which contained dcrypt's nonstandard pre-FIPS Dilithium objects, is rejected.

use alloc::vec::Vec;
use dcrypt_api::{
    error::Error,
    traits::{Serialize, SerializeSecret},
    Result, Signature as SignatureTrait,
};
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};
use dcrypt_sign::ecdsa::{EcdsaP384, EcdsaP384PublicKey, EcdsaP384SecretKey, EcdsaP384Signature};
use dcrypt_sign::mldsa::{MlDsa65, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};

/// Hybrid signature scheme combining ECDSA P-384 and FIPS 204 ML-DSA-65.
pub struct EcdsaMlDsa65Hybrid;

const HYBRID_PUBLIC_KEY_LABEL: &[u8] = b"dcrypt-hybrid-sig/ecdsa-p384+ml-dsa-65/public/v2";
const HYBRID_SECRET_KEY_LABEL: &[u8] = b"dcrypt-hybrid-sig/ecdsa-p384+ml-dsa-65/secret/v2";
const HYBRID_SIGNATURE_LABEL: &[u8] = b"dcrypt-hybrid-sig/ecdsa-p384+ml-dsa-65/signature/v2";

#[derive(Clone)]
pub struct HybridPublicKey {
    ecdsa_pk: <EcdsaP384 as SignatureTrait>::PublicKey,
    ml_dsa_pk: <MlDsa65 as SignatureTrait>::PublicKey,
}

#[derive(Clone)]
pub struct HybridSecretKey {
    ecdsa_sk: <EcdsaP384 as SignatureTrait>::SecretKey,
    ml_dsa_sk: <MlDsa65 as SignatureTrait>::SecretKey,
}

impl Zeroize for HybridSecretKey {
    fn zeroize(&mut self) {
        self.ecdsa_sk.zeroize();
        self.ml_dsa_sk.zeroize();
    }
}

impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for HybridSecretKey {}

#[derive(Clone)]
pub struct HybridSignature {
    ecdsa_sig: <EcdsaP384 as SignatureTrait>::SignatureData,
    ml_dsa_sig: <MlDsa65 as SignatureTrait>::SignatureData,
}

impl HybridPublicKey {
    pub fn components(&self) -> (&EcdsaP384PublicKey, &MlDsaPublicKey) {
        (&self.ecdsa_pk, &self.ml_dsa_pk)
    }
}

impl HybridSecretKey {
    pub fn components(&self) -> (&EcdsaP384SecretKey, &MlDsaSecretKey) {
        (&self.ecdsa_sk, &self.ml_dsa_sk)
    }
}

impl HybridSignature {
    pub fn components(&self) -> (&EcdsaP384Signature, &MlDsaSignature) {
        (&self.ecdsa_sig, &self.ml_dsa_sig)
    }
}

impl Serialize for HybridPublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (ecdsa_bytes, ml_dsa_bytes) = decode_framed(bytes, HYBRID_PUBLIC_KEY_LABEL)?;
        Ok(Self {
            ecdsa_pk: EcdsaP384PublicKey::from_bytes(ecdsa_bytes)?,
            ml_dsa_pk: MlDsaPublicKey::from_bytes(ml_dsa_bytes).map_err(Error::from)?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        encode_framed(
            HYBRID_PUBLIC_KEY_LABEL,
            self.ecdsa_pk.to_bytes(),
            self.ml_dsa_pk.to_bytes(),
        )
    }
}

impl SerializeSecret for HybridSecretKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (ecdsa_bytes, ml_dsa_bytes) = decode_framed(bytes, HYBRID_SECRET_KEY_LABEL)?;
        Ok(Self {
            ecdsa_sk: EcdsaP384SecretKey::from_bytes(ecdsa_bytes)?,
            ml_dsa_sk: MlDsaSecretKey::from_bytes(ml_dsa_bytes).map_err(Error::from)?,
        })
    }

    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        let ecdsa_bytes = self.ecdsa_sk.to_bytes_zeroizing();
        let ml_dsa_bytes = Zeroizing::new(self.ml_dsa_sk.to_bytes().to_vec());
        Zeroizing::new(encode_framed(
            HYBRID_SECRET_KEY_LABEL,
            &ecdsa_bytes,
            &ml_dsa_bytes,
        ))
    }
}

impl Serialize for HybridSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (ecdsa_bytes, ml_dsa_bytes) = decode_framed(bytes, HYBRID_SIGNATURE_LABEL)?;
        Ok(Self {
            ecdsa_sig: EcdsaP384Signature::from_bytes(ecdsa_bytes)?,
            ml_dsa_sig: MlDsaSignature::from_bytes(ml_dsa_bytes).map_err(Error::from)?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        encode_framed(
            HYBRID_SIGNATURE_LABEL,
            self.ecdsa_sig.to_bytes(),
            self.ml_dsa_sig.to_bytes(),
        )
    }
}

impl SignatureTrait for EcdsaMlDsa65Hybrid {
    type PublicKey = HybridPublicKey;
    type SecretKey = HybridSecretKey;
    type SignatureData = HybridSignature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDSA-P384 + ML-DSA-65 Hybrid"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self::KeyPair> {
        // Generate keypairs for both algorithms
        let (ecdsa_pk, ecdsa_sk) = EcdsaP384::keypair(rng)?;
        let (ml_dsa_pk, ml_dsa_sk) = MlDsa65::keypair(rng)?;

        let public_key = HybridPublicKey {
            ecdsa_pk,
            ml_dsa_pk,
        };

        let secret_key = HybridSecretKey {
            ecdsa_sk,
            ml_dsa_sk,
        };

        Ok((public_key, secret_key))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn sign(message: &[u8], secret_key: &Self::SecretKey) -> Result<Self::SignatureData> {
        // Sign with both algorithms
        let ecdsa_sig = EcdsaP384::sign(message, &secret_key.ecdsa_sk)?;
        let ml_dsa_sig = MlDsa65::sign(message, &secret_key.ml_dsa_sk)?;

        Ok(HybridSignature {
            ecdsa_sig,
            ml_dsa_sig,
        })
    }

    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> Result<()> {
        // Verify both signatures
        EcdsaP384::verify(message, &signature.ecdsa_sig, &public_key.ecdsa_pk)?;
        MlDsa65::verify(message, &signature.ml_dsa_sig, &public_key.ml_dsa_pk)?;

        // If both verifications pass, return Ok
        Ok(())
    }
}

fn encode_framed(label: &[u8], first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + label.len() + 8 + first.len() + second.len());
    out.push(label.len() as u8);
    out.extend_from_slice(label);
    out.extend_from_slice(&(first.len() as u32).to_be_bytes());
    out.extend_from_slice(first);
    out.extend_from_slice(&(second.len() as u32).to_be_bytes());
    out.extend_from_slice(second);
    out
}

fn decode_framed<'a>(bytes: &'a [u8], expected_label: &[u8]) -> Result<(&'a [u8], &'a [u8])> {
    let label_len = *bytes.first().ok_or_else(|| Error::SerializationError {
        context: "Hybrid signature decoding",
        #[cfg(feature = "std")]
        message: "Missing hybrid signature label".to_string(),
    })? as usize;

    let label_end = 1 + label_len;
    let label = bytes
        .get(1..label_end)
        .ok_or_else(|| Error::SerializationError {
            context: "Hybrid signature decoding",
            #[cfg(feature = "std")]
            message: "Truncated hybrid signature label".to_string(),
        })?;

    if label != expected_label {
        return Err(Error::SerializationError {
            context: "Hybrid signature decoding",
            #[cfg(feature = "std")]
            message: "Unexpected hybrid signature framing label".to_string(),
        });
    }

    let mut pos = label_end;
    let first_len = read_u32(bytes, &mut pos, "first component length")? as usize;
    let first_end = pos
        .checked_add(first_len)
        .ok_or_else(|| Error::SerializationError {
            context: "Hybrid signature decoding",
            #[cfg(feature = "std")]
            message: "First component length overflows the platform address space".to_string(),
        })?;
    let first = bytes
        .get(pos..first_end)
        .ok_or_else(|| Error::InvalidLength {
            context: "Hybrid signature decoding",
            expected: first_end,
            actual: bytes.len(),
        })?;
    pos = first_end;

    let second_len = read_u32(bytes, &mut pos, "second component length")? as usize;
    let second_end = pos
        .checked_add(second_len)
        .ok_or_else(|| Error::SerializationError {
            context: "Hybrid signature decoding",
            #[cfg(feature = "std")]
            message: "Second component length overflows the platform address space".to_string(),
        })?;
    let second = bytes
        .get(pos..second_end)
        .ok_or_else(|| Error::InvalidLength {
            context: "Hybrid signature decoding",
            expected: second_end,
            actual: bytes.len(),
        })?;
    pos = second_end;

    if pos != bytes.len() {
        return Err(Error::SerializationError {
            context: "Hybrid signature decoding",
            #[cfg(feature = "std")]
            message: "Trailing bytes after hybrid signature payload".to_string(),
        });
    }

    Ok((first, second))
}

fn read_u32(bytes: &[u8], pos: &mut usize, _field: &'static str) -> Result<u32> {
    let end = pos
        .checked_add(4)
        .ok_or_else(|| Error::SerializationError {
            context: "Hybrid signature decoding",
            #[cfg(feature = "std")]
            message: format!("{_field} offset overflows the platform address space"),
        })?;
    let len_bytes = bytes
        .get(*pos..end)
        .ok_or_else(|| Error::SerializationError {
            context: "Hybrid signature decoding",
            #[cfg(feature = "std")]
            message: format!("Missing {_field}"),
        })?;
    *pos = end;
    Ok(u32::from_be_bytes(
        len_bytes.try_into().expect("slice length checked"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_rng::TestRng;
    use dcrypt_api::Signature;

    #[test]
    fn hybrid_signature_roundtrip_preserves_both_components() {
        let mut rng = TestRng;
        let message = b"hybrid signature framing test";
        let (pk, sk) = EcdsaMlDsa65Hybrid::keypair(&mut rng).unwrap();
        let sig = EcdsaMlDsa65Hybrid::sign(message, &sk).unwrap();

        let pk_bytes = pk.to_bytes();
        let sig_bytes = sig.to_bytes();
        let sk_bytes = sk.to_bytes_zeroizing();

        let decoded_pk = HybridPublicKey::from_bytes(&pk_bytes).unwrap();
        let decoded_sig = HybridSignature::from_bytes(&sig_bytes).unwrap();
        let decoded_sk = HybridSecretKey::from_bytes(&sk_bytes).unwrap();

        EcdsaMlDsa65Hybrid::verify(message, &decoded_sig, &decoded_pk).unwrap();
        let resigned = EcdsaMlDsa65Hybrid::sign(message, &decoded_sk).unwrap();
        EcdsaMlDsa65Hybrid::verify(message, &resigned, &decoded_pk).unwrap();

        assert!(pk_bytes.len() > pk.components().0.as_ref().len());
        assert!(sig_bytes.len() > sig.components().0.to_bytes().len());
    }

    #[test]
    fn version_one_nonstandard_dilithium_framing_is_rejected() {
        let mut rng = TestRng;
        let message = b"legacy hybrid framing rejection";
        let (pk, sk) = EcdsaMlDsa65Hybrid::keypair(&mut rng).unwrap();
        let sig = EcdsaMlDsa65Hybrid::sign(message, &sk).unwrap();

        let legacy_pk = encode_framed(
            b"dcrypt-hybrid-sig/ecdsa-p384+dilithium3/public/v1",
            pk.components().0.to_bytes(),
            pk.components().1.to_bytes(),
        );
        let legacy_sig = encode_framed(
            b"dcrypt-hybrid-sig/ecdsa-p384+dilithium3/signature/v1",
            sig.components().0.to_bytes(),
            sig.components().1.to_bytes(),
        );
        let ecdsa_secret = sk.components().0.to_bytes_zeroizing();
        let legacy_sk = encode_framed(
            b"dcrypt-hybrid-sig/ecdsa-p384+dilithium3/secret/v1",
            &ecdsa_secret,
            sk.components().1.to_bytes(),
        );

        assert!(HybridPublicKey::from_bytes(&legacy_pk).is_err());
        assert!(HybridSignature::from_bytes(&legacy_sig).is_err());
        assert!(HybridSecretKey::from_bytes(&legacy_sk).is_err());
    }

    #[test]
    fn malformed_component_lengths_are_rejected_without_overflow() {
        let mut oversized_first = Vec::new();
        oversized_first.push(HYBRID_PUBLIC_KEY_LABEL.len() as u8);
        oversized_first.extend_from_slice(HYBRID_PUBLIC_KEY_LABEL);
        oversized_first.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(HybridPublicKey::from_bytes(&oversized_first).is_err());

        let mut oversized_second = Vec::new();
        oversized_second.push(HYBRID_PUBLIC_KEY_LABEL.len() as u8);
        oversized_second.extend_from_slice(HYBRID_PUBLIC_KEY_LABEL);
        oversized_second.extend_from_slice(&0u32.to_be_bytes());
        oversized_second.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(HybridPublicKey::from_bytes(&oversized_second).is_err());

        let mut impossible_offset = usize::MAX - 2;
        assert!(read_u32(&[], &mut impossible_offset, "test length").is_err());
        assert_eq!(impossible_offset, usize::MAX - 2);
    }
}
