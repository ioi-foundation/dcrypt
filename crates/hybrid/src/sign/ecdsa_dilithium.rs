// File: crates/hybrid/src/sign/ecdsa_dilithium.rs
//! ECDSA + Dilithium hybrid signature scheme
//!
//! This module implements a hybrid signature scheme that combines ECDSA and Dilithium.

use dcrypt_api::{
    error::Error,
    traits::{Serialize, SerializeSecret},
    Result, Signature as SignatureTrait,
};
use dcrypt_sign::dilithium::{
    Dilithium3, DilithiumPublicKey, DilithiumSecretKey, DilithiumSignatureData,
};
use dcrypt_sign::ecdsa::{EcdsaP384, EcdsaP384PublicKey, EcdsaP384SecretKey, EcdsaP384Signature};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Hybrid signature scheme combining ECDSA P-384 and Dilithium3
pub struct EcdsaDilithiumHybrid;

const HYBRID_PUBLIC_KEY_LABEL: &[u8] = b"dcrypt-hybrid-sig/ecdsa-p384+dilithium3/public/v1";
const HYBRID_SECRET_KEY_LABEL: &[u8] = b"dcrypt-hybrid-sig/ecdsa-p384+dilithium3/secret/v1";
const HYBRID_SIGNATURE_LABEL: &[u8] = b"dcrypt-hybrid-sig/ecdsa-p384+dilithium3/signature/v1";

#[derive(Clone, Zeroize)]
pub struct HybridPublicKey {
    ecdsa_pk: <EcdsaP384 as SignatureTrait>::PublicKey,
    dilithium_pk: <Dilithium3 as SignatureTrait>::PublicKey,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    ecdsa_sk: <EcdsaP384 as SignatureTrait>::SecretKey,
    dilithium_sk: <Dilithium3 as SignatureTrait>::SecretKey,
}

#[derive(Clone)]
pub struct HybridSignature {
    ecdsa_sig: <EcdsaP384 as SignatureTrait>::SignatureData,
    dilithium_sig: <Dilithium3 as SignatureTrait>::SignatureData,
}

impl HybridPublicKey {
    pub fn components(&self) -> (&EcdsaP384PublicKey, &DilithiumPublicKey) {
        (&self.ecdsa_pk, &self.dilithium_pk)
    }
}

impl HybridSecretKey {
    pub fn components(&self) -> (&EcdsaP384SecretKey, &DilithiumSecretKey) {
        (&self.ecdsa_sk, &self.dilithium_sk)
    }
}

impl HybridSignature {
    pub fn components(&self) -> (&EcdsaP384Signature, &DilithiumSignatureData) {
        (&self.ecdsa_sig, &self.dilithium_sig)
    }
}

impl Serialize for HybridPublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (ecdsa_bytes, dilithium_bytes) = decode_framed(bytes, HYBRID_PUBLIC_KEY_LABEL)?;
        Ok(Self {
            ecdsa_pk: EcdsaP384PublicKey::from_bytes(ecdsa_bytes)?,
            dilithium_pk: DilithiumPublicKey::from_bytes(dilithium_bytes).map_err(Error::from)?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        encode_framed(
            HYBRID_PUBLIC_KEY_LABEL,
            self.ecdsa_pk.to_bytes(),
            self.dilithium_pk.to_bytes(),
        )
    }
}

impl SerializeSecret for HybridSecretKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (ecdsa_bytes, dilithium_bytes) = decode_framed(bytes, HYBRID_SECRET_KEY_LABEL)?;
        Ok(Self {
            ecdsa_sk: EcdsaP384SecretKey::from_bytes(ecdsa_bytes)?,
            dilithium_sk: DilithiumSecretKey::from_bytes(dilithium_bytes).map_err(Error::from)?,
        })
    }

    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        let ecdsa_bytes = self.ecdsa_sk.to_bytes_zeroizing();
        let dilithium_bytes = self.dilithium_sk.to_bytes().to_vec();
        Zeroizing::new(encode_framed(
            HYBRID_SECRET_KEY_LABEL,
            &ecdsa_bytes,
            &dilithium_bytes,
        ))
    }
}

impl Serialize for HybridSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (ecdsa_bytes, dilithium_bytes) = decode_framed(bytes, HYBRID_SIGNATURE_LABEL)?;
        Ok(Self {
            ecdsa_sig: EcdsaP384Signature::from_bytes(ecdsa_bytes)?,
            dilithium_sig: DilithiumSignatureData::from_bytes(dilithium_bytes)
                .map_err(Error::from)?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        encode_framed(
            HYBRID_SIGNATURE_LABEL,
            self.ecdsa_sig.to_bytes(),
            self.dilithium_sig.to_bytes(),
        )
    }
}

impl SignatureTrait for EcdsaDilithiumHybrid {
    type PublicKey = HybridPublicKey;
    type SecretKey = HybridSecretKey;
    type SignatureData = HybridSignature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDSA-P384 + Dilithium3 Hybrid"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self::KeyPair> {
        // Generate keypairs for both algorithms
        let (ecdsa_pk, ecdsa_sk) = EcdsaP384::keypair(rng)?;
        let (dilithium_pk, dilithium_sk) = Dilithium3::keypair(rng)?;

        let public_key = HybridPublicKey {
            ecdsa_pk,
            dilithium_pk,
        };

        let secret_key = HybridSecretKey {
            ecdsa_sk,
            dilithium_sk,
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
        let dilithium_sig = Dilithium3::sign(message, &secret_key.dilithium_sk)?;

        Ok(HybridSignature {
            ecdsa_sig,
            dilithium_sig,
        })
    }

    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> Result<()> {
        // Verify both signatures
        EcdsaP384::verify(message, &signature.ecdsa_sig, &public_key.ecdsa_pk)?;
        Dilithium3::verify(message, &signature.dilithium_sig, &public_key.dilithium_pk)?;

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
    let first = bytes
        .get(pos..pos + first_len)
        .ok_or_else(|| Error::InvalidLength {
            context: "Hybrid signature decoding",
            expected: pos + first_len,
            actual: bytes.len(),
        })?;
    pos += first_len;

    let second_len = read_u32(bytes, &mut pos, "second component length")? as usize;
    let second = bytes
        .get(pos..pos + second_len)
        .ok_or_else(|| Error::InvalidLength {
            context: "Hybrid signature decoding",
            expected: pos + second_len,
            actual: bytes.len(),
        })?;
    pos += second_len;

    if pos != bytes.len() {
        return Err(Error::SerializationError {
            context: "Hybrid signature decoding",
            #[cfg(feature = "std")]
            message: "Trailing bytes after hybrid signature payload".to_string(),
        });
    }

    Ok((first, second))
}

fn read_u32(bytes: &[u8], pos: &mut usize, field: &'static str) -> Result<u32> {
    let end = *pos + 4;
    let len_bytes = bytes
        .get(*pos..end)
        .ok_or_else(|| Error::SerializationError {
            context: "Hybrid signature decoding",
            #[cfg(feature = "std")]
            message: format!("Missing {field}"),
        })?;
    *pos = end;
    Ok(u32::from_be_bytes(
        len_bytes.try_into().expect("slice length checked"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcrypt_api::Signature;
    use rand::rngs::OsRng;

    #[test]
    fn hybrid_signature_roundtrip_preserves_both_components() {
        let mut rng = OsRng;
        let message = b"hybrid signature framing test";
        let (pk, sk) = EcdsaDilithiumHybrid::keypair(&mut rng).unwrap();
        let sig = EcdsaDilithiumHybrid::sign(message, &sk).unwrap();

        let pk_bytes = pk.to_bytes();
        let sig_bytes = sig.to_bytes();
        let sk_bytes = sk.to_bytes_zeroizing();

        let decoded_pk = HybridPublicKey::from_bytes(&pk_bytes).unwrap();
        let decoded_sig = HybridSignature::from_bytes(&sig_bytes).unwrap();
        let decoded_sk = HybridSecretKey::from_bytes(&sk_bytes).unwrap();

        EcdsaDilithiumHybrid::verify(message, &decoded_sig, &decoded_pk).unwrap();
        let resigned = EcdsaDilithiumHybrid::sign(message, &decoded_sk).unwrap();
        EcdsaDilithiumHybrid::verify(message, &resigned, &decoded_pk).unwrap();

        assert!(pk_bytes.len() > pk.components().0.as_ref().len());
        assert!(sig_bytes.len() > sig.components().0.to_bytes().len());
    }
}
