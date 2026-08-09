// File: crates/hybrid/src/sign/rsa_falcon.rs

use dcrypt_api::{
    traits::{Serialize, SerializeSecret},
    Error, Result, Signature as SignatureTrait,
};
// use dcrypt_sign::traditional::rsa::RsaPss; // RsaPss not yet implemented/exposed in dcrypt-sign
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};
use dcrypt_sign::falcon::{Falcon512, FalconPublicKey, FalconSecretKey, FalconSignature};

// Stub for RsaPss until implemented in dcrypt-sign
// This prevents compilation errors while RsaPss is missing
pub struct RsaPss;
impl SignatureTrait for RsaPss {
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;
    type SignatureData = Vec<u8>;
    type KeyPair = (Vec<u8>, Vec<u8>);
    fn name() -> &'static str {
        "RSA-PSS-STUB"
    }
    fn keypair<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<Self::KeyPair> {
        Err(Error::NotImplemented {
            feature: "RSA-PSS key generation",
        })
    }
    fn public_key(kp: &Self::KeyPair) -> Self::PublicKey {
        kp.0.clone()
    }
    fn secret_key(kp: &Self::KeyPair) -> Self::SecretKey {
        kp.1.clone()
    }
    fn sign(_m: &[u8], _sk: &Self::SecretKey) -> Result<Self::SignatureData> {
        Err(Error::NotImplemented {
            feature: "RSA-PSS signing",
        })
    }
    fn verify(_m: &[u8], _s: &Self::SignatureData, _pk: &Self::PublicKey) -> Result<()> {
        Err(Error::NotImplemented {
            feature: "RSA-PSS verification",
        })
    }
}

/// Hybrid signature scheme combining RSA-PSS and Falcon-512
pub struct RsaFalconHybrid;

const HYBRID_PUBLIC_KEY_LABEL: &[u8] = b"dcrypt-hybrid-sig/rsa-pss+falcon-512/public/v1";
const HYBRID_SECRET_KEY_LABEL: &[u8] = b"dcrypt-hybrid-sig/rsa-pss+falcon-512/secret/v1";
const HYBRID_SIGNATURE_LABEL: &[u8] = b"dcrypt-hybrid-sig/rsa-pss+falcon-512/signature/v1";

#[derive(Clone)]
pub struct HybridPublicKey {
    rsa_pk: <RsaPss as SignatureTrait>::PublicKey,
    falcon_pk: <Falcon512 as SignatureTrait>::PublicKey,
}

impl Zeroize for HybridPublicKey {
    fn zeroize(&mut self) {
        self.rsa_pk.zeroize();
        self.falcon_pk.zeroize();
    }
}

#[derive(Clone)]
pub struct HybridSecretKey {
    rsa_sk: <RsaPss as SignatureTrait>::SecretKey,
    falcon_sk: <Falcon512 as SignatureTrait>::SecretKey,
}

impl Zeroize for HybridSecretKey {
    fn zeroize(&mut self) {
        self.rsa_sk.zeroize();
        self.falcon_sk.zeroize();
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
    rsa_sig: <RsaPss as SignatureTrait>::SignatureData,
    falcon_sig: <Falcon512 as SignatureTrait>::SignatureData,
}

impl HybridPublicKey {
    pub fn components(&self) -> (&Vec<u8>, &FalconPublicKey) {
        (&self.rsa_pk, &self.falcon_pk)
    }
}

impl HybridSecretKey {
    pub fn components(&self) -> (&Vec<u8>, &FalconSecretKey) {
        (&self.rsa_sk, &self.falcon_sk)
    }
}

impl HybridSignature {
    pub fn components(&self) -> (&Vec<u8>, &FalconSignature) {
        (&self.rsa_sig, &self.falcon_sig)
    }
}

impl Serialize for HybridPublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (rsa_bytes, falcon_bytes) = decode_framed(bytes, HYBRID_PUBLIC_KEY_LABEL)?;
        Ok(Self {
            rsa_pk: rsa_bytes.to_vec(),
            falcon_pk: FalconPublicKey(falcon_bytes.to_vec()),
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        encode_framed(
            HYBRID_PUBLIC_KEY_LABEL,
            &self.rsa_pk,
            self.falcon_pk.as_ref(),
        )
    }
}

impl SerializeSecret for HybridSecretKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (rsa_bytes, falcon_bytes) = decode_framed(bytes, HYBRID_SECRET_KEY_LABEL)?;
        Ok(Self {
            rsa_sk: rsa_bytes.to_vec(),
            falcon_sk: FalconSecretKey(falcon_bytes.to_vec()),
        })
    }

    fn to_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(encode_framed(
            HYBRID_SECRET_KEY_LABEL,
            &self.rsa_sk,
            self.falcon_sk.as_ref(),
        ))
    }
}

impl Serialize for HybridSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (rsa_bytes, falcon_bytes) = decode_framed(bytes, HYBRID_SIGNATURE_LABEL)?;
        Ok(Self {
            rsa_sig: rsa_bytes.to_vec(),
            falcon_sig: FalconSignature(falcon_bytes.to_vec()),
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        encode_framed(
            HYBRID_SIGNATURE_LABEL,
            &self.rsa_sig,
            self.falcon_sig.as_ref(),
        )
    }
}

impl SignatureTrait for RsaFalconHybrid {
    type PublicKey = HybridPublicKey;
    type SecretKey = HybridSecretKey;
    type SignatureData = HybridSignature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "RSA-PSS + Falcon-512 Hybrid"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self::KeyPair> {
        // Generate keypairs for both algorithms
        // RsaPss will return Error::NotImplemented, making this entire call safe
        let (rsa_pk, rsa_sk) = RsaPss::keypair(rng)?;
        let (falcon_pk, falcon_sk) = Falcon512::keypair(rng)?;

        let public_key = HybridPublicKey { rsa_pk, falcon_pk };

        let secret_key = HybridSecretKey { rsa_sk, falcon_sk };

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
        let rsa_sig = RsaPss::sign(message, &secret_key.rsa_sk)?;
        let falcon_sig = Falcon512::sign(message, &secret_key.falcon_sk)?;

        Ok(HybridSignature {
            rsa_sig,
            falcon_sig,
        })
    }

    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> Result<()> {
        // Verify both signatures
        RsaPss::verify(message, &signature.rsa_sig, &public_key.rsa_pk)?;
        Falcon512::verify(message, &signature.falcon_sig, &public_key.falcon_pk)?;

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
