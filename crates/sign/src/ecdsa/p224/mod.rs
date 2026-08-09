//! ECDSA implementation for NIST P-224 curve
//!
//! This implementation follows FIPS 186-4: Digital Signature Standard (DSS)
//! and SP 800-56A Rev. 3: Recommendation for Pair-Wise Key-Establishment Schemes
//! Using Discrete Logarithm Cryptography. SHA-224 is used as the hash function.

use crate::ecdsa::common::{
    bits2octets, is_canonical_nonzero_scalar, is_high_s, Rfc6979, SignatureComponents,
};
use alloc::vec::Vec;
use dcrypt_algorithms::ec::p224 as ec;
use dcrypt_algorithms::hash::sha2::Sha224;
use dcrypt_algorithms::hash::HashFunction;
use dcrypt_api::{
    error::Error as ApiError, Result as ApiResult, Signature as SignatureTrait, ZeroizingBytes,
};
use dcrypt_internal::{
    constant_time::ct_eq, zeroizing_bytes_from_slice, CryptoRng, RngCore, Zeroize, ZeroizeOnDrop,
    Zeroizing,
};
use dcrypt_params::traditional::ecdsa::NIST_P224;

/// ECDSA signature scheme using NIST P-224 curve (secp224r1)
pub struct EcdsaP224;

/// P-224 public key in uncompressed format (0x04 || X || Y)
#[derive(Clone)]
pub struct EcdsaP224PublicKey(pub(crate) [u8; ec::P224_POINT_UNCOMPRESSED_SIZE]);

/// P-224 secret key
#[derive(Clone)]
pub struct EcdsaP224SecretKey {
    raw: ec::Scalar,
    bytes: [u8; ec::P224_SCALAR_SIZE],
}

impl Zeroize for EcdsaP224SecretKey {
    fn zeroize(&mut self) {
        self.raw.zeroize();
        self.bytes.zeroize();
    }
}

impl Drop for EcdsaP224SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for EcdsaP224SecretKey {}

/// P-224 signature encoded in ASN.1 DER format
#[derive(Clone)]
pub struct EcdsaP224Signature(pub(crate) Vec<u8>);

// AsRef/AsMut implementations
impl AsRef<[u8]> for EcdsaP224PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for EcdsaP224PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl AsRef<[u8]> for EcdsaP224SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
// REMOVED: AsMut<[u8]> for EcdsaP224SecretKey to prevent direct mutation of secret key bytes

impl AsRef<[u8]> for EcdsaP224Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for EcdsaP224Signature {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl EcdsaP224PublicKey {
    /// Parse an uncompressed P-224 public key with on-curve validation.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        let point = ec::Point::deserialize_uncompressed(bytes).map_err(ApiError::from)?;
        if point.is_identity() {
            return Err(ApiError::InvalidParameter {
                context: "ECDSA-P224 public key",
                #[cfg(feature = "std")]
                message: "Identity is not a valid ECDSA public key".to_string(),
            });
        }
        Ok(Self(point.serialize_uncompressed()))
    }

    /// Return the SEC1 uncompressed encoding.
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl EcdsaP224SecretKey {
    /// Parse a canonical, nonzero P-224 secret scalar.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        let raw = ec::Scalar::deserialize(bytes).map_err(ApiError::from)?;
        let mut serialized = Zeroizing::new([0u8; ec::P224_SCALAR_SIZE]);
        serialized.copy_from_slice(bytes);
        Ok(Self {
            raw,
            bytes: serialized.into_inner(),
        })
    }

    /// Export the secret scalar in a zeroizing buffer.
    pub fn to_bytes_zeroizing(&self) -> ZeroizingBytes {
        zeroizing_bytes_from_slice(&self.bytes)
    }
}

impl EcdsaP224Signature {
    /// Parse a strictly encoded ASN.1 DER ECDSA signature.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        SignatureComponents::from_der(bytes)?;
        Ok(Self(bytes.to_vec()))
    }

    /// Return the DER encoding.
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SignatureTrait for EcdsaP224 {
    type PublicKey = EcdsaP224PublicKey;
    type SecretKey = EcdsaP224SecretKey;
    type SignatureData = EcdsaP224Signature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDSA-P224"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (sk_scalar, pk_point) = ec::generate_keypair(rng).map_err(ApiError::from)?;

        let sk_bytes = Zeroizing::new(sk_scalar.serialize());

        if sk_scalar.is_zero() {
            return Err(ApiError::InvalidParameter {
                context: "ECDSA-P224 keypair",
                #[cfg(feature = "std")]
                message: "Generated secret key is zero".to_string(),
            });
        }

        let secret_key = EcdsaP224SecretKey {
            raw: sk_scalar,
            bytes: sk_bytes.into_inner(),
        };
        let public_key = EcdsaP224PublicKey(pk_point.serialize_uncompressed());
        Ok((public_key, secret_key))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }
    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn sign(message: &[u8], secret_key: &Self::SecretKey) -> ApiResult<Self::SignatureData> {
        let mut hasher = Sha224::new();
        hasher.update(message).map_err(ApiError::from)?;
        let hash_output = hasher.finalize().map_err(ApiError::from)?;

        let z_octets = bits2octets(hash_output.as_ref(), &NIST_P224.n, 224)?;
        let z_bytes: [u8; ec::P224_SCALAR_SIZE] =
            (&z_octets[..])
                .try_into()
                .map_err(|_| ApiError::InvalidLength {
                    context: "ECDSA-P224 hash conversion",
                    expected: ec::P224_SCALAR_SIZE,
                    actual: z_octets.len(),
                })?;
        let z = ec::Scalar::from_bytes_reduced(z_bytes);

        let d = secret_key.raw.clone();
        let mut d_bytes = d.serialize();
        let nonces_result =
            Rfc6979::<Sha224>::new(&d_bytes, hash_output.as_ref(), &NIST_P224.n, 224);
        d_bytes.zeroize();
        let mut nonces = nonces_result?;

        loop {
            let mut nonce = nonces.next_nonce()?;
            let mut nonce_bytes: [u8; ec::P224_SCALAR_SIZE] =
                (&nonce[..])
                    .try_into()
                    .map_err(|_| ApiError::InvalidLength {
                        context: "ECDSA-P224 nonce",
                        expected: ec::P224_SCALAR_SIZE,
                        actual: nonce.len(),
                    })?;
            nonce.zeroize();
            let scalar = ec::Scalar::new(nonce_bytes).map_err(ApiError::from);
            nonce_bytes.zeroize();
            let k = scalar?;

            let kg = ec::scalar_mult_base_g(&k).map_err(ApiError::from)?;

            if kg.is_identity() {
                continue;
            }
            let r_bytes = kg.x_coordinate_bytes();

            let r = match reduce_bytes_to_scalar_p224(&r_bytes) {
                Ok(scalar) if !scalar.is_zero() => scalar,
                _ => continue,
            };

            let k_inv = k.inv_mod_n().map_err(ApiError::from)?;
            let rd = r.mul_mod_n(&d).map_err(ApiError::from)?;
            let z_plus_rd = z.add_mod_n(&rd).map_err(ApiError::from)?;
            let mut s = k_inv.mul_mod_n(&z_plus_rd).map_err(ApiError::from)?;

            if s.is_zero() {
                continue;
            }
            if is_high_s(&s.serialize(), &NIST_P224.n) {
                s = s.negate();
            }

            let sig_comps = SignatureComponents {
                r: r.serialize().to_vec(),
                s: s.serialize().to_vec(),
            };
            return Ok(EcdsaP224Signature(sig_comps.to_der()));
        }
    }

    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> ApiResult<()> {
        let sig_comps = SignatureComponents::from_der(&signature.0)?;

        if sig_comps.r.len() > ec::P224_SCALAR_SIZE || sig_comps.s.len() > ec::P224_SCALAR_SIZE {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA-P224 verify",
                #[cfg(feature = "std")]
                message: "Invalid signature component size".to_string(),
            });
        }

        let mut r_bytes = [0u8; ec::P224_SCALAR_SIZE];
        let mut s_bytes = [0u8; ec::P224_SCALAR_SIZE];
        let r_offset = ec::P224_SCALAR_SIZE.saturating_sub(sig_comps.r.len());
        let s_offset = ec::P224_SCALAR_SIZE.saturating_sub(sig_comps.s.len());
        r_bytes[r_offset..].copy_from_slice(&sig_comps.r);
        s_bytes[s_offset..].copy_from_slice(&sig_comps.s);

        if !is_canonical_nonzero_scalar(&r_bytes, &NIST_P224.n)
            || !is_canonical_nonzero_scalar(&s_bytes, &NIST_P224.n)
        {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA-P224 verify",
                #[cfg(feature = "std")]
                message: "signature components must be canonical integers in [1, n-1]".to_string(),
            });
        }

        let r = ec::Scalar::new(r_bytes).map_err(|_| ApiError::InvalidSignature {
            context: "ECDSA-P224 verify",
            #[cfg(feature = "std")]
            message: "Invalid r component".to_string(),
        })?;
        let s = ec::Scalar::new(s_bytes).map_err(|_| ApiError::InvalidSignature {
            context: "ECDSA-P224 verify",
            #[cfg(feature = "std")]
            message: "Invalid s component".to_string(),
        })?;
        if is_high_s(&s.serialize(), &NIST_P224.n) {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA-P224 verify",
                #[cfg(feature = "std")]
                message: "high-s signatures are non-canonical".to_string(),
            });
        }

        let mut hasher = Sha224::new();
        hasher.update(message).map_err(ApiError::from)?;
        let hash_output = hasher.finalize().map_err(ApiError::from)?;

        let z_octets = bits2octets(hash_output.as_ref(), &NIST_P224.n, 224)?;
        let z_bytes: [u8; ec::P224_SCALAR_SIZE] =
            (&z_octets[..])
                .try_into()
                .map_err(|_| ApiError::InvalidLength {
                    context: "ECDSA-P224 hash conversion",
                    expected: ec::P224_SCALAR_SIZE,
                    actual: z_octets.len(),
                })?;
        let z = ec::Scalar::from_bytes_reduced(z_bytes);

        let s_inv = s.inv_mod_n().map_err(ApiError::from)?;
        let u1 = z.mul_mod_n(&s_inv).map_err(ApiError::from)?;
        let u2 = r.mul_mod_n(&s_inv).map_err(ApiError::from)?;

        let q_point = ec::Point::deserialize_uncompressed(&public_key.0).map_err(ApiError::from)?;

        if q_point.is_identity() {
            return Err(ApiError::InvalidKey {
                context: "ECDSA-P224 verify",
                #[cfg(feature = "std")]
                message: "Public key is the point at infinity".to_string(),
            });
        }

        let u1g = ec::scalar_mult_base_g(&u1).map_err(ApiError::from)?;
        let u2q = ec::scalar_mult(&u2, &q_point).map_err(ApiError::from)?;

        let point = u1g.add(&u2q);

        if point.is_identity() {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA-P224 verify",
                #[cfg(feature = "std")]
                message: "Verification point is identity".to_string(),
            });
        }

        let x1_bytes = point.x_coordinate_bytes();
        let v = reduce_bytes_to_scalar_p224(&x1_bytes)?;

        if !ct_eq(r.serialize(), v.serialize()) {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA-P224 verify",
                #[cfg(feature = "std")]
                message: "Signature verification failed (r != v)".to_string(),
            });
        }
        Ok(())
    }
}

fn reduce_bytes_to_scalar_p224(bytes: &[u8; ec::P224_SCALAR_SIZE]) -> ApiResult<ec::Scalar> {
    Ok(ec::Scalar::from_bytes_reduced(*bytes))
}

#[cfg(test)]
mod tests;
