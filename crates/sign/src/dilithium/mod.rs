//! FIPS 204 Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
//!
//! Key generation, signing, and verification use the portable
//! [`libcrux_ml_dsa`] backend. Its field arithmetic, NTT polynomial arithmetic,
//! and serialization have machine-checked proofs. Dcrypt supplies its existing
//! high-level wrapper types and the [`dcrypt_api::Signature`] adapter. Public
//! keys, expanded private keys, and signatures use Algorithms 22, 24, and 26 of
//! final FIPS 204 exactly. Expanded-key interoperability is checked against an
//! independent implementation in tests; no secondary implementation processes
//! untrusted keys at runtime.
//!
//! The historical `Dilithium2`, `Dilithium3`, and `Dilithium5` type names remain
//! as source-compatible aliases for `MlDsa44`, `MlDsa65`, and `MlDsa87`. They do
//! not select the removed pre-FIPS dcrypt implementation.

use crate::error::Error as SignError;
#[cfg(not(feature = "std"))]
use alloc::{format, string::ToString, vec::Vec};
use core::{fmt, marker::PhantomData};
use dcrypt_algorithms::hash::{HashFunction, Shake256};
use dcrypt_api::{Result as ApiResult, Signature as SignatureTrait};
use dcrypt_params::pqc::dilithium::{
    Dilithium2Params, Dilithium3Params, Dilithium5Params, DilithiumSchemeParams,
};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// ML-DSA public key encoded with FIPS 204 Algorithm 22 (`pkEncode`).
#[derive(Clone, Debug, Zeroize)]
pub struct DilithiumPublicKey(pub(crate) Vec<u8>);

/// ML-DSA expanded private key encoded with FIPS 204 Algorithm 24 (`skEncode`).
///
/// In particular, bytes `64..128` contain the complete 64-byte `tr = H(pk, 64)`
/// value. Bare bytes do not carry a format version, so use paired import or
/// external provenance/framing when distinguishing affected legacy objects.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DilithiumSecretKey {
    bytes: Vec<u8>,
    public_key: Option<Vec<u8>>,
}

/// ML-DSA signature encoded with FIPS 204 Algorithm 26 (`sigEncode`).
#[derive(Clone, Debug)]
pub struct DilithiumSignatureData(pub(crate) Vec<u8>);

/// Standards-oriented spelling of [`DilithiumPublicKey`].
pub type MlDsaPublicKey = DilithiumPublicKey;
/// Standards-oriented spelling of [`DilithiumSecretKey`].
pub type MlDsaSecretKey = DilithiumSecretKey;
/// Standards-oriented spelling of [`DilithiumSignatureData`].
pub type MlDsaSignature = DilithiumSignatureData;

impl fmt::Debug for DilithiumSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DilithiumSecretKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl AsRef<[u8]> for DilithiumPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for DilithiumPublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for DilithiumSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for DilithiumSignatureData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for DilithiumSignatureData {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl DilithiumSecretKey {
    /// Decode a syntactically valid final-FIPS-204 expanded private key.
    ///
    /// An expanded private-key encoding does not carry enough information for
    /// this backend to derive and validate its public key without reintroducing
    /// a second secret-arithmetic implementation. Use
    /// [`Self::from_bytes_with_public_key`] when the corresponding public key is
    /// available. A key decoded with this method can sign, but
    /// [`Self::public_key`] returns an error instead of guessing or panicking.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        match bytes.len() {
            2560 => Dilithium2Params::validate_secret_key(bytes)?,
            4032 => Dilithium3Params::validate_secret_key(bytes)?,
            4896 => Dilithium5Params::validate_secret_key(bytes)?,
            _ => {
                return Err(SignError::Deserialization(format!(
                    "invalid ML-DSA expanded private key size: {} bytes",
                    bytes.len()
                )))
            }
        }

        Ok(Self {
            bytes: bytes.to_vec(),
            public_key: None,
        })
    }

    /// Decode an expanded private key and validate it against its public key.
    ///
    /// Besides the exact FIPS 204 encodings, this checks the stored 64-byte
    /// `tr`, then performs a deterministic sign/verify coherence check through
    /// the libcrux backend. This is the preferred import API.
    pub fn from_bytes_with_public_key(
        bytes: &[u8],
        public_key: &DilithiumPublicKey,
    ) -> Result<Self, SignError> {
        match bytes.len() {
            2560 => Dilithium2Params::validate_key_pair(bytes, public_key.as_ref())?,
            4032 => Dilithium3Params::validate_key_pair(bytes, public_key.as_ref())?,
            4896 => Dilithium5Params::validate_key_pair(bytes, public_key.as_ref())?,
            _ => {
                return Err(SignError::Deserialization(format!(
                    "invalid ML-DSA expanded private key size: {} bytes",
                    bytes.len()
                )))
            }
        }

        Ok(Self {
            bytes: bytes.to_vec(),
            public_key: Some(public_key.as_ref().to_vec()),
        })
    }

    /// Return the exact FIPS 204 expanded private-key encoding.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the public key retained at generation or paired import time.
    pub fn public_key(&self) -> Result<DilithiumPublicKey, SignError> {
        self.public_key
            .as_ref()
            .cloned()
            .map(DilithiumPublicKey)
            .ok_or_else(|| {
                SignError::InvalidKey(
                    "public-key derivation is unavailable for an unpaired imported ML-DSA expanded key; import with from_bytes_with_public_key"
                        .to_string(),
                )
            })
    }
}

impl DilithiumPublicKey {
    /// Decode and validate a final-FIPS-204 public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        match bytes.len() {
            1312 => Dilithium2Params::validate_public_key(bytes)?,
            1952 => Dilithium3Params::validate_public_key(bytes)?,
            2592 => Dilithium5Params::validate_public_key(bytes)?,
            _ => {
                return Err(SignError::Deserialization(format!(
                    "invalid ML-DSA public key size: {} bytes",
                    bytes.len()
                )))
            }
        }

        Ok(Self(bytes.to_vec()))
    }

    /// Return the exact FIPS 204 public-key encoding.
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl DilithiumSignatureData {
    /// Decode a final-FIPS-204 signature and enforce canonical hint encoding.
    ///
    /// Duplicate or unsorted hint indices, non-monotonic hint boundaries, and
    /// nonzero unused hint bytes are rejected here and again during verification.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        match bytes.len() {
            2420 => validate_hint_encoding(bytes, 32 + 4 * 576, 80, 4)?,
            3309 => validate_hint_encoding(bytes, 48 + 5 * 640, 55, 6)?,
            4627 => validate_hint_encoding(bytes, 64 + 7 * 640, 75, 8)?,
            _ => {
                return Err(SignError::InvalidSignatureSize {
                    expected: 0,
                    actual: bytes.len(),
                })
            }
        }

        Ok(Self(bytes.to_vec()))
    }

    /// Return the exact FIPS 204 signature encoding.
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn validate_hint_encoding(
    signature: &[u8],
    hint_offset: usize,
    omega: usize,
    k: usize,
) -> Result<(), SignError> {
    let hint = signature
        .get(hint_offset..)
        .ok_or_else(|| SignError::Deserialization("truncated ML-DSA hint".to_string()))?;
    if hint.len() != omega + k {
        return Err(SignError::Deserialization(
            "invalid ML-DSA hint length".to_string(),
        ));
    }

    let (indices, boundaries) = hint.split_at(omega);
    let mut start = 0usize;
    for &boundary in boundaries {
        let end = usize::from(boundary);
        if end < start || end > omega {
            return Err(SignError::Deserialization(
                "non-monotonic ML-DSA hint boundaries".to_string(),
            ));
        }
        if !indices[start..end].windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(SignError::Deserialization(
                "duplicate or unsorted ML-DSA hint indices".to_string(),
            ));
        }
        start = end;
    }

    if indices[start..].iter().any(|&byte| byte != 0) {
        return Err(SignError::Deserialization(
            "nonzero unused ML-DSA hint bytes".to_string(),
        ));
    }

    Ok(())
}

/// Internal adapter implemented only for the three parameter sets standardized
/// by FIPS 204. It is public solely because it appears in a public trait impl.
#[doc(hidden)]
pub trait MlDsaBackend: DilithiumSchemeParams {
    fn validate_public_key(bytes: &[u8]) -> Result<(), SignError>;
    fn validate_secret_key(bytes: &[u8]) -> Result<(), SignError>;
    fn validate_key_pair(secret_key: &[u8], public_key: &[u8]) -> Result<(), SignError>;
    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>), SignError>;
    fn sign_with_rng<R: CryptoRng + RngCore>(
        message: &[u8],
        secret_key: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, SignError>;
    fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), SignError>;
}

fn fixed_array<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], SignError> {
    bytes.try_into().map_err(|_| {
        SignError::Deserialization(format!(
            "invalid {what} size: expected {N}, got {}",
            bytes.len()
        ))
    })
}

fn validate_expanded_secret_encoding(
    bytes: &[u8],
    eta: u16,
    k: usize,
    l: usize,
) -> Result<(), SignError> {
    let bits_per_coefficient = if eta == 2 { 3 } else { 4 };
    let packed_secret_len = (k + l) * 256 * bits_per_coefficient / 8;
    let packed_secret = bytes
        .get(128..128 + packed_secret_len)
        .ok_or_else(|| SignError::InvalidKey("truncated ML-DSA private key".to_string()))?;
    let maximum = eta * 2;

    for coefficient in 0..((k + l) * 256) {
        let bit_offset = coefficient * bits_per_coefficient;
        let byte_offset = bit_offset / 8;
        let shift = bit_offset % 8;
        let mut window = u32::from(packed_secret[byte_offset]);
        if let Some(&next) = packed_secret.get(byte_offset + 1) {
            window |= u32::from(next) << 8;
        }
        let value = (window >> shift) & ((1u32 << bits_per_coefficient) - 1);
        if value > u32::from(maximum) {
            return Err(SignError::InvalidKey(
                "ML-DSA private key contains an out-of-range s1/s2 coefficient".to_string(),
            ));
        }
    }

    Ok(())
}

macro_rules! impl_mldsa_backend {
    (
        $params:ty,
        $module:ident,
        $verification_key:ident,
        $signing_key:ident,
        $signature:ident,
        $pk_len:expr,
        $sk_len:expr,
        $sig_len:expr,
        $eta:expr,
        $k:expr,
        $l:expr
    ) => {
        impl MlDsaBackend for $params {
            fn validate_public_key(bytes: &[u8]) -> Result<(), SignError> {
                // pkEncode uses rho followed by fixed-width t1 coefficients, so
                // every exactly sized bit string is a canonical syntactic
                // encoding. Semantic validity is enforced during verification.
                let _ = fixed_array::<$pk_len>(bytes, "ML-DSA public key")?;
                Ok(())
            }

            fn validate_secret_key(bytes: &[u8]) -> Result<(), SignError> {
                let encoded = Zeroizing::new(fixed_array::<$sk_len>(
                    bytes,
                    "ML-DSA expanded private key",
                )?);
                validate_expanded_secret_encoding(encoded.as_ref(), $eta, $k, $l)?;
                Ok(())
            }

            fn validate_key_pair(
                secret_key: &[u8],
                public_key: &[u8],
            ) -> Result<(), SignError> {
                Self::validate_secret_key(secret_key)?;
                Self::validate_public_key(public_key)?;

                let encoded_secret = Zeroizing::new(fixed_array::<$sk_len>(
                    secret_key,
                    "ML-DSA expanded private key",
                )?);
                let encoded_public = fixed_array::<$pk_len>(public_key, "ML-DSA public key")?;
                let expected_tr = Shake256::digest(&encoded_public)
                    .map_err(|error| SignError::Hashing(error.to_string()))?;
                if encoded_secret[64..128] != expected_tr.as_ref()[..] {
                    return Err(SignError::InvalidKey(
                        "ML-DSA private key tr does not match SHAKE256(pk, 64)".to_string(),
                    ));
                }

                let mut secret =
                    libcrux_ml_dsa::$module::$signing_key::new(*encoded_secret);
                let validation_signature = libcrux_ml_dsa::$module::portable::sign(
                    &secret,
                    b"dcrypt ML-DSA expanded-key import validation",
                    &[],
                    [0xA5; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE],
                );
                secret.as_mut_slice().zeroize();
                let validation_signature = validation_signature.map_err(|details| {
                    SignError::InvalidKey(format!(
                        "ML-DSA expanded key cannot produce a validation signature: {details:?}"
                    ))
                })?;

                let public =
                    libcrux_ml_dsa::$module::$verification_key::new(encoded_public);
                libcrux_ml_dsa::$module::portable::verify(
                    &public,
                    b"dcrypt ML-DSA expanded-key import validation",
                    &[],
                    &validation_signature,
                )
                .map_err(|details| {
                    SignError::InvalidKey(format!(
                        "ML-DSA expanded private/public key mismatch: {details:?}"
                    ))
                })
            }

            fn keypair<R: CryptoRng + RngCore>(
                rng: &mut R,
            ) -> Result<(Vec<u8>, Vec<u8>), SignError> {
                let mut seed = Zeroizing::new([
                    0u8;
                    libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE
                ]);
                rng.try_fill_bytes(seed.as_mut()).map_err(|details| {
                    SignError::KeyGeneration {
                        algorithm: <$params>::NAME,
                        details: details.to_string(),
                    }
                })?;

                let mut keypair =
                    libcrux_ml_dsa::$module::portable::generate_key_pair(*seed);
                let public = keypair.verification_key.as_slice().to_vec();
                let secret = keypair.signing_key.as_slice().to_vec();
                keypair.signing_key.as_mut_slice().zeroize();
                Ok((public, secret))
            }

            fn sign_with_rng<R: CryptoRng + RngCore>(
                message: &[u8],
                secret_key: &[u8],
                rng: &mut R,
            ) -> Result<Vec<u8>, SignError> {
                let encoded = Zeroizing::new(fixed_array::<$sk_len>(
                    secret_key,
                    "ML-DSA expanded private key",
                )?);
                let mut randomness =
                    Zeroizing::new([0u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE]);
                rng.try_fill_bytes(randomness.as_mut()).map_err(|details| {
                    SignError::SignatureGeneration {
                        algorithm: <$params>::NAME,
                        details: details.to_string(),
                    }
                })?;

                let mut secret =
                    libcrux_ml_dsa::$module::$signing_key::new(*encoded);
                let signature = libcrux_ml_dsa::$module::portable::sign(
                    &secret,
                    message,
                    &[],
                    *randomness,
                );
                secret.as_mut_slice().zeroize();
                let signature = signature.map_err(|details| {
                    SignError::SignatureGeneration {
                        algorithm: <$params>::NAME,
                        details: format!("{details:?}"),
                    }
                })?;
                Ok(signature.as_slice().to_vec())
            }

            fn verify(
                message: &[u8],
                signature: &[u8],
                public_key: &[u8],
            ) -> Result<(), SignError> {
                let encoded_key = fixed_array::<$pk_len>(public_key, "ML-DSA public key")?;
                let encoded_signature = fixed_array::<$sig_len>(signature, "ML-DSA signature")?;
                let public =
                    libcrux_ml_dsa::$module::$verification_key::new(encoded_key);
                let signature =
                    libcrux_ml_dsa::$module::$signature::new(encoded_signature);

                libcrux_ml_dsa::$module::portable::verify(
                    &public,
                    message,
                    &[],
                    &signature,
                )
                .map_err(|details| SignError::Verification {
                        algorithm: <$params>::NAME,
                        details: format!("ML-DSA signature verification failed: {details:?}"),
                    })
            }
        }
    };
}

impl_mldsa_backend!(
    Dilithium2Params,
    ml_dsa_44,
    MLDSA44VerificationKey,
    MLDSA44SigningKey,
    MLDSA44Signature,
    1312,
    2560,
    2420,
    2,
    4,
    4
);
impl_mldsa_backend!(
    Dilithium3Params,
    ml_dsa_65,
    MLDSA65VerificationKey,
    MLDSA65SigningKey,
    MLDSA65Signature,
    1952,
    4032,
    3309,
    4,
    6,
    5
);
impl_mldsa_backend!(
    Dilithium5Params,
    ml_dsa_87,
    MLDSA87VerificationKey,
    MLDSA87SigningKey,
    MLDSA87Signature,
    2592,
    4896,
    4627,
    2,
    8,
    7
);

/// ML-DSA signature scheme parameterized by a final FIPS 204 parameter set.
pub struct Dilithium<P: DilithiumSchemeParams + 'static> {
    _params: PhantomData<P>,
}

impl<P> Dilithium<P>
where
    P: MlDsaBackend + Send + Sync + 'static,
{
    /// Generate a randomized FIPS 204 signature with an explicit caller RNG.
    ///
    /// The [`dcrypt_api::Signature::sign`] implementation delegates to this
    /// method with the operating system RNG.
    pub fn sign_with_rng<R: CryptoRng + RngCore>(
        message: &[u8],
        secret_key: &DilithiumSecretKey,
        rng: &mut R,
    ) -> ApiResult<DilithiumSignatureData> {
        let signature =
            P::sign_with_rng(message, secret_key.as_ref(), rng).map_err(dcrypt_api::Error::from)?;
        Ok(DilithiumSignatureData(signature))
    }
}

impl<P> SignatureTrait for Dilithium<P>
where
    P: MlDsaBackend + Send + Sync + 'static,
{
    type PublicKey = DilithiumPublicKey;
    type SecretKey = DilithiumSecretKey;
    type SignatureData = DilithiumSignatureData;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        P::NAME
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (public, secret) = P::keypair(rng).map_err(dcrypt_api::Error::from)?;
        Ok((
            DilithiumPublicKey(public.clone()),
            DilithiumSecretKey {
                bytes: secret,
                public_key: Some(public),
            },
        ))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn sign(message: &[u8], secret_key: &Self::SecretKey) -> ApiResult<Self::SignatureData> {
        Self::sign_with_rng(message, secret_key, &mut rand::rngs::OsRng)
    }

    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> ApiResult<()> {
        validate_hint_encoding_for_len(signature.as_ref()).map_err(dcrypt_api::Error::from)?;
        P::verify(message, signature.as_ref(), public_key.as_ref()).map_err(dcrypt_api::Error::from)
    }
}

fn validate_hint_encoding_for_len(signature: &[u8]) -> Result<(), SignError> {
    match signature.len() {
        2420 => validate_hint_encoding(signature, 32 + 4 * 576, 80, 4),
        3309 => validate_hint_encoding(signature, 48 + 5 * 640, 55, 6),
        4627 => validate_hint_encoding(signature, 64 + 7 * 640, 75, 8),
        actual => Err(SignError::InvalidSignatureSize {
            expected: 0,
            actual,
        }),
    }
}

/// ML-DSA-44 (FIPS 204 security category 2).
pub type MlDsa44 = Dilithium<Dilithium2Params>;
/// ML-DSA-65 (FIPS 204 security category 3).
pub type MlDsa65 = Dilithium<Dilithium3Params>;
/// ML-DSA-87 (FIPS 204 security category 5).
pub type MlDsa87 = Dilithium<Dilithium5Params>;

/// Compatibility alias for [`MlDsa44`].
pub type Dilithium2 = MlDsa44;
/// Compatibility alias for [`MlDsa65`].
pub type Dilithium3 = MlDsa65;
/// Compatibility alias for [`MlDsa87`].
pub type Dilithium5 = MlDsa87;

#[cfg(test)]
mod tests;
