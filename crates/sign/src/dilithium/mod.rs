//! FIPS 204 Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
//!
//! Key generation, signing, verification, sampling, arithmetic, and encoding
//! are implemented in safe Rust in this crate. Public keys, expanded private
//! keys, and signatures use Algorithms 22, 24, and 26 of final FIPS 204.
//! Independent implementations are used only as verification-workspace oracles.
//!
//! Version 3 exposes only the final-standard `MlDsa44`, `MlDsa65`, and
//! `MlDsa87` names. Pre-standard Dilithium names are deliberately absent so a
//! caller cannot mistake legacy encodings or semantics for FIPS 204 objects.

use crate::error::Error as SignError;
#[cfg(not(feature = "std"))]
use alloc::{format, string::ToString, vec::Vec};
use core::{fmt, marker::PhantomData};
use dcrypt_api::{Result as ApiResult, Signature as SignatureTrait};
use dcrypt_internal::{CryptoRng, RngCore, Zeroize, ZeroizeOnDrop, Zeroizing};
use dcrypt_params::pqc::dilithium::{
    Dilithium2Params, Dilithium3Params, Dilithium5Params, DilithiumSchemeParams,
};

mod arithmetic;
mod encoding;
mod polyvec;
mod sampling;
mod sign;

/// ML-DSA public key encoded with FIPS 204 Algorithm 22 (`pkEncode`).
#[derive(Clone, Debug)]
pub struct MlDsaPublicKey(pub(crate) Vec<u8>);

/// ML-DSA expanded private key encoded with FIPS 204 Algorithm 24 (`skEncode`).
///
/// In particular, bytes `64..128` contain the complete 64-byte `tr = H(pk, 64)`
/// value. Bare bytes do not carry a format version, so use paired import or
/// external provenance/framing when distinguishing affected legacy objects.
#[derive(Clone)]
pub struct MlDsaSecretKey {
    bytes: Vec<u8>,
    public_key: Option<Vec<u8>>,
}

/// ML-DSA signature encoded with FIPS 204 Algorithm 26 (`sigEncode`).
#[derive(Clone, Debug)]
pub struct MlDsaSignature(pub(crate) Vec<u8>);

impl Zeroize for MlDsaSecretKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        self.public_key.zeroize();
    }
}

impl Drop for MlDsaSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MlDsaSecretKey {}

impl fmt::Debug for MlDsaSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaSecretKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl AsRef<[u8]> for MlDsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for MlDsaPublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for MlDsaSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for MlDsaSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for MlDsaSignature {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl MlDsaSecretKey {
    /// Decode and fully validate a final-FIPS-204 expanded private key.
    ///
    /// Validation recomputes `A*s1+s2`, `t1`, `t0`, the public key, and the
    /// 64-byte `tr`; the returned key always retains its derived public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        let public_key = match bytes.len() {
            2560 => Dilithium2Params::validate_secret_key(bytes)?,
            4032 => Dilithium3Params::validate_secret_key(bytes)?,
            4896 => Dilithium5Params::validate_secret_key(bytes)?,
            _ => {
                return Err(SignError::Deserialization(format!(
                    "invalid ML-DSA expanded private key size: {} bytes",
                    bytes.len()
                )))
            }
        };

        Ok(Self {
            bytes: bytes.to_vec(),
            public_key: Some(public_key),
        })
    }

    /// Decode an expanded private key and validate it against its public key.
    ///
    /// Besides validating the expanded key itself, this requires the supplied
    /// public key to equal the public key derived from all secret components.
    pub fn from_bytes_with_public_key(
        bytes: &[u8],
        public_key: &MlDsaPublicKey,
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
    pub fn public_key(&self) -> Result<MlDsaPublicKey, SignError> {
        self.public_key
            .as_ref()
            .cloned()
            .map(MlDsaPublicKey)
            .ok_or_else(|| {
                SignError::InvalidKey(
                    "public-key derivation is unavailable for an unpaired imported ML-DSA expanded key; import with from_bytes_with_public_key"
                        .to_string(),
                )
            })
    }
}

impl MlDsaPublicKey {
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

impl MlDsaSignature {
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
pub trait MlDsaBackend: DilithiumSchemeParams + Sized {
    fn validate_public_key(bytes: &[u8]) -> Result<(), SignError> {
        encoding::unpack_public_key::<Self>(bytes).map(|_| ())
    }

    fn validate_secret_key(bytes: &[u8]) -> Result<Vec<u8>, SignError> {
        sign::validate_secret_key_internal::<Self>(bytes)
    }

    fn validate_key_pair(secret_key: &[u8], public_key: &[u8]) -> Result<(), SignError> {
        Self::validate_public_key(public_key)?;
        sign::validate_key_pair_internal::<Self>(secret_key, public_key)
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>), SignError> {
        sign::keypair_internal::<Self, R>(rng)
    }

    fn sign_internal(
        formatted_message: &[u8],
        secret_key: &[u8],
        randomizer: &[u8; 32],
        supplied_mu: Option<&[u8; 64]>,
    ) -> Result<Vec<u8>, SignError> {
        sign::sign_internal::<Self>(formatted_message, secret_key, randomizer, supplied_mu)
    }

    fn verify_internal(
        formatted_message: &[u8],
        signature: &[u8],
        public_key: &[u8],
        supplied_mu: Option<&[u8; 64]>,
    ) -> Result<(), SignError> {
        sign::verify_internal::<Self>(formatted_message, signature, public_key, supplied_mu)
    }
}

impl MlDsaBackend for Dilithium2Params {}
impl MlDsaBackend for Dilithium3Params {}
impl MlDsaBackend for Dilithium5Params {}

/// ML-DSA signature scheme parameterized by a final FIPS 204 parameter set.
pub struct MlDsa<P: DilithiumSchemeParams + 'static> {
    _params: PhantomData<P>,
}

fn format_pure_message(message: &[u8], context: &[u8]) -> Result<Vec<u8>, SignError> {
    if context.len() > u8::MAX as usize {
        return Err(SignError::InvalidParameter(format!(
            "ML-DSA context is {} bytes; maximum is 255",
            context.len()
        )));
    }
    let mut formatted = Vec::with_capacity(2 + context.len() + message.len());
    formatted.push(0);
    formatted.push(context.len() as u8);
    formatted.extend_from_slice(context);
    formatted.extend_from_slice(message);
    Ok(formatted)
}

impl<P> MlDsa<P>
where
    P: MlDsaBackend + Send + Sync + 'static,
{
    /// Generate a hedged FIPS 204 pure signature with an explicit caller RNG.
    pub fn sign_with_rng<R: CryptoRng + RngCore>(
        message: &[u8],
        secret_key: &MlDsaSecretKey,
        rng: &mut R,
    ) -> ApiResult<MlDsaSignature> {
        Self::sign_with_context_rng(message, &[], secret_key, rng)
    }

    /// Generate a hedged FIPS 204 pure signature with a context and caller RNG.
    pub fn sign_with_context_rng<R: CryptoRng + RngCore>(
        message: &[u8],
        context: &[u8],
        secret_key: &MlDsaSecretKey,
        rng: &mut R,
    ) -> ApiResult<MlDsaSignature> {
        let formatted = format_pure_message(message, context).map_err(dcrypt_api::Error::from)?;
        let mut randomizer = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(&mut *randomizer)
            .map_err(|error| dcrypt_api::Error::from(SignError::Rng(error.to_string())))?;
        let result = P::sign_internal(&formatted, secret_key.as_ref(), &randomizer, None)
            .map(MlDsaSignature)
            .map_err(dcrypt_api::Error::from);
        result
    }

    /// Generate the optional deterministic FIPS 204 pure signature.
    pub fn sign_deterministic(
        message: &[u8],
        secret_key: &MlDsaSecretKey,
    ) -> ApiResult<MlDsaSignature> {
        Self::sign_deterministic_with_context(message, &[], secret_key)
    }

    /// Generate the optional deterministic FIPS 204 pure signature with context.
    pub fn sign_deterministic_with_context(
        message: &[u8],
        context: &[u8],
        secret_key: &MlDsaSecretKey,
    ) -> ApiResult<MlDsaSignature> {
        let formatted = format_pure_message(message, context).map_err(dcrypt_api::Error::from)?;
        let signature = P::sign_internal(&formatted, secret_key.as_ref(), &[0u8; 32], None)
            .map_err(dcrypt_api::Error::from)?;
        Ok(MlDsaSignature(signature))
    }

    /// Verify a pure FIPS 204 signature with an explicit context.
    pub fn verify_with_context(
        message: &[u8],
        context: &[u8],
        signature: &MlDsaSignature,
        public_key: &MlDsaPublicKey,
    ) -> ApiResult<()> {
        validate_hint_encoding_for_len(signature.as_ref()).map_err(dcrypt_api::Error::from)?;
        let formatted = format_pure_message(message, context).map_err(dcrypt_api::Error::from)?;
        P::verify_internal(&formatted, signature.as_ref(), public_key.as_ref(), None)
            .map_err(dcrypt_api::Error::from)
    }

    /// ACVP/internal interface: sign an already formatted `M'` with exact `rnd`.
    #[doc(hidden)]
    pub fn sign_internal_with_randomizer(
        formatted_message: &[u8],
        secret_key: &MlDsaSecretKey,
        randomizer: &[u8; 32],
    ) -> ApiResult<MlDsaSignature> {
        P::sign_internal(formatted_message, secret_key.as_ref(), randomizer, None)
            .map(MlDsaSignature)
            .map_err(dcrypt_api::Error::from)
    }

    /// ACVP/internal interface: sign an externally supplied 64-byte `mu`.
    #[doc(hidden)]
    pub fn sign_mu_with_randomizer(
        mu: &[u8; 64],
        secret_key: &MlDsaSecretKey,
        randomizer: &[u8; 32],
    ) -> ApiResult<MlDsaSignature> {
        P::sign_internal(&[], secret_key.as_ref(), randomizer, Some(mu))
            .map(MlDsaSignature)
            .map_err(dcrypt_api::Error::from)
    }

    /// ACVP/internal interface: verify an already formatted `M'`.
    #[doc(hidden)]
    pub fn verify_internal_message(
        formatted_message: &[u8],
        signature: &MlDsaSignature,
        public_key: &MlDsaPublicKey,
    ) -> ApiResult<()> {
        validate_hint_encoding_for_len(signature.as_ref()).map_err(dcrypt_api::Error::from)?;
        P::verify_internal(
            formatted_message,
            signature.as_ref(),
            public_key.as_ref(),
            None,
        )
        .map_err(dcrypt_api::Error::from)
    }

    /// ACVP/internal interface: verify against an externally supplied `mu`.
    #[doc(hidden)]
    pub fn verify_mu(
        mu: &[u8; 64],
        signature: &MlDsaSignature,
        public_key: &MlDsaPublicKey,
    ) -> ApiResult<()> {
        validate_hint_encoding_for_len(signature.as_ref()).map_err(dcrypt_api::Error::from)?;
        P::verify_internal(&[], signature.as_ref(), public_key.as_ref(), Some(mu))
            .map_err(dcrypt_api::Error::from)
    }
}

impl<P> SignatureTrait for MlDsa<P>
where
    P: MlDsaBackend + Send + Sync + 'static,
{
    type PublicKey = MlDsaPublicKey;
    type SecretKey = MlDsaSecretKey;
    type SignatureData = MlDsaSignature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        P::NAME
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let (public, secret) = P::keypair(rng).map_err(dcrypt_api::Error::from)?;
        Ok((
            MlDsaPublicKey(public.clone()),
            MlDsaSecretKey {
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
        Self::sign_deterministic(message, secret_key)
    }

    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> ApiResult<()> {
        Self::verify_with_context(message, &[], signature, public_key)
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
pub type MlDsa44 = MlDsa<Dilithium2Params>;
/// ML-DSA-65 (FIPS 204 security category 3).
pub type MlDsa65 = MlDsa<Dilithium3Params>;
/// ML-DSA-87 (FIPS 204 security category 5).
pub type MlDsa87 = MlDsa<Dilithium5Params>;

#[cfg(test)]
mod tests;
