//! BLS signatures over BLS12-381 with minimum-size public keys.
//!
//! This module implements the Basic, Message Augmentation, and Proof of
//! Possession schemes from `draft-irtf-cfrg-bls-signature-07`. Public keys are
//! 48-byte compressed G1 points and signatures are 96-byte compressed G2
//! points. [`Eth2Bls12381G2PopV4`] is a deliberately separate adapter for the
//! legacy draft-v4 profile retained by Ethereum consensus.
//!
//! The standard profile is pinned to
//! [`draft-irtf-cfrg-bls-signature-07`](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-07),
//! published 6 July 2026. That draft's Appendix B still marks minimum-public-
//! key vectors as TBA; dcrypt therefore combines published EIP-2333 v4 KeyGen
//! vectors with byte-for-byte tests against an independent BLS12-381 oracle in
//! the excluded verification workspace.
//!
//! ```
//! use dcrypt_sign::bls::{Bls12381G2Basic, Bls12381SecretKey};
//!
//! // Production IKM must be at least 32 unpredictable bytes. Draft-07 also
//! // requires the caller to choose the salt explicitly.
//! let ikm = [7u8; 32];
//! let secret = Bls12381SecretKey::key_gen(&ikm, b"example application salt")?;
//! let public = secret.public_key()?;
//! let signature = Bls12381G2Basic::sign(&secret, b"message")?;
//! Bls12381G2Basic::verify(&public, b"message", &signature)?;
//! # Ok::<(), dcrypt_api::Error>(())
//! ```
//!
//! Secret keys are non-`Copy`, non-`Clone`, exact-width clearing owners. They
//! never expose a plain byte-array serialization. The arithmetic bridge uses a
//! fixed 256-bit scalar-multiplication schedule and explicitly clears scalar
//! and byte temporaries; target-specific compiler inspection remains necessary
//! for a concrete side-channel claim.

#![forbid(unsafe_code)]

use alloc::vec::Vec;
use core::fmt;

use dcrypt_algorithms::ec::bls12_381::{
    pairing, Bls12_381Scalar, G1Affine, G1Projective, G2Affine, G2Projective, Gt,
};
use dcrypt_algorithms::hash::{sha2::Sha256, HashFunction};
use dcrypt_algorithms::kdf::Hkdf;
use dcrypt_api::{Error as ApiError, Result as ApiResult};
use dcrypt_internal::{
    random::try_fill_bytes_zeroing_on_error, CryptoRng, RngCore, Zeroize, ZeroizeOnDrop, Zeroizing,
};

/// Size of a canonical BLS12-381 secret scalar encoding.
pub const BLS_SECRET_KEY_SIZE: usize = 32;
/// Size of a compressed minimum-size BLS12-381 public key in G1.
pub const BLS_PUBLIC_KEY_SIZE: usize = 48;
/// Size of a compressed minimum-public-key BLS12-381 signature in G2.
pub const BLS_SIGNATURE_SIZE: usize = 96;

/// Draft-07 minimum-public-key Basic ciphersuite domain separation tag.
pub const BLS_BASIC_G2_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
/// Draft-07 minimum-public-key Message Augmentation domain separation tag.
pub const BLS_AUG_G2_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";
/// Draft-07 minimum-public-key Proof of Possession signature tag.
pub const BLS_POP_G2_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Draft-07 minimum-public-key proof-generation tag, distinct from signatures.
pub const BLS_POP_PROOF_G2_DST: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

const KEYGEN_V4_SALT_TAG: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
const KEYGEN_L: usize = 48;

fn invalid_key(context: &'static str, _message: &'static str) -> ApiError {
    ApiError::InvalidKey {
        context,
        #[cfg(feature = "std")]
        message: _message.into(),
    }
}

fn invalid_signature(context: &'static str, _message: &'static str) -> ApiError {
    ApiError::InvalidSignature {
        context,
        #[cfg(feature = "std")]
        message: _message.into(),
    }
}

fn invalid_parameter(context: &'static str, _message: &'static str) -> ApiError {
    ApiError::InvalidParameter {
        context,
        #[cfg(feature = "std")]
        message: _message.into(),
    }
}

/// Protected canonical nonzero BLS12-381 secret scalar.
///
/// This type deliberately implements neither `Copy` nor `Clone` and exposes no
/// shared or mutable byte-slice trait. Use [`Self::to_bytes_zeroizing`] only
/// when an explicit protected export is required.
pub struct Bls12381SecretKey {
    bytes: Zeroizing<[u8; BLS_SECRET_KEY_SIZE]>,
}

impl fmt::Debug for Bls12381SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Bls12381SecretKey([REDACTED])")
    }
}

impl Zeroize for Bls12381SecretKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for Bls12381SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Bls12381SecretKey {}

impl Bls12381SecretKey {
    /// Import a canonical 32-byte big-endian scalar in the range `1..r`.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != BLS_SECRET_KEY_SIZE {
            return Err(ApiError::InvalidLength {
                context: "Bls12381SecretKey::from_bytes",
                expected: BLS_SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut protected = Zeroizing::new([0u8; BLS_SECRET_KEY_SIZE]);
        protected.copy_from_slice(bytes);
        if !bool::from(Bls12_381Scalar::secret_key_bytes_are_valid(&protected)) {
            return Err(invalid_key(
                "Bls12381SecretKey::from_bytes",
                "secret scalar must be canonical and nonzero",
            ));
        }
        Ok(Self { bytes: protected })
    }

    /// Draft-07 KeyGen with the optional `key_info` value defaulting to empty.
    ///
    /// `ikm` must contain at least 32 unpredictable bytes. Draft-07 requires
    /// callers to choose and supply `salt`; an empty salt is permitted by HKDF,
    /// but it is still an explicit caller choice.
    pub fn key_gen(ikm: &[u8], salt: &[u8]) -> ApiResult<Self> {
        Self::key_gen_with_info(ikm, salt, &[])
    }

    /// Draft-07 KeyGen with explicit caller-required `salt` and `key_info`.
    pub fn key_gen_with_info(ikm: &[u8], salt: &[u8], key_info: &[u8]) -> ApiResult<Self> {
        Self::key_gen_inner(ikm, salt, key_info, |current_salt, protected_ikm, info| {
            Hkdf::<Sha256>::derive(Some(current_salt), protected_ikm, Some(info), KEYGEN_L)
                .map_err(ApiError::from)
        })
    }

    /// Generate 32 bytes of IKM from a caller-supplied cryptographic RNG, then
    /// apply draft-07 KeyGen with an empty `key_info` value.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R, salt: &[u8]) -> ApiResult<Self> {
        Self::generate_with_info(rng, salt, &[])
    }

    /// Generate IKM from a caller-supplied RNG and apply draft-07 KeyGen.
    pub fn generate_with_info<R: CryptoRng + RngCore>(
        rng: &mut R,
        salt: &[u8],
        key_info: &[u8],
    ) -> ApiResult<Self> {
        let mut ikm = Zeroizing::new([0u8; 32]);
        try_fill_bytes_zeroing_on_error(rng, &mut *ikm).map_err(|_| {
            ApiError::RandomGenerationError {
                context: "Bls12381SecretKey::generate",
                #[cfg(feature = "std")]
                message: "caller-provided randomness source failed".into(),
            }
        })?;
        Self::key_gen_with_info(&*ikm, salt, key_info)
    }

    fn key_gen_inner<F>(ikm: &[u8], salt: &[u8], key_info: &[u8], mut derive: F) -> ApiResult<Self>
    where
        F: FnMut(&[u8], &[u8], &[u8]) -> ApiResult<dcrypt_internal::zeroing::ZeroizingBytes>,
    {
        if ikm.len() < 32 {
            return Err(ApiError::InvalidLength {
                context: "Bls12381SecretKey::key_gen IKM",
                expected: 32,
                actual: ikm.len(),
            });
        }

        let ikm_len = ikm.len().checked_add(1).ok_or_else(|| {
            invalid_parameter("Bls12381SecretKey::key_gen", "IKM length overflow")
        })?;
        let mut protected_ikm =
            Zeroizing::new(dcrypt_internal::zeroing::boxed_bytes_zeroed(ikm_len));
        protected_ikm[..ikm.len()].copy_from_slice(ikm);

        let info_len = key_info.len().checked_add(2).ok_or_else(|| {
            invalid_parameter("Bls12381SecretKey::key_gen", "key_info length overflow")
        })?;
        let mut info = Vec::with_capacity(info_len);
        info.extend_from_slice(key_info);
        info.extend_from_slice(&(KEYGEN_L as u16).to_be_bytes());

        let mut current_salt = salt.to_vec();
        loop {
            let okm = derive(&current_salt, &protected_ikm, &info)?;
            if okm.len() != KEYGEN_L {
                return Err(invalid_parameter(
                    "Bls12381SecretKey::key_gen",
                    "HKDF returned an unexpected output length",
                ));
            }

            let mut scalar =
                Bls12_381Scalar::from_be_bytes_mod_order(&okm).map_err(ApiError::from)?;
            if !bool::from(scalar.is_zero()) {
                let bytes = scalar.to_be_bytes_zeroizing();
                scalar.zeroize();
                return Ok(Self { bytes });
            }
            scalar.zeroize();

            let mut digest = Sha256::digest(&current_salt).map_err(ApiError::from)?;
            current_salt.clear();
            current_salt.extend_from_slice(digest.as_ref());
            digest.zeroize();
        }
    }

    /// Derive the canonical minimum-size public key in G1.
    pub fn public_key(&self) -> ApiResult<Bls12381PublicKey> {
        let point = G1Projective::generator()
            .multiply_secret_be_bytes(&self.bytes)
            .map_err(ApiError::from)?;
        Bls12381PublicKey::from_point(point)
    }

    /// Export the canonical big-endian scalar in a clearing fixed-width owner.
    pub fn to_bytes_zeroizing(&self) -> Zeroizing<[u8; BLS_SECRET_KEY_SIZE]> {
        self.bytes.clone()
    }

    fn bytes(&self) -> &[u8; BLS_SECRET_KEY_SIZE] {
        &self.bytes
    }
}

/// Canonical, nonidentity, prime-subgroup minimum-size public key in G1.
#[derive(Clone, Eq, PartialEq)]
pub struct Bls12381PublicKey {
    bytes: [u8; BLS_PUBLIC_KEY_SIZE],
}

impl fmt::Debug for Bls12381PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Bls12381PublicKey")
            .field("length", &BLS_PUBLIC_KEY_SIZE)
            .finish()
    }
}

impl Bls12381PublicKey {
    /// Parse a canonical, nonidentity G1 point in the prime-order subgroup.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        if bytes.len() != BLS_PUBLIC_KEY_SIZE {
            return Err(ApiError::InvalidLength {
                context: "Bls12381PublicKey::from_bytes",
                expected: BLS_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        G1Projective::from_bytes_validated(bytes).map_err(|_| {
            invalid_key(
                "Bls12381PublicKey::from_bytes",
                "invalid encoding, identity, or point outside the subgroup",
            )
        })?;
        let encoded: [u8; BLS_PUBLIC_KEY_SIZE] = bytes.try_into().map_err(|_| {
            invalid_key(
                "Bls12381PublicKey::from_bytes",
                "validated public-key length changed unexpectedly",
            )
        })?;
        Ok(Self { bytes: encoded })
    }

    /// Return the canonical compressed encoding.
    pub fn to_bytes(&self) -> [u8; BLS_PUBLIC_KEY_SIZE] {
        self.bytes
    }

    /// Validate an external public-key encoding without retaining it.
    pub fn key_validate(bytes: &[u8]) -> bool {
        Self::from_bytes(bytes).is_ok()
    }

    /// Aggregate one or more validated public keys, rejecting an identity sum.
    pub fn aggregate(public_keys: &[Self]) -> ApiResult<Self> {
        let first = public_keys.first().ok_or_else(|| {
            invalid_parameter(
                "Bls12381PublicKey::aggregate",
                "at least one public key is required",
            )
        })?;
        let mut aggregate = first.point()?;
        for public_key in &public_keys[1..] {
            aggregate += public_key.point()?;
        }
        Self::from_point(aggregate)
    }

    fn point(&self) -> ApiResult<G1Projective> {
        G1Projective::from_bytes_validated(&self.bytes).map_err(|_| {
            invalid_key(
                "Bls12381PublicKey",
                "stored public-key invariant was violated",
            )
        })
    }

    fn from_point(point: G1Projective) -> ApiResult<Self> {
        if bool::from(point.is_identity()) {
            return Err(invalid_key(
                "Bls12381PublicKey",
                "aggregate public key is the identity",
            ));
        }
        Ok(Self {
            bytes: point.to_bytes(),
        })
    }
}

/// Canonical prime-subgroup signature in G2.
///
/// The canonical identity encoding is accepted, as required by the draft's
/// `signature_to_point` contract. Ordinary verification rejects it through the
/// pairing equation. The Ethereum adapter exposes its one specified empty-set
/// exception explicitly.
#[derive(Clone, Eq, PartialEq)]
pub struct Bls12381Signature {
    bytes: [u8; BLS_SIGNATURE_SIZE],
}

impl fmt::Debug for Bls12381Signature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Bls12381Signature")
            .field("length", &BLS_SIGNATURE_SIZE)
            .finish()
    }
}

impl Bls12381Signature {
    /// Parse a canonical G2 point and enforce prime-order subgroup membership.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        let encoded: [u8; BLS_SIGNATURE_SIZE] =
            bytes.try_into().map_err(|_| ApiError::InvalidLength {
                context: "Bls12381Signature::from_bytes",
                expected: BLS_SIGNATURE_SIZE,
                actual: bytes.len(),
            })?;
        G2Projective::from_bytes(&encoded)
            .into_option()
            .ok_or_else(|| {
                invalid_signature(
                    "Bls12381Signature::from_bytes",
                    "invalid encoding or point outside the subgroup",
                )
            })?;
        Ok(Self { bytes: encoded })
    }

    /// Return the canonical compressed encoding.
    pub fn to_bytes(&self) -> [u8; BLS_SIGNATURE_SIZE] {
        self.bytes
    }

    /// Return whether this is the canonical G2 identity.
    pub fn is_identity(&self) -> bool {
        self.point()
            .map(|point| bool::from(point.is_identity()))
            .unwrap_or(false)
    }

    /// Aggregate one or more canonical subgroup signatures.
    pub fn aggregate(signatures: &[Self]) -> ApiResult<Self> {
        let first = signatures.first().ok_or_else(|| {
            invalid_parameter(
                "Bls12381Signature::aggregate",
                "at least one signature is required",
            )
        })?;
        let mut aggregate = first.point()?;
        for signature in &signatures[1..] {
            aggregate += signature.point()?;
        }
        Ok(Self::from_point(aggregate))
    }

    fn point(&self) -> ApiResult<G2Projective> {
        G2Projective::from_bytes(&self.bytes)
            .into_option()
            .ok_or_else(|| {
                invalid_signature(
                    "Bls12381Signature",
                    "stored signature invariant was violated",
                )
            })
    }

    fn from_point(point: G2Projective) -> Self {
        Self {
            bytes: point.to_bytes(),
        }
    }
}

/// Canonical prime-subgroup proof of possession in G2.
#[derive(Clone, Eq, PartialEq)]
pub struct Bls12381ProofOfPossession {
    bytes: [u8; BLS_SIGNATURE_SIZE],
}

impl fmt::Debug for Bls12381ProofOfPossession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Bls12381ProofOfPossession")
            .field("length", &BLS_SIGNATURE_SIZE)
            .finish()
    }
}

impl Bls12381ProofOfPossession {
    /// Parse a canonical G2 proof and enforce subgroup membership.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        let signature = Bls12381Signature::from_bytes(bytes)?;
        Ok(Self {
            bytes: signature.bytes,
        })
    }

    /// Return the canonical compressed encoding.
    pub fn to_bytes(&self) -> [u8; BLS_SIGNATURE_SIZE] {
        self.bytes
    }

    fn signature(&self) -> Bls12381Signature {
        Bls12381Signature { bytes: self.bytes }
    }
}

#[derive(Clone, Copy)]
enum MessageMode {
    Raw,
    Augmented,
}

fn message_equal(
    mode: MessageMode,
    public_keys: &[Bls12381PublicKey],
    messages: &[&[u8]],
    left: usize,
    right: usize,
) -> bool {
    match mode {
        MessageMode::Raw => messages[left] == messages[right],
        MessageMode::Augmented => {
            public_keys[left] == public_keys[right] && messages[left] == messages[right]
        }
    }
}

fn hash_message(
    mode: MessageMode,
    public_key: &Bls12381PublicKey,
    message: &[u8],
    dst: &[u8],
) -> ApiResult<G2Projective> {
    match mode {
        MessageMode::Raw => G2Projective::hash_to_curve(message, dst).map_err(ApiError::from),
        MessageMode::Augmented => {
            let length = BLS_PUBLIC_KEY_SIZE
                .checked_add(message.len())
                .ok_or_else(|| {
                    invalid_parameter("BLS message augmentation", "message length overflow")
                })?;
            let mut augmented = Vec::with_capacity(length);
            augmented.extend_from_slice(&public_key.bytes);
            augmented.extend_from_slice(message);
            G2Projective::hash_to_curve(&augmented, dst).map_err(ApiError::from)
        }
    }
}

fn core_sign(
    secret_key: &Bls12381SecretKey,
    public_key: &Bls12381PublicKey,
    message: &[u8],
    dst: &[u8],
    mode: MessageMode,
) -> ApiResult<Bls12381Signature> {
    let message_point = hash_message(mode, public_key, message, dst)?;
    let signature = message_point
        .multiply_secret_be_bytes(secret_key.bytes())
        .map_err(ApiError::from)?;
    Ok(Bls12381Signature::from_point(signature))
}

fn core_verify(
    public_key: &Bls12381PublicKey,
    message: &[u8],
    signature: &Bls12381Signature,
    dst: &[u8],
    mode: MessageMode,
) -> ApiResult<()> {
    let public_key_point = G1Affine::from(public_key.point()?);
    let signature_point = G2Affine::from(signature.point()?);
    let message_point = G2Affine::from(hash_message(mode, public_key, message, dst)?);

    if pairing(&public_key_point, &message_point)
        == pairing(&G1Affine::generator(), &signature_point)
    {
        Ok(())
    } else {
        Err(invalid_signature(
            "BLS verification",
            "pairing equation failed",
        ))
    }
}

fn validate_parallel_inputs(
    context: &'static str,
    public_keys: &[Bls12381PublicKey],
    messages: &[&[u8]],
) -> ApiResult<()> {
    if public_keys.is_empty() {
        return Err(invalid_parameter(
            context,
            "at least one public key and message is required",
        ));
    }
    if public_keys.len() != messages.len() {
        return Err(invalid_parameter(
            context,
            "public-key and message counts differ",
        ));
    }
    Ok(())
}

fn core_aggregate_verify(
    public_keys: &[Bls12381PublicKey],
    messages: &[&[u8]],
    signature: &Bls12381Signature,
    dst: &[u8],
    mode: MessageMode,
) -> ApiResult<()> {
    validate_parallel_inputs("BLS aggregate verification", public_keys, messages)?;

    let mut product = Gt::identity();
    for index in 0..public_keys.len() {
        if (0..index).any(|previous| message_equal(mode, public_keys, messages, previous, index)) {
            continue;
        }

        let mut aggregate_public_key = public_keys[index].point()?;
        let mut group_len = 1usize;
        for next in (index + 1)..public_keys.len() {
            if message_equal(mode, public_keys, messages, index, next) {
                aggregate_public_key += public_keys[next].point()?;
                group_len += 1;
            }
        }

        // Draft-07 validates each grouped aggregate public key. This prevents
        // splitting-zero groups even though every component key is valid.
        if group_len > 1 && bool::from(aggregate_public_key.is_identity()) {
            return Err(invalid_key(
                "BLS aggregate verification",
                "same-message aggregate public key is the identity",
            ));
        }

        let message_point = G2Affine::from(hash_message(
            mode,
            &public_keys[index],
            messages[index],
            dst,
        )?);
        product += pairing(&G1Affine::from(aggregate_public_key), &message_point);
    }

    let signature_point = G2Affine::from(signature.point()?);
    let expected = pairing(&G1Affine::generator(), &signature_point);
    if product == expected {
        Ok(())
    } else {
        Err(invalid_signature(
            "BLS aggregate verification",
            "aggregate pairing equation failed",
        ))
    }
}

/// Draft-07 minimum-public-key Basic scheme.
pub struct Bls12381G2Basic;

impl Bls12381G2Basic {
    /// Deterministically sign with the Basic ciphersuite.
    pub fn sign(secret_key: &Bls12381SecretKey, message: &[u8]) -> ApiResult<Bls12381Signature> {
        let public_key = secret_key.public_key()?;
        core_sign(
            secret_key,
            &public_key,
            message,
            BLS_BASIC_G2_DST,
            MessageMode::Raw,
        )
    }

    /// Verify one Basic signature.
    pub fn verify(
        public_key: &Bls12381PublicKey,
        message: &[u8],
        signature: &Bls12381Signature,
    ) -> ApiResult<()> {
        core_verify(
            public_key,
            message,
            signature,
            BLS_BASIC_G2_DST,
            MessageMode::Raw,
        )
    }

    /// Aggregate one or more signatures.
    pub fn aggregate(signatures: &[Bls12381Signature]) -> ApiResult<Bls12381Signature> {
        Bls12381Signature::aggregate(signatures)
    }

    /// Verify a Basic aggregate, rejecting every repeated message.
    pub fn aggregate_verify(
        public_keys: &[Bls12381PublicKey],
        messages: &[&[u8]],
        signature: &Bls12381Signature,
    ) -> ApiResult<()> {
        validate_parallel_inputs("BLS Basic aggregate verification", public_keys, messages)?;
        for left in 0..messages.len() {
            for right in (left + 1)..messages.len() {
                if messages[left] == messages[right] {
                    return Err(invalid_parameter(
                        "BLS Basic aggregate verification",
                        "Basic scheme messages must be distinct",
                    ));
                }
            }
        }
        core_aggregate_verify(
            public_keys,
            messages,
            signature,
            BLS_BASIC_G2_DST,
            MessageMode::Raw,
        )
    }
}

/// Draft-07 minimum-public-key Message Augmentation scheme.
pub struct Bls12381G2MessageAugmentation;

impl Bls12381G2MessageAugmentation {
    /// Sign `PK || message` with the Message Augmentation ciphersuite.
    pub fn sign(secret_key: &Bls12381SecretKey, message: &[u8]) -> ApiResult<Bls12381Signature> {
        let public_key = secret_key.public_key()?;
        core_sign(
            secret_key,
            &public_key,
            message,
            BLS_AUG_G2_DST,
            MessageMode::Augmented,
        )
    }

    /// Verify a Message Augmentation signature over `PK || message`.
    pub fn verify(
        public_key: &Bls12381PublicKey,
        message: &[u8],
        signature: &Bls12381Signature,
    ) -> ApiResult<()> {
        core_verify(
            public_key,
            message,
            signature,
            BLS_AUG_G2_DST,
            MessageMode::Augmented,
        )
    }

    /// Aggregate one or more signatures.
    pub fn aggregate(signatures: &[Bls12381Signature]) -> ApiResult<Bls12381Signature> {
        Bls12381Signature::aggregate(signatures)
    }

    /// Verify an augmented aggregate. Duplicate raw messages are permitted
    /// because the signed input includes each public-key encoding.
    pub fn aggregate_verify(
        public_keys: &[Bls12381PublicKey],
        messages: &[&[u8]],
        signature: &Bls12381Signature,
    ) -> ApiResult<()> {
        core_aggregate_verify(
            public_keys,
            messages,
            signature,
            BLS_AUG_G2_DST,
            MessageMode::Augmented,
        )
    }
}

/// Draft-07 minimum-public-key Proof of Possession scheme.
pub struct Bls12381G2ProofOfPossession;

impl Bls12381G2ProofOfPossession {
    /// Sign with the Proof of Possession signature ciphersuite.
    pub fn sign(secret_key: &Bls12381SecretKey, message: &[u8]) -> ApiResult<Bls12381Signature> {
        let public_key = secret_key.public_key()?;
        core_sign(
            secret_key,
            &public_key,
            message,
            BLS_POP_G2_DST,
            MessageMode::Raw,
        )
    }

    /// Produce a proof over the canonical public-key encoding using the
    /// distinct `BLS_POP_...` proof domain.
    pub fn pop_prove(secret_key: &Bls12381SecretKey) -> ApiResult<Bls12381ProofOfPossession> {
        let public_key = secret_key.public_key()?;
        let message_point = G2Projective::hash_to_curve(&public_key.bytes, BLS_POP_PROOF_G2_DST)
            .map_err(ApiError::from)?;
        let proof = message_point
            .multiply_secret_be_bytes(secret_key.bytes())
            .map_err(ApiError::from)?;
        Ok(Bls12381ProofOfPossession {
            bytes: proof.to_bytes(),
        })
    }

    /// Validate a proof of possession for a public key.
    pub fn pop_verify(
        public_key: &Bls12381PublicKey,
        proof: &Bls12381ProofOfPossession,
    ) -> ApiResult<()> {
        core_verify(
            public_key,
            &public_key.bytes,
            &proof.signature(),
            BLS_POP_PROOF_G2_DST,
            MessageMode::Raw,
        )
    }

    /// Verify a PoP signature after validating the accompanying proof.
    pub fn verify(
        public_key: &Bls12381PublicKey,
        proof: &Bls12381ProofOfPossession,
        message: &[u8],
        signature: &Bls12381Signature,
    ) -> ApiResult<()> {
        Self::pop_verify(public_key, proof)?;
        core_verify(
            public_key,
            message,
            signature,
            BLS_POP_G2_DST,
            MessageMode::Raw,
        )
    }

    /// Aggregate one or more signatures.
    pub fn aggregate(signatures: &[Bls12381Signature]) -> ApiResult<Bls12381Signature> {
        Bls12381Signature::aggregate(signatures)
    }

    /// Verify an aggregate after validating one proof per public key.
    pub fn aggregate_verify(
        public_keys: &[Bls12381PublicKey],
        proofs: &[Bls12381ProofOfPossession],
        messages: &[&[u8]],
        signature: &Bls12381Signature,
    ) -> ApiResult<()> {
        validate_parallel_inputs("BLS PoP aggregate verification", public_keys, messages)?;
        if public_keys.len() != proofs.len() {
            return Err(invalid_parameter(
                "BLS PoP aggregate verification",
                "public-key and proof counts differ",
            ));
        }
        for (public_key, proof) in public_keys.iter().zip(proofs) {
            Self::pop_verify(public_key, proof)?;
        }
        core_aggregate_verify(
            public_keys,
            messages,
            signature,
            BLS_POP_G2_DST,
            MessageMode::Raw,
        )
    }

    /// Verify an aggregate over one shared message after validating every
    /// proof of possession. The empty input is rejected by draft-07.
    pub fn fast_aggregate_verify(
        public_keys: &[Bls12381PublicKey],
        proofs: &[Bls12381ProofOfPossession],
        message: &[u8],
        signature: &Bls12381Signature,
    ) -> ApiResult<()> {
        if public_keys.is_empty() {
            return Err(invalid_parameter(
                "BLS PoP fast aggregate verification",
                "at least one public key is required",
            ));
        }
        if public_keys.len() != proofs.len() {
            return Err(invalid_parameter(
                "BLS PoP fast aggregate verification",
                "public-key and proof counts differ",
            ));
        }
        for (public_key, proof) in public_keys.iter().zip(proofs) {
            Self::pop_verify(public_key, proof)?;
        }
        let aggregate_public_key = Bls12381PublicKey::aggregate(public_keys)?;
        core_verify(
            &aggregate_public_key,
            message,
            signature,
            BLS_POP_G2_DST,
            MessageMode::Raw,
        )
    }
}

/// Ethereum consensus adapter for the minimum-public-key draft-v4 PoP profile.
///
/// This adapter keeps Ethereum's POP signature DST and v4-compatible KeyGen
/// salt behavior. Unlike the draft-07 PoP API, verification methods do not take
/// proofs: Ethereum relies on protocol registration to establish possession.
/// Callers outside that context should use [`Bls12381G2ProofOfPossession`].
pub struct Eth2Bls12381G2PopV4;

impl Eth2Bls12381G2PopV4 {
    /// Draft-v4-compatible KeyGen, using `SHA-256("BLS-SIG-KEYGEN-SALT-")`
    /// as the first HKDF salt and an empty `key_info` value.
    pub fn key_gen(ikm: &[u8]) -> ApiResult<Bls12381SecretKey> {
        Self::key_gen_with_info(ikm, &[])
    }

    /// Draft-v4-compatible KeyGen with explicit `key_info`.
    pub fn key_gen_with_info(ikm: &[u8], key_info: &[u8]) -> ApiResult<Bls12381SecretKey> {
        let mut salt = Sha256::digest(KEYGEN_V4_SALT_TAG).map_err(ApiError::from)?;
        let result = Bls12381SecretKey::key_gen_with_info(ikm, salt.as_ref(), key_info);
        salt.zeroize();
        result
    }

    /// Generate v4-compatible IKM from a caller-provided cryptographic RNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Bls12381SecretKey> {
        let mut ikm = Zeroizing::new([0u8; 32]);
        try_fill_bytes_zeroing_on_error(rng, &mut *ikm).map_err(|_| {
            ApiError::RandomGenerationError {
                context: "Eth2Bls12381G2PopV4::generate",
                #[cfg(feature = "std")]
                message: "caller-provided randomness source failed".into(),
            }
        })?;
        Self::key_gen(&*ikm)
    }

    /// Sign using Ethereum's draft-v4 POP signature DST.
    pub fn sign(secret_key: &Bls12381SecretKey, message: &[u8]) -> ApiResult<Bls12381Signature> {
        Bls12381G2ProofOfPossession::sign(secret_key, message)
    }

    /// Verify under the Ethereum registration precondition.
    pub fn verify(
        public_key: &Bls12381PublicKey,
        message: &[u8],
        signature: &Bls12381Signature,
    ) -> ApiResult<()> {
        core_verify(
            public_key,
            message,
            signature,
            BLS_POP_G2_DST,
            MessageMode::Raw,
        )
    }

    /// Aggregate one or more Ethereum-profile signatures.
    pub fn aggregate(signatures: &[Bls12381Signature]) -> ApiResult<Bls12381Signature> {
        Bls12381Signature::aggregate(signatures)
    }

    /// Verify a draft-v4 POP aggregate under Ethereum's registration
    /// precondition.
    pub fn aggregate_verify(
        public_keys: &[Bls12381PublicKey],
        messages: &[&[u8]],
        signature: &Bls12381Signature,
    ) -> ApiResult<()> {
        core_aggregate_verify(
            public_keys,
            messages,
            signature,
            BLS_POP_G2_DST,
            MessageMode::Raw,
        )
    }

    /// Ethereum's `AggregatePKs` extension. Inputs must be nonempty and the
    /// aggregate must remain a valid nonidentity public key.
    pub fn aggregate_public_keys(
        public_keys: &[Bls12381PublicKey],
    ) -> ApiResult<Bls12381PublicKey> {
        Bls12381PublicKey::aggregate(public_keys)
    }

    /// Ethereum's `eth_fast_aggregate_verify` wrapper.
    ///
    /// Its sole empty-set exception accepts exactly the canonical G2 identity.
    /// Every nonempty call follows draft-v4 FastAggregateVerify and assumes the
    /// keys were possession-validated during protocol registration.
    pub fn fast_aggregate_verify(
        public_keys: &[Bls12381PublicKey],
        message: &[u8; 32],
        signature: &Bls12381Signature,
    ) -> ApiResult<()> {
        if public_keys.is_empty() {
            return if signature.is_identity() {
                Ok(())
            } else {
                Err(invalid_signature(
                    "Eth2 fast aggregate verification",
                    "empty public-key input requires the G2 identity signature",
                ))
            };
        }

        let aggregate_public_key = Bls12381PublicKey::aggregate(public_keys)?;
        core_verify(
            &aggregate_public_key,
            message,
            signature,
            BLS_POP_G2_DST,
            MessageMode::Raw,
        )
    }
}

#[cfg(test)]
mod tests;
