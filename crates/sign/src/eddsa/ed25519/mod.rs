//! Ed25519 signatures backed by `ed25519-dalek`.
//!
//! The previous in-tree Edwards arithmetic accepted weak public keys and used
//! secret-dependent branches during scalar multiplication. Keeping dcrypt's
//! byte-oriented API while delegating the primitive to dalek provides strict
//! point/scalar decoding and a backend designed for constant-time secret
//! arithmetic. Compiler-, target-, and operation-specific review is still
//! required for a concrete side-channel claim.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::constants::{ED25519_PUBLIC_KEY_SIZE, ED25519_SECRET_KEY_SIZE, ED25519_SIGNATURE_SIZE};
use curve25519_dalek::edwards::CompressedEdwardsY;
use dcrypt_api::{error::Error as ApiError, Result as ApiResult, Signature as SignatureTrait};
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, VerifyingKey};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

/// Ed25519 signature scheme.
pub struct Ed25519;

/// Canonically encoded, non-weak Ed25519 public key.
#[derive(Clone, Zeroize)]
pub struct Ed25519PublicKey(pub [u8; ED25519_PUBLIC_KEY_SIZE]);

impl core::fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed25519PublicKey")
            .field("algorithm", &"Ed25519")
            .finish()
    }
}

/// Ed25519 secret seed, wiped on drop.
#[derive(Clone)]
pub struct Ed25519SecretKey {
    seed: [u8; ED25519_SECRET_KEY_SIZE],
}

impl Zeroize for Ed25519SecretKey {
    fn zeroize(&mut self) {
        self.seed.zeroize();
    }
}

impl Drop for Ed25519SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for Ed25519SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed25519SecretKey")
            .field("algorithm", &"Ed25519")
            .finish()
    }
}

/// Ed25519 signature bytes (`R || S`).
#[derive(Clone, Zeroize)]
pub struct Ed25519Signature(pub [u8; ED25519_SIGNATURE_SIZE]);

impl core::fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed25519Signature")
            .field("length", &self.0.len())
            .finish()
    }
}

fn invalid_key(context: &'static str, message: &'static str) -> ApiError {
    ApiError::InvalidKey {
        context,
        #[cfg(feature = "std")]
        message: message.to_string(),
    }
}

fn invalid_signature(context: &'static str, message: &'static str) -> ApiError {
    ApiError::InvalidSignature {
        context,
        #[cfg(feature = "std")]
        message: message.to_string(),
    }
}

fn validate_canonical_prime_order_point(bytes: &[u8; 32], context: &'static str) -> ApiResult<()> {
    let point = CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or_else(|| invalid_key(context, "point encoding does not decompress"))?;
    if point.compress().to_bytes() != *bytes {
        return Err(invalid_key(context, "point encoding is non-canonical"));
    }
    if point.is_small_order() || !point.is_torsion_free() {
        return Err(invalid_key(
            context,
            "point is not in the prime-order subgroup",
        ));
    }
    Ok(())
}

impl Ed25519PublicKey {
    /// Parse a canonical public key and reject every small-order key.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        let key_bytes: [u8; ED25519_PUBLIC_KEY_SIZE] =
            bytes.try_into().map_err(|_| ApiError::InvalidLength {
                context: "Ed25519PublicKey::from_bytes",
                expected: ED25519_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            })?;
        validate_canonical_prime_order_point(&key_bytes, "Ed25519PublicKey::from_bytes")?;
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
            invalid_key(
                "Ed25519PublicKey::from_bytes",
                "public key is not a canonical Edwards point",
            )
        })?;
        Ok(Self(key_bytes))
    }

    pub fn to_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_SIZE] {
        self.0
    }

    fn verifying_key(&self) -> ApiResult<VerifyingKey> {
        validate_canonical_prime_order_point(&self.0, "Ed25519 verify")?;
        let key = VerifyingKey::from_bytes(&self.0)
            .map_err(|_| invalid_key("Ed25519 verify", "public key encoding is invalid"))?;
        Ok(key)
    }
}

impl Ed25519SecretKey {
    pub fn from_seed(seed: &[u8; ED25519_SECRET_KEY_SIZE]) -> ApiResult<Self> {
        Ok(Self { seed: *seed })
    }

    pub fn seed(&self) -> &[u8; ED25519_SECRET_KEY_SIZE] {
        &self.seed
    }

    pub fn export_seed(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.seed.to_vec())
    }

    pub fn public_key(&self) -> ApiResult<Ed25519PublicKey> {
        Ed25519::derive_public_from_secret(self)
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }
}

impl Ed25519Signature {
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        let signature: [u8; ED25519_SIGNATURE_SIZE] =
            bytes.try_into().map_err(|_| ApiError::InvalidLength {
                context: "Ed25519Signature::from_bytes",
                expected: ED25519_SIGNATURE_SIZE,
                actual: bytes.len(),
            })?;
        Ok(Self(signature))
    }

    pub fn to_bytes(&self) -> [u8; ED25519_SIGNATURE_SIZE] {
        self.0
    }
}

impl SignatureTrait for Ed25519 {
    type PublicKey = Ed25519PublicKey;
    type SecretKey = Ed25519SecretKey;
    type SignatureData = Ed25519Signature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "Ed25519"
    }

    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        let mut seed = [0u8; ED25519_SECRET_KEY_SIZE];
        rng.fill_bytes(&mut seed);
        let secret = Ed25519SecretKey::from_seed(&seed)?;
        seed.zeroize();
        let public = secret.public_key()?;
        Ok((public, secret))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    fn sign(message: &[u8], secret_key: &Self::SecretKey) -> ApiResult<Self::SignatureData> {
        let signature: DalekSignature = secret_key.signing_key().sign(message);
        Ok(Ed25519Signature(signature.to_bytes()))
    }

    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> ApiResult<()> {
        let verifying_key = public_key.verifying_key()?;
        let r_bytes: [u8; 32] = signature.0[..32]
            .try_into()
            .map_err(|_| invalid_signature("Ed25519 verify", "invalid R encoding"))?;
        validate_canonical_prime_order_point(&r_bytes, "Ed25519 signature R")
            .map_err(|_| invalid_signature("Ed25519 verify", "R is non-canonical or torsion"))?;
        let signature = DalekSignature::from_bytes(&signature.0);
        verifying_key
            .verify_strict(message, &signature)
            .map_err(|_| invalid_signature("Ed25519 verify", "strict verification failed"))
    }
}

impl Ed25519 {
    pub fn derive_public_from_secret(secret_key: &Ed25519SecretKey) -> ApiResult<Ed25519PublicKey> {
        let bytes = secret_key.signing_key().verifying_key().to_bytes();
        Ed25519PublicKey::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests;
