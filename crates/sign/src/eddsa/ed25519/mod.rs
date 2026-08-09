//! Dcrypt-owned Ed25519 signing and strict verification.
//!
//! The implementation follows RFC 8032 and keeps all arithmetic in safe Rust.
//! Point encodings are canonical, public keys and signature commitments must
//! be non-identity prime-order points, and signature scalars must be below the
//! subgroup order.  Secret scalar multiplication uses a fixed 256-iteration
//! schedule with constant-time point selection.  Compiler- and target-specific
//! validation is still required for a concrete side-channel claim.

#![forbid(unsafe_code)]

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use dcrypt_algorithms::hash::sha2::Sha512;
use dcrypt_algorithms::hash::HashFunction;
use dcrypt_api::{error::Error as ApiError, Result as ApiResult, Signature as SignatureTrait};
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::constants::{ED25519_PUBLIC_KEY_SIZE, ED25519_SECRET_KEY_SIZE, ED25519_SIGNATURE_SIZE};
use super::point::EdwardsPoint;
use super::scalar::Scalar;

/// Ed25519 signature scheme.
pub struct Ed25519;

/// Canonically encoded, non-identity, prime-order Ed25519 public key.
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

/// Canonically encoded Ed25519 signature bytes (`R || S`).
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

fn decode_prime_order_point(bytes: &[u8; 32], context: &'static str) -> ApiResult<EdwardsPoint> {
    let point = EdwardsPoint::decompress(bytes)
        .ok_or_else(|| invalid_key(context, "point encoding is invalid or non-canonical"))?;
    if !point.is_strict_prime_order() {
        return Err(invalid_key(
            context,
            "point is identity, small-order, or not torsion-free",
        ));
    }
    Ok(point)
}

fn hash_parts(parts: &[&[u8]]) -> ApiResult<Zeroizing<[u8; 64]>> {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part).map_err(ApiError::from)?;
    }
    let mut digest = hasher.finalize().map_err(ApiError::from)?;
    let mut output = Zeroizing::new([0u8; 64]);
    output.copy_from_slice(digest.as_ref());
    digest.zeroize();
    Ok(output)
}

impl Ed25519PublicKey {
    /// Parse a canonical, non-identity point in the prime-order subgroup.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        let key_bytes: [u8; ED25519_PUBLIC_KEY_SIZE] =
            bytes.try_into().map_err(|_| ApiError::InvalidLength {
                context: "Ed25519PublicKey::from_bytes",
                expected: ED25519_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            })?;
        decode_prime_order_point(&key_bytes, "Ed25519PublicKey::from_bytes")?;
        Ok(Self(key_bytes))
    }

    pub fn to_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_SIZE] {
        self.0
    }

    fn point(&self) -> ApiResult<EdwardsPoint> {
        decode_prime_order_point(&self.0, "Ed25519 verify")
    }
}

impl Ed25519SecretKey {
    /// Construct a secret key from the RFC 8032 32-byte seed.
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

    fn expanded(&self) -> ApiResult<Zeroizing<[u8; 64]>> {
        let mut expanded = hash_parts(&[&self.seed])?;
        expanded[0] &= 248;
        expanded[31] &= 127;
        expanded[31] |= 64;
        Ok(expanded)
    }
}

impl Ed25519Signature {
    /// Parse a signature with a canonical prime-order `R` and canonical `S`.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        let signature: [u8; ED25519_SIGNATURE_SIZE] =
            bytes.try_into().map_err(|_| ApiError::InvalidLength {
                context: "Ed25519Signature::from_bytes",
                expected: ED25519_SIGNATURE_SIZE,
                actual: bytes.len(),
            })?;
        let r_bytes: [u8; 32] = signature[..32]
            .try_into()
            .map_err(|_| invalid_signature("Ed25519Signature::from_bytes", "invalid R length"))?;
        decode_prime_order_point(&r_bytes, "Ed25519Signature::from_bytes")
            .map_err(|_| invalid_signature("Ed25519Signature::from_bytes", "invalid R point"))?;
        let s_bytes: [u8; 32] = signature[32..]
            .try_into()
            .map_err(|_| invalid_signature("Ed25519Signature::from_bytes", "invalid S length"))?;
        Scalar::from_canonical_bytes(&s_bytes).ok_or_else(|| {
            invalid_signature("Ed25519Signature::from_bytes", "S is not below group order")
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

    /// Generate a key from caller-provided cryptographic randomness.
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
        let expanded = secret_key.expanded()?;
        let mut secret_scalar_bytes = Zeroizing::new([0u8; 32]);
        secret_scalar_bytes.copy_from_slice(&expanded[..32]);
        let secret_scalar = Scalar::reduce_32(&secret_scalar_bytes);

        let nonce_digest = hash_parts(&[&expanded[32..], message])?;
        let nonce = Scalar::reduce_64(&nonce_digest);
        let commitment = EdwardsPoint::basepoint().scalar_mult(&nonce);
        if bool::from(commitment.is_identity()) {
            return Err(invalid_signature(
                "Ed25519 sign",
                "derived commitment is the identity",
            ));
        }
        let r_bytes = commitment.compress();
        let public_bytes = EdwardsPoint::basepoint()
            .scalar_mult(&secret_scalar)
            .compress();

        let challenge_digest = hash_parts(&[&r_bytes, &public_bytes, message])?;
        let challenge = Scalar::reduce_64(&challenge_digest);
        let response = nonce.add(&challenge.mul(&secret_scalar));

        let mut signature = [0u8; ED25519_SIGNATURE_SIZE];
        signature[..32].copy_from_slice(&r_bytes);
        signature[32..].copy_from_slice(&response.to_bytes());
        Ok(Ed25519Signature(signature))
    }

    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> ApiResult<()> {
        // Revalidate tuple-struct values so direct construction cannot bypass
        // canonical and subgroup checks.
        let public_point = public_key.point()?;
        let r_bytes: [u8; 32] = signature.0[..32]
            .try_into()
            .map_err(|_| invalid_signature("Ed25519 verify", "invalid R length"))?;
        let r_point = decode_prime_order_point(&r_bytes, "Ed25519 signature R")
            .map_err(|_| invalid_signature("Ed25519 verify", "invalid R point"))?;
        let s_bytes: [u8; 32] = signature.0[32..]
            .try_into()
            .map_err(|_| invalid_signature("Ed25519 verify", "invalid S length"))?;
        let response = Scalar::from_canonical_bytes(&s_bytes)
            .ok_or_else(|| invalid_signature("Ed25519 verify", "S is not below group order"))?;

        let challenge_digest = hash_parts(&[&r_bytes, &public_key.0, message])?;
        let challenge = Scalar::reduce_64(&challenge_digest);
        let left = EdwardsPoint::basepoint().scalar_mult(&response);
        let right = r_point.add(&public_point.scalar_mult(&challenge));

        if bool::from(left.ct_eq(&right)) {
            Ok(())
        } else {
            Err(invalid_signature(
                "Ed25519 verify",
                "strict signature equation failed",
            ))
        }
    }
}

impl Ed25519 {
    pub fn derive_public_from_secret(secret_key: &Ed25519SecretKey) -> ApiResult<Ed25519PublicKey> {
        let expanded = secret_key.expanded()?;
        let mut scalar_bytes = Zeroizing::new([0u8; 32]);
        scalar_bytes.copy_from_slice(&expanded[..32]);
        let scalar = Scalar::reduce_32(&scalar_bytes);
        let bytes = EdwardsPoint::basepoint().scalar_mult(&scalar).compress();
        Ed25519PublicKey::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests;
