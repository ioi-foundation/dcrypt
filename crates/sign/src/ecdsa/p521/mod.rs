//! ECDSA implementation for NIST P-521 curve
//!
//! This implementation follows FIPS 186-4: Digital Signature Standard (DSS)
//! and SP 800-56A Rev. 3: Recommendation for Pair-Wise Key-Establishment Schemes
//! Using Discrete Logarithm Cryptography

use crate::ecdsa::common::{is_canonical_nonzero_scalar, is_high_s, Rfc6979, SignatureComponents};
use alloc::vec::Vec;
use dcrypt_algorithms::ec::p521 as ec;
use dcrypt_algorithms::hash::sha2::Sha512;
use dcrypt_algorithms::hash::HashFunction;
use dcrypt_api::{
    error::Error as ApiError, Result as ApiResult, Signature as SignatureTrait, ZeroizingBytes,
};
use dcrypt_internal::{
    constant_time::ct_eq, zeroizing_bytes_from_slice, CryptoRng, RngCore, Zeroize, ZeroizeOnDrop,
};
use dcrypt_params::traditional::ecdsa::NIST_P521;

/// ECDSA signature scheme using NIST P-521 curve (secp521r1)
///
/// Implements ECDSA as specified in FIPS 186-4, Section 6, with SHA-512
/// as specified in FIPS 186-5 for P-521.
pub struct EcdsaP521;

/// P-521 public key in uncompressed format (0x04 || X || Y)
///
/// Format: 133 bytes total (1 byte prefix + 66 bytes X + 66 bytes Y)
#[derive(Clone)]
pub struct EcdsaP521PublicKey(pub(crate) [u8; ec::P521_POINT_UNCOMPRESSED_SIZE]);

/// P-521 secret key
///
/// Contains both the raw scalar value and its byte representation
/// for efficient operations. The scalar d must satisfy 1 ≤ d ≤ n-1
/// where n is the order of the base point G.
#[derive(Clone)]
pub struct EcdsaP521SecretKey {
    raw: ec::Scalar,
    bytes: [u8; ec::P521_SCALAR_SIZE],
}

// Manual Zeroize implementation for EcdsaP521SecretKey
impl Zeroize for EcdsaP521SecretKey {
    fn zeroize(&mut self) {
        self.raw.zeroize();
        // Zeroize the byte representation
        self.bytes.zeroize();
    }
}

// Secure cleanup on drop
impl Drop for EcdsaP521SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for EcdsaP521SecretKey {}

/// P-521 signature encoded in ASN.1 DER format
///
/// Format: SEQUENCE { r INTEGER, s INTEGER }
#[derive(Clone)]
pub struct EcdsaP521Signature(pub(crate) Vec<u8>);

// AsRef/AsMut implementations for byte access
impl AsRef<[u8]> for EcdsaP521PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for EcdsaP521PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for EcdsaP521SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// REMOVED: AsMut<[u8]> for EcdsaP521SecretKey
// This implementation was removed for security reasons. Direct mutation of secret
// key bytes could create invalid keys outside the valid range [1, n-1], leading
// to security vulnerabilities.

impl AsRef<[u8]> for EcdsaP521Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for EcdsaP521Signature {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl EcdsaP521PublicKey {
    /// Parse an uncompressed P-521 public key with on-curve validation.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        let point = ec::Point::deserialize_uncompressed(bytes).map_err(ApiError::from)?;
        if point.is_identity() {
            return Err(ApiError::InvalidParameter {
                context: "ECDSA-P521 public key",
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

impl EcdsaP521SecretKey {
    /// Parse a canonical, nonzero P-521 secret scalar.
    pub fn from_bytes(bytes: &[u8]) -> ApiResult<Self> {
        let raw = ec::Scalar::deserialize(bytes).map_err(ApiError::from)?;
        let mut serialized = [0u8; ec::P521_SCALAR_SIZE];
        serialized.copy_from_slice(bytes);
        Ok(Self {
            raw,
            bytes: serialized,
        })
    }

    /// Export the secret scalar in a zeroizing buffer.
    pub fn to_bytes_zeroizing(&self) -> ZeroizingBytes {
        zeroizing_bytes_from_slice(&self.bytes)
    }
}

impl EcdsaP521Signature {
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

impl SignatureTrait for EcdsaP521 {
    type PublicKey = EcdsaP521PublicKey;
    type SecretKey = EcdsaP521SecretKey;
    type SignatureData = EcdsaP521Signature;
    type KeyPair = (Self::PublicKey, Self::SecretKey);

    fn name() -> &'static str {
        "ECDSA-P521"
    }

    /// Generate an ECDSA key pair
    ///
    /// Generates a random private key d ∈ [1, n-1] and computes
    /// the corresponding public key Q = d·G where G is the base point.
    ///
    /// Reference: FIPS 186-4, Appendix B.4.1
    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> ApiResult<Self::KeyPair> {
        // Generate EC keypair with private key in valid range [1, n-1]
        let (sk_scalar, pk_point) = ec::generate_keypair(rng).map_err(ApiError::from)?;

        // Serialize the private key scalar
        let sk_bytes: [u8; ec::P521_SCALAR_SIZE] = sk_scalar.serialize();

        // Verify the private key is non-zero (should never happen with proper generation)
        if sk_bytes.iter().all(|&b| b == 0) {
            return Err(ApiError::InvalidParameter {
                context: "ECDSA-P521 keypair",
                #[cfg(feature = "std")]
                message: "Generated secret key is zero (internal error)".to_string(),
            });
        }

        // Create the secret key structure
        let secret_key = EcdsaP521SecretKey {
            raw: sk_scalar,
            bytes: sk_bytes,
        };

        // Serialize public key in uncompressed format
        let public_key = EcdsaP521PublicKey(pk_point.serialize_uncompressed());

        Ok((public_key, secret_key))
    }

    fn public_key(keypair: &Self::KeyPair) -> Self::PublicKey {
        keypair.0.clone()
    }

    fn secret_key(keypair: &Self::KeyPair) -> Self::SecretKey {
        keypair.1.clone()
    }

    /// Sign a message using ECDSA
    ///
    /// Implements the ECDSA signature generation algorithm as specified in
    /// FIPS 186-4, Section 6.3, with deterministic nonce generation per
    /// RFC 6979.
    ///
    /// Algorithm:
    /// 1. e = HASH(M), where HASH is SHA-512
    /// 2. z = the leftmost min(N, bitlen(e)) bits of e, where N = 521
    /// 3. Generate k deterministically per RFC 6979
    /// 4. (x₁, y₁) = k·G
    /// 5. r = x₁ mod n; if r = 0, go back to step 3
    /// 6. s = k⁻¹(z + rd) mod n; if s = 0, go back to step 3
    /// 7. Return signature (r, s)
    fn sign(message: &[u8], secret_key: &Self::SecretKey) -> ApiResult<Self::SignatureData> {
        // Step 1: Hash the message using SHA-512 (FIPS 186-5 specifies SHA-512 for P-521)
        let mut hasher = Sha512::new();
        hasher.update(message).map_err(ApiError::from)?;
        let hash_output = hasher.finalize().map_err(ApiError::from)?;

        // Step 2: Convert hash to integer z
        // For P-521, we use the leftmost min(521, 512) = 512 bits of the hash
        // SHA-512 produces 512 bits, so we use all of it
        let mut z_bytes = [0u8; ec::P521_SCALAR_SIZE];
        // Pad the hash output to 66 bytes by prepending zeros
        z_bytes[ec::P521_SCALAR_SIZE - 64..].copy_from_slice(hash_output.as_ref());
        let z = reduce_bytes_to_scalar(&z_bytes)?;

        // Get the private key scalar d
        let d = secret_key.raw.clone();
        let mut d_bytes = d.serialize();
        let nonces_result =
            Rfc6979::<Sha512>::new(&d_bytes, hash_output.as_ref(), &NIST_P521.n, 521);
        d_bytes.zeroize();
        let mut nonces = nonces_result?;

        loop {
            let mut nonce = nonces.next_nonce()?;
            let mut nonce_bytes: [u8; ec::P521_SCALAR_SIZE] =
                (&nonce[..])
                    .try_into()
                    .map_err(|_| ApiError::InvalidLength {
                        context: "ECDSA-P521 nonce",
                        expected: ec::P521_SCALAR_SIZE,
                        actual: nonce.len(),
                    })?;
            nonce.zeroize();
            let scalar = ec::Scalar::new(nonce_bytes).map_err(ApiError::from);
            nonce_bytes.zeroize();
            let k = scalar?;

            // Step 4: Compute (x₁, y₁) = k·G
            let kg = ec::scalar_mult_base_g(&k).map_err(ApiError::from)?;
            let r_bytes = kg.x_coordinate_bytes();

            // Step 5: Compute r = x₁ mod n
            let r = reduce_bytes_to_scalar(&r_bytes)?;
            if r.is_zero() {
                continue;
            }

            // Compute k⁻¹ mod n
            let k_inv = k.inv_mod_n().map_err(ApiError::from)?;

            // Step 6: Compute s = k⁻¹(z + rd) mod n
            let rd = r.mul_mod_n(&d).map_err(ApiError::from)?;

            let z_plus_rd = z.add_mod_n(&rd).map_err(ApiError::from)?;

            let mut s = k_inv.mul_mod_n(&z_plus_rd).map_err(ApiError::from)?;

            // If s = 0, try again (extremely unlikely)
            if s.is_zero() {
                continue;
            }
            if is_high_s(&s.serialize(), &NIST_P521.n) {
                s = s.negate();
            }

            // Step 7: Create signature (r, s)
            let sig = SignatureComponents {
                r: r.serialize().to_vec(),
                s: s.serialize().to_vec(),
            };

            // Encode signature in DER format
            let der_sig = sig.to_der();

            return Ok(EcdsaP521Signature(der_sig));
        }
    }

    /// Verify an ECDSA signature
    ///
    /// Implements the ECDSA signature verification algorithm as specified in
    /// FIPS 186-4, Section 6.4.
    ///
    /// Algorithm:
    /// 1. Verify that r and s are integers in [1, n-1]
    /// 2. e = HASH(M), where HASH is SHA-512
    /// 3. z = the leftmost min(N, bitlen(e)) bits of e, where N = 521
    /// 4. w = s⁻¹ mod n
    /// 5. u₁ = zw mod n and u₂ = rw mod n
    /// 6. (x₁, y₁) = u₁·G + u₂·Q
    /// 7. If (x₁, y₁) = O, reject the signature
    /// 8. v = x₁ mod n
    /// 9. Accept the signature if and only if v = r
    fn verify(
        message: &[u8],
        signature: &Self::SignatureData,
        public_key: &Self::PublicKey,
    ) -> ApiResult<()> {
        // Parse signature from DER format
        let sig = SignatureComponents::from_der(&signature.0)?;

        // Step 1: Verify r and s are in valid range [1, n-1]
        if sig.r.len() > ec::P521_SCALAR_SIZE || sig.s.len() > ec::P521_SCALAR_SIZE {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA-P521 verify",
                #[cfg(feature = "std")]
                message: "Invalid signature component size".to_string(),
            });
        }

        // Convert r and s to scalars (with proper padding)
        let mut r_bytes = [0u8; ec::P521_SCALAR_SIZE];
        let mut s_bytes = [0u8; ec::P521_SCALAR_SIZE];
        r_bytes[ec::P521_SCALAR_SIZE - sig.r.len()..].copy_from_slice(&sig.r);
        s_bytes[ec::P521_SCALAR_SIZE - sig.s.len()..].copy_from_slice(&sig.s);

        if !is_canonical_nonzero_scalar(&r_bytes, &NIST_P521.n)
            || !is_canonical_nonzero_scalar(&s_bytes, &NIST_P521.n)
        {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA-P521 verify",
                #[cfg(feature = "std")]
                message: "signature components must be canonical integers in [1, n-1]".to_string(),
            });
        }

        let r = ec::Scalar::new(r_bytes).map_err(|_| ApiError::InvalidSignature {
            context: "ECDSA-P521 verify",
            #[cfg(feature = "std")]
            message: "Invalid r component".to_string(),
        })?;

        let s = ec::Scalar::new(s_bytes).map_err(|_| ApiError::InvalidSignature {
            context: "ECDSA-P521 verify",
            #[cfg(feature = "std")]
            message: "Invalid s component".to_string(),
        })?;
        if is_high_s(&s.serialize(), &NIST_P521.n) {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA-P521 verify",
                #[cfg(feature = "std")]
                message: "high-s signatures are non-canonical".to_string(),
            });
        }

        // Step 2: Hash the message using SHA-512
        let mut hasher = Sha512::new();
        hasher.update(message).map_err(ApiError::from)?;
        let hash_output = hasher.finalize().map_err(ApiError::from)?;

        // Step 3: Convert hash to integer z
        let mut z_bytes = [0u8; ec::P521_SCALAR_SIZE];
        z_bytes[ec::P521_SCALAR_SIZE - 64..].copy_from_slice(hash_output.as_ref());
        let z = reduce_bytes_to_scalar(&z_bytes)?;

        // Step 4: Compute w = s⁻¹ mod n
        let s_inv = s.inv_mod_n().map_err(ApiError::from)?;

        // Step 5: Compute u₁ = zw mod n and u₂ = rw mod n
        let u1 = z.mul_mod_n(&s_inv).map_err(ApiError::from)?;
        let u2 = r.mul_mod_n(&s_inv).map_err(ApiError::from)?;

        // Parse the public key point Q
        let q = ec::Point::deserialize_uncompressed(&public_key.0).map_err(ApiError::from)?;

        // Step 6: Compute point (x₁, y₁) = u₁·G + u₂·Q
        let u1g = ec::scalar_mult_base_g(&u1).map_err(ApiError::from)?;

        let u2q = ec::scalar_mult(&u2, &q).map_err(ApiError::from)?;

        let point = u1g.add(&u2q);

        // Step 7: Check if point is identity (point at infinity)
        if point.is_identity() {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA-P521 verify",
                #[cfg(feature = "std")]
                message: "Invalid signature: verification point is identity".to_string(),
            });
        }

        // Step 8: Compute v = x₁ mod n
        let x1_bytes = point.x_coordinate_bytes();
        let x1 = reduce_bytes_to_scalar(&x1_bytes)?;

        // Step 9: Verify v = r using constant-time comparison
        if !ct_eq(r.serialize(), x1.serialize()) {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA-P521 verify",
                #[cfg(feature = "std")]
                message: "Signature verification failed".to_string(),
            });
        }

        Ok(())
    }
}

fn reduce_bytes_to_scalar(bytes: &[u8; 66]) -> ApiResult<ec::Scalar> {
    Ok(ec::Scalar::from_bytes_reduced(*bytes))
}

#[cfg(test)]
mod tests;
