//! ECDSA implementation for NIST P-521 curve
//!
//! This implementation follows FIPS 186-4: Digital Signature Standard (DSS)
//! and SP 800-56A Rev. 3: Recommendation for Pair-Wise Key-Establishment Schemes
//! Using Discrete Logarithm Cryptography

use crate::ecdsa::common::SignatureComponents;
use dcrypt_algorithms::ec::p521 as ec;
use dcrypt_algorithms::hash::sha2::Sha512;
use dcrypt_algorithms::hash::HashFunction;
use dcrypt_algorithms::mac::hmac::Hmac;
use dcrypt_api::{error::Error as ApiError, Result as ApiResult, Signature as SignatureTrait};
use dcrypt_internal::constant_time::ct_eq;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// ECDSA signature scheme using NIST P-521 curve (secp521r1)
///
/// Implements ECDSA as specified in FIPS 186-4, Section 6, with SHA-512
/// as specified in FIPS 186-5 for P-521.
pub struct EcdsaP521;

/// P-521 public key in uncompressed format (0x04 || X || Y)
///
/// Format: 133 bytes total (1 byte prefix + 66 bytes X + 66 bytes Y)
#[derive(Clone, Zeroize)]
pub struct EcdsaP521PublicKey(pub [u8; ec::P521_POINT_UNCOMPRESSED_SIZE]);

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

/// P-521 signature encoded in ASN.1 DER format
///
/// Format: SEQUENCE { r INTEGER, s INTEGER }
#[derive(Clone)]
pub struct EcdsaP521Signature(pub Vec<u8>);

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
    /// RFC 6979 hedged with additional entropy (FIPS 186-5, Section 6.4).
    ///
    /// Algorithm:
    /// 1. e = HASH(M), where HASH is SHA-512
    /// 2. z = the leftmost min(N, bitlen(e)) bits of e, where N = 521
    /// 3. Generate k deterministically per RFC 6979 with extra entropy
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

        // Generate ephemeral key using RFC 6979 deterministic + hedged nonce generation
        let mut rng = rand::thread_rng();

        loop {
            // Step 3: Derive deterministic k with extra entropy
            let k = deterministic_k_hedged(&d, &z, &mut rng);

            // Step 4: Compute (x₁, y₁) = k·G
            let kg = ec::scalar_mult_base_g(&k).map_err(ApiError::from)?;
            let r_bytes = kg.x_coordinate_bytes();

            // Step 5: Compute r = x₁ mod n
            let r = match reduce_bytes_to_scalar(&r_bytes) {
                Ok(scalar) => scalar,
                Err(_) => continue, // If r = 0, try again
            };

            // Compute k⁻¹ mod n
            let k_inv = k.inv_mod_n().map_err(ApiError::from)?;

            // Step 6: Compute s = k⁻¹(z + rd) mod n
            let rd = r.mul_mod_n(&d).map_err(ApiError::from)?;

            let z_plus_rd = z.add_mod_n(&rd).map_err(ApiError::from)?;

            let s = k_inv.mul_mod_n(&z_plus_rd).map_err(ApiError::from)?;

            // If s = 0, try again (extremely unlikely)
            if s.is_zero() {
                continue;
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

/* ------------------------------------------------------------------------- */
/*                      RFC 6979 + extra-entropy helper                      */
/* ------------------------------------------------------------------------- */

/// Derive a deterministic nonce k as per RFC 6979 §3.2, hedged with
/// 66 bytes of RNG-supplied entropy (recommended by §3.6 / FIPS 186-5 §6.4).
///
/// This implementation combines deterministic nonce generation with additional
/// randomness to provide defense against weak RNG states while maintaining
/// the benefits of deterministic signatures for fault attack resistance.
fn deterministic_k_hedged<R: RngCore + CryptoRng>(
    d: &ec::Scalar,
    z: &ec::Scalar,
    rng: &mut R,
) -> ec::Scalar {
    use zeroize::Zeroize;

    let mut rbuf = [0u8; 66];
    rng.fill_bytes(&mut rbuf); // extra entropy R

    // For P-521 with SHA-512, we use 128-byte blocks
    let mut v = [0x01u8; 128];
    let mut k = [0x00u8; 128];

    // ----- step C -----
    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || R)
    {
        let mut mac = Hmac::<Sha512>::new(&k).unwrap();
        mac.update(&v).unwrap();
        mac.update(&[0x00]).unwrap();
        mac.update(&d.serialize()).unwrap();
        mac.update(&z.serialize()).unwrap();
        mac.update(&rbuf).unwrap();
        let mac_output = mac.finalize().unwrap();
        // HMAC-SHA512 outputs 64 bytes, but k is 128 bytes for block size
        k[..64].copy_from_slice(&mac_output);
        k[64..].fill(0);
    }

    // ----- step D -----
    // V = HMAC_K(V)
    let v_new = Hmac::<Sha512>::mac(&k, &v).unwrap();
    v[..64].copy_from_slice(&v_new);
    v[64..].fill(0);

    // ----- step E -----
    // K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1) || R)
    {
        let mut mac = Hmac::<Sha512>::new(&k).unwrap();
        mac.update(&v).unwrap();
        mac.update(&[0x01]).unwrap();
        mac.update(&d.serialize()).unwrap();
        mac.update(&z.serialize()).unwrap();
        mac.update(&rbuf).unwrap();
        let mac_output = mac.finalize().unwrap();
        k[..64].copy_from_slice(&mac_output);
        k[64..].fill(0);
    }

    // ----- step F -----
    // V = HMAC_K(V)
    let v_new = Hmac::<Sha512>::mac(&k, &v).unwrap();
    v[..64].copy_from_slice(&v_new);
    v[64..].fill(0);

    // ----- step G/H -----
    // Generate candidate k values until we find a valid one
    loop {
        let v_new = Hmac::<Sha512>::mac(&k, &v).unwrap();
        v[..64].copy_from_slice(&v_new);
        v[64..].fill(0);

        // Take the first 66 bytes for P-521 scalar
        let mut candidate_bytes = [0u8; 66];
        candidate_bytes.copy_from_slice(&v[..66]);

        if let Ok(candidate) = ec::Scalar::new(candidate_bytes) {
            if !candidate.is_zero() {
                rbuf.zeroize(); // scrub extra entropy
                return candidate;
            }
        }

        // retry path (step H): update K and V if candidate was invalid
        let mut mac = Hmac::<Sha512>::new(&k).unwrap();
        mac.update(&v).unwrap();
        mac.update(&[0x00]).unwrap();
        let mac_output = mac.finalize().unwrap();
        k[..64].copy_from_slice(&mac_output);
        k[64..].fill(0);

        let v_new = Hmac::<Sha512>::mac(&k, &v).unwrap();
        v[..64].copy_from_slice(&v_new);
        v[64..].fill(0);
    }
}

/* ------------------------------------------------------------------------- */
/*                        P-521 scalar reduction helper                      */
/* ------------------------------------------------------------------------- */

/// P-521 curve order n in big-endian format
const N_BE: [u8; 66] = [
    0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F, 0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09,
    0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F, 0xB7, 0x1E, 0x91, 0x38,
    0x64, 0x09,
];

/// Check if big-endian a >= b
fn ge_be(a: &[u8], b: &[u8]) -> bool {
    for (&ai, &bi) in a.iter().zip(b) {
        if ai > bi {
            return true;
        }
        if ai < bi {
            return false;
        }
    }
    true
}

/// Subtract n from candidate (modular reduction)
fn sub_mod_n(candidate: &mut [u8], n_be: &[u8]) {
    let mut borrow = 0u16;
    for i in (0..candidate.len()).rev() {
        let tmp = (candidate[i] as i16) - (n_be[i] as i16) - (borrow as i16);
        if tmp < 0 {
            candidate[i] = (tmp + 256) as u8;
            borrow = 1;
        } else {
            candidate[i] = tmp as u8;
            borrow = 0;
        }
    }
}

/// Reduce a 66-byte value modulo the curve order *n*.
/// Returns a scalar in **[1, n-1]**; zero inputs are **rejected** (the caller
/// must decide how to handle them – e.g. retry in the signing loop or treat
/// them as invalid during verification).
fn reduce_bytes_to_scalar(bytes: &[u8; 66]) -> ApiResult<ec::Scalar> {
    let mut candidate = *bytes;

    // Full reduction: repeatedly subtract until < n
    while ge_be(&candidate, &N_BE) {
        sub_mod_n(&mut candidate, &N_BE);
    }

    ec::Scalar::new(candidate).map_err(ApiError::from)
}

#[cfg(test)]
mod tests;
