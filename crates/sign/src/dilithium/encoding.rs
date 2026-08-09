//! Serialization functions for ML-DSA per FIPS 204.
//!
//! Key aspects:
//! - FIPS-204 compliant HintBitPack/HintBitUnpack encoding that matches final spec.
//! - Challenge hash size varies by security level (32/48/64 bytes).
//! - Uses Z_BITS instead of GAMMA1_BITS for packing z coefficients.
//! - Implements only FIPS 204 standard format (no ACVP variations).

use super::arithmetic::w1_bits_needed;
use super::polyvec::{PolyVecK, PolyVecL};
use crate::error::Error as SignError;
#[cfg(not(feature = "std"))]
use alloc::{format, vec, vec::Vec};
use dcrypt_algorithms::poly::serialize::{
    CoefficientPacker, CoefficientUnpacker, DefaultCoefficientSerde,
};
use dcrypt_api::SecretVec;
use dcrypt_internal::{boxed_bytes_zeroed, Zeroizing};
use dcrypt_params::pqc::ml_dsa::{MlDsaSchemeParams, ML_DSA_N, ML_DSA_Q};

#[inline]
fn centered_coefficient(coefficient: u32) -> i32 {
    let reduced = coefficient % ML_DSA_Q;
    if reduced > ML_DSA_Q / 2 {
        reduced as i32 - ML_DSA_Q as i32
    } else {
        reduced as i32
    }
}

#[inline]
fn signed_to_mod_q(value: i32) -> u32 {
    (value as i64).rem_euclid(ML_DSA_Q as i64) as u32
}

// ---------------------------------------------------------------------------
// Helper algorithms 24 / 25 – HintBitPack / HintBitUnpack (FIPS‑204 final)
// ---------------------------------------------------------------------------

/// Packs the hint vector *h* using the final FIPS‑204 "HintBitPack" layout
fn pack_hints_bitpacked<P: MlDsaSchemeParams>(
    h_hint_poly: &PolyVecK<P>,
) -> Result<Vec<u8>, SignError> {
    let omega = P::OMEGA_PARAM as usize;
    let mut packed = vec![0u8; omega + P::K_DIM];
    let mut index = 0usize;

    for (row, poly) in h_hint_poly.polys.iter().enumerate() {
        for (col, &bit) in poly.coeffs.iter().enumerate() {
            match bit {
                0 => {}
                1 => {
                    if index >= omega {
                        return Err(SignError::Serialization(
                            "too many ML-DSA hint coefficients".into(),
                        ));
                    }
                    packed[index] = col as u8;
                    index += 1;
                }
                _ => {
                    return Err(SignError::Serialization(
                        "ML-DSA hint coefficients must be zero or one".into(),
                    ));
                }
            }
        }
        // FIPS 204 stores cumulative boundaries, not per-row counts.
        packed[omega + row] = index as u8;
    }

    Ok(packed)
}

/// Inverse of `pack_hints_bitpacked` (Algorithm 25)
fn unpack_hints_bitpacked<P: MlDsaSchemeParams>(
    bytes: &[u8],
) -> Result<(PolyVecK<P>, usize), SignError> {
    let omega = P::OMEGA_PARAM as usize;
    if bytes.len() != omega + P::K_DIM {
        return Err(SignError::Deserialization(
            "invalid ML-DSA hint length".into(),
        ));
    }

    // Split at exactly ω bytes (not based on content)
    let (idx_bytes, boundaries) = bytes.split_at(omega);

    let mut h_poly = PolyVecK::<P>::zero();
    let mut start = 0usize;
    for (row, &boundary) in boundaries.iter().enumerate() {
        let end = usize::from(boundary);
        if end < start || end > omega {
            return Err(SignError::Deserialization(
                "non-monotonic ML-DSA hint boundaries".into(),
            ));
        }

        if !idx_bytes[start..end]
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(SignError::Deserialization(
                "duplicate or unsorted ML-DSA hint indices".into(),
            ));
        }

        for &idx in &idx_bytes[start..end] {
            h_poly.polys[row].coeffs[usize::from(idx)] = 1;
        }
        start = end;
    }

    if idx_bytes[start..].iter().any(|&byte| byte != 0) {
        return Err(SignError::Deserialization(
            "nonzero unused ML-DSA hint bytes".into(),
        ));
    }

    Ok((h_poly, start))
}

/// Packs public key (ρ, t1) according to Algorithm 13.
pub fn pack_public_key<P: MlDsaSchemeParams>(
    rho_seed: &[u8; 32], // SEED_RHO_BYTES is always 32
    t1_vec: &PolyVecK<P>,
) -> Result<Vec<u8>, SignError> {
    let mut pk_bytes = Vec::with_capacity(P::PUBLIC_KEY_BYTES);

    // Pack ρ
    pk_bytes.extend_from_slice(rho_seed);

    // Pack t1 (each coefficient uses 10 bits for all parameter sets)
    for i in 0..P::K_DIM {
        let packed_poly = DefaultCoefficientSerde::pack_coeffs(&t1_vec.polys[i], 10)
            .map_err(SignError::from_algo)?;
        pk_bytes.extend_from_slice(&packed_poly);
    }

    if pk_bytes.len() != P::PUBLIC_KEY_BYTES {
        return Err(SignError::Serialization(format!(
            "Public key size mismatch: expected {}, got {}",
            P::PUBLIC_KEY_BYTES,
            pk_bytes.len()
        )));
    }

    Ok(pk_bytes)
}

/// Unpacks public key from bytes according to Algorithm 14.
pub fn unpack_public_key<P: MlDsaSchemeParams>(
    pk_bytes: &[u8],
) -> Result<([u8; 32], PolyVecK<P>), SignError> {
    if pk_bytes.len() != P::PUBLIC_KEY_BYTES {
        return Err(SignError::Deserialization(format!(
            "Public key size mismatch: expected {}, got {}",
            P::PUBLIC_KEY_BYTES,
            pk_bytes.len()
        )));
    }

    // Unpack ρ
    let mut rho_seed = [0u8; 32];
    rho_seed.copy_from_slice(&pk_bytes[0..32]);

    // Unpack t1
    let mut t1_vec = PolyVecK::<P>::zero();
    let mut offset = P::SEED_RHO_BYTES;
    let bytes_per_poly = ML_DSA_N * 10 / 8; // 320 bytes

    for i in 0..P::K_DIM {
        let poly_bytes = &pk_bytes[offset..offset + bytes_per_poly];
        t1_vec.polys[i] =
            DefaultCoefficientSerde::unpack_coeffs(poly_bytes, 10).map_err(SignError::from_algo)?;
        offset += bytes_per_poly;
    }

    Ok((rho_seed, t1_vec))
}

/// Packs secret key (ρ, K, tr, s1, s2, t0) according to Algorithm 15.
/// FIPS 204 compliant format only.
pub fn pack_secret_key<P: MlDsaSchemeParams>(
    rho_seed: &[u8; 32], // SEED_RHO_BYTES is always 32
    k_seed: &[u8; 32],
    tr_hash: &[u8; 64],
    s1_vec: &PolyVecL<P>,
    s2_vec: &PolyVecK<P>,
    t0_vec: &PolyVecK<P>,
) -> Result<SecretVec, SignError> {
    let mut sk_bytes = SecretVec::empty();

    // Pack ρ, K, tr
    sk_bytes.extend_from_slice(rho_seed);
    sk_bytes.extend_from_slice(k_seed);
    sk_bytes.extend_from_slice(tr_hash);

    // Calculate bits needed for s1, s2 encoding
    let eta_bits = if P::ETA_S1S2 == 2 { 3 } else { 4 }; // η=2 needs 3 bits, η=4 needs 4 bits
    let bytes_per_s_poly = ML_DSA_N * eta_bits / 8;
    let bytes_per_t0_poly = ML_DSA_N * P::D_PARAM as usize / 8;

    // Pack s1 (coefficients in [-η, η])
    for i in 0..P::L_DIM {
        let mut temp_poly = s1_vec.polys[i].clone();
        for c in temp_poly.coeffs.iter_mut() {
            let centered = centered_coefficient(*c);
            if !(-(P::ETA_S1S2 as i32)..=P::ETA_S1S2 as i32).contains(&centered) {
                return Err(SignError::Serialization(
                    "s1 coefficient out of range".into(),
                ));
            }
            *c = (P::ETA_S1S2 as i32 - centered) as u32;
        }
        let mut packed = Zeroizing::new(boxed_bytes_zeroed(bytes_per_s_poly));
        DefaultCoefficientSerde::pack_coeffs_into(&temp_poly, eta_bits, &mut packed)
            .map_err(SignError::from_algo)?;
        sk_bytes.extend_from_slice(&packed);
    }

    // Pack s2 (same as s1)
    for i in 0..P::K_DIM {
        let mut temp_poly = s2_vec.polys[i].clone();
        for c in temp_poly.coeffs.iter_mut() {
            let centered = centered_coefficient(*c);
            if !(-(P::ETA_S1S2 as i32)..=P::ETA_S1S2 as i32).contains(&centered) {
                return Err(SignError::Serialization(
                    "s2 coefficient out of range".into(),
                ));
            }
            *c = (P::ETA_S1S2 as i32 - centered) as u32;
        }
        let mut packed = Zeroizing::new(boxed_bytes_zeroed(bytes_per_s_poly));
        DefaultCoefficientSerde::pack_coeffs_into(&temp_poly, eta_bits, &mut packed)
            .map_err(SignError::from_algo)?;
        sk_bytes.extend_from_slice(&packed);
    }

    // Pack t0 (coefficients in (-2^(d-1), 2^(d-1)])
    let t0_offset = 1 << (P::D_PARAM - 1);
    for i in 0..P::K_DIM {
        let mut temp_poly = t0_vec.polys[i].clone();
        for c in temp_poly.coeffs.iter_mut() {
            let centered = centered_coefficient(*c);
            if !(-(t0_offset - 1)..=t0_offset).contains(&centered) {
                return Err(SignError::Serialization(
                    "t0 coefficient out of range".into(),
                ));
            }
            *c = (t0_offset - centered) as u32;
        }
        let mut packed = Zeroizing::new(boxed_bytes_zeroed(bytes_per_t0_poly));
        DefaultCoefficientSerde::pack_coeffs_into(&temp_poly, P::D_PARAM as usize, &mut packed)
            .map_err(SignError::from_algo)?;
        sk_bytes.extend_from_slice(&packed);
    }

    if sk_bytes.len() != P::SECRET_KEY_BYTES {
        return Err(SignError::Serialization(format!(
            "secret key size mismatch: expected {}, got {}",
            P::SECRET_KEY_BYTES,
            sk_bytes.len()
        )));
    }

    debug_assert_eq!(sk_bytes.len(), P::SECRET_KEY_BYTES);
    Ok(sk_bytes)
}

/// Type alias for the complex return type of unpack_secret_key
pub type UnpackedSecretKey<P> = (
    [u8; 32],            // rho
    Zeroizing<[u8; 32]>, // k
    Zeroizing<[u8; 64]>, // tr
    PolyVecL<P>,
    PolyVecK<P>,
    PolyVecK<P>,
);

/// Unpacks secret key from bytes according to Algorithm 16.
/// FIPS 204 compliant format only.
pub fn unpack_secret_key<P: MlDsaSchemeParams>(
    sk_bytes: &[u8],
) -> Result<UnpackedSecretKey<P>, SignError> {
    if sk_bytes.len() != P::SECRET_KEY_BYTES {
        return Err(SignError::Deserialization(format!(
            "Secret key size mismatch: expected {}, got {}",
            P::SECRET_KEY_BYTES,
            sk_bytes.len()
        )));
    }

    let mut offset = 0;

    // Unpack ρ, K, tr
    let mut rho_seed = [0u8; 32];
    rho_seed.copy_from_slice(&sk_bytes[offset..offset + 32]);
    offset += 32;

    let mut k_seed = Zeroizing::new([0u8; 32]);
    k_seed.copy_from_slice(&sk_bytes[offset..offset + 32]);
    offset += 32;

    let mut tr_hash = Zeroizing::new([0u8; 64]);
    tr_hash.copy_from_slice(&sk_bytes[offset..offset + 64]);
    offset += 64;

    // Calculate sizes
    let eta_bits = if P::ETA_S1S2 == 2 { 3 } else { 4 };
    let bytes_per_s_poly = ML_DSA_N * eta_bits / 8;
    let bytes_per_t0_poly = ML_DSA_N * P::D_PARAM as usize / 8;

    // Unpack s1
    let mut s1_vec = PolyVecL::<P>::zero();
    for i in 0..P::L_DIM {
        let poly_bytes = &sk_bytes[offset..offset + bytes_per_s_poly];
        let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, eta_bits)
            .map_err(SignError::from_algo)?;
        for c in temp_poly.coeffs.iter_mut() {
            if *c > 2 * P::ETA_S1S2 {
                return Err(SignError::InvalidKey(
                    "ML-DSA s1 coefficient out of range".into(),
                ));
            }
            let signed = P::ETA_S1S2 as i32 - *c as i32;
            *c = signed_to_mod_q(signed);
        }
        s1_vec.polys[i] = temp_poly;
        offset += bytes_per_s_poly;
    }

    // Unpack s2
    let mut s2_vec = PolyVecK::<P>::zero();
    for i in 0..P::K_DIM {
        let poly_bytes = &sk_bytes[offset..offset + bytes_per_s_poly];
        let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, eta_bits)
            .map_err(SignError::from_algo)?;
        for c in temp_poly.coeffs.iter_mut() {
            if *c > 2 * P::ETA_S1S2 {
                return Err(SignError::InvalidKey(
                    "ML-DSA s2 coefficient out of range".into(),
                ));
            }
            let signed = P::ETA_S1S2 as i32 - *c as i32;
            *c = signed_to_mod_q(signed);
        }
        s2_vec.polys[i] = temp_poly;
        offset += bytes_per_s_poly;
    }

    // Unpack t0 - Keep t₀ centered instead of converting negatives to large positives
    let mut t0_vec = PolyVecK::<P>::zero();
    let t0_offset = 1 << (P::D_PARAM - 1);
    for i in 0..P::K_DIM {
        let poly_bytes = &sk_bytes[offset..offset + bytes_per_t0_poly];
        let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, P::D_PARAM as usize)
            .map_err(SignError::from_algo)?;
        for c in temp_poly.coeffs.iter_mut() {
            let signed = t0_offset - *c as i32;
            *c = signed_to_mod_q(signed);
        }
        t0_vec.polys[i] = temp_poly;
        offset += bytes_per_t0_poly;
    }

    if offset != sk_bytes.len() {
        return Err(SignError::Deserialization(format!(
            "secret key decoding consumed {offset} of {} bytes",
            sk_bytes.len(),
        )));
    }

    Ok((rho_seed, k_seed, tr_hash, s1_vec, s2_vec, t0_vec))
}

/// Packs signature (c̃, z, h) according to FIPS 204 Algorithm 17 with variable challenge size
/// Uses Z_BITS instead of GAMMA1_BITS for packing z coefficients
pub fn pack_signature<P: MlDsaSchemeParams>(
    c_tilde_seed: &[u8], // Now variable size: 32/48/64 bytes
    z_vec: &PolyVecL<P>,
    h_hint_poly: &PolyVecK<P>,
) -> Result<Vec<u8>, SignError> {
    // Verify challenge seed is the correct size
    if c_tilde_seed.len() != P::CHALLENGE_BYTES {
        return Err(SignError::Serialization(format!(
            "Challenge seed size mismatch: expected {}, got {}",
            P::CHALLENGE_BYTES,
            c_tilde_seed.len()
        )));
    }

    let mut sig_bytes = Vec::with_capacity(P::SIGNATURE_SIZE);

    // Pack c̃ (variable size: 32/48/64 bytes)
    sig_bytes.extend_from_slice(c_tilde_seed);

    // Algorithm 17 encodes b - w with a = gamma1-1 and b = gamma1.
    for i in 0..P::L_DIM {
        let mut temp_poly = z_vec.polys[i].clone();
        for c in temp_poly.coeffs.iter_mut() {
            let centered = centered_coefficient(*c);
            let lower = -(P::GAMMA1_PARAM as i32) + 1;
            let upper = P::GAMMA1_PARAM as i32;
            if !(lower..=upper).contains(&centered) {
                return Err(SignError::Serialization(
                    "z coefficient out of range".into(),
                ));
            }
            *c = (P::GAMMA1_PARAM as i32 - centered) as u32;
        }
        // Use Z_BITS instead of GAMMA1_BITS
        let packed = DefaultCoefficientSerde::pack_coeffs(&temp_poly, P::Z_BITS)
            .map_err(SignError::from_algo)?;
        sig_bytes.extend_from_slice(&packed);
    }

    // Pack h using HintBitPack encoding (FIPS 204 Algorithm 24)
    let hint_bytes = pack_hints_bitpacked::<P>(h_hint_poly)?;
    sig_bytes.extend_from_slice(&hint_bytes);

    // Final length check (no manual padding)
    if sig_bytes.len() != P::SIGNATURE_SIZE {
        return Err(SignError::Serialization(format!(
            "Signature size mismatch: expected {}, got {}",
            P::SIGNATURE_SIZE,
            sig_bytes.len(),
        )));
    }

    Ok(sig_bytes)
}

/// Packs w1 for computing challenge hash using FIPS 204 final w1Encode.
/// Packs full gamma-bucket indices: 6 bits for ML-DSA-44, 4 bits for ML-DSA-65/87.
pub fn pack_polyveck_w1<P: MlDsaSchemeParams>(w1_vec: &PolyVecK<P>) -> Result<Vec<u8>, SignError> {
    let bits_per_coeff = w1_bits_needed::<P>();
    let maximum = (ML_DSA_Q - 1) / (2 * P::GAMMA2_PARAM) - 1;
    let mut packed = Vec::with_capacity(P::K_DIM * ML_DSA_N * bits_per_coeff as usize / 8);
    for poly in &w1_vec.polys {
        for &coeff in &poly.coeffs {
            if coeff > maximum {
                return Err(SignError::Serialization(
                    "w1 coefficient out of range".into(),
                ));
            }
        }
        let encoded = DefaultCoefficientSerde::pack_coeffs(poly, bits_per_coeff as usize)
            .map_err(SignError::from_algo)?;
        packed.extend_from_slice(&encoded);
    }

    Ok(packed)
}

/// Type alias for the complex return type of unpack_signature
pub type UnpackedSignature<P> = (Vec<u8>, PolyVecL<P>, PolyVecK<P>);

/// Unpacks signature from bytes according to FIPS 204 Algorithm 18 with variable challenge size
/// Uses Z_BITS instead of GAMMA1_BITS for unpacking z coefficients
pub fn unpack_signature<P: MlDsaSchemeParams>(
    sig_bytes: &[u8],
) -> Result<UnpackedSignature<P>, SignError> {
    if sig_bytes.len() != P::SIGNATURE_SIZE {
        return Err(SignError::Deserialization(format!(
            "Signature size mismatch: expected {}, got {}",
            P::SIGNATURE_SIZE,
            sig_bytes.len()
        )));
    }

    let mut offset = 0;

    // Unpack c̃ (variable size: 32/48/64 bytes)
    let mut c_tilde_seed = vec![0u8; P::CHALLENGE_BYTES];
    c_tilde_seed.copy_from_slice(&sig_bytes[offset..offset + P::CHALLENGE_BYTES]);
    offset += P::CHALLENGE_BYTES;

    // Unpack z
    let mut z_vec = PolyVecL::<P>::zero();
    // Use Z_BITS instead of GAMMA1_BITS
    let bytes_per_z_poly = ML_DSA_N * P::Z_BITS / 8;

    for i in 0..P::L_DIM {
        let poly_bytes = &sig_bytes[offset..offset + bytes_per_z_poly];
        // Use Z_BITS instead of GAMMA1_BITS
        let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, P::Z_BITS)
            .map_err(SignError::from_algo)?;
        for c in temp_poly.coeffs.iter_mut() {
            let value = P::GAMMA1_PARAM as i32 - *c as i32;
            *c = signed_to_mod_q(value);
        }
        z_vec.polys[i] = temp_poly;
        offset += bytes_per_z_poly;
    }

    // Unpack h using HintBitUnpack decoding (FIPS 204 Algorithm 25)
    let hint_bytes = &sig_bytes[offset..];
    let (h_hint_poly, _hint_cnt) = unpack_hints_bitpacked::<P>(hint_bytes)?;

    Ok((c_tilde_seed, z_vec, h_hint_poly))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcrypt_params::pqc::ml_dsa::MlDsa44Params;

    #[test]
    fn test_roundtrip_hints_basic() {
        // Test basic roundtrip with hints in different polynomials
        let mut h = PolyVecK::<MlDsa44Params>::zero();
        h.polys[1].coeffs[5] = 1;
        h.polys[2].coeffs[20] = 1;

        let packed = pack_hints_bitpacked::<MlDsa44Params>(&h).unwrap();
        let (unpacked, cnt) = unpack_hints_bitpacked::<MlDsa44Params>(&packed).unwrap();

        assert_eq!(cnt, 2, "Hint count mismatch");
        assert_eq!(
            unpacked.polys[1].coeffs[5], 1,
            "Lost hint at poly[1].coeff[5]"
        );
        assert_eq!(
            unpacked.polys[2].coeffs[20], 1,
            "Lost hint at poly[2].coeff[20]"
        );

        // Verify no spurious hints
        for i in 0..MlDsa44Params::K_DIM {
            for j in 0..256 {
                if !((i == 1 && j == 5) || (i == 2 && j == 20)) {
                    assert_eq!(
                        unpacked.polys[i].coeffs[j], 0,
                        "Spurious hint at poly[{}].coeff[{}]",
                        i, j
                    );
                }
            }
        }
    }
}
