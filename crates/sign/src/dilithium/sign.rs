//! Core implementation of Dilithium key generation, signing, and verification per FIPS 204.
//!
//! Implements lattice-based signatures using Fiat-Shamir with Aborts.
//! Security based on Module-LWE and Module-SIS problems.
//!
//! Critical invariants (DO NOT MODIFY):
//! - `||z||∞ ≤ γ1 - β` (prevents key recovery)
//! - `||LowBits(w - cs2)||∞ ≤ γ2 - β` (ensures uniformity)
//! - `||ct0 - cs2||∞ ≤ γ2 - β` (ensures hint mechanism works)
//! - `hint_count ≤ ω` (ensures verifier can reconstruct w1)
//! - Rejection sampling protects against side-channel leakage
//!
//! Implementation notes:
//! - Signing is deterministic (randomness from key + counter)
//! - Challenge polynomial multiplications use schoolbook_mul (both operands in standard domain)
//! - NTT library functions handle domain management correctly per FIPS 204
//! - After inv_ntt_inplace(), coefficients are in standard domain per FIPS 204
//! - Expected signing iterations: 5-8 for Dilithium2 (varies by parameter set)
//! - The stricter rejection sampling (including the z_for_hint norm check)
//!   ensures mathematical correctness but increases iteration count slightly
//!
//! Internal module - use public `Dilithium2/3/5` types instead.

use super::arithmetic::{
    challenge_poly_mul, check_norm_polyvec_k, check_norm_polyvec_l, highbits_polyvec,
    lowbits_polyvec, make_hint_polyveck, power2round_polyvec, schoolbook_mul_generic,
    use_hint_polyveck,
};
use super::encoding::{
    pack_polyveck_w1, pack_public_key, pack_secret_key, pack_signature, unpack_public_key,
    unpack_secret_key, unpack_signature,
};
use super::polyvec::{expand_matrix_a, matrix_polyvecl_mul, PolyVecK};
use super::sampling::{
    sample_challenge_c, sample_polyveck_cbd_eta, sample_polyvecl_cbd_eta,
    sample_polyvecl_uniform_gamma1,
};

use crate::error::Error as SignError;
use dcrypt_algorithms::hash::sha3::Sha3_256;
use dcrypt_algorithms::hash::HashFunction;
use dcrypt_algorithms::poly::params::{DilithiumParams, Modulus};
use dcrypt_algorithms::xof::shake::ShakeXof256;
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use dcrypt_params::pqc::dilithium::{DilithiumSchemeParams, DILITHIUM_N};
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

/// Key Generation (Algorithm 9 from FIPS 204)
///
/// Generates (pk, sk) where pk = (ρ, t1) and sk = (ρ, K, tr, s1, s2, t0).
/// Matrix A expanded from ρ, secrets s1,s2 from CBD(η).
pub(crate) fn keypair_internal<P, R>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>), SignError>
where
    P: DilithiumSchemeParams,
    R: RngCore + CryptoRng,
{
    // Step 1: Sample ζ - ensure we get a fresh seed for each keypair
    let mut zeta_seed = [0u8; 32]; // SEED_ZETA_BYTES is always 32
    rng.fill_bytes(&mut zeta_seed);

    // Step 2: Expand seeds using G = SHAKE256
    let mut xof = ShakeXof256::new();
    xof.update(&zeta_seed).map_err(SignError::from_algo)?;

    // Generate all three seeds from the single zeta seed
    let mut rho_seed = [0u8; 32];
    let mut sigma_seed = [0u8; 32];
    let mut k_seed = [0u8; 32];

    // Squeeze each seed separately to ensure proper domain separation
    xof.squeeze(&mut rho_seed).map_err(SignError::from_algo)?;
    xof.squeeze(&mut sigma_seed).map_err(SignError::from_algo)?;
    xof.squeeze(&mut k_seed).map_err(SignError::from_algo)?;

    // Step 3: Expand A from ρ
    let matrix_a = expand_matrix_a::<P>(&rho_seed)?;

    // Convert A to NTT domain (Â)
    let mut matrix_a_hat = Vec::with_capacity(P::K_DIM);
    for row in matrix_a {
        let mut row_ntt = row;
        row_ntt.ntt_inplace().map_err(SignError::from_algo)?;
        matrix_a_hat.push(row_ntt);
    }

    // Step 4: Sample s1, s2
    let s1_vec = sample_polyvecl_cbd_eta::<P>(&sigma_seed, 0, P::ETA_S1S2)?;
    let s2_vec = sample_polyveck_cbd_eta::<P>(&sigma_seed, P::L_DIM as u8, P::ETA_S1S2)?;

    // Convert to NTT domain
    let mut s1_hat_vec = s1_vec.clone();
    s1_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;

    let mut s2_hat_vec = s2_vec.clone();
    s2_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;

    // Step 5: t̂ = Â·ŝ1 + ŝ2
    let mut t_hat_vec = matrix_polyvecl_mul(&matrix_a_hat, &s1_hat_vec);
    t_hat_vec = t_hat_vec.add(&s2_hat_vec);

    // Convert back to standard domain
    let mut t_vec = t_hat_vec.clone();
    t_vec.inv_ntt_inplace().map_err(SignError::from_algo)?;

    // Step 6: (t0, t1) = Power2Round(t)
    let (t0_vec, t1_vec) = power2round_polyvec(&t_vec, P::D_PARAM);

    // Step 7: Pack public key
    let pk_bytes = pack_public_key::<P>(&rho_seed, &t1_vec)?;

    // Step 8: tr = H(pk)
    let mut hasher = Sha3_256::new();
    hasher.update(&pk_bytes).map_err(SignError::from_algo)?;
    let tr_digest = hasher.finalize().map_err(SignError::from_algo)?;
    let mut tr = [0u8; 32];
    tr.copy_from_slice(&tr_digest);

    // Step 9: Pack secret key in FIPS 204 format
    let sk_bytes = pack_secret_key::<P>(&rho_seed, &k_seed, &tr, &s1_vec, &s2_vec, &t0_vec)?;

    Ok((pk_bytes, sk_bytes))
}

/// Signing (Algorithm 10 from FIPS 204)
///
/// Accepts FIPS 204 format secret key bytes
pub(crate) fn sign_internal<P, R>(
    message: &[u8],
    sk_bytes: &[u8],
    _rng: &mut R,
) -> Result<Vec<u8>, SignError>
where
    P: DilithiumSchemeParams,
    R: RngCore + CryptoRng,
{
    // Unpack the FIPS 204 format secret key
    let (rho_seed, k_seed, tr_hash, s1_vec, s2_vec, t0_vec) = unpack_secret_key::<P>(sk_bytes)?;

    let matrix_a = expand_matrix_a::<P>(&rho_seed)?;
    let mut matrix_a_hat = Vec::with_capacity(P::K_DIM);
    for row in matrix_a {
        let mut row_ntt = row;
        row_ntt.ntt_inplace().map_err(SignError::from_algo)?;
        matrix_a_hat.push(row_ntt);
    }

    let mut xof_mu = ShakeXof256::new();
    xof_mu.update(&tr_hash).map_err(SignError::from_algo)?;
    xof_mu.update(message).map_err(SignError::from_algo)?;
    let mut mu = vec![0u8; 64];
    xof_mu.squeeze(&mut mu).map_err(SignError::from_algo)?;

    let mut kappa: u16 = 0;

    loop {
        if kappa >= P::MAX_SIGN_ABORTS {
            return Err(SignError::SignatureGeneration {
                algorithm: P::NAME,
                details: "Exceeded max signing attempts".into(),
            });
        }

        let y_vec = sample_polyvecl_uniform_gamma1::<P>(&k_seed, kappa, P::GAMMA1_PARAM)?;

        let mut y_hat_vec = y_vec.clone();
        y_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;

        let w_hat_vec = matrix_polyvecl_mul(&matrix_a_hat, &y_hat_vec);

        let mut w_vec = w_hat_vec.clone();
        w_vec.inv_ntt_inplace().map_err(SignError::from_algo)?;

        let w1_vec = highbits_polyvec(&w_vec, 2 * P::GAMMA2_PARAM);

        let w1_packed = pack_polyveck_w1::<P>(&w1_vec)?;

        // Compute challenge
        let mut xof_c = ShakeXof256::new();
        xof_c.update(&mu).map_err(SignError::from_algo)?;
        xof_c.update(&w1_packed).map_err(SignError::from_algo)?;

        let mut c_tilde_seed = vec![0u8; P::CHALLENGE_BYTES];
        xof_c
            .squeeze(&mut c_tilde_seed)
            .map_err(SignError::from_algo)?;

        // Sample challenge polynomial
        let c_poly = sample_challenge_c::<P>(&c_tilde_seed, P::TAU_PARAM as u32)?;

        // Compute z = y + cs1
        let mut z_vec = y_vec.clone();
        for i in 0..P::L_DIM {
            let cs1_i = schoolbook_mul_generic(&c_poly, &s1_vec.polys[i], true, true);
            z_vec.polys[i] = z_vec.polys[i].add(&cs1_i);
        }

        if !check_norm_polyvec_l::<P>(&z_vec, P::GAMMA1_PARAM - P::BETA_PARAM) {
            kappa = kappa.wrapping_add(1);
            continue;
        }

        // Compute cs2
        let mut cs2_vec = PolyVecK::<P>::zero();
        for i in 0..P::K_DIM {
            cs2_vec.polys[i] = schoolbook_mul_generic(&c_poly, &s2_vec.polys[i], true, true);
        }
        let w_minus_cs2 = w_vec.sub(&cs2_vec);

        let r0_vec = lowbits_polyvec(&w_minus_cs2, 2 * P::GAMMA2_PARAM);

        if !check_norm_polyvec_k::<P>(&r0_vec, P::GAMMA2_PARAM - P::BETA_PARAM) {
            kappa = kappa.wrapping_add(1);
            continue;
        }

        // Compute ct0
        let mut ct0_vec = PolyVecK::<P>::zero();
        for i in 0..P::K_DIM {
            ct0_vec.polys[i] = schoolbook_mul_generic(&c_poly, &t0_vec.polys[i], true, true);
        }

        // Compute z_for_hint = ct0 - cs2 using centered subtraction
        let z_for_hint = ct0_vec.sub_centered(&cs2_vec);

        // Check the centered norm
        let mut max_norm = 0i32;
        for i in 0..P::K_DIM {
            for j in 0..DILITHIUM_N {
                let coeff = z_for_hint.polys[i].coeffs[j];
                let centered = if coeff > DilithiumParams::Q / 2 {
                    coeff as i32 - DilithiumParams::Q as i32
                } else {
                    coeff as i32
                };
                max_norm = max_norm.max(centered.abs());
            }
        }

        if max_norm > (P::GAMMA2_PARAM - P::BETA_PARAM) as i32 {
            kappa = kappa.wrapping_add(1);
            continue;
        }

        // Generate hints
        let (h_hint_poly, hint_count) = match make_hint_polyveck::<P>(&w_vec, &z_for_hint) {
            Ok((hints, count)) => (hints, count),
            Err(_) => {
                kappa = kappa.wrapping_add(1);
                continue;
            }
        };

        if hint_count > P::OMEGA_PARAM as usize {
            kappa = kappa.wrapping_add(1);
            continue;
        }

        // Check ||c · t0||∞ < γ2 − β
        if !check_norm_polyvec_k::<P>(&ct0_vec, P::GAMMA2_PARAM - P::BETA_PARAM) {
            kappa = kappa.wrapping_add(1);
            continue;
        }

        // All checks passed - success!
        let sig_bytes = pack_signature::<P>(&c_tilde_seed, &z_vec, &h_hint_poly)?;

        return Ok(sig_bytes);
    }
}

/// Verification (Algorithm 11 from FIPS 204)
///
/// Accepts if: c̃ = H(μ || UseHint(h, Az - ct1·2^d)) and ||z||∞ ≤ γ1 - β.
pub(crate) fn verify_internal<P>(
    message: &[u8],
    sig_bytes: &[u8],
    pk_bytes: &[u8],
) -> Result<(), SignError>
where
    P: DilithiumSchemeParams,
{
    // Step 1: Unpack public key (ρ, t1)
    let (rho_seed, t1_vec) = unpack_public_key::<P>(pk_bytes)?;

    // Step 2: Unpack signature (c̃, z, h)
    let (c_tilde_seed_sig, z_vec, h_hint_poly) = unpack_signature::<P>(sig_bytes)?;

    // Step 3: Check ||z||∞ < γ1 - β
    if !check_norm_polyvec_l::<P>(&z_vec, P::GAMMA1_PARAM - P::BETA_PARAM) {
        return Err(SignError::Verification {
            algorithm: P::NAME,
            details: "Verification failed: z norm check".into(),
        });
    }

    // Step 4: Expand A from ρ, then convert to Â
    let matrix_a = expand_matrix_a::<P>(&rho_seed)?;
    let mut matrix_a_hat = Vec::with_capacity(P::K_DIM);
    for row in matrix_a {
        let mut row_ntt = row;
        row_ntt.ntt_inplace().map_err(SignError::from_algo)?;
        matrix_a_hat.push(row_ntt);
    }

    // Step 5: tr = H(pk)
    let mut hasher_tr = Sha3_256::new();
    hasher_tr.update(pk_bytes).map_err(SignError::from_algo)?;
    let tr_digest = hasher_tr.finalize().map_err(SignError::from_algo)?;
    let mut tr = [0u8; 32];
    tr.copy_from_slice(&tr_digest);

    // Step 6: μ = H(tr || M)
    let mut xof_mu = ShakeXof256::new();
    xof_mu.update(&tr).map_err(SignError::from_algo)?;
    xof_mu.update(message).map_err(SignError::from_algo)?;
    let mut mu = vec![0u8; 64];
    xof_mu.squeeze(&mut mu).map_err(SignError::from_algo)?;

    // Step 7: c = SampleInBall(c̃_sig)
    let c_poly = sample_challenge_c::<P>(&c_tilde_seed_sig, P::TAU_PARAM as u32)?;

    // Compute Az
    let mut z_hat_vec = z_vec.clone();
    z_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;

    let mut w_prime_vec = matrix_polyvecl_mul(&matrix_a_hat, &z_hat_vec);
    w_prime_vec
        .inv_ntt_inplace()
        .map_err(SignError::from_algo)?;

    // Scale t1 by 2^d
    let two_d = 1u32 << P::D_PARAM;
    let mut t1_scaled = t1_vec.clone();
    for poly in t1_scaled.polys.iter_mut() {
        for coeff in poly.coeffs.iter_mut() {
            *coeff = ((*coeff as u64 * two_d as u64) % DilithiumParams::Q as u64) as u32;
        }
    }

    // Subtract c · (t1·2^d)
    for i in 0..P::K_DIM {
        let ct1 = challenge_poly_mul(&c_poly, &t1_scaled.polys[i]);
        w_prime_vec.polys[i] = w_prime_vec.polys[i].sub(&ct1);
    }

    // Ensure coefficients are in [0, q)
    for i in 0..P::K_DIM {
        for j in 0..DILITHIUM_N {
            let val = w_prime_vec.polys[i].coeffs[j];
            if val >= DilithiumParams::Q {
                w_prime_vec.polys[i].coeffs[j] = val % DilithiumParams::Q;
            }
        }
    }

    // Apply UseHint
    let w1_double_prime_vec = use_hint_polyveck::<P>(&h_hint_poly, &w_prime_vec)?;

    // Pack w1''
    let w1_double_prime_packed = pack_polyveck_w1::<P>(&w1_double_prime_vec)?;

    // Recompute challenge
    let mut xof_c_recompute = ShakeXof256::new();
    xof_c_recompute.update(&mu).map_err(SignError::from_algo)?;
    xof_c_recompute
        .update(&w1_double_prime_packed)
        .map_err(SignError::from_algo)?;

    let mut c_tilde_seed_recomputed = vec![0u8; P::CHALLENGE_BYTES];
    xof_c_recompute
        .squeeze(&mut c_tilde_seed_recomputed)
        .map_err(SignError::from_algo)?;

    // 1. Check challenge equality (Constant Time)
    let challenge_match = c_tilde_seed_sig.ct_eq(&c_tilde_seed_recomputed);

    // 2. Verify hint count (Always execute to prevent timing leaks)
    let mut total_ones = 0usize;
    for row in &h_hint_poly.polys {
        total_ones += row.coeffs.iter().filter(|&&b| b == 1).count();
    }
    let hints_valid = total_ones <= P::OMEGA_PARAM as usize;

    // 3. Return errors if necessary (Branching)
    // We check challenge match first to maintain error precedence,
    // but the timing leak is plugged because the hint counting loop above ran regardless.
    if !bool::from(challenge_match) {
        return Err(SignError::Verification {
            algorithm: P::NAME,
            details: "Verification failed: challenge mismatch".into(),
        });
    }

    if !hints_valid {
        return Err(SignError::Verification {
            algorithm: P::NAME,
            details: "Verification failed: too many hints in signature".into(),
        });
    }

    Ok(())
}