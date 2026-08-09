//! Core implementation of Dilithium key generation, signing, and verification per FIPS 204.
//!
//! Implements lattice-based signatures using Fiat-Shamir with Aborts.
//! Security based on Module-LWE and Module-SIS problems.
//!
//! Critical invariants (DO NOT MODIFY):
//! - `||z||∞ ≤ γ1 - β` (prevents key recovery)
//! - `||LowBits(w - cs2)||∞ ≤ γ2 - β` (ensures uniformity)
//! - `||ct0||∞ < γ2` when this check is reachable for the parameter set
//! - `hint_count ≤ ω` (ensures verifier can reconstruct w1)
//! - Rejection sampling protects against side-channel leakage
//!
//! Implementation notes:
//! - Signing accepts either caller-supplied randomness or the optional deterministic
//!   ML-DSA internal variant (`rnd = 0^32`)
//! - The per-attempt products `cs1`, `cs2`, and `ct0` are computed in the NTT domain
//! - NTT library functions handle domain management correctly per FIPS 204
//! - After inv_ntt_inplace(), coefficients are in standard domain per FIPS 204
//!
//! Internal module - use public `Dilithium2/3/5` types instead.

use super::arithmetic::{
    challenge_poly_mul, check_norm_polyvec_k_ct, check_norm_polyvec_l_ct, highbits_polyvec,
    lowbits_polyvec, make_hint_polyveck_ct, power2round_polyvec, use_hint_polyveck,
};
use super::encoding::{
    pack_polyveck_w1, pack_public_key, pack_secret_key, pack_signature, unpack_public_key,
    unpack_secret_key, unpack_signature,
};
use super::polyvec::{expand_matrix_a, matrix_polyvecl_mul, PolyVecK, PolyVecL};
use super::sampling::{
    sample_challenge_c, sample_polyveck_rej_bounded, sample_polyvecl_rej_bounded,
    sample_polyvecl_uniform_gamma1,
};

use crate::error::Error as SignError;
#[cfg(not(feature = "std"))]
use alloc::{format, vec, vec::Vec};
use dcrypt_algorithms::poly::params::{DilithiumParams, Modulus};
use dcrypt_algorithms::xof::shake::ShakeXof256;
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use dcrypt_params::pqc::dilithium::{DilithiumSchemeParams, DILITHIUM_N};
use rand::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

struct SigningAttempt<P: DilithiumSchemeParams> {
    c_tilde_seed: Vec<u8>,
    z_vec: PolyVecL<P>,
    h_hint_poly: PolyVecK<P>,
    candidate_valid: Choice,
}

#[inline(always)]
fn ct_assign_bytes(dst: &mut [u8], src: &[u8], choice: Choice) {
    for (dst_byte, src_byte) in dst.iter_mut().zip(src.iter()) {
        *dst_byte = u8::conditional_select(dst_byte, src_byte, choice);
    }
}

#[inline(always)]
fn ct_eq_u64(a: u64, b: u64) -> Choice {
    let diff = a ^ b;
    Choice::from((((diff | diff.wrapping_neg()) >> 63) ^ 1) as u8)
}

#[inline(always)]
fn ct_le_usize(a: usize, b: usize) -> Choice {
    let lt = Choice::from((((a as u64).wrapping_sub(b as u64)) >> 63) as u8);
    lt | ct_eq_u64(a as u64, b as u64)
}

fn prepare_signing_inputs<P>(
    formatted_message: &[u8],
    sk_bytes: &[u8],
    randomizer: &[u8; 32],
    supplied_mu: Option<&[u8; 64]>,
) -> Result<
    (
        [u8; 64],
        Vec<PolyVecL<P>>,
        Vec<u8>,
        PolyVecL<P>,
        PolyVecK<P>,
        PolyVecK<P>,
    ),
    SignError,
>
where
    P: DilithiumSchemeParams,
{
    let (rho_seed, k_seed, tr_hash, s1_vec, s2_vec, t0_vec) = unpack_secret_key::<P>(sk_bytes)?;

    let matrix_a_hat = expand_matrix_a::<P>(&rho_seed)?;

    let mut mu = vec![0u8; 64];
    if let Some(external_mu) = supplied_mu {
        mu.copy_from_slice(external_mu);
    } else {
        let mut xof_mu = ShakeXof256::new();
        xof_mu.update(&tr_hash).map_err(SignError::from_algo)?;
        xof_mu
            .update(formatted_message)
            .map_err(SignError::from_algo)?;
        xof_mu.squeeze(&mut mu).map_err(SignError::from_algo)?;
    }

    let mut rho_double_prime = [0u8; 64];
    let mut xof_rho = ShakeXof256::new();
    xof_rho.update(&k_seed).map_err(SignError::from_algo)?;
    xof_rho.update(randomizer).map_err(SignError::from_algo)?;
    xof_rho.update(&mu).map_err(SignError::from_algo)?;
    xof_rho
        .squeeze(&mut rho_double_prime)
        .map_err(SignError::from_algo)?;

    let mut s1_hat_vec = s1_vec;
    s1_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;

    let mut s2_hat_vec = s2_vec;
    s2_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;

    let mut t0_hat_vec = t0_vec;
    t0_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;

    Ok((
        rho_double_prime,
        matrix_a_hat,
        mu,
        s1_hat_vec,
        s2_hat_vec,
        t0_hat_vec,
    ))
}

fn evaluate_signing_attempt<P>(
    rho_double_prime: &[u8; 64],
    matrix_a_hat: &[PolyVecL<P>],
    mu: &[u8],
    s1_hat_vec: &PolyVecL<P>,
    s2_hat_vec: &PolyVecK<P>,
    t0_hat_vec: &PolyVecK<P>,
    attempt_index: u16,
) -> Result<SigningAttempt<P>, SignError>
where
    P: DilithiumSchemeParams,
{
    let kappa = attempt_index.wrapping_mul(P::L_DIM as u16);
    let mut y_vec = sample_polyvecl_uniform_gamma1::<P>(rho_double_prime, kappa, P::GAMMA1_PARAM)?;

    let mut y_hat_vec = y_vec.clone();
    y_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;

    let w_hat_vec = matrix_polyvecl_mul(matrix_a_hat, &y_hat_vec);

    let mut w_vec = w_hat_vec.clone();
    w_vec.inv_ntt_inplace().map_err(SignError::from_algo)?;

    let w1_vec = highbits_polyvec(&w_vec, 2 * P::GAMMA2_PARAM);

    let w1_packed = pack_polyveck_w1::<P>(&w1_vec)?;

    let mut xof_c = ShakeXof256::new();
    xof_c.update(mu).map_err(SignError::from_algo)?;
    xof_c.update(&w1_packed).map_err(SignError::from_algo)?;

    let mut c_tilde_seed = vec![0u8; P::CHALLENGE_BYTES];
    xof_c
        .squeeze(&mut c_tilde_seed)
        .map_err(SignError::from_algo)?;

    let c_poly = sample_challenge_c::<P>(&c_tilde_seed, P::TAU_PARAM as u32)?;
    let mut c_hat = c_poly.clone();
    c_hat.ntt_inplace().map_err(SignError::from_algo)?;

    let mut cs1_vec = PolyVecL::<P>::zero();
    for i in 0..P::L_DIM {
        cs1_vec.polys[i] = c_hat.ntt_mul(&s1_hat_vec.polys[i]);
    }
    cs1_vec.inv_ntt_inplace().map_err(SignError::from_algo)?;

    let mut z_vec = y_vec.clone();
    for i in 0..P::L_DIM {
        z_vec.polys[i] = z_vec.polys[i].add(&cs1_vec.polys[i]);
    }

    let z_ok = check_norm_polyvec_l_ct::<P>(&z_vec, P::GAMMA1_PARAM - P::BETA_PARAM);

    let mut cs2_vec = PolyVecK::<P>::zero();
    for i in 0..P::K_DIM {
        cs2_vec.polys[i] = c_hat.ntt_mul(&s2_hat_vec.polys[i]);
    }
    cs2_vec.inv_ntt_inplace().map_err(SignError::from_algo)?;
    let w_minus_cs2 = w_vec.sub(&cs2_vec);

    let r0_vec = lowbits_polyvec(&w_minus_cs2, 2 * P::GAMMA2_PARAM);

    let r0_ok = check_norm_polyvec_k_ct::<P>(&r0_vec, P::GAMMA2_PARAM - P::BETA_PARAM);

    let mut ct0_vec = PolyVecK::<P>::zero();
    for i in 0..P::K_DIM {
        ct0_vec.polys[i] = c_hat.ntt_mul(&t0_hat_vec.polys[i]);
    }
    ct0_vec.inv_ntt_inplace().map_err(SignError::from_algo)?;

    let mut w_prime_approx = w_minus_cs2.add(&ct0_vec);
    let mut neg_ct0_vec = ct0_vec.neg_mod_q();
    let (h_hint_poly, hint_count) = make_hint_polyveck_ct::<P>(&neg_ct0_vec, &w_prime_approx);

    let ct0_ok = check_norm_polyvec_k_ct::<P>(&ct0_vec, P::GAMMA2_PARAM);
    let hint_count_ok = ct_le_usize(hint_count, P::OMEGA_PARAM as usize);

    let candidate_valid = z_ok & r0_ok & hint_count_ok & ct0_ok;

    y_vec.zeroize();
    y_hat_vec.zeroize();
    w_vec.zeroize();
    cs1_vec.zeroize();
    cs2_vec.zeroize();
    ct0_vec.zeroize();
    w_prime_approx.zeroize();
    neg_ct0_vec.zeroize();

    Ok(SigningAttempt {
        c_tilde_seed,
        z_vec,
        h_hint_poly,
        candidate_valid,
    })
}

/// FIPS 204 Algorithm 1, with caller-supplied randomness.
pub(crate) fn keypair_internal<P, R>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>), SignError>
where
    P: DilithiumSchemeParams,
    R: RngCore + CryptoRng,
{
    let mut xi = [0u8; 32];
    rng.try_fill_bytes(&mut xi)
        .map_err(|error| SignError::KeyGeneration {
            algorithm: P::NAME,
            details: error.to_string(),
        })?;
    let result = keypair_from_seed_internal::<P>(&xi);
    xi.zeroize();
    result
}

/// FIPS 204 Algorithm 6, exposed within the crate for exact ACVP replay.
pub(crate) fn keypair_from_seed_internal<P: DilithiumSchemeParams>(
    xi: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), SignError> {
    let mut xof = ShakeXof256::new();
    xof.update(xi).map_err(SignError::from_algo)?;
    xof.update(&[P::K_DIM as u8, P::L_DIM as u8])
        .map_err(SignError::from_algo)?;

    let mut rho_seed = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut k_seed = [0u8; 32];
    xof.squeeze(&mut rho_seed).map_err(SignError::from_algo)?;
    xof.squeeze(&mut rho_prime).map_err(SignError::from_algo)?;
    xof.squeeze(&mut k_seed).map_err(SignError::from_algo)?;

    let matrix_a_hat = expand_matrix_a::<P>(&rho_seed)?;

    let mut s1_vec = sample_polyvecl_rej_bounded::<P>(&rho_prime, P::ETA_S1S2)?;
    let mut s2_vec = sample_polyveck_rej_bounded::<P>(&rho_prime, P::ETA_S1S2)?;

    let mut s1_hat_vec = s1_vec.clone();
    s1_hat_vec.ntt_inplace().map_err(SignError::from_algo)?;

    let mut t_vec = matrix_polyvecl_mul(&matrix_a_hat, &s1_hat_vec);
    t_vec.inv_ntt_inplace().map_err(SignError::from_algo)?;
    t_vec = t_vec.add(&s2_vec);

    let (mut t0_vec, t1_vec) = power2round_polyvec(&t_vec, P::D_PARAM);

    let pk_bytes = pack_public_key::<P>(&rho_seed, &t1_vec)?;

    let mut tr = [0u8; 64];
    let mut tr_xof = ShakeXof256::new();
    tr_xof.update(&pk_bytes).map_err(SignError::from_algo)?;
    tr_xof.squeeze(&mut tr).map_err(SignError::from_algo)?;

    let sk_bytes = pack_secret_key::<P>(&rho_seed, &k_seed, &tr, &s1_vec, &s2_vec, &t0_vec)?;

    rho_prime.zeroize();
    k_seed.zeroize();
    tr.zeroize();
    s1_vec.zeroize();
    s2_vec.zeroize();
    s1_hat_vec.zeroize();
    t0_vec.zeroize();

    Ok((pk_bytes, sk_bytes))
}

/// Validate an expanded private key and derive its corresponding public key.
///
/// This recomputes `A*s1+s2`, both halves of `Power2Round`, `pk`, and `tr`,
/// then requires the original expanded-key bytes to equal the canonical
/// re-encoding. In particular, malformed or incoherent `t0` values cannot be
/// accepted merely because a trial signature happens to verify.
pub(crate) fn validate_secret_key_internal<P: DilithiumSchemeParams>(
    sk_bytes: &[u8],
) -> Result<Vec<u8>, SignError> {
    let (rho, mut k_seed, mut stored_tr, mut s1, mut s2, mut stored_t0) =
        unpack_secret_key::<P>(sk_bytes)?;

    let matrix_a_hat = expand_matrix_a::<P>(&rho)?;
    let mut s1_hat = s1.clone();
    s1_hat.ntt_inplace().map_err(SignError::from_algo)?;
    let mut t = matrix_polyvecl_mul(&matrix_a_hat, &s1_hat);
    t.inv_ntt_inplace().map_err(SignError::from_algo)?;
    t = t.add(&s2);
    let (mut expected_t0, t1) = power2round_polyvec(&t, P::D_PARAM);
    let public_key = pack_public_key::<P>(&rho, &t1)?;

    let mut expected_tr = [0u8; 64];
    let mut tr_xof = ShakeXof256::new();
    tr_xof.update(&public_key).map_err(SignError::from_algo)?;
    tr_xof
        .squeeze(&mut expected_tr)
        .map_err(SignError::from_algo)?;

    let mut canonical = pack_secret_key::<P>(&rho, &k_seed, &expected_tr, &s1, &s2, &expected_t0)?;
    let coherent = bool::from(canonical.as_slice().ct_eq(sk_bytes));

    k_seed.zeroize();
    stored_tr.zeroize();
    expected_tr.zeroize();
    s1.zeroize();
    s2.zeroize();
    stored_t0.zeroize();
    expected_t0.zeroize();
    s1_hat.zeroize();
    t.zeroize();
    canonical.zeroize();

    if coherent {
        Ok(public_key)
    } else {
        Err(SignError::InvalidKey(
            "ML-DSA expanded private key is not coherent".into(),
        ))
    }
}

pub(crate) fn validate_key_pair_internal<P: DilithiumSchemeParams>(
    sk_bytes: &[u8],
    pk_bytes: &[u8],
) -> Result<(), SignError> {
    let derived = validate_secret_key_internal::<P>(sk_bytes)?;
    if bool::from(derived.as_slice().ct_eq(pk_bytes)) {
        Ok(())
    } else {
        Err(SignError::InvalidKey(
            "ML-DSA expanded private/public key mismatch".into(),
        ))
    }
}

/// Signing (Algorithm 10 from FIPS 204)
///
/// Accepts FIPS 204 format secret key bytes
pub(crate) fn sign_internal<P>(
    formatted_message: &[u8],
    sk_bytes: &[u8],
    randomizer: &[u8; 32],
    supplied_mu: Option<&[u8; 64]>,
) -> Result<Vec<u8>, SignError>
where
    P: DilithiumSchemeParams,
{
    let (rho_double_prime, matrix_a_hat, mu, s1_hat_vec, s2_hat_vec, t0_hat_vec) =
        prepare_signing_inputs::<P>(formatted_message, sk_bytes, randomizer, supplied_mu)?;

    let mut selected_c_tilde = vec![0u8; P::CHALLENGE_BYTES];
    let mut selected_z = PolyVecL::<P>::zero();
    let mut selected_h = PolyVecK::<P>::zero();
    let mut found_valid = Choice::from(0u8);

    for kappa in 0..P::FIXED_SIGNING_WINDOW {
        let mut attempt = evaluate_signing_attempt::<P>(
            &rho_double_prime,
            &matrix_a_hat,
            &mu,
            &s1_hat_vec,
            &s2_hat_vec,
            &t0_hat_vec,
            kappa,
        )?;

        let take_candidate = (!found_valid) & attempt.candidate_valid;
        ct_assign_bytes(&mut selected_c_tilde, &attempt.c_tilde_seed, take_candidate);
        selected_z = PolyVecL::<P>::conditional_select(&selected_z, &attempt.z_vec, take_candidate);
        selected_h =
            PolyVecK::<P>::conditional_select(&selected_h, &attempt.h_hint_poly, take_candidate);
        found_valid = found_valid | attempt.candidate_valid;

        attempt.c_tilde_seed.zeroize();
        attempt.z_vec.zeroize();
        attempt.h_hint_poly.zeroize();
    }

    if bool::from(found_valid) {
        let sig = pack_signature::<P>(&selected_c_tilde, &selected_z, &selected_h)?;
        selected_c_tilde.zeroize();
        selected_z.zeroize();
        selected_h.zeroize();
        Ok(sig)
    } else {
        selected_c_tilde.zeroize();
        selected_z.zeroize();
        selected_h.zeroize();
        Err(SignError::SignatureGeneration {
            algorithm: P::NAME,
            details: format!(
                "Exceeded fixed signing window of {} attempts",
                P::FIXED_SIGNING_WINDOW
            ),
        })
    }
}

/// Verification (Algorithm 11 from FIPS 204)
///
/// Accepts if: c̃ = H(μ || UseHint(h, Az - ct1·2^d)) and ||z||∞ ≤ γ1 - β.
pub(crate) fn verify_internal<P>(
    formatted_message: &[u8],
    sig_bytes: &[u8],
    pk_bytes: &[u8],
    supplied_mu: Option<&[u8; 64]>,
) -> Result<(), SignError>
where
    P: DilithiumSchemeParams,
{
    // Step 1: Unpack public key (ρ, t1)
    let (rho_seed, t1_vec) = unpack_public_key::<P>(pk_bytes)?;

    // Step 2: Unpack signature (c̃, z, h)
    let (c_tilde_seed_sig, z_vec, h_hint_poly) = unpack_signature::<P>(sig_bytes)?;

    // Accumulate all verification checks and branch only once at the end.
    let mut verification_ok = check_norm_polyvec_l_ct::<P>(&z_vec, P::GAMMA1_PARAM - P::BETA_PARAM);

    // ExpandA returns the matrix directly in NTT representation.
    let matrix_a_hat = expand_matrix_a::<P>(&rho_seed)?;

    let mut tr = [0u8; 64];
    let mut tr_xof = ShakeXof256::new();
    tr_xof.update(pk_bytes).map_err(SignError::from_algo)?;
    tr_xof.squeeze(&mut tr).map_err(SignError::from_algo)?;

    let mut mu = vec![0u8; 64];
    if let Some(external_mu) = supplied_mu {
        mu.copy_from_slice(external_mu);
    } else {
        let mut xof_mu = ShakeXof256::new();
        xof_mu.update(&tr).map_err(SignError::from_algo)?;
        xof_mu
            .update(formatted_message)
            .map_err(SignError::from_algo)?;
        xof_mu.squeeze(&mut mu).map_err(SignError::from_algo)?;
    }

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
            w_prime_vec.polys[i].coeffs[j] = val % DilithiumParams::Q;
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
        for coeff in &row.coeffs {
            total_ones = total_ones.wrapping_add((*coeff == 1) as usize);
        }
    }
    let hints_valid = ct_le_usize(total_ones, P::OMEGA_PARAM as usize);

    verification_ok &= challenge_match & hints_valid;

    let verification_error = SignError::Verification {
        algorithm: P::NAME,
        details: "Verification failed".into(),
    };

    if bool::from(verification_ok) {
        drop(verification_error);
        Ok(())
    } else {
        Err(verification_error)
    }
}
