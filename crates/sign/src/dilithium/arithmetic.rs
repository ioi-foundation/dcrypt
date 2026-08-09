// arithmetic.rs
//! Arithmetic functions crucial for Dilithium, implementing FIPS 204 algorithms.
//!
//! All functions are spec-compliant with FIPS 204, matching the reference implementation exactly.

use super::polyvec::{PolyVecK, PolyVecL};
use crate::error::Error as SignError;
use dcrypt_algorithms::poly::params::{DilithiumParams, Modulus};
use dcrypt_algorithms::poly::polynomial::Polynomial;
use dcrypt_params::pqc::dilithium::{DilithiumSchemeParams, DILITHIUM_N, DILITHIUM_Q};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Dilithium modulus Q
const Q: i32 = 8_380_417;

#[inline(always)]
fn ct_lt_u32(a: u32, b: u32) -> Choice {
    Choice::from((((a as u64).wrapping_sub(b as u64)) >> 63) as u8)
}

#[inline(always)]
fn ct_gt_u32(a: u32, b: u32) -> Choice {
    ct_lt_u32(b, a)
}

#[inline(always)]
fn ct_lt_u64(a: u64, b: u64) -> Choice {
    Choice::from((a.wrapping_sub(b) >> 63) as u8)
}

#[inline(always)]
fn ct_lt_i32(a: i32, b: i32) -> Choice {
    ct_lt_u32((a as u32) ^ 0x8000_0000, (b as u32) ^ 0x8000_0000)
}

#[inline(always)]
fn ct_lt_i64(a: i64, b: i64) -> Choice {
    ct_lt_u64(
        (a as u64) ^ 0x8000_0000_0000_0000,
        (b as u64) ^ 0x8000_0000_0000_0000,
    )
}

#[inline(always)]
fn ct_select_i32(a: i32, b: i32, choice: Choice) -> i32 {
    i32::from_ne_bytes(u32::conditional_select(&(a as u32), &(b as u32), choice).to_ne_bytes())
}

#[inline(always)]
fn ct_select_i64(a: i64, b: i64, choice: Choice) -> i64 {
    i64::from_ne_bytes(u64::conditional_select(&(a as u64), &(b as u64), choice).to_ne_bytes())
}

#[inline(always)]
fn ct_abs_i32(value: i32) -> u32 {
    let mask = value >> 31;
    ((value ^ mask).wrapping_sub(mask)) as u32
}

/// Helper - number of high-bit buckets (m) for the given decomposition width α = 2γ₂.
///
/// FIPS 204 Algorithm 40 defines m = (q - 1) / (2γ₂). For ML-DSA-44 this gives 44
/// high-bit values, and for ML-DSA-65/87 it gives 16.
#[inline]
pub(crate) const fn buckets(alpha: u32) -> u32 {
    (DILITHIUM_Q - 1) / alpha
}

/// Interpret a coefficient in [0,q) as a signed value in (-q/2, q/2].
#[inline]
pub(crate) fn to_centered(v: u32) -> i32 {
    let negative = v as i32 - DilithiumParams::Q as i32;
    ct_select_i32(v as i32, negative, ct_gt_u32(v, DilithiumParams::Q / 2))
}

/// Generic schoolbook multiplication that handles all coefficient interpretation cases.
/// This unified implementation ensures algebraic consistency across all polynomial multiplications.
///
/// Parameters:
/// - a: First polynomial
/// - b: Second polynomial
/// - a_centered: If true, interpret a's coefficients as centered (Q-1 represents -1)
/// - b_centered: If true, interpret b's coefficients as centered
pub fn schoolbook_mul_generic(
    a: &Polynomial<DilithiumParams>,
    b: &Polynomial<DilithiumParams>,
    a_centered: bool,
    b_centered: bool,
) -> Polynomial<DilithiumParams> {
    let mut result = Polynomial::<DilithiumParams>::zero();

    for i in 0..DILITHIUM_N {
        let a_i = if a_centered {
            to_centered(a.coeffs[i]) as i64
        } else {
            a.coeffs[i] as i64
        };

        for j in 0..DILITHIUM_N {
            let b_j = if b_centered {
                to_centered(b.coeffs[j]) as i64
            } else {
                b.coeffs[j] as i64
            };

            let prod = a_i * b_j;
            let idx = (i + j) % DILITHIUM_N;

            // Handle wrap-around with negation for X^n + 1
            if i + j >= DILITHIUM_N {
                result.coeffs[idx] =
                    ((result.coeffs[idx] as i64 - prod).rem_euclid(DILITHIUM_Q as i64)) as u32;
            } else {
                result.coeffs[idx] =
                    ((result.coeffs[idx] as i64 + prod).rem_euclid(DILITHIUM_Q as i64)) as u32;
            }
        }
    }

    result
}

/// Multiply a challenge polynomial by a standard polynomial.
///
/// This function correctly handles the special case where:
/// - The challenge polynomial `c` has coefficients in {-1, 0, 1} stored as {Q-1, 0, 1}
/// - The standard polynomial has coefficients in [0, Q)
///
/// This is specifically needed for computing c·t₁·2ᵈ during verification,
/// where the challenge must be interpreted as centered but t₁·2ᵈ is in standard form.
pub fn challenge_poly_mul(
    c: &Polynomial<DilithiumParams>,
    standard_poly: &Polynomial<DilithiumParams>,
) -> Polynomial<DilithiumParams> {
    // Use generic function with c centered, standard_poly non-centered
    schoolbook_mul_generic(c, standard_poly, true, false)
}

/// Implements `Power2Round_q` from FIPS 204, Algorithm 29.
/// Decomposes r ∈ Z_q into (r0, r1) such that r ≡ r1·2^d + r0 (mod q)
/// where r0 ∈ (-2^(d-1), 2^(d-1)]
pub fn power2round(r: u32, d: u32) -> (i32, u32) {
    let q = DilithiumParams::Q;
    let r_plus = r % q;
    let half = 1 << (d - 1);

    // mod± chooses the representative in (-2^(d-1), 2^(d-1)].
    let r1 = (r_plus + half - 1) >> d;
    let r0 = r_plus as i32 - (r1 as i32) * (1 << d);
    (r0, r1)
}

/// Split a ∈ [0,q) into (a₁, a₀) such that
///     a = a₁·α  +  a₀
/// with  a₀ ∈ (-γ2, γ2]  and  a₁ fits in appropriate number of bits.
///
/// FIPS-204 compliant implementation - follows Algorithm 36 exactly.
/// Uses centered remainder mod±(2γ₂) to put a₀ in (-γ2, γ2].
/// Special case: when a = q - 1, set r₁ ← 0 and r₀ ← r₀ - 1
#[inline]
pub fn decompose(a: u32, alpha_param: u32) -> (i32, u32) {
    let q = Q as u32;
    let a = a % q;
    let alpha = alpha_param;
    let gamma2 = alpha / 2;

    let r0_raw = (a % alpha) as i32;
    let r0_adjusted = r0_raw - alpha as i32;
    let r0 = ct_select_i32(r0_raw, r0_adjusted, ct_gt_u32(r0_raw as u32, gamma2));

    let r1 = (((a as i64) - (r0 as i64)) / (alpha as i64)) as u32;

    let adjusted = (a as i64) - (r0 as i64);
    let special = (adjusted as u32).ct_eq(&(q - 1));
    (
        ct_select_i32(r0, r0 - 1, special),
        u32::conditional_select(&r1, &0u32, special),
    )
}

/// Implements `HighBits` from FIPS 204.
/// Returns r1 where (r0, r1) = Decompose(r, alpha)
pub fn highbits(r_coeff: u32, alpha: u32) -> u32 {
    decompose(r_coeff, alpha).1
}

/// Implements `LowBits` from FIPS 204.
/// Returns r0 where (r0, r1) = Decompose(r, alpha)
/// Result is in (-γ2, γ2] per FIPS 204 Algorithm 36
pub fn lowbits(r_coeff: u32, alpha: u32) -> i32 {
    decompose(r_coeff, alpha).0
}

/// FIPS 204 final w1Encode (Algorithm 28).
/// Returns the FULL gamma-bucket index r1 (no truncation).
/// For ML-DSA-44: r1 ∈ [0,43] requires 6 bits
/// For ML-DSA-65/87: r1 ∈ [0,15] requires 4 bits
///
/// Note: Earlier drafts truncated/shifted these values, but FIPS 204 final
/// specifies that w1 encoding returns r1 directly (identity function).
#[inline]
pub fn w1_encode_gamma(r1_gamma: u32) -> u32 {
    // FIPS 204 final: return the full r1 value
    r1_gamma
}

/// Compute the number of bits needed to represent w1 coefficients.
/// This is b = bitlen((q-1)/(2γ₂) - 1) as per FIPS 204 Algorithm 28.
#[inline]
pub fn w1_bits_needed<P: DilithiumSchemeParams>() -> u32 {
    let m = buckets(2 * P::GAMMA2_PARAM);
    32 - (m - 1).leading_zeros()
}

// ---------------------------------------------------------------------------
// Hint system – Algorithms 39 & 40 (FIPS 204 final)
// ---------------------------------------------------------------------------

/// FIPS 204 Algorithm 40 (UseHint) - FINAL SPECIFICATION COMPLIANT
///
/// The final FIPS 204 specification (13-Aug-2024) defines UseHint as:
///
/// Step 3: "if h = 1 and r₀ > 0 return (r₁ + 1) mod m"     [rotate UP when positive]
/// Step 4: "if h = 1 and r₀ ≤ 0 return (r₁ − 1) mod m"     [rotate DOWN when zero/negative]
/// Step 5: "return r₁"                                      [no hint case]
///
/// This means:
/// - r₀ > 0   → rotate UP (+1 mod m)
/// - r₀ ≤ 0   → rotate DOWN (-1 mod m)
#[inline]
pub fn use_hint_coeff<P: DilithiumSchemeParams>(hint_bit: bool, r_coeff: u32) -> u32 {
    let gamma2 = P::GAMMA2_PARAM;
    let alpha = 2 * gamma2;
    let m = buckets(alpha);

    let (r0, r1) = decompose(r_coeff, alpha);
    let adjusted = u32::conditional_select(&((r1 + m - 1) % m), &((r1 + 1) % m), ct_lt_i32(0, r0));
    u32::conditional_select(&r1, &adjusted, Choice::from(hint_bit as u8))
}

/// Checks if the infinity norm of a polynomial is at most `bound`.
/// Coefficients are centered in (-Q/2, Q/2]
pub(crate) fn check_norm_poly_ct(poly: &Polynomial<DilithiumParams>, bound: u32) -> Choice {
    let mut valid = Choice::from(1u8);
    for &coeff in poly.coeffs.iter() {
        let centered = to_centered(coeff);
        valid = valid & ct_lt_u32(ct_abs_i32(centered), bound);
    }
    valid
}

/// Checks if the infinity norm of all polynomials in a PolyVecL is at most `bound`.
pub(crate) fn check_norm_polyvec_l_ct<P: DilithiumSchemeParams>(
    pv: &PolyVecL<P>,
    bound: u32,
) -> Choice {
    let mut valid = Choice::from(1u8);
    for poly in pv.polys.iter() {
        valid = valid & check_norm_poly_ct(poly, bound);
    }
    valid
}

/// Checks if the infinity norm of all polynomials in a PolyVecK is at most `bound`.
pub(crate) fn check_norm_polyvec_k_ct<P: DilithiumSchemeParams>(
    pv: &PolyVecK<P>,
    bound: u32,
) -> Choice {
    let mut valid = Choice::from(1u8);
    for poly in pv.polys.iter() {
        valid = valid & check_norm_poly_ct(poly, bound);
    }
    valid
}

/// Applies `Power2Round` element-wise to a PolyVecK.
pub fn power2round_polyvec<P: DilithiumSchemeParams>(
    pv: &PolyVecK<P>,
    d_param: u32,
) -> (PolyVecK<P>, PolyVecK<P>) {
    let mut pv0 = PolyVecK::<P>::zero();
    let mut pv1 = PolyVecK::<P>::zero();

    for i in 0..P::K_DIM {
        for j in 0..DilithiumParams::N {
            let (r0_signed, r1) = power2round(pv.polys[i].coeffs[j], d_param);
            // Store r0 as positive representative in [0, Q-1]
            pv0.polys[i].coeffs[j] =
                ((r0_signed + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
            pv1.polys[i].coeffs[j] = r1;
        }
    }

    (pv0, pv1)
}

/// Applies `HighBits` element-wise to a PolyVecK.
pub fn highbits_polyvec<P: DilithiumSchemeParams>(pv: &PolyVecK<P>, alpha: u32) -> PolyVecK<P> {
    let mut res = PolyVecK::<P>::zero();

    for i in 0..P::K_DIM {
        for j in 0..DilithiumParams::N {
            res.polys[i].coeffs[j] = highbits(pv.polys[i].coeffs[j], alpha);
        }
    }

    res
}

/// Applies `LowBits` element-wise to a PolyVecK.
pub fn lowbits_polyvec<P: DilithiumSchemeParams>(pv: &PolyVecK<P>, alpha: u32) -> PolyVecK<P> {
    let mut res = PolyVecK::<P>::zero();

    for i in 0..P::K_DIM {
        for j in 0..DilithiumParams::N {
            let r0_signed = lowbits(pv.polys[i].coeffs[j], alpha);
            // Convert from signed (−γ2, γ2] to canonical mod q representation [0, Q)
            res.polys[i].coeffs[j] =
                ((r0_signed + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
        }
    }

    res
}

/// FIPS 204 Algorithm 39 applied componentwise to polynomial vectors.
///
/// The inputs match the standard directly: `z_polyvec` is the additive offset and
/// `r_polyvec` is the base vector whose high bits will be adjusted by `UseHint`.
pub(crate) fn make_hint_polyveck_ct<P: DilithiumSchemeParams>(
    z_polyvec: &PolyVecK<P>,
    r_polyvec: &PolyVecK<P>,
) -> (PolyVecK<P>, usize) {
    let mut hints_pv = PolyVecK::<P>::zero();
    let mut hint_count: usize = 0;

    for i in 0..P::K_DIM {
        for j in 0..DILITHIUM_N {
            let r = r_polyvec.polys[i].coeffs[j];
            let z = z_polyvec.polys[i].coeffs[j];

            let z_signed = to_centered(z) as i64;
            let sum = r as i64 + z_signed;
            let with_q = sum + DilithiumParams::Q as i64;
            let non_negative = ct_select_i64(sum, with_q, ct_lt_i64(sum, 0));
            let reduced = non_negative - DilithiumParams::Q as i64;
            let r_plus_z = ct_select_i64(
                non_negative,
                reduced,
                !ct_lt_u64(non_negative as u64, DilithiumParams::Q as u64),
            ) as u32;

            let r1 = highbits(r, 2 * P::GAMMA2_PARAM);
            let v1 = highbits(r_plus_z, 2 * P::GAMMA2_PARAM);
            let hint_bit = !r1.ct_eq(&v1);

            hints_pv.polys[i].coeffs[j] = u32::conditional_select(&0u32, &1u32, hint_bit);
            hint_count = hint_count.wrapping_add(hint_bit.unwrap_u8() as usize);
        }
    }

    (hints_pv, hint_count)
}

/// Applies `UseHint` to recover high bits using hint vector.
/// Returns w1-encoded values (full gamma-bucket indices) for challenge hash computation.
///
/// Parameters:
/// - h_polyvec: Hint vector (0/1 coefficients)
/// - w_prime_polyvec: w' = Az - ct1*2^d (the combined value)
pub fn use_hint_polyveck<P: DilithiumSchemeParams>(
    h_polyvec: &PolyVecK<P>,       // Hint vector (0/1 coefficients)
    w_prime_polyvec: &PolyVecK<P>, // w' = Az - ct1*2^d (the combined value)
) -> Result<PolyVecK<P>, SignError> {
    let mut corrected_pv = PolyVecK::<P>::zero();

    for i in 0..P::K_DIM {
        for j in 0..DilithiumParams::N {
            let hint_bit = h_polyvec.polys[i].coeffs[j] == 1;
            let w_prime_coeff = w_prime_polyvec.polys[i].coeffs[j];

            // Apply UseHint to get the corrected γ-bucket index
            let r1_prime = use_hint_coeff::<P>(hint_bit, w_prime_coeff);

            // FIPS 204 final: store the full gamma-bucket index
            corrected_pv.polys[i].coeffs[j] = w1_encode_gamma(r1_prime);
        }
    }

    Ok(corrected_pv)
}
