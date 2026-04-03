//! Number Theoretic Transform Implementation
//!
//! Generic NTT/iNTT for polynomials over finite fields, with full
//! FIPS-204 compliance for Dilithium and support for Kyber variants.
//!
//! ## Dilithium (FIPS-204)
//! - Forward NTT: Algorithm 41 (DIF with standard domain I/O)
//! - Inverse NTT: Algorithm 42 (GS with standard domain I/O)
//! - Twiddle factors: Precomputed in Montgomery form (ζ·R mod q)
//! - Butterfly differences: Kept in [0, 2Q) range as per spec
//! - Pointwise multiplication: Standard domain multiplication
//!
//! ## Kyber
//! - Cooley-Tukey NTT with on-the-fly twiddle computation
//! - Full Montgomery domain processing
//! - Pointwise multiplication: Montgomery domain multiplication

#![cfg_attr(not(feature = "std"), no_std)]

use super::params::{Modulus, NttModulus, PostInvNtt};
use super::polynomial::Polynomial;
use crate::error::{Error, Result};

/// Modular exponentiation in standard domain
#[inline(always)]
fn pow_mod<M: Modulus>(mut base: u32, mut exp: u32) -> u32 {
    let mut acc: u32 = 1;
    while exp != 0 {
        if (exp & 1) == 1 {
            acc = ((acc as u64 * base as u64) % M::Q as u64) as u32;
        }
        base = ((base as u64 * base as u64) % M::Q as u64) as u32;
        exp >>= 1;
    }
    acc
}

/// Forward Number Theoretic Transform
pub trait NttOperator<M: NttModulus> {
    /// Performs forward NTT on polynomial in-place
    ///
    /// # Dilithium (FIPS-204)
    /// - Implements Algorithm 41 (DIF)
    /// - Input: coefficients in standard domain
    /// - Output: coefficients in standard domain
    ///
    /// # Kyber
    /// - Implements Cooley-Tukey NTT
    /// - Converts to Montgomery domain internally
    fn ntt(poly: &mut Polynomial<M>) -> Result<()>;
}

/// Inverse Number Theoretic Transform
pub trait InverseNttOperator<M: NttModulus> {
    /// Performs inverse NTT on polynomial in-place
    ///
    /// # Dilithium (FIPS-204)
    /// - Implements Algorithm 42 (GS)
    /// - Input: coefficients in standard domain
    /// - Output: standard or Montgomery domain based on POST_INVNTT_MODE
    ///
    /// # Kyber
    /// - Implements Cooley-Tukey inverse NTT
    /// - Scales by N^(-1) and converts back to standard domain
    fn inv_ntt(poly: &mut Polynomial<M>) -> Result<()>;
}

/// Cooley-Tukey NTT implementation
pub struct CooleyTukeyNtt;

/// Montgomery reduction: computes a * R^-1 mod Q
///
/// For a ∈ [0, Q·R), returns a·R^(-1) mod Q in [0, Q)
#[inline(always)]
pub fn montgomery_reduce<M: NttModulus>(a: u64) -> u32 {
    let q = M::Q as u64;
    let neg_qinv = M::NEG_QINV as u64;

    // Compute m = (a * NEG_QINV) mod 2^32
    let m = ((a as u32) as u64).wrapping_mul(neg_qinv) & 0xFFFFFFFF;
    // Compute t = (a + m * q) >> 32
    let t = a.wrapping_add(m.wrapping_mul(q)) >> 32;

    // Conditional reduction
    let result = t as u32;
    let mask = ((result >= M::Q) as u32).wrapping_neg();
    result.wrapping_sub(M::Q & mask)
}

/// Reduce any u32 to [0, Q)
/// Handles both normal range and wrapped values from underflow
#[inline]
fn reduce_to_q<M: Modulus>(x: u32) -> u32 {
    // Fast path for common case (x < 4Q)
    let mut y = x;
    y -= M::Q & ((y >= M::Q) as u32).wrapping_neg();
    y -= M::Q & ((y >= M::Q) as u32).wrapping_neg();

    if y < M::Q {
        return y;
    }

    // Barrett reduction for large/wrapped values
    let (mu, k) = if M::BARRETT_MU != 0 {
        (M::BARRETT_MU, M::BARRETT_K)
    } else {
        // Dynamic computation for moduli without precomputed constants
        let log_q = 64 - (M::Q as u64).leading_zeros(); // FIXED: Removed unnecessary cast
        let k = log_q + 32;
        let mu = (1u128 << k) / M::Q as u128; // FIXED: Removed unnecessary cast
        (mu, k)
    };

    let x_wide = y as u128;
    let q = ((x_wide * mu) >> k) as u32;
    let mut r = y.wrapping_sub(q.wrapping_mul(M::Q));

    r = r.wrapping_sub(M::Q & ((r >= M::Q) as u32).wrapping_neg());
    r
}

/// Montgomery multiplication: a * b * R^-1 mod Q
/// Accepts extended range inputs (e.g., [0, 9Q)) to preserve sign encoding
#[inline(always)]
fn montgomery_mul<M: NttModulus>(a: u32, b: u32) -> u32 {
    montgomery_reduce::<M>((a as u64) * (b as u64))
}

/// Modular addition with full reduction
#[inline(always)]
fn add_mod<M: Modulus>(a: u32, b: u32) -> u32 {
    ((a as u64 + b as u64) % M::Q as u64) as u32
}

/// Fast modular addition for inputs < Q
#[inline(always)]
fn add_mod_fast<M: Modulus>(a: u32, b: u32) -> u32 {
    let s = a + b;
    let mask = ((s >= M::Q) as u32).wrapping_neg();
    s - (M::Q & mask)
}

/// Fast modular subtraction for inputs < Q
#[inline(always)]
fn sub_mod_fast<M: Modulus>(a: u32, b: u32) -> u32 {
    let t = a.wrapping_add(M::Q).wrapping_sub(b);
    let mask = ((t >= M::Q) as u32).wrapping_neg();
    t - (M::Q & mask)
}

/// Modular subtraction returning [0, 2Q)
/// Used in FIPS-204 butterflies to preserve sign information
#[inline(always)]
fn sub_mod_upto_2q<M: Modulus>(a: u32, b: u32) -> u32 {
    a.wrapping_add(M::Q).wrapping_sub(b)
}

/// Convert standard domain to Montgomery domain
#[inline(always)]
fn to_montgomery<M: NttModulus>(val: u32) -> u32 {
    ((val as u64 * M::MONT_R as u64) % M::Q as u64) as u32
}

impl<M: NttModulus> NttOperator<M> for CooleyTukeyNtt {
    fn ntt(poly: &mut Polynomial<M>) -> Result<()> {
        let n = M::N;
        if n & (n - 1) != 0 {
            return Err(Error::Parameter {
                name: "NTT".into(),
                reason: "Polynomial degree must be a power of 2".into(),
            });
        }

        let coeffs = poly.as_mut_coeffs_slice();
        let is_dilithium = !M::ZETAS.is_empty(); // FIXED: Use is_empty()

        if is_dilithium {
            // FIPS-204 Algorithm 41: Forward NTT
            // Decimation-in-Frequency (DIF) with row-major twiddle traversal
            // Input: standard domain, Output: standard domain
            let mut k = 0;
            let mut len = n / 2; // Start at 128 for N=256

            while len >= 1 {
                // Row-major (block-first) iteration matches twiddle table order
                for start in (0..n).step_by(2 * len) {
                    let zeta = M::ZETAS[k]; // ζ·R mod q (Montgomery form)
                    k += 1;

                    for j in start..start + len {
                        let a = coeffs[j];
                        let b = coeffs[j + len];

                        // FIPS-204 DIF butterfly:
                        // t = ζ * b (Montgomery mul with ζ·R gives standard domain)
                        let t = montgomery_mul::<M>(b, zeta);
                        // a' = a + t mod q
                        coeffs[j] = add_mod::<M>(a, t);
                        // b' = a - t + Q (kept in [0, 2Q) per Algorithm 41)
                        coeffs[j + len] = sub_mod_upto_2q::<M>(a, t);
                    }
                }

                len >>= 1;
            }

            // Reduce all coefficients to [0, Q) for Dilithium compatibility
            for c in coeffs.iter_mut() {
                *c = reduce_to_q::<M>(*c);
            }
        } else {
            // Kyber NTT
            for c in coeffs.iter_mut() {
                *c = to_montgomery::<M>(*c);
            }

            let mut len = 1_usize;
            while len < n {
                let exp = n / (len << 1);
                let root_std = pow_mod::<M>(M::ZETA, exp as u32);
                let root_mont = to_montgomery::<M>(root_std);

                for start in (0..n).step_by(len << 1) {
                    let mut w_mont = M::MONT_R;

                    for j in 0..len {
                        let u = coeffs[start + j];
                        let v = montgomery_mul::<M>(coeffs[start + j + len], w_mont);

                        coeffs[start + j] = add_mod_fast::<M>(u, v);
                        coeffs[start + j + len] = sub_mod_fast::<M>(u, v);

                        w_mont = montgomery_mul::<M>(w_mont, root_mont);
                    }
                }
                len <<= 1;
            }
            // Kyber: Do NOT reduce here - coefficients must stay in Montgomery form!
        }

        Ok(())
    }
}

impl<M: NttModulus> InverseNttOperator<M> for CooleyTukeyNtt {
    fn inv_ntt(poly: &mut Polynomial<M>) -> Result<()> {
        let n = M::N;
        if n & (n - 1) != 0 {
            return Err(Error::Parameter {
                name: "Inverse NTT".into(),
                reason: "Polynomial degree must be a power of 2".into(),
            });
        }

        let coeffs = poly.as_mut_coeffs_slice();
        let is_dilithium = !M::ZETAS.is_empty(); // FIXED: Use is_empty()

        if is_dilithium {
            // FIPS-204 Algorithm 42: Inverse NTT
            // Gentleman-Sande (GS) with row-major traversal

            // Pre-condition: ensure coefficients < Q for GS butterflies
            for c in coeffs.iter_mut() {
                *c = reduce_to_q::<M>(*c);
            }

            let mut k = M::ZETAS.len(); // Start after last entry
            let mut len = 1;

            while len < n {
                // Row-major iteration matching forward NTT structure
                for start in (0..n).step_by(2 * len) {
                    k -= 1; // Traverse ZETAS in reverse

                    // Use negated forward twiddle for inverse
                    let zeta_fwd = M::ZETAS[k];
                    let zeta = if zeta_fwd == 0 { 0 } else { M::Q - zeta_fwd };

                    for j in start..start + len {
                        let t = coeffs[j];
                        let u = coeffs[j + len];

                        // FIPS-204 GS butterfly:
                        // Line 13: w_j ← w_j + w_{j+len}
                        coeffs[j] = add_mod::<M>(t, u);
                        // Line 14: w_{j+len} ← ζ^(-1) * (w_j - w_{j+len})
                        let diff = sub_mod_upto_2q::<M>(t, u);
                        coeffs[j + len] = montgomery_mul::<M>(diff, zeta);
                    }
                }

                len <<= 1;
            }

            // Final reduction before N^(-1) scaling
            for c in coeffs.iter_mut() {
                *c = reduce_to_q::<M>(*c);
            }

            // Scale by N^(-1) in standard domain
            let n_inv_std = pow_mod::<M>(M::N as u32, M::Q - 2);
            for c in coeffs.iter_mut() {
                *c = ((*c as u64 * n_inv_std as u64) % M::Q as u64) as u32;
            }

            match M::POST_INVNTT_MODE {
                PostInvNtt::Standard => {} // Already in standard domain
                PostInvNtt::Montgomery => {
                    // Convert to Montgomery if requested
                    for c in coeffs.iter_mut() {
                        *c = to_montgomery::<M>(*c);
                    }
                }
            }
        } else {
            // Kyber Inverse NTT
            let root_inv_std = pow_mod::<M>(M::ZETA, M::Q - 2); // FIXED: Removed unnecessary cast

            let mut len = n >> 1;
            while len >= 1 {
                let exp = n / (len << 1);
                let root_std = pow_mod::<M>(root_inv_std, exp as u32);
                let root_mont = to_montgomery::<M>(root_std);

                for start in (0..n).step_by(len << 1) {
                    let mut w_mont = M::MONT_R;

                    for j in 0..len {
                        let u = coeffs[start + j];
                        let v = coeffs[start + j + len];

                        coeffs[start + j] = add_mod_fast::<M>(u, v);
                        coeffs[start + j + len] =
                            montgomery_mul::<M>(sub_mod_fast::<M>(u, v), w_mont);

                        w_mont = montgomery_mul::<M>(w_mont, root_mont);
                    }
                }
                len >>= 1;
            }

            // Scale by N^(-1)
            for c in coeffs.iter_mut() {
                *c = montgomery_mul::<M>(*c, M::N_INV);
            }

            if M::POST_INVNTT_MODE == PostInvNtt::Standard {
                for c in coeffs.iter_mut() {
                    *c = montgomery_reduce::<M>(*c as u64);
                }
            }
        }

        Ok(())
    }
}

/// Extension methods for Polynomial
impl<M: NttModulus> Polynomial<M> {
    /// Convert polynomial to NTT domain
    pub fn ntt_inplace(&mut self) -> Result<()> {
        CooleyTukeyNtt::ntt(self)
    }

    /// Convert polynomial from NTT domain
    pub fn from_ntt_inplace(&mut self) -> Result<()> {
        CooleyTukeyNtt::inv_ntt(self)
    }

    /// Pointwise multiplication in NTT domain
    ///
    /// Both polynomials must already be in NTT domain.
    /// For Dilithium: inputs/output in standard domain (post-NTT)
    /// For Kyber: inputs/output in Montgomery domain
    pub fn ntt_mul(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        let n = M::N;
        let is_dilithium = !M::ZETAS.is_empty(); // FIXED: Use is_empty()

        if is_dilithium {
            // Dilithium: coefficients are in standard domain after NTT
            // Use standard multiplication
            for i in 0..n {
                result.coeffs[i] =
                    ((self.coeffs[i] as u64 * other.coeffs[i] as u64) % M::Q as u64) as u32;
            }
        } else {
            // Kyber: coefficients are in Montgomery domain after NTT
            // Use Montgomery multiplication to keep result in Montgomery domain
            for i in 0..n {
                result.coeffs[i] = montgomery_mul::<M>(self.coeffs[i], other.coeffs[i]);
            }
        }

        result
    }
}

#[cfg(test)]
mod tests;
