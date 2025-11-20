// Path: dcrypt/crates/algorithms/src/poly/fft/mod.rs
//! Fast Fourier Transform (FFT) over the BLS12-381 Scalar Field
//!
//! This module implements a Number Theoretic Transform (NTT), which is an FFT
//! adapted for finite fields. It operates on vectors of `Scalar` elements from the
//! BLS12-381 curve, enabling O(n log n) polynomial multiplication and interpolation.
//!
//! This is the high-performance engine required for schemes like Verkle trees that
//! rely on polynomial commitments over large prime fields.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::needless_range_loop)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::ec::bls12_381::Bls12_381Scalar as Scalar;
use crate::error::{Error, Result};
use std::sync::OnceLock;

const FFT_SIZE: usize = 256;

// --- field-specific 2-adicity and odd cofactor for BLS12-381 Fr ---
const TWO_ADICITY_FR: u32 = 32;
const FR_ODD_PART: [u64; 4] = [
    0xfffe_5bfe_ffff_ffff,
    0x09a1_d805_53bd_a402,
    0x299d_7d48_3339_d808,
    0x0000_0000_73ed_a753,
];

// Statics
static ROOT_OF_UNITY: OnceLock<Scalar> = OnceLock::new();
static FFT_N_ROOT: OnceLock<Scalar> = OnceLock::new();
static ROOTS_OF_UNITY: OnceLock<Vec<Scalar>> = OnceLock::new();
static INVERSE_ROOTS_OF_UNITY: OnceLock<Vec<Scalar>> = OnceLock::new();
static N_INV: OnceLock<Scalar> = OnceLock::new();
static PRIMITIVE_2N_ROOT: OnceLock<Scalar> = OnceLock::new();
static TWIST_FACTORS: OnceLock<Vec<Scalar>> = OnceLock::new();
static INVERSE_TWIST_FACTORS: OnceLock<Vec<Scalar>> = OnceLock::new();

// The original hardcoded constant (kept as a seed candidate).
fn get_root_of_unity() -> &'static Scalar {
    ROOT_OF_UNITY.get_or_init(|| {
        Scalar::from_raw([
            0x4253_d252_a210_b619, 0x81c3_5f15_01a0_2431,
            0xb734_6a32_008b_0320, 0x0a16_14a8_64b3_09e1
        ])
    })
}

// --- NEW: small helpers ---

#[inline]
fn pow_vartime_u64x4(base: Scalar, by: &[u64; 4]) -> Scalar {
    let mut res = Scalar::one();
    for e in by.iter().rev() {
        for i in (0..64).rev() {
            res = res.square();
            if ((*e >> i) & 1) == 1 {
                res *= base;
            }
        }
    }
    res
}

/// Project an arbitrary element into μ_{2^S}: x ↦ x^T
#[inline]
fn project_to_2power(x: Scalar) -> Scalar {
    pow_vartime_u64x4(x, &FR_ODD_PART)
}

/// Compute the 2-adic order k of an element r ∈ μ_{2^S}:
/// the smallest k ≥ 1 such that r^(2^k) = 1.
fn two_adicity(mut r: Scalar) -> u32 {
    for k in 1..=TWO_ADICITY_FR {
        r = r.square();
        if r == Scalar::one() {
            return k;
        }
    }
    // FIX: Escape the curly braces in the format string.
    debug_assert!(false, "two_adicity: element not in μ_{{2^S}}");
    TWO_ADICITY_FR
}

/// Deterministically pick a seed in μ_{2^S} whose 2-adic order k ≥ min_k.
fn select_2power_seed(min_k: u32) -> (Scalar, u32) {
    let bases: [Scalar; 12] = [
        *get_root_of_unity(),
        Scalar::from(5u64), Scalar::from(7u64), Scalar::from(2u64),
        Scalar::from(3u64), Scalar::from(11u64), Scalar::from(13u64),
        Scalar::from(17u64), Scalar::from(19u64), Scalar::from(29u64),
        Scalar::from(31u64), Scalar::from(37u64),
    ];

    for base in bases.iter() {
        let seed = project_to_2power(*base);
        if !bool::from(seed.is_zero()) {
            let k = two_adicity(seed);
            if k >= min_k {
                return (seed, k);
            }
        }
    }

    panic!("Could not find a suitable 2-power root of unity seed");
}

// --- Derived roots built from a consistent seed ---

fn get_fft_n_root() -> &'static Scalar {
    FFT_N_ROOT.get_or_init(|| {
        let need = FFT_SIZE.trailing_zeros();
        let (seed, k) = select_2power_seed(need);

        let mut w_n = seed;
        for _ in 0..(k - need) {
            w_n = w_n.square();
        }

        #[cfg(debug_assertions)]
        {
            let mut t = w_n;
            for _ in 0..need { t = t.square(); }
            debug_assert_eq!(t, Scalar::one(), "w_N^N must be 1");

            let mut half = w_n;
            for _ in 0..(need - 1) { half = half.square(); }
            debug_assert_eq!(half, -Scalar::one(), "w_N^(N/2) must be -1");
        }
        w_n
    })
}

fn get_roots_of_unity() -> &'static Vec<Scalar> {
    ROOTS_OF_UNITY.get_or_init(|| {
        let w_n = *get_fft_n_root();
        let mut roots = vec![Scalar::one(); FFT_SIZE];
        for i in 1..FFT_SIZE {
            roots[i] = roots[i - 1] * w_n;
        }
        roots
    })
}

fn get_inverse_roots_of_unity() -> &'static Vec<Scalar> {
    INVERSE_ROOTS_OF_UNITY.get_or_init(|| {
        let inv_w_n = get_fft_n_root().invert().unwrap();
        let mut roots = vec![Scalar::one(); FFT_SIZE];
        for i in 1..FFT_SIZE {
            roots[i] = roots[i - 1] * inv_w_n;
        }
        roots
    })
}

fn get_n_inv() -> &'static Scalar {
    N_INV.get_or_init(|| Scalar::from(FFT_SIZE as u64).invert().unwrap())
}

fn get_primitive_2n_root() -> &'static Scalar {
    PRIMITIVE_2N_ROOT.get_or_init(|| {
        let need = FFT_SIZE.trailing_zeros();
        let (seed, k) = select_2power_seed(need + 1);

        let mut g = seed;
        for _ in 0..(k - (need + 1)) {
            g = g.square();
        }

        debug_assert_eq!(g.square(), *get_fft_n_root(), "g^2 must equal w_N");
        
        let mut gn = g;
        for _ in 0..need { gn = gn.square(); }
        debug_assert_eq!(gn, -Scalar::one(), "g^N must be -1");

        g
    })
}

fn get_twist_factors() -> &'static Vec<Scalar> {
    TWIST_FACTORS.get_or_init(|| {
        let g = *get_primitive_2n_root();
        let mut factors = vec![Scalar::one(); FFT_SIZE];
        for i in 1..FFT_SIZE {
            factors[i] = factors[i - 1] * g;
        }
        factors
    })
}

fn get_inverse_twist_factors() -> &'static Vec<Scalar> {
    INVERSE_TWIST_FACTORS.get_or_init(|| {
        let inv_g = get_primitive_2n_root().invert().unwrap();
        let mut factors = vec![Scalar::one(); FFT_SIZE];
        for i in 1..FFT_SIZE {
            factors[i] = factors[i - 1] * inv_g;
        }
        factors
    })
}


/// Performs a bit-reversal permutation on the input slice in-place.
fn bit_reverse_permutation<T>(data: &mut [T]) {
    let n = data.len();
    let mut j = 0;
    for i in 1..n {
        let mut bit = n >> 1;
        while (j & bit) != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            data.swap(i, j);
        }
    }
}

/// Core Cooley-Tukey FFT/NTT algorithm.
fn fft_cooley_tukey(coeffs: &mut [Scalar], roots: &[Scalar]) {
    let n = coeffs.len();
    let mut len = 2;
    while len <= n {
        let half_len = len >> 1;
        let step = roots.len() / len;
        let root = roots[step];
        for i in (0..n).step_by(len) {
            let mut w = Scalar::one();
            for j in 0..half_len {
                let u = coeffs[i + j];
                let v = coeffs[i + j + half_len] * w;
                coeffs[i + j] = u + v;
                coeffs[i + j + half_len] = u - v;
                w *= root;
            }
        }
        len <<= 1;
    }
}

/// Computes the forward Fast Fourier Transform (NTT) of a polynomial for **cyclic** convolution.
pub fn fft(coeffs: &mut [Scalar]) -> Result<()> {
    if coeffs.len() != FFT_SIZE || !coeffs.len().is_power_of_two() {
        return Err(Error::Parameter {
            name: "coeffs".into(),
            reason: "FFT length must be a power of two (256)".into(),
        });
    }
    bit_reverse_permutation(coeffs);
    fft_cooley_tukey(coeffs, get_roots_of_unity());
    Ok(())
}

/// Computes the inverse Fast Fourier Transform (iNTT) for **cyclic** convolution.
pub fn ifft(evals: &mut [Scalar]) -> Result<()> {
    if evals.len() != FFT_SIZE || !evals.len().is_power_of_two() {
        return Err(Error::Parameter {
            name: "evals".into(),
            reason: "FFT length must be a power of two (256)".into(),
        });
    }
    bit_reverse_permutation(evals);
    fft_cooley_tukey(evals, get_inverse_roots_of_unity());

    let n_inv = get_n_inv();
    for c in evals.iter_mut() {
        *c *= *n_inv;
    }
    Ok(())
}

/// Computes the forward **negacyclic** NTT.
pub fn fft_negacyclic(coeffs: &mut [Scalar]) -> Result<()> {
    if coeffs.len() != FFT_SIZE {
        return Err(Error::Parameter {
            name: "coeffs".into(),
            reason: "Negacyclic FFT requires length 256".into(),
        });
    }
    
    let twists = get_twist_factors();
    for i in 0..FFT_SIZE {
        coeffs[i] *= twists[i];
    }

    fft(coeffs)
}

/// Computes the inverse **negacyclic** NTT.
pub fn ifft_negacyclic(evals: &mut [Scalar]) -> Result<()> {
    if evals.len() != FFT_SIZE {
        return Err(Error::Parameter {
            name: "evals".into(),
            reason: "Negacyclic IFFT requires length 256".into(),
        });
    }
    
    ifft(evals)?;

    let inv_twists = get_inverse_twist_factors();
    for i in 0..FFT_SIZE {
        evals[i] *= inv_twists[i];
    }
    
    Ok(())
}


#[cfg(test)]
mod tests;