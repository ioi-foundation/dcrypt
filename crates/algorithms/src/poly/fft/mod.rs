// File: algorithms/src/poly/fft/mod.rs
//! Fast Fourier Transform (FFT) over the BLS12-381 Scalar Field
//!
//! This module implements a Number Theoretic Transform (NTT), which is an FFT
//! adapted for finite fields. It operates on vectors of `Scalar` elements from the
//! BLS12-381 curve, enabling O(n log n) polynomial multiplication and interpolation.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::needless_range_loop)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec;

use crate::ec::bls12_381::Bls12_381Scalar as Scalar;
use crate::error::{Error, Result};

#[cfg(feature = "std")]
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

// Statics for caching (only available in std)
#[cfg(feature = "std")]
static FFT_N_ROOT: OnceLock<Scalar> = OnceLock::new();
#[cfg(feature = "std")]
static ROOTS_OF_UNITY: OnceLock<Vec<Scalar>> = OnceLock::new();
#[cfg(feature = "std")]
static INVERSE_ROOTS_OF_UNITY: OnceLock<Vec<Scalar>> = OnceLock::new();
#[cfg(feature = "std")]
static PRIMITIVE_2N_ROOT: OnceLock<Scalar> = OnceLock::new();
#[cfg(feature = "std")]
static TWIST_FACTORS: OnceLock<Vec<Scalar>> = OnceLock::new();
#[cfg(feature = "std")]
static INVERSE_TWIST_FACTORS: OnceLock<Vec<Scalar>> = OnceLock::new();

// The root of unity seed is constant
fn get_root_of_unity_seed() -> Scalar {
    Scalar::from_raw([
        0x4253_d252_a210_b619,
        0x81c3_5f15_01a0_2431,
        0xb734_6a32_008b_0320,
        0x0a16_14a8_64b3_09e1,
    ])
}

// --- Helpers ---

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

/// Compute the 2-adic order k of an element r ∈ μ_{2^S}
fn two_adicity(mut r: Scalar) -> u32 {
    for k in 1..=TWO_ADICITY_FR {
        r = r.square();
        if r == Scalar::one() {
            return k;
        }
    }
    // Should generally be unreachable if input is projected correctly
    TWO_ADICITY_FR
}

/// Deterministically pick a seed in μ_{2^S} whose 2-adic order k ≥ min_k.
fn select_2power_seed(min_k: u32) -> (Scalar, u32) {
    let bases: [Scalar; 12] = [
        get_root_of_unity_seed(),
        Scalar::from(5u64),
        Scalar::from(7u64),
        Scalar::from(2u64),
        Scalar::from(3u64),
        Scalar::from(11u64),
        Scalar::from(13u64),
        Scalar::from(17u64),
        Scalar::from(19u64),
        Scalar::from(29u64),
        Scalar::from(31u64),
        Scalar::from(37u64),
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

    // Fallback (should not happen for BLS12-381 params)
    (Scalar::one(), 0)
}

// --- Generator Functions ---

fn generate_fft_n_root() -> Scalar {
    let need = FFT_SIZE.trailing_zeros();
    let (seed, k) = select_2power_seed(need);

    let mut w_n = seed;
    for _ in 0..(k - need) {
        w_n = w_n.square();
    }
    w_n
}

fn generate_roots_of_unity() -> Vec<Scalar> {
    let w_n = generate_fft_n_root();
    let mut roots = vec![Scalar::one(); FFT_SIZE];
    for i in 1..FFT_SIZE {
        roots[i] = roots[i - 1] * w_n;
    }
    roots
}

fn generate_inverse_roots_of_unity() -> Vec<Scalar> {
    let inv_w_n = generate_fft_n_root().invert().unwrap();
    let mut roots = vec![Scalar::one(); FFT_SIZE];
    for i in 1..FFT_SIZE {
        roots[i] = roots[i - 1] * inv_w_n;
    }
    roots
}

fn generate_primitive_2n_root() -> Scalar {
    let need = FFT_SIZE.trailing_zeros();
    let (seed, k) = select_2power_seed(need + 1);

    let mut g = seed;
    for _ in 0..(k - (need + 1)) {
        g = g.square();
    }
    g
}

fn generate_twist_factors() -> Vec<Scalar> {
    let g = generate_primitive_2n_root();
    let mut factors = vec![Scalar::one(); FFT_SIZE];
    for i in 1..FFT_SIZE {
        factors[i] = factors[i - 1] * g;
    }
    factors
}

fn generate_inverse_twist_factors() -> Vec<Scalar> {
    let inv_g = generate_primitive_2n_root().invert().unwrap();
    let mut factors = vec![Scalar::one(); FFT_SIZE];
    for i in 1..FFT_SIZE {
        factors[i] = factors[i - 1] * inv_g;
    }
    factors
}

// --- Accessors handling std vs no_std ---

#[cfg(feature = "std")]
fn get_roots_of_unity() -> &'static Vec<Scalar> {
    ROOTS_OF_UNITY.get_or_init(generate_roots_of_unity)
}

#[cfg(not(feature = "std"))]
fn get_roots_of_unity() -> Vec<Scalar> {
    generate_roots_of_unity()
}

#[cfg(feature = "std")]
fn get_inverse_roots_of_unity() -> &'static Vec<Scalar> {
    INVERSE_ROOTS_OF_UNITY.get_or_init(generate_inverse_roots_of_unity)
}

#[cfg(not(feature = "std"))]
fn get_inverse_roots_of_unity() -> Vec<Scalar> {
    generate_inverse_roots_of_unity()
}

#[cfg(feature = "std")]
fn get_twist_factors() -> &'static Vec<Scalar> {
    TWIST_FACTORS.get_or_init(generate_twist_factors)
}

#[cfg(not(feature = "std"))]
fn get_twist_factors() -> Vec<Scalar> {
    generate_twist_factors()
}

#[cfg(feature = "std")]
fn get_inverse_twist_factors() -> &'static Vec<Scalar> {
    INVERSE_TWIST_FACTORS.get_or_init(generate_inverse_twist_factors)
}

#[cfg(not(feature = "std"))]
fn get_inverse_twist_factors() -> Vec<Scalar> {
    generate_inverse_twist_factors()
}

// --- FFT Logic ---

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
        for i in (0..n).step_by(len) {
            for j in 0..half_len {
                let root = roots[step * j * (roots.len() / n * (n / len))]; // Simplified indexing logic mapping
                                                                            // Actually, for iterative FFT with bit-reversed input:
                                                                            // The roots access pattern usually depends on structure.
                                                                            // Standard iterative CT:
                let root = roots[step * j]; // Approximation of look-up
                                            // For standard CT with bit-reversed input, we need w^k.
                                            // Let's use a simpler logic: root = roots[(n/len) * j] ?
                                            // With precomputed roots 0..N-1:
                let idx = (roots.len() / len) * j;
                let w = roots[idx];

                let u = coeffs[i + j];
                let v = coeffs[i + j + half_len] * w;
                coeffs[i + j] = u + v;
                coeffs[i + j + half_len] = u - v;
            }
        }
        len <<= 1;
    }
}

/// Computes the forward Fast Fourier Transform (NTT) of a polynomial for **cyclic** convolution.
pub fn fft(coeffs: &mut [Scalar]) -> Result<()> {
    if coeffs.len() != FFT_SIZE {
        return Err(Error::Parameter {
            name: "coeffs".into(),
            reason: "FFT length must be 256".into(),
        });
    }
    bit_reverse_permutation(coeffs);
    let roots = get_roots_of_unity();
    // Note: in no_std `roots` is a temporary Vec. In std it's a reference.
    // We can dereference to slice.
    fft_cooley_tukey(coeffs, &roots);
    Ok(())
}

/// Computes the inverse Fast Fourier Transform (iNTT) for **cyclic** convolution.
pub fn ifft(evals: &mut [Scalar]) -> Result<()> {
    if evals.len() != FFT_SIZE {
        return Err(Error::Parameter {
            name: "evals".into(),
            reason: "FFT length must be 256".into(),
        });
    }
    bit_reverse_permutation(evals);
    let roots = get_inverse_roots_of_unity();
    fft_cooley_tukey(evals, &roots);

    let n_inv = Scalar::from(FFT_SIZE as u64).invert().unwrap();
    for c in evals.iter_mut() {
        *c *= n_inv;
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