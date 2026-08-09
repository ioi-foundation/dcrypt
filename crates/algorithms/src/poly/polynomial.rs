//! polynomial.rs - Enhanced implementation with arithmetic operations

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::ntt::montgomery_reduce;
use super::params::{Modulus, NttModulus}; // FIXED: Import NttModulus from params
use crate::error::{Error, Result};
use core::marker::PhantomData;
use core::ops::{Add, Neg, Sub};
use dcrypt_internal::zeroing::Zeroize;

/// Convert a value from standard domain to Montgomery domain
#[inline(always)]
fn to_montgomery<M: NttModulus>(val: u32) -> u32 {
    ((val as u64 * M::MONT_R as u64) % M::Q as u64) as u32
}

/// A polynomial in a ring `R_Q = Z_Q[X]/(X^N + 1)`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial<M: Modulus> {
    /// Coefficients of the polynomial, stored in standard representation
    #[cfg(feature = "alloc")]
    pub coeffs: Vec<u32>,
    /// Coefficients of the polynomial, stored in standard representation
    #[cfg(not(feature = "alloc"))]
    pub coeffs: [u32; 256], // Will need const generics for proper support
    _marker: PhantomData<M>,
}

// Custom Zeroize implementation that preserves vector length
impl<M: Modulus> Zeroize for Polynomial<M> {
    fn zeroize(&mut self) {
        // Zero all coefficients without changing the length
        #[cfg(feature = "alloc")]
        {
            for coeff in self.coeffs.iter_mut() {
                coeff.zeroize();
            }
        }
        #[cfg(not(feature = "alloc"))]
        {
            self.coeffs.zeroize();
        }
    }
}

impl<M: Modulus> Polynomial<M> {
    /// Creates a new polynomial with all coefficients set to zero
    pub fn zero() -> Self {
        Self {
            coeffs: vec![0; M::N], // length = 256, every coeff = 0
            _marker: PhantomData,
        }
    }

    /// Creates a polynomial from a slice of coefficients
    pub fn from_coeffs(coeffs_slice: &[u32]) -> Result<Self> {
        if coeffs_slice.len() != M::N {
            return Err(Error::Parameter {
                name: "coeffs_slice".into(),
                reason: "Incorrect number of coefficients for polynomial degree N".into(),
            });
        }

        #[cfg(feature = "alloc")]
        let coeffs = coeffs_slice.to_vec();

        #[cfg(not(feature = "alloc"))]
        let mut coeffs = [0u32; 256];
        #[cfg(not(feature = "alloc"))]
        coeffs[..M::N].copy_from_slice(coeffs_slice);

        Ok(Self {
            coeffs,
            _marker: PhantomData,
        })
    }

    /// Returns the degree N of the polynomial
    pub fn degree() -> usize {
        M::N
    }

    /// Returns the modulus Q for coefficient arithmetic
    pub fn modulus_q() -> u32 {
        M::Q
    }

    /// Returns a slice view of the coefficients
    pub fn as_coeffs_slice(&self) -> &[u32] {
        &self.coeffs[..M::N]
    }

    /// Returns a mutable slice view of the coefficients
    pub fn as_mut_coeffs_slice(&mut self) -> &mut [u32] {
        &mut self.coeffs[..M::N]
    }

    /// Branch-free modular reduction of a single coefficient
    #[inline(always)]
    fn reduce_coefficient(a: u32) -> u32 {
        // Branch-free reduction: a - Q if a >= Q else a
        let q = M::Q;
        let mask = ((a >= q) as u32).wrapping_neg();
        a.wrapping_sub(q & mask)
    }

    /// Branch-free conditional subtraction for signed results
    /// FIXED: Simplified to use rem_euclid for proper modular arithmetic
    #[inline(always)]
    fn conditional_sub_q(a: i64) -> u32 {
        let q = M::Q as i64;
        // Use rem_euclid for proper modular arithmetic
        a.rem_euclid(q) as u32
    }

    /// Polynomial addition modulo Q
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..M::N {
            let sum = self.coeffs[i].wrapping_add(other.coeffs[i]);
            result.coeffs[i] = Self::reduce_coefficient(sum);
        }
        result
    }

    /// Polynomial subtraction modulo Q
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..M::N {
            let diff = (self.coeffs[i] as i64) - (other.coeffs[i] as i64);
            result.coeffs[i] = Self::conditional_sub_q(diff);
        }
        result
    }

    /// Polynomial negation modulo Q
    pub fn neg(&self) -> Self {
        let mut result = Self::zero();
        for i in 0..M::N {
            // Mask is 0xFFFF_FFFF when coeff ≠ 0, 0 otherwise
            let mask = ((self.coeffs[i] != 0) as u32).wrapping_neg();
            result.coeffs[i] = (M::Q - self.coeffs[i]) & mask;
        }
        result
    }

    /// Scalar multiplication
    pub fn scalar_mul(&self, scalar: u32) -> Self {
        let mut result = Self::zero();
        for i in 0..M::N {
            let prod = (self.coeffs[i] as u64) * (scalar as u64);
            result.coeffs[i] = (prod % M::Q as u64) as u32;
        }
        result
    }

    /// Schoolbook polynomial multiplication with NEGACYCLIC reduction for Dilithium
    /// In ring `R_q[x]/(x^N + 1)`, when degree >= N, we have `x^N ≡ -1`
    pub fn schoolbook_mul(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        let n = M::N;
        let q = M::Q as u64;

        // Use a temporary array to accumulate products without modular reduction
        // This prevents overflow: max value is n * (q-1)^2 < 2^64 for Dilithium
        let mut tmp = vec![0u64; 2 * n];

        // Step 1: Compute full convolution without modular reduction
        // FIXED: Use iterator instead of indexing
        for (i, &ai_u32) in self.coeffs.iter().enumerate().take(n) {
            let ai = ai_u32 as u64;
            for (j, &bj_u32) in other.coeffs.iter().enumerate().take(n) {
                let bj = bj_u32 as u64;
                tmp[i + j] = tmp[i + j].wrapping_add(ai * bj);
            }
        }

        // Step 2: Apply negacyclic reduction (x^N = -1)
        // Fold upper half back with negation
        for k in n..(2 * n) {
            // When reducing x^k where k >= n, we use x^n = -1
            // So x^k = -x^(k-n)
            let upper_val = tmp[k] % q;
            if upper_val > 0 {
                // Subtract from lower coefficient (equivalent to adding the negative)
                tmp[k - n] = (tmp[k - n] + q - upper_val) % q;
            }
        }

        // Step 3: Final reduction to [0, q)
        #[allow(clippy::needless_range_loop)]
        // We need indexed access here to match tmp and result.coeffs indices
        for i in 0..n {
            result.coeffs[i] = (tmp[i] % q) as u32;
        }

        result
    }

    /// In-place coefficient reduction to ensure all coefficients are < Q
    pub fn reduce_coeffs(&mut self) {
        for i in 0..M::N {
            self.coeffs[i] = Self::reduce_coefficient(self.coeffs[i]);
        }
    }
}

// NTT operations are implemented in ntt.rs as extension methods

/// Extension trait for polynomials with NTT-enabled modulus
pub trait PolynomialNttExt<M: NttModulus> {
    // FIXED: Now uses params::NttModulus
    /// Fast scalar multiplication using Montgomery reduction
    fn scalar_mul_montgomery(&self, scalar: u32) -> Polynomial<M>;
}

impl<M: NttModulus> PolynomialNttExt<M> for Polynomial<M> {
    // FIXED: Now uses params::NttModulus
    fn scalar_mul_montgomery(&self, scalar: u32) -> Polynomial<M> {
        let mut result = Polynomial::<M>::zero();
        // FIXED: Convert scalar to Montgomery form before multiplication
        let scalar_mont = to_montgomery::<M>(scalar);
        for i in 0..M::N {
            // Now both operands are in Montgomery form, so the result stays in Montgomery form
            let prod = (self.coeffs[i] as u64) * (scalar_mont as u64);
            result.coeffs[i] = montgomery_reduce::<M>(prod);
        }
        result
    }
}

/// Barrett reduction for fast modular arithmetic
#[inline(always)]
pub fn barrett_reduce<M: Modulus>(a: u32) -> u32 {
    // Simplified Barrett reduction
    // In production, would use precomputed Barrett constant
    a % M::Q
}

// Implement standard ops traits for ergonomic usage
// Define reference implementations first
impl<M: Modulus> Add for &Polynomial<M> {
    type Output = Polynomial<M>;

    fn add(self, other: Self) -> Self::Output {
        self.add(other)
    }
}

impl<M: Modulus> Sub for &Polynomial<M> {
    type Output = Polynomial<M>;

    fn sub(self, other: Self) -> Self::Output {
        self.sub(other)
    }
}

impl<M: Modulus> Neg for &Polynomial<M> {
    type Output = Polynomial<M>;

    fn neg(self) -> Self::Output {
        self.neg()
    }
}

// Now owned implementations can use the reference implementations
impl<M: Modulus> Add for Polynomial<M> {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        &self + &other
    }
}

impl<M: Modulus> Sub for Polynomial<M> {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        &self - &other
    }
}

impl<M: Modulus> Neg for Polynomial<M> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        -&self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test modulus for unit tests
    #[derive(Clone)]
    struct TestModulus;
    impl Modulus for TestModulus {
        const Q: u32 = 3329;
        const N: usize = 4; // Small for testing
    }

    #[test]
    fn test_polynomial_creation() {
        let poly = Polynomial::<TestModulus>::zero();
        assert_eq!(poly.as_coeffs_slice(), &[0, 0, 0, 0]);

        let coeffs = vec![1, 2, 3, 4];
        let poly = Polynomial::<TestModulus>::from_coeffs(&coeffs).unwrap();
        assert_eq!(poly.as_coeffs_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_polynomial_addition() {
        let a = Polynomial::<TestModulus>::from_coeffs(&[1, 2, 3, 4]).unwrap();
        let b = Polynomial::<TestModulus>::from_coeffs(&[5, 6, 7, 8]).unwrap();
        // Use the + operator directly to avoid explicit borrows
        let c = a + b;
        assert_eq!(c.as_coeffs_slice(), &[6, 8, 10, 12]);
    }

    #[test]
    fn test_polynomial_subtraction() {
        let a = Polynomial::<TestModulus>::from_coeffs(&[10, 20, 30, 40]).unwrap();
        let b = Polynomial::<TestModulus>::from_coeffs(&[5, 6, 7, 8]).unwrap();
        // Use the - operator directly to avoid explicit borrows
        let c = a - b;
        assert_eq!(c.as_coeffs_slice(), &[5, 14, 23, 32]);
    }

    #[test]
    fn test_polynomial_negation() {
        let a = Polynomial::<TestModulus>::from_coeffs(&[1, 2, 0, 4]).unwrap();
        // Use the - operator directly to avoid explicit borrows
        let neg_a = -a;
        assert_eq!(neg_a.as_coeffs_slice(), &[3328, 3327, 0, 3325]);
    }

    #[test]
    fn test_modular_reduction() {
        let a = Polynomial::<TestModulus>::from_coeffs(&[3330, 3331, 3328, 0]).unwrap();
        let mut b = a.clone();
        b.reduce_coeffs();
        assert_eq!(b.as_coeffs_slice(), &[1, 2, 3328, 0]);
    }

    #[test]
    fn test_zeroization() {
        let mut poly = Polynomial::<TestModulus>::from_coeffs(&[1, 2, 3, 4]).unwrap();
        poly.zeroize();
        assert_eq!(poly.as_coeffs_slice(), &[0, 0, 0, 0]);
        assert_eq!(poly.coeffs.len(), 4); // Length preserved
    }

    #[test]
    fn test_schoolbook_mul_negacyclic() {
        // Test negacyclic property: x^N = -1
        // For N=4, x^4 = -1, so x^3 * x = -1
        let mut x_cubed = Polynomial::<TestModulus>::zero();
        x_cubed.coeffs[3] = 1; // x^3

        let mut x = Polynomial::<TestModulus>::zero();
        x.coeffs[1] = 1; // x

        let result = x_cubed.schoolbook_mul(&x);
        // x^3 * x = x^4 = -1 mod q = q-1
        assert_eq!(result.coeffs[0], TestModulus::Q - 1);
        assert_eq!(result.coeffs[1], 0);
        assert_eq!(result.coeffs[2], 0);
        assert_eq!(result.coeffs[3], 0);

        // Test a more complex example
        let a = Polynomial::<TestModulus>::from_coeffs(&[1, 2, 3, 4]).unwrap();
        let b = Polynomial::<TestModulus>::from_coeffs(&[5, 6, 7, 8]).unwrap();
        let c = a.schoolbook_mul(&b);

        // Manually compute expected result with negacyclic reduction
        // (1 + 2x + 3x^2 + 4x^3)(5 + 6x + 7x^2 + 8x^3)
        //
        // Full expansion (before reduction):
        // 1*5 = 5
        // 1*6x + 2*5x = 6x + 10x = 16x
        // 1*7x^2 + 2*6x^2 + 3*5x^2 = 7x^2 + 12x^2 + 15x^2 = 34x^2
        // 1*8x^3 + 2*7x^3 + 3*6x^3 + 4*5x^3 = 8x^3 + 14x^3 + 18x^3 + 20x^3 = 60x^3
        // 2*8x^4 + 3*7x^4 + 4*6x^4 = 16x^4 + 21x^4 + 24x^4 = 61x^4
        // 3*8x^5 + 4*7x^5 = 24x^5 + 28x^5 = 52x^5
        // 4*8x^6 = 32x^6
        //
        // Now apply x^4 = -1:
        // x^4 = -1
        // x^5 = -x
        // x^6 = -x^2
        //
        // So:
        // Constant: 5 - 61 = -56 → 3329 - 56 = 3273
        // x: 16 - 52 = -36 → 3329 - 36 = 3293
        // x^2: 34 - 32 = 2
        // x^3: 60

        let expected_0 = ((5i32 - 61i32).rem_euclid(TestModulus::Q as i32)) as u32;
        let expected_1 = ((16i32 - 52i32).rem_euclid(TestModulus::Q as i32)) as u32;
        let expected_2 = ((34i32 - 32i32).rem_euclid(TestModulus::Q as i32)) as u32;
        let expected_3 = 60u32;

        assert_eq!(c.coeffs[0], expected_0);
        assert_eq!(c.coeffs[1], expected_1);
        assert_eq!(c.coeffs[2], expected_2);
        assert_eq!(c.coeffs[3], expected_3);
    }

    #[test]
    fn test_dilithium_negacyclic() {
        // Test with Dilithium-like parameters
        #[derive(Clone)]
        struct DilithiumTestModulus;
        impl Modulus for DilithiumTestModulus {
            const Q: u32 = 8380417; // Dilithium's Q
            const N: usize = 4; // Small for testing, but same negacyclic property
        }

        // Test that x^N = -1 in the ring
        let mut x_to_n_minus_1 = Polynomial::<DilithiumTestModulus>::zero();
        x_to_n_minus_1.coeffs[3] = 1; // x^3

        let mut x = Polynomial::<DilithiumTestModulus>::zero();
        x.coeffs[1] = 1; // x

        let result = x_to_n_minus_1.schoolbook_mul(&x);
        // x^3 * x = x^4 = -1 mod q = q-1
        assert_eq!(result.coeffs[0], DilithiumTestModulus::Q - 1);
        assert_eq!(result.coeffs[1], 0);
        assert_eq!(result.coeffs[2], 0);
        assert_eq!(result.coeffs[3], 0);

        // Test with sparse polynomial (like challenge polynomial c)
        let mut sparse = Polynomial::<DilithiumTestModulus>::zero();
        sparse.coeffs[0] = 1; // +1
        sparse.coeffs[2] = DilithiumTestModulus::Q - 1; // -1

        let dense = Polynomial::<DilithiumTestModulus>::from_coeffs(&[100, 200, 300, 400]).unwrap();
        let result = sparse.schoolbook_mul(&dense);

        // (1 - x^2) * (100 + 200x + 300x^2 + 400x^3)
        // = 100 + 200x + 300x^2 + 400x^3 - 100x^2 - 200x^3 - 300x^4 - 400x^5
        // With x^4 = -1, x^5 = -x:
        // = 100 + 200x + (300-100)x^2 + (400-200)x^3 + 300 + 400x
        // = (100+300) + (200+400)x + 200x^2 + 200x^3
        // = 400 + 600x + 200x^2 + 200x^3

        assert_eq!(result.coeffs[0], 400);
        assert_eq!(result.coeffs[1], 600);
        assert_eq!(result.coeffs[2], 200);
        assert_eq!(result.coeffs[3], 200);
    }
}
