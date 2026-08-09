//! Polynomial vector types and operations for ML-DSA.
//!
//! IMPORTANT: This module uses TWO different parameter sets:
//! 1. `algorithms::poly::params::MlDsaParams` - Contains NTT constants for polynomial arithmetic
//! 2. `params::pqc::ml_dsa::MlDsaSchemeParams` - Contains signature scheme parameters
//!
//! The polynomial type MUST use the algorithms version to get correct NTT scaling factors!

use crate::error::Error as SignError;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::marker::PhantomData;
use dcrypt_algorithms::error::Result as AlgoResult;
use dcrypt_algorithms::poly::params::{MlDsaParams, Modulus};
use dcrypt_algorithms::poly::polynomial::Polynomial;
use dcrypt_algorithms::xof::shake::ShakeXof128;
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use dcrypt_internal::{Choice, ConditionallySelectable, Zeroize};
use dcrypt_params::pqc::ml_dsa::MlDsaSchemeParams;

// Montgomery reduce is available from algorithms::poly::ntt when needed

/// A vector of polynomials of length L (columns of A).
#[derive(Debug)]
pub struct PolyVecL<P: MlDsaSchemeParams> {
    pub(crate) polys: Vec<Polynomial<MlDsaParams>>,
    _params: PhantomData<P>,
}

/// A vector of polynomials of length K (rows of A).
#[derive(Debug)]
pub struct PolyVecK<P: MlDsaSchemeParams> {
    pub(crate) polys: Vec<Polynomial<MlDsaParams>>,
    _params: PhantomData<P>,
}

impl<P: MlDsaSchemeParams> Clone for PolyVecL<P> {
    fn clone(&self) -> Self {
        Self {
            polys: self.polys.clone(),
            _params: PhantomData,
        }
    }
}
impl<P: MlDsaSchemeParams> Clone for PolyVecK<P> {
    fn clone(&self) -> Self {
        Self {
            polys: self.polys.clone(),
            _params: PhantomData,
        }
    }
}

impl<P: MlDsaSchemeParams> Zeroize for PolyVecL<P> {
    fn zeroize(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.coeffs.as_mut_slice().zeroize(); // Zeroes in place, length intact
        }
    }
}
impl<P: MlDsaSchemeParams> Zeroize for PolyVecK<P> {
    fn zeroize(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.coeffs.as_mut_slice().zeroize(); // Zeroes in place, length intact
        }
    }
}

impl<P: MlDsaSchemeParams> PolyVecL<P> {
    /// Creates a new PolyVecL with all coefficients = 0.
    pub fn zero() -> Self {
        let mut polys = Vec::with_capacity(P::L_DIM);
        for _ in 0..P::L_DIM {
            polys.push(Polynomial::<MlDsaParams>::zero());
        }
        Self {
            polys,
            _params: PhantomData,
        }
    }

    /// Apply forward NTT in‐place to every polynomial.
    pub fn ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            p.ntt_inplace()?;
        }
        Ok(())
    }

    /// Apply inverse NTT in-place to every polynomial.
    pub fn inv_ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            p.from_ntt_inplace()?;
        }
        Ok(())
    }

    /// Point-wise product and accumulate into one Polynomial (all in NTT domain).
    pub fn pointwise_dot_product(&self, other: &PolyVecL<P>) -> Polynomial<MlDsaParams> {
        let mut acc = Polynomial::<MlDsaParams>::zero();
        for i in 0..P::L_DIM {
            let prod = self.polys[i].ntt_mul(&other.polys[i]);
            acc = acc.add(&prod);
        }
        acc
    }

    pub fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut out = Self::zero();
        for i in 0..P::L_DIM {
            for j in 0..MlDsaParams::N {
                out.polys[i].coeffs[j] =
                    u32::conditional_select(&a.polys[i].coeffs[j], &b.polys[i].coeffs[j], choice);
            }
        }
        out
    }
}

impl<P: MlDsaSchemeParams> PolyVecK<P> {
    /// Creates a new PolyVecK with all coefficients = 0.
    pub fn zero() -> Self {
        let mut polys = Vec::with_capacity(P::K_DIM);
        for _ in 0..P::K_DIM {
            polys.push(Polynomial::<MlDsaParams>::zero());
        }
        Self {
            polys,
            _params: PhantomData,
        }
    }

    /// Apply forward NTT in‐place.
    pub fn ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            p.ntt_inplace()?;
        }
        Ok(())
    }

    /// Apply inverse NTT in‐place.
    pub fn inv_ntt_inplace(&mut self) -> AlgoResult<()> {
        for p in self.polys.iter_mut() {
            // p.from_ntt_inplace() from algorithms/poly/ntt.rs implements InvNTT_R_logN (FIPS 204 Alg 27),
            // which results in coefficients in standard domain per FIPS 204
            p.from_ntt_inplace()?;
        }
        Ok(())
    }

    /// self + other, element-wise.
    pub fn add(&self, other: &Self) -> Self {
        let mut res = Self::zero();
        for i in 0..P::K_DIM {
            res.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        res
    }

    /// Additive inverse modulo q, coefficient-wise.
    pub fn neg_mod_q(&self) -> Self {
        let mut res = Self::zero();
        for i in 0..P::K_DIM {
            for j in 0..MlDsaParams::N {
                let coeff = self.polys[i].coeffs[j];
                res.polys[i].coeffs[j] = if coeff == 0 {
                    0
                } else {
                    MlDsaParams::Q - coeff
                };
            }
        }
        res
    }

    /// self − other, element-wise.
    pub fn sub(&self, other: &Self) -> Self {
        let mut res = Self::zero();
        for i in 0..P::K_DIM {
            res.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        res
    }

    pub fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut out = Self::zero();
        for i in 0..P::K_DIM {
            for j in 0..MlDsaParams::N {
                out.polys[i].coeffs[j] =
                    u32::conditional_select(&a.polys[i].coeffs[j], &b.polys[i].coeffs[j], choice);
            }
        }
        out
    }
}

/// Matrix‐vector multiply: Â (K×L) × vec_l̂ (L). All in NTT domain.
/// Returns a K‐vector in NTT domain.
pub fn matrix_polyvecl_mul<P: MlDsaSchemeParams>(
    matrix_a_hat: &[PolyVecL<P>], // K rows, each has L polys in NTT domain
    vector_l_hat: &PolyVecL<P>,   // L polys in NTT domain
) -> PolyVecK<P> {
    let mut result_veck = PolyVecK::<P>::zero();

    for (i, row) in matrix_a_hat.iter().enumerate() {
        result_veck.polys[i] = row.pointwise_dot_product(vector_l_hat);
    }

    result_veck
}

/// FIPS 204 Algorithm 32, `ExpandA`.
///
/// The returned coefficient arrays are already elements of `Tq` (the NTT
/// representation). They must not be transformed again before pointwise use.
pub fn expand_matrix_a<P: MlDsaSchemeParams>(
    rho_seed: &[u8; 32], // always 32 bytes
) -> Result<Vec<PolyVecL<P>>, SignError> {
    let mut matrix_a = Vec::with_capacity(P::K_DIM);

    for i in 0..P::K_DIM {
        let mut row = PolyVecL::<P>::zero();
        for j in 0..P::L_DIM {
            let mut xof = ShakeXof128::new();
            xof.update(rho_seed).map_err(SignError::from_algo)?;
            xof.update(&[j as u8]).map_err(SignError::from_algo)?;
            xof.update(&[i as u8]).map_err(SignError::from_algo)?;

            let mut poly = Polynomial::<MlDsaParams>::zero();
            let mut ctr = 0;
            let mut temp_buf = [0u8; 3];

            while ctr < MlDsaParams::N {
                xof.squeeze(&mut temp_buf).map_err(SignError::from_algo)?;
                // CoeffFromThreeBytes clears the top bit and interprets the
                // remaining 23 bits in little-endian order.
                let candidate = u32::from(temp_buf[0])
                    | (u32::from(temp_buf[1]) << 8)
                    | (u32::from(temp_buf[2] & 0x7f) << 16);

                if candidate < MlDsaParams::Q {
                    poly.coeffs[ctr] = candidate;
                    ctr += 1;
                }
            }

            row.polys[j] = poly;
        }
        matrix_a.push(row);
    }
    Ok(matrix_a)
}
