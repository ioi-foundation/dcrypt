//! FIPS 204 pseudorandom sampling functions for ML-DSA.

use super::polyvec::{PolyVecK, PolyVecL};
use crate::error::Error as SignError;
#[cfg(not(feature = "std"))]
use alloc::format;
use dcrypt_algorithms::poly::params::{MlDsaParams, Modulus};
use dcrypt_algorithms::poly::polynomial::Polynomial;
use dcrypt_algorithms::xof::shake::ShakeXof256;
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use dcrypt_internal::Zeroizing;
use dcrypt_params::pqc::ml_dsa::MlDsaSchemeParams;

#[inline]
fn coeff_from_half_byte(value: u8, eta: u32) -> Option<i32> {
    match eta {
        2 if value < 15 => Some(2 - i32::from(value % 5)),
        4 if value < 9 => Some(4 - i32::from(value)),
        _ => None,
    }
}

/// FIPS 204 Algorithm 31, `RejBoundedPoly`.
pub fn sample_poly_rej_bounded(
    seed: &[u8; 64],
    nonce: u16,
    eta: u32,
) -> Result<Polynomial<MlDsaParams>, SignError> {
    if eta != 2 && eta != 4 {
        return Err(SignError::Sampling(format!(
            "unsupported ML-DSA eta: {eta}"
        )));
    }

    let mut xof = ShakeXof256::new();
    xof.update(seed).map_err(SignError::from_algo)?;
    xof.update(&nonce.to_le_bytes())
        .map_err(SignError::from_algo)?;

    let mut poly = Polynomial::<MlDsaParams>::zero();
    let mut coefficient = 0usize;
    while coefficient < MlDsaParams::N {
        let mut byte = Zeroizing::new([0u8; 1]);
        xof.squeeze(&mut *byte).map_err(SignError::from_algo)?;
        for half in [byte[0] & 0x0f, byte[0] >> 4] {
            if let Some(value) = coeff_from_half_byte(half, eta) {
                poly.coeffs[coefficient] = centered_to_mod_q(value);
                coefficient += 1;
                if coefficient == MlDsaParams::N {
                    break;
                }
            }
        }
    }
    Ok(poly)
}

/// FIPS 204 Algorithm 33, the `s1` half of `ExpandS`.
pub fn sample_polyvecl_rej_bounded<P: MlDsaSchemeParams>(
    seed: &[u8; 64],
    eta: u32,
) -> Result<PolyVecL<P>, SignError> {
    let mut pv = PolyVecL::<P>::zero();

    for i in 0..P::L_DIM {
        pv.polys[i] = sample_poly_rej_bounded(seed, i as u16, eta)?;
    }

    Ok(pv)
}

/// FIPS 204 Algorithm 33, the `s2` half of `ExpandS`.
pub fn sample_polyveck_rej_bounded<P: MlDsaSchemeParams>(
    seed: &[u8; 64],
    eta: u32,
) -> Result<PolyVecK<P>, SignError> {
    let mut pv = PolyVecK::<P>::zero();

    for i in 0..P::K_DIM {
        pv.polys[i] = sample_poly_rej_bounded(seed, (P::L_DIM + i) as u16, eta)?;
    }

    Ok(pv)
}

/// Samples `y = ExpandMask(rho'', mu)` per FIPS 204 Algorithm 34.
///
/// Each polynomial uses `rho || IntegerToBytes(mu + r, 2)` as the XOF input and
/// unpacks coefficients into the range `[-gamma1 + 1, gamma1]`.
pub fn sample_polyvecl_uniform_gamma1<P: MlDsaSchemeParams>(
    mask_seed: &[u8],
    mu: u16,
    gamma1: u32,
) -> Result<PolyVecL<P>, SignError> {
    let mut pv = PolyVecL::<P>::zero();

    for i in 0..P::L_DIM {
        let nonce = mu.wrapping_add(i as u16);
        let mut xof = ShakeXof256::new();
        xof.update(mask_seed).map_err(SignError::from_algo)?;
        xof.update(&nonce.to_le_bytes())
            .map_err(SignError::from_algo)?;

        match gamma1 {
            val if val == (1 << 17) => {
                let mut buf = Zeroizing::new([0u8; MlDsaParams::N * 18 / 8]);
                xof.squeeze(&mut *buf).map_err(SignError::from_algo)?;

                for chunk in 0..(MlDsaParams::N / 4) {
                    let off = 9 * chunk;
                    let t0 = (buf[off] as u32)
                        | ((buf[off + 1] as u32) << 8)
                        | (((buf[off + 2] as u32) & 0x03) << 16);
                    let t1 = ((buf[off + 2] as u32) >> 2)
                        | ((buf[off + 3] as u32) << 6)
                        | (((buf[off + 4] as u32) & 0x0F) << 14);
                    let t2 = ((buf[off + 4] as u32) >> 4)
                        | ((buf[off + 5] as u32) << 4)
                        | (((buf[off + 6] as u32) & 0x3F) << 12);
                    let t3 = ((buf[off + 6] as u32) >> 6)
                        | ((buf[off + 7] as u32) << 2)
                        | ((buf[off + 8] as u32) << 10);

                    pv.polys[i].coeffs[4 * chunk] = centered_to_mod_q((gamma1 as i32) - t0 as i32);
                    pv.polys[i].coeffs[4 * chunk + 1] =
                        centered_to_mod_q((gamma1 as i32) - t1 as i32);
                    pv.polys[i].coeffs[4 * chunk + 2] =
                        centered_to_mod_q((gamma1 as i32) - t2 as i32);
                    pv.polys[i].coeffs[4 * chunk + 3] =
                        centered_to_mod_q((gamma1 as i32) - t3 as i32);
                }
            }
            val if val == (1 << 19) => {
                let mut buf = Zeroizing::new([0u8; MlDsaParams::N * 20 / 8]);
                xof.squeeze(&mut *buf).map_err(SignError::from_algo)?;

                for chunk in 0..(MlDsaParams::N / 2) {
                    let off = 5 * chunk;
                    let t0 = (buf[off] as u32)
                        | ((buf[off + 1] as u32) << 8)
                        | (((buf[off + 2] as u32) & 0x0F) << 16);
                    let t1 = ((buf[off + 2] as u32) >> 4)
                        | ((buf[off + 3] as u32) << 4)
                        | ((buf[off + 4] as u32) << 12);

                    pv.polys[i].coeffs[2 * chunk] = centered_to_mod_q((gamma1 as i32) - t0 as i32);
                    pv.polys[i].coeffs[2 * chunk + 1] =
                        centered_to_mod_q((gamma1 as i32) - t1 as i32);
                }
            }
            _ => return Err(SignError::Sampling("Unsupported gamma1 value".into())),
        }
    }

    Ok(pv)
}

#[inline(always)]
fn centered_to_mod_q(value: i32) -> u32 {
    (value as i64).rem_euclid(MlDsaParams::Q as i64) as u32
}

/// FIPS 204 Algorithm 29, `SampleInBall`.
pub fn sample_challenge_c<P: MlDsaSchemeParams>(
    c_tilde_seed: &[u8],
    tau: u32,
) -> Result<Polynomial<MlDsaParams>, SignError> {
    if c_tilde_seed.len() != P::CHALLENGE_BYTES || tau as usize != P::TAU_PARAM {
        return Err(SignError::Sampling(
            "invalid SampleInBall parameters".into(),
        ));
    }

    let mut c_poly = Polynomial::<MlDsaParams>::zero();
    let mut xof = ShakeXof256::new();
    xof.update(c_tilde_seed).map_err(SignError::from_algo)?;

    let mut signs = [0u8; 8];
    xof.squeeze(&mut signs).map_err(SignError::from_algo)?;

    let tau = tau as usize;
    for i in (MlDsaParams::N - tau)..MlDsaParams::N {
        let mut byte = [0u8; 1];
        loop {
            xof.squeeze(&mut byte).map_err(SignError::from_algo)?;
            if usize::from(byte[0]) <= i {
                break;
            }
        }

        let j = usize::from(byte[0]);
        c_poly.coeffs[i] = c_poly.coeffs[j];
        let sign_index = i + tau - MlDsaParams::N;
        let negative = ((signs[sign_index / 8] >> (sign_index % 8)) & 1) != 0;
        c_poly.coeffs[j] = if negative { MlDsaParams::Q - 1 } else { 1 };
    }

    Ok(c_poly)
}
