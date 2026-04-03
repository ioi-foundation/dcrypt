//! Sampling functions for Dilithium implementing FIPS 203 algorithms.

use super::polyvec::{PolyVecK, PolyVecL};
use crate::error::Error as SignError;
use dcrypt_algorithms::poly::params::{DilithiumParams, Modulus};
use dcrypt_algorithms::poly::polynomial::Polynomial;
use dcrypt_algorithms::xof::shake::ShakeXof256;
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use dcrypt_params::pqc::dilithium::DilithiumSchemeParams;

/// Samples a polynomial with coefficients from CBD_eta (Algorithm 22).
/// Uses SHAKE256(seed || nonce) as randomness source.
#[allow(clippy::extra_unused_type_parameters)]
pub fn sample_poly_cbd_eta<P: DilithiumSchemeParams>(
    seed: &[u8; 32], // SEED_KEY_BYTES is always 32
    nonce: u8,
    eta: u32,
) -> Result<Polynomial<DilithiumParams>, SignError> {
    if eta == 0 || eta > 8 {
        return Err(SignError::Sampling(format!("Invalid eta for CBD: {}", eta)));
    }

    let mut xof = ShakeXof256::new();
    xof.update(seed).map_err(SignError::from_algo)?;
    xof.update(&[nonce]).map_err(SignError::from_algo)?;

    if eta == 2 {
        // CBD2 implementation using bit counting
        let mut buf = [0u8; 128];
        xof.squeeze(&mut buf).map_err(SignError::from_algo)?;

        let mut poly = Polynomial::<DilithiumParams>::zero();
        for i in 0..(DilithiumParams::N / 8) {
            let t = u32::from_le_bytes(buf[4 * i..4 * i + 4].try_into().unwrap());
            let d = t & 0x5555_5555;
            let a = d.count_ones();
            let b = ((t >> 1) & 0x5555_5555).count_ones();
            for k in 0..8 {
                let coeff = ((a >> k) & 1) as i32 - ((b >> k) & 1) as i32;
                poly.coeffs[8 * i + k] =
                    (coeff as i64).rem_euclid(DilithiumParams::Q as i64) as u32;
            }
        }
        Ok(poly)
    } else if eta == 4 {
        // CBD4 implementation
        let mut buf = [0u8; 256];
        xof.squeeze(&mut buf).map_err(SignError::from_algo)?;

        let mut poly = Polynomial::<DilithiumParams>::zero();
        for (i, &byte) in buf.iter().enumerate().take(DilithiumParams::N) {
            let t = byte as u32;
            let a = (t & 0x0F).count_ones();
            let b = (t >> 4).count_ones();
            poly.coeffs[i] =
                ((a as i32 - b as i32) as i64).rem_euclid(DilithiumParams::Q as i64) as u32;
        }
        Ok(poly)
    } else {
        // General case for other eta values
        let bytes_needed = (DilithiumParams::N * 2 * eta as usize).div_ceil(8);
        let mut buf = vec![0u8; bytes_needed];
        xof.squeeze(&mut buf).map_err(SignError::from_algo)?;

        let mut poly = Polynomial::<DilithiumParams>::zero();
        let mut bit_offset = 0;
        for i in 0..DilithiumParams::N {
            let mut sum1 = 0i32;
            let mut sum2 = 0i32;

            for _ in 0..eta {
                sum1 += ((buf[bit_offset / 8] >> (bit_offset % 8)) & 1) as i32;
                bit_offset += 1;
            }
            for _ in 0..eta {
                sum2 += ((buf[bit_offset / 8] >> (bit_offset % 8)) & 1) as i32;
                bit_offset += 1;
            }

            // CBD sample is in range [-eta, eta]
            let val_signed = sum1 - sum2;
            poly.coeffs[i] = (val_signed as i64).rem_euclid(DilithiumParams::Q as i64) as u32;
        }
        Ok(poly)
    }
}

/// Samples a PolyVecL from CBD_eta.
pub fn sample_polyvecl_cbd_eta<P: DilithiumSchemeParams>(
    seed: &[u8; 32], // SEED_KEY_BYTES is always 32
    initial_nonce: u8,
    eta: u32,
) -> Result<PolyVecL<P>, SignError> {
    let mut pv = PolyVecL::<P>::zero();
    let mut current_nonce = initial_nonce;

    for i in 0..P::L_DIM {
        pv.polys[i] = sample_poly_cbd_eta::<P>(seed, current_nonce, eta)?;
        current_nonce = current_nonce.wrapping_add(1);
    }

    Ok(pv)
}

/// Samples a PolyVecK from CBD_eta.
pub fn sample_polyveck_cbd_eta<P: DilithiumSchemeParams>(
    seed: &[u8; 32], // SEED_KEY_BYTES is always 32
    initial_nonce: u8,
    eta: u32,
) -> Result<PolyVecK<P>, SignError> {
    let mut pv = PolyVecK::<P>::zero();
    let mut current_nonce = initial_nonce;

    for i in 0..P::K_DIM {
        pv.polys[i] = sample_poly_cbd_eta::<P>(seed, current_nonce, eta)?;
        current_nonce = current_nonce.wrapping_add(1);
    }

    Ok(pv)
}

/// Samples `y = ExpandMask(rho'', mu)` per FIPS 204 Algorithm 34.
///
/// Each polynomial uses `rho || IntegerToBytes(mu + r, 2)` as the XOF input and
/// unpacks coefficients into the range `[-gamma1 + 1, gamma1]`.
pub fn sample_polyvecl_uniform_gamma1<P: DilithiumSchemeParams>(
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
                let mut buf = [0u8; DilithiumParams::N * 18 / 8];
                xof.squeeze(&mut buf).map_err(SignError::from_algo)?;

                for chunk in 0..(DilithiumParams::N / 4) {
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
                let mut buf = [0u8; DilithiumParams::N * 20 / 8];
                xof.squeeze(&mut buf).map_err(SignError::from_algo)?;

                for chunk in 0..(DilithiumParams::N / 2) {
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
    (value as i64).rem_euclid(DilithiumParams::Q as i64) as u32
}

/// Samples challenge polynomial c with τ nonzero coefficients (Algorithm 8).
/// Uses SHAKE256(c_tilde_seed) as randomness source.
/// Accepts variable-sized challenge seeds (32/48/64 bytes)
#[allow(clippy::extra_unused_type_parameters)]
pub fn sample_challenge_c<P: DilithiumSchemeParams>(
    c_tilde_seed: &[u8], // Variable size: 32/48/64 bytes
    tau: u32,
) -> Result<Polynomial<DilithiumParams>, SignError> {
    // Allow 32 / 48 / 64 bytes as mandated by FIPS 204
    if ![32, 48, 64].contains(&c_tilde_seed.len()) {
        return Err(SignError::Sampling(
            "Challenge seed must be 32, 48, or 64 bytes".into(),
        ));
    }

    let mut c_poly = Polynomial::<DilithiumParams>::zero();

    let mut xof = ShakeXof256::new();
    xof.update(c_tilde_seed).map_err(SignError::from_algo)?;

    // First, squeeze sign bits (τ bits packed into bytes)
    let sign_bytes = tau.div_ceil(8);
    let mut signs = vec![0u8; sign_bytes as usize];
    xof.squeeze(&mut signs).map_err(SignError::from_algo)?;

    // Track which positions have been set
    let mut positions_used = [false; DilithiumParams::N];

    // Place τ non-zero coefficients
    for i in 0..tau {
        let mut pos: u8;
        loop {
            let mut byte = [0u8; 1];
            xof.squeeze(&mut byte).map_err(SignError::from_algo)?;
            pos = byte[0];

            // Find next available position
            let mut j = pos as usize;
            while j < DilithiumParams::N && positions_used[j] {
                j += 1;
            }

            if j < DilithiumParams::N {
                positions_used[j] = true;

                // Set coefficient with appropriate sign
                let sign_bit = (signs[i as usize / 8] >> (i % 8)) & 1;
                if sign_bit == 0 {
                    c_poly.coeffs[j] = 1;
                } else {
                    c_poly.coeffs[j] = DilithiumParams::Q - 1; // -1 mod Q
                }
                break;
            }
        }
    }

    Ok(c_poly)
}
