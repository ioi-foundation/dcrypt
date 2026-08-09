// kem/src/kyber/cpa_pke.rs

//! Kyber CPA-secure Public Key Encryption scheme.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use dcrypt_algorithms::error::{Error as AlgoError, Result as AlgoResult};
use dcrypt_algorithms::poly::params::Modulus; // Add this import
use dcrypt_algorithms::poly::polynomial::Polynomial;
use dcrypt_algorithms::xof::shake::{ShakeXof128, ShakeXof256};
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::Zeroizing;

use super::params::{
    KyberParams, KyberPolyModParams, KYBER_NOISE_SEED_BYTES, KYBER_RHO_SEED_BYTES,
    KYBER_SYMKEY_SEED_BYTES,
};
use super::polyvec::PolyVec;

// Type aliases for clarity within CPA PKE context
pub(crate) type CpaPublicKeyInner<P> = (PolyVec<P>, [u8; KYBER_RHO_SEED_BYTES]); // (t_hat, rho_for_A)
pub(crate) type CpaSecretKeyInner<P> = PolyVec<P>; // s_hat (NTT form)
pub(crate) type CpaCiphertextInner<P> = (PolyVec<P>, Polynomial<KyberPolyModParams>); // (u, v)

/// Generate matrix A from seed using SHAKE128
fn gen_matrix_a<P: KyberParams>(rho: &[u8; KYBER_RHO_SEED_BYTES]) -> AlgoResult<Vec<PolyVec<P>>> {
    let mut a = Vec::with_capacity(P::K);

    for i in 0..P::K {
        let mut row = PolyVec::<P>::zero();

        for j in 0..P::K {
            // Generate polynomial A[i][j] using SHAKE128(rho || i || j)
            let mut xof = ShakeXof128::new();
            xof.update(rho)?;
            xof.update(&[i as u8, j as u8])?;

            // Sample uniform polynomial
            let mut poly = Polynomial::<KyberPolyModParams>::zero();
            let mut buf = [0u8; 3]; // For 12-bit sampling
            let mut count = 0;

            while count < KyberPolyModParams::N {
                xof.squeeze(&mut buf)?;

                // Extract two 12-bit values
                let d1 = ((buf[0] as u16) | ((buf[1] as u16 & 0x0F) << 8)) as u32;
                let d2 = (((buf[1] as u16) >> 4) | ((buf[2] as u16) << 4)) as u32;

                // Rejection sampling
                if d1 < KyberPolyModParams::Q && count < KyberPolyModParams::N {
                    poly.coeffs[count] = d1;
                    count += 1;
                }
                if d2 < KyberPolyModParams::Q && count < KyberPolyModParams::N {
                    poly.coeffs[count] = d2;
                    count += 1;
                }
            }

            row.polys[j] = poly;
        }

        a.push(row);
    }

    Ok(a)
}

/// Sample polynomial from CBD using SHAKE256
fn sample_poly_cbd<P: KyberParams>(
    seed: &[u8; KYBER_NOISE_SEED_BYTES],
    nonce: u8,
    eta: u8,
) -> AlgoResult<Polynomial<KyberPolyModParams>> {
    let mut xof = ShakeXof256::new();
    xof.update(seed)?;
    xof.update(&[nonce])?;

    // Generate enough bytes for CBD sampling
    let bytes_needed = (eta as usize * KyberPolyModParams::N) / 4;
    let mut buf = Zeroizing::new(vec![0u8; bytes_needed]);
    xof.squeeze(buf.as_mut_slice())?;

    // CBD sampling
    let mut poly = Polynomial::<KyberPolyModParams>::zero();
    let mut buf_idx = 0;

    for i in 0..KyberPolyModParams::N {
        let mut a = 0u32;
        let mut b = 0u32;

        for _ in 0..eta {
            let byte_idx = buf_idx / 8;
            let bit_idx = buf_idx % 8;
            a += ((buf[byte_idx] >> bit_idx) & 1) as u32;
            buf_idx += 1;
        }

        for _ in 0..eta {
            let byte_idx = buf_idx / 8;
            let bit_idx = buf_idx % 8;
            b += ((buf[byte_idx] >> bit_idx) & 1) as u32;
            buf_idx += 1;
        }

        // CBD sample in range [-eta, eta], then reduce mod Q
        let sample = (a as i32 - b as i32 + KyberPolyModParams::Q as i32) as u32;
        poly.coeffs[i] = sample % KyberPolyModParams::Q;
    }

    Ok(poly)
}

/// Sample PolyVec from CBD
fn sample_polyvec_cbd<P: KyberParams>(
    seed: &[u8; KYBER_NOISE_SEED_BYTES],
    nonce: u8,
    eta: u8,
) -> AlgoResult<PolyVec<P>> {
    let mut pv = PolyVec::<P>::zero();

    for i in 0..P::K {
        pv.polys[i] = sample_poly_cbd::<P>(seed, nonce + i as u8, eta)?;
    }

    Ok(pv)
}

/// Encode message bytes to polynomial
fn encode_message(msg: &[u8; KYBER_SYMKEY_SEED_BYTES]) -> Polynomial<KyberPolyModParams> {
    let mut poly = Polynomial::<KyberPolyModParams>::zero();

    for i in 0..KyberPolyModParams::N {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = (msg[byte_idx] >> bit_idx) & 1;
        poly.coeffs[i] = (bit as u32) * KyberPolyModParams::Q.div_ceil(2);
    }

    poly
}

/// Decode polynomial to message bytes
fn decode_message(poly: &Polynomial<KyberPolyModParams>) -> [u8; KYBER_SYMKEY_SEED_BYTES] {
    let mut msg = [0u8; KYBER_SYMKEY_SEED_BYTES];

    for i in 0..KyberPolyModParams::N {
        let t = ((poly.coeffs[i] << 1) + KyberPolyModParams::Q / 2) / KyberPolyModParams::Q;
        let bit = t & 1;

        let byte_idx = i / 8;
        let bit_idx = i % 8;
        msg[byte_idx] |= (bit as u8) << bit_idx;
    }

    msg
}

/// Kyber CPA PKE Key Generation.
pub(crate) fn keypair_cpa<P: KyberParams, R: RngCore + CryptoRng>(
    rng: &mut R,
) -> AlgoResult<(CpaPublicKeyInner<P>, CpaSecretKeyInner<P>)> {
    // Generate seeds
    let mut rho = Zeroizing::new([0u8; KYBER_RHO_SEED_BYTES]);
    let mut sigma = Zeroizing::new([0u8; KYBER_NOISE_SEED_BYTES]);
    rng.try_fill_bytes(rho.as_mut())
        .map_err(|_| AlgoError::Processing {
            operation: "Kyber CPA key generation",
            details: "caller-provided randomness source failed",
        })?;
    rng.try_fill_bytes(sigma.as_mut())
        .map_err(|_| AlgoError::Processing {
            operation: "Kyber CPA key generation",
            details: "caller-provided randomness source failed",
        })?;

    // Generate matrix A
    let a = gen_matrix_a::<P>(&rho)?;

    // Sample s and e
    let mut s = sample_polyvec_cbd::<P>(&sigma, 0, P::ETA1)?;
    let e = sample_polyvec_cbd::<P>(&sigma, P::K as u8, P::ETA1)?;

    // Transform s to NTT domain
    s.ntt_inplace()?;

    // Compute t = A*s + e in NTT domain
    let mut t = PolyVec::<P>::zero();
    for (i, row) in a.iter().enumerate().take(P::K) {
        let mut sum = Polynomial::<KyberPolyModParams>::zero();
        for j in 0..P::K {
            let mut a_ij = row.polys[j].clone();
            a_ij.ntt_inplace()?;
            let prod = a_ij.ntt_mul(&s.polys[j]);
            sum = sum.add(&prod);
        }
        sum.from_ntt_inplace()?;
        t.polys[i] = sum.add(&e.polys[i]);
    }

    // Transform t to NTT domain for storage
    t.ntt_inplace()?;

    Ok(((t, *rho), s))
}

/// Kyber CPA PKE Encryption.
pub(crate) fn encrypt_cpa<P: KyberParams>(
    pk_cpa_inner: &CpaPublicKeyInner<P>,
    msg_bytes: &[u8; KYBER_SYMKEY_SEED_BYTES],
    coins_bytes: &[u8; KYBER_SYMKEY_SEED_BYTES],
) -> AlgoResult<CpaCiphertextInner<P>> {
    let (t_hat, rho) = pk_cpa_inner;

    // Generate matrix A^T
    let a_transpose = gen_matrix_a::<P>(rho)?;

    // Sample r, e1, e2
    let r = sample_polyvec_cbd::<P>(coins_bytes, 0, P::ETA1)?;
    let e1 = sample_polyvec_cbd::<P>(coins_bytes, P::K as u8, P::ETA2)?;
    let e2 = sample_poly_cbd::<P>(coins_bytes, 2 * P::K as u8, P::ETA2)?;

    // Transform r to NTT domain
    let mut r_hat = r.clone();
    r_hat.ntt_inplace()?;

    // Compute u = A^T * r + e1
    let mut u = PolyVec::<P>::zero();
    for i in 0..P::K {
        let mut sum = Polynomial::<KyberPolyModParams>::zero();
        for (j, row) in a_transpose.iter().enumerate().take(P::K) {
            let mut a_ji = row.polys[i].clone();
            a_ji.ntt_inplace()?;
            let prod = a_ji.ntt_mul(&r_hat.polys[j]);
            sum = sum.add(&prod);
        }
        sum.from_ntt_inplace()?;
        u.polys[i] = sum.add(&e1.polys[i]);
    }

    // Compute v = t^T * r + e2 + m
    let v_intermediate_ntt = t_hat.pointwise_accum(&r_hat);
    let mut v_intermediate = v_intermediate_ntt;
    v_intermediate.from_ntt_inplace()?;

    let m_poly = encode_message(msg_bytes);
    let v_final = v_intermediate.add(&e2).add(&m_poly);

    Ok((u, v_final))
}

/// Kyber CPA PKE Decryption.
pub(crate) fn decrypt_cpa<P: KyberParams>(
    sk_hat_ntt: &CpaSecretKeyInner<P>,
    cpa_ciphertext_inner: &CpaCiphertextInner<P>,
) -> AlgoResult<Zeroizing<[u8; KYBER_SYMKEY_SEED_BYTES]>> {
    let (u, v) = cpa_ciphertext_inner;

    // Transform u to NTT domain
    let mut u_hat = u.clone();
    u_hat.ntt_inplace()?;

    // Compute s^T * u
    let s_transpose_u_ntt = sk_hat_ntt.pointwise_accum(&u_hat);
    let mut s_transpose_u = s_transpose_u_ntt;
    s_transpose_u.from_ntt_inplace()?;

    // Compute m' = v - s^T * u
    let m_prime_poly = v.sub(&s_transpose_u);

    // Decode to bytes
    let m_prime_bytes = decode_message(&m_prime_poly);

    Ok(Zeroizing::new(m_prime_bytes))
}
