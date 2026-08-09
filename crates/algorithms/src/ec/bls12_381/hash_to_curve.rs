//! RFC 9380 hash-to-curve suites for BLS12-381 G1 and G2.
//!
//! This module implements `expand_message_xmd` with SHA-256, `hash_to_field`,
//! the suite-specific isogenous simplified-SWU maps, point addition, and
//! cofactor clearing for the random-oracle suites in RFC 9380 Section 8.8.

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;

use super::field::fp::Fp;
use super::field::fp2::Fp2;
use super::hash_to_curve_g1::map_to_curve_g1;
use super::hash_to_curve_g2::map_to_curve_g2;
use super::{G1Projective, G2Projective};
use crate::error::{Error, Result};
use crate::hash::sha2::Sha256;
use crate::hash::HashFunction;

const SHA256_BLOCK_SIZE: usize = 64;
const SHA256_OUTPUT_SIZE: usize = 32;
const RFC9380_L: usize = 64;
const OVERSIZE_DST_PREFIX: &[u8] = b"H2C-OVERSIZE-DST-";

fn parameter_error(name: &'static str, reason: &'static str) -> Error {
    Error::Parameter {
        name: name.into(),
        reason: reason.into(),
    }
}

fn normalized_dst(dst: &[u8]) -> Result<Vec<u8>> {
    if dst.len() <= u8::MAX as usize {
        return Ok(dst.to_vec());
    }

    let mut hasher = Sha256::new();
    hasher.update(OVERSIZE_DST_PREFIX)?;
    hasher.update(dst)?;
    Ok(hasher.finalize()?.as_ref().to_vec())
}

/// RFC 9380 Section 5.3.1 `expand_message_xmd` specialized to SHA-256.
pub(super) fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>> {
    if len_in_bytes == 0 || len_in_bytes > u16::MAX as usize {
        return Err(parameter_error(
            "len_in_bytes",
            "XMD output length must be in 1..=65535",
        ));
    }

    let block_count = len_in_bytes.div_ceil(SHA256_OUTPUT_SIZE);
    if block_count > u8::MAX as usize {
        return Err(parameter_error(
            "len_in_bytes",
            "XMD output requires more than 255 hash blocks",
        ));
    }

    let dst = normalized_dst(dst)?;
    let dst_length = u8::try_from(dst.len())
        .map_err(|_| parameter_error("dst", "normalized DST is too long"))?;

    let mut hasher = Sha256::new();
    hasher.update(&[0u8; SHA256_BLOCK_SIZE])?;
    hasher.update(msg)?;
    hasher.update(&(len_in_bytes as u16).to_be_bytes())?;
    hasher.update(&[0u8])?;
    hasher.update(&dst)?;
    hasher.update(&[dst_length])?;
    let b0 = hasher.finalize()?;

    let mut hasher = Sha256::new();
    hasher.update(b0.as_ref())?;
    hasher.update(&[1u8])?;
    hasher.update(&dst)?;
    hasher.update(&[dst_length])?;
    let digest = hasher.finalize()?;
    let mut previous = [0u8; SHA256_OUTPUT_SIZE];
    previous.copy_from_slice(digest.as_ref());

    let mut uniform = Vec::with_capacity(block_count * SHA256_OUTPUT_SIZE);
    uniform.extend_from_slice(&previous);

    for index in 2..=block_count {
        let mut xor = [0u8; SHA256_OUTPUT_SIZE];
        for byte_index in 0..SHA256_OUTPUT_SIZE {
            xor[byte_index] = b0.as_ref()[byte_index] ^ previous[byte_index];
        }

        let mut hasher = Sha256::new();
        hasher.update(&xor)?;
        hasher.update(&[index as u8])?;
        hasher.update(&dst)?;
        hasher.update(&[dst_length])?;
        let digest = hasher.finalize()?;
        previous.copy_from_slice(digest.as_ref());
        uniform.extend_from_slice(&previous);
    }

    uniform.truncate(len_in_bytes);
    Ok(uniform)
}

/// RFC 9380 `OS2IP(tv) mod p` for a 64-byte BLS12-381 base-field input.
fn fp_from_okm(okm: &[u8]) -> Result<Fp> {
    if okm.len() != RFC9380_L {
        return Err(parameter_error(
            "okm",
            "BLS12-381 base-field input must be 64 bytes",
        ));
    }

    // Split the big-endian 512-bit integer into two 256-bit values:
    // OS2IP(okm[0..32]) * 2^256 + OS2IP(okm[32..64]).
    const TWO_TO_256: Fp = Fp::from_raw_unchecked([
        0x075b_3cd7_c5ce_820f,
        0x3ec6_ba62_1c3e_db0b,
        0x168a_13d8_2bff_6bce,
        0x8766_3c4b_f8c4_49d2,
        0x15f3_4c83_ddc8_d830,
        0x0f96_28b4_9caa_2e85,
    ]);

    let mut encoded = [0u8; 48];
    encoded[16..].copy_from_slice(&okm[..32]);
    let high = Fp::from_bytes(&encoded).unwrap_or(Fp::zero());
    encoded[16..].copy_from_slice(&okm[32..]);
    let low = Fp::from_bytes(&encoded).unwrap_or(Fp::zero());
    Ok(high * TWO_TO_256 + low)
}

/// Hash a message to G1 using `BLS12381G1_XMD:SHA-256_SSWU_RO_`.
pub fn hash_to_curve_g1(msg: &[u8], dst: &[u8]) -> Result<G1Projective> {
    let uniform = expand_message_xmd(msg, dst, 2 * RFC9380_L)?;
    let u0 = fp_from_okm(&uniform[..RFC9380_L])?;
    let u1 = fp_from_okm(&uniform[RFC9380_L..])?;
    Ok((map_to_curve_g1(&u0) + map_to_curve_g1(&u1)).clear_cofactor())
}

/// Hash a message to G2 using `BLS12381G2_XMD:SHA-256_SSWU_RO_`.
pub fn hash_to_curve_g2(msg: &[u8], dst: &[u8]) -> Result<G2Projective> {
    let uniform = expand_message_xmd(msg, dst, 4 * RFC9380_L)?;
    let u0 = Fp2 {
        c0: fp_from_okm(&uniform[..RFC9380_L])?,
        c1: fp_from_okm(&uniform[RFC9380_L..2 * RFC9380_L])?,
    };
    let u1 = Fp2 {
        c0: fp_from_okm(&uniform[2 * RFC9380_L..3 * RFC9380_L])?,
        c1: fp_from_okm(&uniform[3 * RFC9380_L..])?,
    };
    Ok((map_to_curve_g2(&u0) + map_to_curve_g2(&u1)).clear_cofactor())
}
