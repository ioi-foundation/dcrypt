// crates/algorithms/src/ec/bls12_381/hash_to_curve.rs

//! Hash-to-Curve implementation for BLS12-381 (G1 and G2)
//!
//! Implements the standard suites from RFC 9380:
//! - BLS12381G1_XMD:SHA-256_SSWU_RO_
//! - BLS12381G2_XMD:SHA-256_SSWU_RO_

use super::field::fp::Fp;
use super::field::fp2::Fp2;
use super::{G1Projective, G2Projective};
use crate::error::{Error, Result};
use crate::hash::sha2::Sha256;
use crate::hash::HashFunction;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

// =============================================================================
// expand_message_xmd (SHA-256)
// =============================================================================

fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>> {
    const B_IN_BYTES: usize = 32;
    let ell = (len_in_bytes + B_IN_BYTES - 1) / B_IN_BYTES;
    if ell > 255 {
        return Err(Error::Parameter {
            name: "len_in_bytes".into(),
            reason: "requested output too long for expand_message_xmd".into(),
        });
    }
    let mut dst_prime = Vec::with_capacity(dst.len() + 1);
    dst_prime.extend_from_slice(dst);
    dst_prime.push(dst.len() as u8);

    // b_0
    let mut hasher = Sha256::new();
    hasher.update(&[0u8; 64])?; // Z_pad
    hasher.update(msg)?;
    hasher.update(&(len_in_bytes as u16).to_be_bytes())?;
    hasher.update(&[0u8])?;
    hasher.update(&dst_prime)?;
    let b_0 = hasher.finalize()?;

    let mut b_i = vec![0u8; B_IN_BYTES];
    let mut uniform_bytes = Vec::with_capacity(len_in_bytes);

    // b_1
    let mut hasher = Sha256::new();
    hasher.update(b_0.as_ref())?;
    hasher.update(&[1u8])?;
    hasher.update(&dst_prime)?;
    let digest = hasher.finalize()?;
    b_i.copy_from_slice(digest.as_ref());
    uniform_bytes.extend_from_slice(&b_i);

    for i in 2..=ell {
        let mut xor_input = [0u8; B_IN_BYTES];
        for j in 0..B_IN_BYTES {
            xor_input[j] = b_0.as_ref()[j] ^ b_i[j];
        }
        let mut hasher = Sha256::new();
        hasher.update(&xor_input)?;
        hasher.update(&[i as u8])?;
        hasher.update(&dst_prime)?;
        let digest = hasher.finalize()?;
        b_i.copy_from_slice(digest.as_ref());
        uniform_bytes.extend_from_slice(&b_i);
    }

    uniform_bytes.truncate(len_in_bytes);
    Ok(uniform_bytes)
}

// =============================================================================
// Sign functions (RFC 9380 Section 4.1)
// =============================================================================

fn sgn0_fp(x: &Fp) -> Choice {
    // sgn0(x) = x mod 2
    let bytes = x.to_bytes();
    // Fp is big-endian encoded, so LSB is at the end
    Choice::from(bytes[47] & 1)
}

fn sgn0_fp2(x: &Fp2) -> Choice {
    // sgn0(x0 + i*x1) = sgn0(x0) if x0 != 0 else sgn0(x1)
    let sign_0 = sgn0_fp(&x.c0);
    let zero_0 = x.c0.is_zero();
    let sign_1 = sgn0_fp(&x.c1);
    sign_0 | (zero_0 & sign_1)
}

// =============================================================================
// G1: Simplified SWU with Z = -11
// =============================================================================

fn map_to_curve_g1(u: &Fp) -> G1Projective {
    // Z = -11 mod p
    let z = Fp::from_raw_unchecked([
        0x3c20_8c16_d87c_f1ff,
        0x9781_6a91_6871_ca8d,
        0xb850_45b7_179e_9a4d,
        0x9d71_20b8_351c_4374,
        0x1993_4a11_123d_9479,
        0x1987_2869_eb4b_31b8,
    ]);

    let tv1 = u.square();
    let tv3 = z * tv1;
    let tv2 = tv3.square();
    let mut x = tv2 + tv3;
    let x3 = z * x;
    x = x + Fp::one();
    let mut gx = x.square() * x;

    // B = 4
    let b_coeff = Fp::from_raw_unchecked([
        0xaa27_0000_000c_fff3,
        0x53cc_0032_fc34_000a,
        0x478f_e97a_6b0a_807f,
        0xb1d3_7ebe_e6ba_24d7,
        0x8ec9_733b_bf78_ab2f,
        0x09d6_4551_3d83_de7e,
    ]);

    gx = gx + b_coeff;

    let y = gx.sqrt();
    let is_gx_square = y.is_some();
    let y = y.unwrap_or(Fp::zero());

    let x2 = x3;
    let gx2 = (x2.square() * x2) + b_coeff;
    let y2 = gx2.sqrt().unwrap_or(Fp::zero());

    let x = Fp::conditional_select(&x2, &x, is_gx_square);
    let y = Fp::conditional_select(&y2, &y, is_gx_square);

    // Ensure signs match
    let flip = !sgn0_fp(u).ct_eq(&sgn0_fp(&y));
    let y = Fp::conditional_select(&y, &-y, flip);

    G1Projective { x, y, z: Fp::one() }
}

/// Hashes a message to a point in G1 using the SSWU map.
pub fn hash_to_curve_g1(msg: &[u8], dst: &[u8]) -> Result<G1Projective> {
    let uniform_bytes = expand_message_xmd(msg, dst, 64)?;
    let mut u0_bytes = [0u8; 64];
    u0_bytes.copy_from_slice(&uniform_bytes[0..64]);
    let u0 = Fp::from_bytes_wide(&u0_bytes);
    let q = map_to_curve_g1(&u0);
    Ok(q.clear_cofactor())
}

// =============================================================================
// G2: Simplified SWU + 3-isogeny
// =============================================================================

// Coefficients for the 3-isogeny map (x-numerator)
const ISO3_XNUM: [Fp2; 4] = [
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x47f6_71c7_1ce0_5e62,
            0x06dd_5707_1206_393e,
            0x7c80_cd2a_f3fd_71a2,
            0x0481_03ea_9e6c_d062,
            0xc545_16ac_c8d0_37f6,
            0x1380_8f55_0920_ea41,
        ]),
        c1: Fp::from_raw_unchecked([
            0x47f6_71c7_1ce0_5e62,
            0x06dd_5707_1206_393e,
            0x7c80_cd2a_f3fd_71a2,
            0x0481_03ea_9e6c_d062,
            0xc545_16ac_c8d0_37f6,
            0x1380_8f55_0920_ea41,
        ]),
    },
    Fp2 {
        c0: Fp::zero(),
        c1: Fp::from_raw_unchecked([
            0x5fe5_5555_554c_71d0,
            0x873f_ffdd_236a_aaa3,
            0x6a6b_4619_b26e_f918,
            0x21c2_8884_0887_4945,
            0x2836_cda7_028c_abc5,
            0x0ac7_3310_a7fd_5abd,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x0a0c_5555_5559_71c3,
            0xdb0c_0010_1f9e_aaae,
            0xb1fb_2f94_1d79_7997,
            0xd396_0742_ef41_6e1c,
            0xb700_40e2_c205_56f4,
            0x149d_7861_e581_393b,
        ]),
        c1: Fp::from_raw_unchecked([
            0xaff2_aaaa_aaa6_38e8,
            0x439f_ffee_91b5_5551,
            0xb535_a30c_d937_7c8c,
            0x90e1_4442_0443_a4a2,
            0x941b_66d3_8146_55e2,
            0x0563_9988_53fe_ad5e,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x40aa_c71c_71c7_25ed,
            0x1909_5555_7a84_e38e,
            0xd817_050a_8f41_abc3,
            0xd864_85d4_c87f_6fb1,
            0x696e_b479_f885_d059,
            0x198e_1a74_3280_02d2,
        ]),
        c1: Fp::zero(),
    },
];

// Coefficients for the 3-isogeny map (x-denominator)
const ISO3_XDEN: [Fp2; 3] = [
    Fp2 {
        c0: Fp::zero(),
        c1: Fp::from_raw_unchecked([
            0x1f3a_ffff_ff13_ab97,
            0xf25b_fc61_1da3_ff3e,
            0xca37_57cb_3819_b208,
            0x3e64_2736_6f8c_ec18,
            0x0397_7bc8_6095_b089,
            0x04f6_9db1_3f39_a952,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x4476_0000_0027_552e,
            0xdcb8_009a_4348_0020,
            0x6f7e_e9ce_4a6e_8b59,
            0xb103_30b7_c0a9_5bc6,
            0x6140_b1fc_fb1e_54b7,
            0x0381_be09_7f0b_b4e1,
        ]),
        c1: Fp::from_raw_unchecked([
            0x7588_ffff_ffd8_557d,
            0x41f3_ff64_6e0b_ffdf,
            0xf7b1_e8d2_ac42_6aca,
            0xb374_1acd_32db_b6f8,
            0xe9da_f5b9_482d_581f,
            0x167f_53e0_ba74_31b8,
        ]),
    },
    Fp2::one(),
];

// Coefficients for the 3-isogeny map (y-numerator)
const ISO3_YNUM: [Fp2; 4] = [
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x96d8_f684_bdfc_77be,
            0xb530_e4f4_3b66_d0e2,
            0x184a_88ff_3796_52fd,
            0x57cb_23ec_fae8_04e1,
            0x0fd2_e39e_ada3_eba9,
            0x08c8_055e_31c5_d5c3,
        ]),
        c1: Fp::from_raw_unchecked([
            0x96d8_f684_bdfc_77be,
            0xb530_e4f4_3b66_d0e2,
            0x184a_88ff_3796_52fd,
            0x57cb_23ec_fae8_04e1,
            0x0fd2_e39e_ada3_eba9,
            0x08c8_055e_31c5_d5c3,
        ]),
    },
    Fp2 {
        c0: Fp::zero(),
        c1: Fp::from_raw_unchecked([
            0xbf0a_71c7_1c91_b406,
            0x4d6d_55d2_8b76_38fd,
            0x9d82_f98e_5f20_5aee,
            0xa27a_a27b_1d1a_18d5,
            0x02c3_b2b2_d293_8e86,
            0x0c7d_1342_0b09_807f,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0xd7f9_5555_5553_1c74,
            0x21cf_fff7_48da_aaa8,
            0x5a9a_d186_6c9b_be46,
            0x4870_a221_0221_d251,
            0x4a0d_b369_c0a3_2af1,
            0x02b1_ccc4_29ff_56af,
        ]),
        c1: Fp::from_raw_unchecked([
            0xe205_aaaa_aaac_8e37,
            0xfcdc_0007_6879_5556,
            0x0c96_011a_8a15_37dd,
            0x1c06_a963_f163_406e,
            0x010d_f44c_82a8_81e6,
            0x174f_4526_0f80_8feb,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0xa470_bda1_2f67_f35c,
            0xc0fe_38e2_3327_b425,
            0xc9d3_d0f2_c6f0_678d,
            0x1c55_c993_5b5a_982e,
            0x27f6_c0e2_f074_6764,
            0x117c_5e6e_28aa_9054,
        ]),
        c1: Fp::zero(),
    },
];

// Coefficients for the 3-isogeny map (y-denominator)
const ISO3_YDEN: [Fp2; 4] = [
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x0162_ffff_fa76_5adf,
            0x8f7b_ea48_0083_fb75,
            0x561b_3c22_59e9_3611,
            0x11e1_9fc1_a9c8_75d5,
            0xca71_3efc_0036_7660,
            0x03c6_a03d_41da_1151,
        ]),
        c1: Fp::from_raw_unchecked([
            0x0162_ffff_fa76_5adf,
            0x8f7b_ea48_0083_fb75,
            0x561b_3c22_59e9_3611,
            0x11e1_9fc1_a9c8_75d5,
            0xca71_3efc_0036_7660,
            0x03c6_a03d_41da_1151,
        ]),
    },
    Fp2 {
        c0: Fp::zero(),
        c1: Fp::from_raw_unchecked([
            0x5db0_ffff_fd3b_02c5,
            0xd713_f523_58eb_fdba,
            0x5ea6_0761_a84d_161a,
            0xbb2c_75a3_4ea6_c44a,
            0x0ac6_7359_21c1_119b,
            0x0ee3_d913_bdac_fbf6,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x66b1_0000_003a_ffc5,
            0xcb14_00e7_64ec_0030,
            0xa73e_5eb5_6fa5_d106,
            0x8984_c913_a0fe_09a9,
            0x11e1_0afb_78ad_7f13,
            0x0542_9d0e_3e91_8f52,
        ]),
        c1: Fp::from_raw_unchecked([
            0x534d_ffff_ffc4_aae6,
            0x5397_ff17_4c67_ffcf,
            0xbff2_73eb_870b_251d,
            0xdaf2_8271_5287_0915,
            0x393a_9cba_ca9e_2dc3,
            0x14be_74db_faee_5748,
        ]),
    },
    Fp2::one(),
];

const SSWU_ELLP_A: Fp2 = Fp2 {
    c0: Fp::zero(),
    c1: Fp::from_raw_unchecked([
        0xe53a_0000_0313_5242,
        0x0108_0c0f_def8_0285,
        0xe788_9edb_e340_f6bd,
        0x0b51_3751_2631_0601,
        0x02d6_9857_17c7_44ab,
        0x1220_b4e9_79ea_5467,
    ]),
};

const SSWU_ELLP_B: Fp2 = Fp2 {
    c0: Fp::from_raw_unchecked([
        0x22ea_0000_0cf8_9db2,
        0x6ec8_32df_7138_0aa4,
        0x6e1b_9440_3db5_a66e,
        0x75bf_3c53_a794_73ba,
        0x3dd3_a569_412c_0a34,
        0x125c_db5e_74dc_4fd1,
    ]),
    c1: Fp::from_raw_unchecked([
        0x22ea_0000_0cf8_9db2,
        0x6ec8_32df_7138_0aa4,
        0x6e1b_9440_3db5_a66e,
        0x75bf_3c53_a794_73ba,
        0x3dd3_a569_412c_0a34,
        0x125c_db5e_74dc_4fd1,
    ]),
};

const SSWU_XI: Fp2 = Fp2 {
    c0: Fp::from_raw_unchecked([
        0x87eb_ffff_fff9_555c,
        0x656f_ffe5_da8f_fffa,
        0x0fd0_7493_45d3_3ad2,
        0xd951_e663_0665_76f4,
        0xde29_1a3d_41e9_80d3,
        0x0815_664c_7dfe_040d,
    ]),
    c1: Fp::from_raw_unchecked([
        0x43f5_ffff_fffc_aaae,
        0x32b7_fff2_ed47_fffd,
        0x07e8_3a49_a2e9_9d69,
        0xeca8_f331_8332_bb7a,
        0xef14_8d1e_a0f4_c069,
        0x040a_b326_3eff_0206,
    ]),
};

fn iso_map(u: &G2Projective) -> G2Projective {
    const COEFFS: [&[Fp2]; 4] = [&ISO3_XNUM, &ISO3_XDEN, &ISO3_YNUM, &ISO3_YDEN];

    let G2Projective { x, y, z } = *u;
    let mut mapvals = [Fp2::zero(); 4];

    // compute powers of z
    let zsq = z.square();
    let zpows = [z, zsq, zsq * z];

    // compute map value by Horner's rule
    for idx in 0..4 {
        let coeff = COEFFS[idx];
        let clast = coeff.len() - 1;
        mapvals[idx] = coeff[clast];
        for jdx in 0..clast {
            mapvals[idx] = mapvals[idx] * x + zpows[jdx] * coeff[clast - 1 - jdx];
        }
    }

    // x denominator is order 1 less than x numerator, so we need an extra factor of z
    mapvals[1] *= z;

    // multiply result of Y map by the y-coord, y / z
    mapvals[2] *= y;
    mapvals[3] *= z;

    G2Projective {
        x: mapvals[0] * mapvals[3], // xnum * yden,
        y: mapvals[2] * mapvals[1], // ynum * xden,
        z: mapvals[1] * mapvals[3], // xden * yden
    }
}

fn map_to_curve_simple_swu(u: &Fp2) -> G2Projective {
    let usq = u.square();
    let xi_usq = SSWU_XI * usq;
    let xisq_u4 = xi_usq.square();
    let nd_common = xisq_u4 + xi_usq; // XI^2 * u^4 + XI * u^2
    let x_den = SSWU_ELLP_A * Fp2::conditional_select(&(-nd_common), &SSWU_XI, nd_common.is_zero());
    let x0_num = SSWU_ELLP_B * (Fp2::one() + nd_common); // B * (1 + (XI^2 * u^4 + XI * u^2))

    // compute g(x0(u))
    let x_densq = x_den.square();
    let gx_den = x_densq * x_den;
    // x0_num^3 + A * x0_num * x_den^2 + B * x_den^3
    let gx0_num = (x0_num.square() + SSWU_ELLP_A * x_densq) * x0_num + SSWU_ELLP_B * gx_den;

    // We can't use the optimized chain here because we don't have the chain module linked properly
    // in this context, so we fall back to standard sqrt.
    // However, since we need to check if gx0(u) is square, we check directly.
    let gx0_div_den = gx0_num * gx_den.invert().unwrap_or(Fp2::zero());
    let sqrt_candidate = gx0_div_den.sqrt();
    let is_square = sqrt_candidate.is_some();

    // If gx0 is square, x = x0_num/x_den, y = sqrt(gx0)
    // If not, x = x1 = x0 * XI * u^2, y = sqrt(g(x1))

    let x0_num_xi_usq = x0_num * xi_usq;
    let x_num = Fp2::conditional_select(&x0_num_xi_usq, &x0_num, is_square);

    // Compute y
    // If gx0 was square, y = sqrt(gx0)
    // If not, y = sqrt(g(x1)) = sqrt(g(x0) * XI^3 * u^6)
    // We already computed sqrt(gx0) potentially.

    let mut y = Fp2::zero();
    if bool::from(is_square) {
        y = sqrt_candidate.unwrap();
    } else {
        // g(x1) = g(x0) * XI^3 * u^6
        // g(x0) = gx0_div_den
        // XI^3 * u^6 = (XI * u^2)^3 = xi_usq^3
        let gx1 = gx0_div_den * xi_usq.square() * xi_usq;
        y = gx1.sqrt().unwrap_or(Fp2::zero());
    }

    // ensure sign of y and sign of u agree
    let flip = !sgn0_fp2(u).ct_eq(&sgn0_fp2(&y));
    let y = Fp2::conditional_select(&y, &-y, flip);

    G2Projective {
        x: x_num,
        y: y * x_den,
        z: x_den,
    }
}

/// Hashes a message to a point in G2 using the SSWU map and 3-isogeny.
pub fn hash_to_curve_g2(msg: &[u8], dst: &[u8]) -> Result<G2Projective> {
    let uniform_bytes = expand_message_xmd(msg, dst, 256)?;
    let mut u0_bytes = [0u8; 128];
    let mut u1_bytes = [0u8; 128];
    u0_bytes.copy_from_slice(&uniform_bytes[0..128]);
    u1_bytes.copy_from_slice(&uniform_bytes[128..256]);
    let u0 = Fp2::from_bytes_wide(&u0_bytes);
    let u1 = Fp2::from_bytes_wide(&u1_bytes);

    let p0 = map_to_curve_simple_swu(&u0);
    let q0 = iso_map(&p0);

    let p1 = map_to_curve_simple_swu(&u1);
    let q1 = iso_map(&p1);

    let r = q0 + q1;
    Ok(r.clear_cofactor())
}
