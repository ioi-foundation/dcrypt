//! RFC 9380 BLS12-381 G2 simplified-SWU and 3-isogeny map.
//!
//! The constants are the Montgomery-form values from RFC 9380 Appendix E.3.
//! The formulas follow RFC 9380 Sections 6.6.2 and 8.8.2.

use super::field::fp::Fp;
use super::field::fp2::Fp2;
use super::G2Projective;
use dcrypt_internal::constant_time::{Choice, ConditionallySelectable};

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

fn sgn0_fp(value: &Fp) -> Choice {
    let bytes = value.to_bytes();
    Choice::from(bytes[47] & 1)
}

fn sgn0(value: &Fp2) -> Choice {
    let sign_c0 = sgn0_fp(&value.c0);
    sign_c0 | (value.c0.is_zero() & sgn0_fp(&value.c1))
}

fn map_to_isogenous_curve(u: &Fp2) -> G2Projective {
    let u_squared = u.square();
    let xi_u_squared = SSWU_XI * u_squared;
    let nd_common = xi_u_squared.square() + xi_u_squared;
    let x_den = SSWU_ELLP_A * Fp2::conditional_select(&-nd_common, &SSWU_XI, nd_common.is_zero());
    let x0_num = SSWU_ELLP_B * (Fp2::one() + nd_common);

    let x_den_squared = x_den.square();
    let gx_den = x_den_squared * x_den;
    let gx0_num = (x0_num.square() + SSWU_ELLP_A * x_den_squared) * x0_num + SSWU_ELLP_B * gx_den;

    // Evaluate both candidates without branching on the square test.
    let gx_den_inverse = gx_den.invert().unwrap_or(Fp2::zero());
    let gx0 = gx0_num * gx_den_inverse;
    let y0 = gx0.sqrt();

    let x1_num = x0_num * xi_u_squared;
    let gx1_num = (x1_num.square() + SSWU_ELLP_A * x_den_squared) * x1_num + SSWU_ELLP_B * gx_den;
    let gx1 = gx1_num * gx_den_inverse;
    let y1 = gx1.sqrt();

    let gx0_is_square = y0.is_some();
    let x_num = Fp2::conditional_select(&x1_num, &x0_num, gx0_is_square);
    let y0 = y0.unwrap_or(Fp2::zero());
    let y1 = y1.unwrap_or(Fp2::zero());
    let y = Fp2::conditional_select(&y1, &y0, gx0_is_square);
    let y = Fp2::conditional_select(&y, &-y, sgn0(&y) ^ sgn0(u));

    G2Projective {
        x: x_num,
        y: y * x_den,
        z: x_den,
    }
}

fn isogeny_map(point: &G2Projective) -> G2Projective {
    const COEFFICIENTS: [&[Fp2]; 4] = [&ISO3_XNUM, &ISO3_XDEN, &ISO3_YNUM, &ISO3_YDEN];

    let G2Projective { x, y, z } = *point;
    let mut values = [Fp2::zero(); 4];
    let z_squared = z.square();
    let z_powers = [z, z_squared, z_squared * z];

    for index in 0..4 {
        let coefficients = COEFFICIENTS[index];
        let last = coefficients.len() - 1;
        values[index] = coefficients[last];
        for coefficient_index in 0..last {
            values[index] = values[index] * x
                + z_powers[coefficient_index] * coefficients[last - 1 - coefficient_index];
        }
    }

    values[1] *= z;
    values[2] *= y;
    values[3] *= z;

    G2Projective {
        x: values[0] * values[3],
        y: values[2] * values[1],
        z: values[1] * values[3],
    }
}

pub(super) fn map_to_curve_g2(field_element: &Fp2) -> G2Projective {
    isogeny_map(&map_to_isogenous_curve(field_element))
}
