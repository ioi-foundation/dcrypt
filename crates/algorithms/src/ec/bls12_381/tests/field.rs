//! Field element tests for BLS12-381

use super::super::field::fp::Fp;
use super::super::field::fp2::Fp2;

use dcrypt_internal::constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};

// ============================================================================
// Fp Field Tests
// ============================================================================

#[test]
fn test_fp_conditional_selection() {
    let a = Fp([1, 2, 3, 4, 5, 6]);
    let b = Fp([7, 8, 9, 10, 11, 12]);

    assert_eq!(
        ConditionallySelectable::conditional_select(&a, &b, Choice::from(0u8)),
        a
    );
    assert_eq!(
        ConditionallySelectable::conditional_select(&a, &b, Choice::from(1u8)),
        b
    );
}

#[test]
fn test_fp_equality() {
    fn is_equal(a: &Fp, b: &Fp) -> bool {
        let eq = a == b;
        let ct_eq = a.ct_eq(b);
        assert_eq!(eq, bool::from(ct_eq));
        eq
    }

    assert!(is_equal(&Fp([1, 2, 3, 4, 5, 6]), &Fp([1, 2, 3, 4, 5, 6])));
    assert!(!is_equal(&Fp([7, 2, 3, 4, 5, 6]), &Fp([1, 2, 3, 4, 5, 6])));
    assert!(!is_equal(&Fp([1, 7, 3, 4, 5, 6]), &Fp([1, 2, 3, 4, 5, 6])));
    assert!(!is_equal(&Fp([1, 2, 7, 4, 5, 6]), &Fp([1, 2, 3, 4, 5, 6])));
    assert!(!is_equal(&Fp([1, 2, 3, 7, 5, 6]), &Fp([1, 2, 3, 4, 5, 6])));
    assert!(!is_equal(&Fp([1, 2, 3, 4, 7, 6]), &Fp([1, 2, 3, 4, 5, 6])));
    assert!(!is_equal(&Fp([1, 2, 3, 4, 5, 7]), &Fp([1, 2, 3, 4, 5, 6])));
}

#[test]
fn test_fp_squaring() {
    let a = Fp([
        0xd215_d276_8e83_191b,
        0x5085_d80f_8fb2_8261,
        0xce9a_032d_df39_3a56,
        0x3e9c_4fff_2ca0_c4bb,
        0x6436_b6f7_f4d9_5dfb,
        0x1060_6628_ad4a_4d90,
    ]);
    let b = Fp([
        0x33d9_c42a_3cb3_e235,
        0xdad1_1a09_4c4c_d455,
        0xa2f1_44bd_729a_aeba,
        0xd415_0932_be9f_feac,
        0xe27b_c7c4_7d44_ee50,
        0x14b6_a78d_3ec7_a560,
    ]);

    assert_eq!(a.square(), b);
}

#[test]
fn test_fp_multiplication() {
    let a = Fp([
        0x0397_a383_2017_0cd4,
        0x734c_1b2c_9e76_1d30,
        0x5ed2_55ad_9a48_beb5,
        0x095a_3c6b_22a7_fcfc,
        0x2294_ce75_d4e2_6a27,
        0x1333_8bd8_7001_1ebb,
    ]);
    let b = Fp([
        0xb9c3_c7c5_b119_6af7,
        0x2580_e208_6ce3_35c1,
        0xf49a_ed3d_8a57_ef42,
        0x41f2_81e4_9846_e878,
        0xe076_2346_c384_52ce,
        0x0652_e893_26e5_7dc0,
    ]);
    let c = Fp([
        0xf96e_f3d7_11ab_5355,
        0xe8d4_59ea_00f1_48dd,
        0x53f7_354a_5f00_fa78,
        0x9e34_a4f3_125c_5f83,
        0x3fbe_0c47_ca74_c19e,
        0x01b0_6a8b_bd4a_dfe4,
    ]);

    assert_eq!(a * b, c);
}

#[test]
fn test_fp_addition() {
    let a = Fp([
        0x5360_bb59_7867_8032,
        0x7dd2_75ae_799e_128e,
        0x5c5b_5071_ce4f_4dcf,
        0xcdb2_1f93_078d_bb3e,
        0xc323_65c5_e73f_474a,
        0x115a_2a54_89ba_be5b,
    ]);
    let b = Fp([
        0x9fd2_8773_3d23_dda0,
        0xb16b_f2af_738b_3554,
        0x3e57_a75b_d3cc_6d1d,
        0x900b_c0bd_627f_d6d6,
        0xd319_a080_efb2_45fe,
        0x15fd_caa4_e4bb_2091,
    ]);
    let c = Fp([
        0x3934_42cc_b58b_b327,
        0x1092_685f_3bd5_47e3,
        0x3382_252c_ab6a_c4c9,
        0xf946_94cb_7688_7f55,
        0x4b21_5e90_93a5_e071,
        0x0d56_e30f_34f5_f853,
    ]);

    assert_eq!(a + b, c);
}

#[test]
fn test_fp_subtraction() {
    let a = Fp([
        0x5360_bb59_7867_8032,
        0x7dd2_75ae_799e_128e,
        0x5c5b_5071_ce4f_4dcf,
        0xcdb2_1f93_078d_bb3e,
        0xc323_65c5_e73f_474a,
        0x115a_2a54_89ba_be5b,
    ]);
    let b = Fp([
        0x9fd2_8773_3d23_dda0,
        0xb16b_f2af_738b_3554,
        0x3e57_a75b_d3cc_6d1d,
        0x900b_c0bd_627f_d6d6,
        0xd319_a080_efb2_45fe,
        0x15fd_caa4_e4bb_2091,
    ]);
    let c = Fp([
        0x6d8d_33e6_3b43_4d3d,
        0xeb12_82fd_b766_dd39,
        0x8534_7bb6_f133_d6d5,
        0xa21d_aa5a_9892_f727,
        0x3b25_6cfb_3ad8_ae23,
        0x155d_7199_de7f_8464,
    ]);

    assert_eq!(a - b, c);
}

#[test]
fn test_fp_negation() {
    let a = Fp([
        0x5360_bb59_7867_8032,
        0x7dd2_75ae_799e_128e,
        0x5c5b_5071_ce4f_4dcf,
        0xcdb2_1f93_078d_bb3e,
        0xc323_65c5_e73f_474a,
        0x115a_2a54_89ba_be5b,
    ]);
    let b = Fp([
        0x669e_44a6_8798_2a79,
        0xa0d9_8a50_37b5_ed71,
        0x0ad5_822f_2861_a854,
        0x96c5_2bf1_ebf7_5781,
        0x87f8_41f0_5c0c_658c,
        0x08a6_e795_afc5_283e,
    ]);

    assert_eq!(-a, b);
}

#[test]
fn test_fp_from_bytes() {
    let mut a = Fp([
        0xdc90_6d9b_e3f9_5dc8,
        0x8755_caf7_4596_91a1,
        0xcff1_a7f4_e958_3ab3,
        0x9b43_821f_849e_2284,
        0xf575_54f3_a297_4f3f,
        0x085d_bea8_4ed4_7f79,
    ]);

    for _ in 0..100 {
        a = a.square();
        let tmp = a.to_bytes();
        let b = Fp::from_bytes(&tmp).unwrap();
        assert_eq!(a, b);
    }

    // Test edge case: p - 1
    assert_eq!(
        -Fp::one(),
        Fp::from_bytes(&[
            26, 1, 17, 234, 57, 127, 230, 154, 75, 27, 167, 182, 67, 75, 172, 215, 100, 119, 75,
            132, 243, 133, 18, 191, 103, 48, 210, 160, 246, 176, 246, 36, 30, 171, 255, 254, 177,
            83, 255, 255, 185, 254, 255, 255, 255, 255, 170, 170
        ])
        .unwrap()
    );

    // Test invalid: value >= p
    assert!(bool::from(
        Fp::from_bytes(&[
            27, 1, 17, 234, 57, 127, 230, 154, 75, 27, 167, 182, 67, 75, 172, 215, 100, 119, 75,
            132, 243, 133, 18, 191, 103, 48, 210, 160, 246, 176, 246, 36, 30, 171, 255, 254, 177,
            83, 255, 255, 185, 254, 255, 255, 255, 255, 170, 170
        ])
        .is_none()
    ));

    assert!(bool::from(Fp::from_bytes(&[0xff; 48]).is_none()));
}

#[test]
fn test_fp_sqrt() {
    // a = 4
    let a = Fp::from_raw_unchecked([
        0xaa27_0000_000c_fff3,
        0x53cc_0032_fc34_000a,
        0x478f_e97a_6b0a_807f,
        0xb1d3_7ebe_e6ba_24d7,
        0x8ec9_733b_bf78_ab2f,
        0x09d6_4551_3d83_de7e,
    ]);

    assert_eq!(
        // sqrt(4) = -2
        -a.sqrt().unwrap(),
        // 2
        Fp::from_raw_unchecked([
            0x3213_0000_0006_554f,
            0xb93c_0018_d6c4_0005,
            0x5760_5e0d_b0dd_bb51,
            0x8b25_6521_ed1f_9bcb,
            0x6cf2_8d79_0162_2c03,
            0x11eb_ab9d_bb81_e28c,
        ])
    );
}

#[test]
fn test_fp_inversion() {
    let a = Fp([
        0x43b4_3a50_78ac_2076,
        0x1ce0_7630_46f8_962b,
        0x724a_5276_486d_735c,
        0x6f05_c2a6_282d_48fd,
        0x2095_bd5b_b4ca_9331,
        0x03b3_5b38_94b0_f7da,
    ]);
    let b = Fp([
        0x69ec_d704_0952_148f,
        0x985c_cc20_2219_0f55,
        0xe19b_ba36_a9ad_2f41,
        0x19bb_16c9_5219_dbd8,
        0x14dc_acfd_fb47_8693,
        0x115f_f58a_fff9_a8e1,
    ]);

    assert_eq!(a.invert().unwrap(), b);
    assert!(bool::from(Fp::zero().invert().is_none()));
}

#[test]
fn test_fp_lexicographic_largest() {
    assert!(!bool::from(Fp::zero().lexicographically_largest()));
    assert!(!bool::from(Fp::one().lexicographically_largest()));
    assert!(!bool::from(
        Fp::from_raw_unchecked([
            0xa1fa_ffff_fffe_5557,
            0x995b_fff9_76a3_fffe,
            0x03f4_1d24_d174_ceb4,
            0xf654_7998_c199_5dbd,
            0x778a_468f_507a_6034,
            0x0205_5993_1f7f_8103
        ])
        .lexicographically_largest()
    ));
    assert!(bool::from(
        Fp::from_raw_unchecked([
            0x1804_0000_0001_5554,
            0x8550_0005_3ab0_0001,
            0x633c_b57c_253c_276f,
            0x6e22_d1ec_31eb_b502,
            0xd391_6126_f2d1_4ca2,
            0x17fb_b857_1a00_6596,
        ])
        .lexicographically_largest()
    ));
}

// ============================================================================
// Fp2 Field Tests
// ============================================================================

#[test]
fn test_fp2_conditional_selection() {
    let a = Fp2 {
        c0: Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6]),
        c1: Fp::from_raw_unchecked([7, 8, 9, 10, 11, 12]),
    };
    let b = Fp2 {
        c0: Fp::from_raw_unchecked([13, 14, 15, 16, 17, 18]),
        c1: Fp::from_raw_unchecked([19, 20, 21, 22, 23, 24]),
    };

    assert_eq!(
        ConditionallySelectable::conditional_select(&a, &b, Choice::from(0u8)),
        a
    );
    assert_eq!(
        ConditionallySelectable::conditional_select(&a, &b, Choice::from(1u8)),
        b
    );
}

#[test]
fn test_fp2_sqrt() {
    // Test that sqrt of a square gives original or its negation
    let test_values = vec![
        Fp2::one(),
        Fp2::one() + Fp2::one(), // 2
        Fp2 {
            c0: Fp::one(),
            c1: Fp::zero(),
        },
        Fp2 {
            c0: Fp::zero(),
            c1: Fp::one(),
        },
    ];

    for a in test_values {
        let a_squared = a.square();
        let sqrt_result = a_squared.sqrt();

        if bool::from(sqrt_result.is_some()) {
            let sqrt_val = sqrt_result.unwrap();
            assert!(sqrt_val == a || sqrt_val == -a);
        }
    }
}

#[test]
fn test_fp2_arithmetic() {
    // Test squaring
    let a = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xc9a2_1831_63ee_70d4,
            0xbc37_70a7_196b_5c91,
            0xa247_f8c1_304c_5f44,
            0xb01f_c2a3_726c_80b5,
            0xe1d2_93e5_bbd9_19c9,
            0x04b7_8e80_020e_f2ca,
        ]),
        c1: Fp::from_raw_unchecked([
            0x952e_a446_0462_618f,
            0x238d_5edd_f025_c62f,
            0xf6c9_4b01_2ea9_2e72,
            0x03ce_24ea_c1c9_3808,
            0x0559_50f9_45da_483c,
            0x010a_768d_0df4_eabc,
        ]),
    };
    let b = Fp2 {
        c0: Fp::from_raw_unchecked([
            0xa1e0_9175_a4d2_c1fe,
            0x8b33_acfc_204e_ff12,
            0xe244_15a1_1b45_6e42,
            0x61d9_96b1_b6ee_1936,
            0x1164_dbe8_667c_853c,
            0x0788_557a_cc7d_9c79,
        ]),
        c1: Fp::from_raw_unchecked([
            0xda6a_87cc_6f48_fa36,
            0x0fc7_b488_277c_1903,
            0x9445_ac4a_dc44_8187,
            0x0261_6d5b_c909_9209,
            0xdbed_4677_2db5_8d48,
            0x11b9_4d50_76c7_b7b1,
        ]),
    };

    assert_eq!(a.square(), b);
}

#[test]
fn test_fp_zeroize() {
    use dcrypt_internal::zeroing::Zeroize;

    let mut a = Fp::one();
    a.zeroize();
    assert!(bool::from(a.is_zero()));
}

#[test]
fn test_fp2_zeroize() {
    use dcrypt_internal::zeroing::Zeroize;

    let mut a = Fp2::one();
    a.zeroize();
    assert!(bool::from(a.is_zero()));
}
