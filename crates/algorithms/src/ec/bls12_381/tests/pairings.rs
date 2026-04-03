//! Pairing tests for BLS12-381

use super::super::pairings::{pairing, Gt};
use super::super::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

#[cfg(feature = "alloc")]
use super::super::pairings::{multi_miller_loop, G2Prepared};

use rand_core::OsRng;

// ============================================================================
// Basic Pairing Tests
// ============================================================================

#[test]
fn test_pairing_bilinearity() {
    // Use smaller, deterministic points for more reliable testing
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    // Create multiples of the generators
    let p1 = G1Affine::from(G1Projective::from(g1) * Scalar::from(2u64));
    let p2 = G1Affine::from(G1Projective::from(g1) * Scalar::from(3u64));
    let q1 = G2Affine::from(G2Projective::from(g2) * Scalar::from(5u64));
    let q2 = G2Affine::from(G2Projective::from(g2) * Scalar::from(7u64));

    // Test: e(P1 + P2, Q) == e(P1, Q) * e(P2, Q)
    let left = pairing(
        &G1Affine::from(G1Projective::from(p1) + G1Projective::from(p2)),
        &q1,
    );
    let right = pairing(&p1, &q1) + pairing(&p2, &q1);
    assert_eq!(left, right);

    // Test: e(P, Q1 + Q2) == e(P, Q1) * e(P, Q2)
    let left = pairing(
        &p1,
        &G2Affine::from(G2Projective::from(q1) + G2Projective::from(q2)),
    );
    let right = pairing(&p1, &q1) + pairing(&p1, &q2);
    assert_eq!(left, right);
}

#[test]
fn test_pairing_scalar_multiplication() {
    // Use generators for predictable results
    let p = G1Affine::generator();
    let q = G2Affine::generator();
    let a = Scalar::from(42u64);
    let b = Scalar::from(69u64);

    // Test: e([a]P, [b]Q) == e(P, Q)^(a*b)
    let left = pairing(
        &G1Affine::from(G1Projective::from(p) * a),
        &G2Affine::from(G2Projective::from(q) * b),
    );
    let right = pairing(&p, &q) * (a * b);
    assert_eq!(left, right);
}

#[test]
fn test_pairing_non_degeneracy() {
    // e(g1, g2) should not equal 1
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let result = pairing(&g1, &g2);

    assert!(!bool::from(result.is_identity()));
}

#[test]
fn test_pairing_with_identity() {
    let p = G1Affine::from(G1Projective::random(&mut OsRng));
    let q = G2Affine::from(G2Projective::random(&mut OsRng));

    // pairing(Identity, Q) = 1
    assert_eq!(pairing(&G1Affine::identity(), &q), Gt::identity());

    // pairing(P, Identity) = 1
    assert_eq!(pairing(&p, &G2Affine::identity()), Gt::identity());

    // pairing(Identity, Identity) = 1
    assert_eq!(
        pairing(&G1Affine::identity(), &G2Affine::identity()),
        Gt::identity()
    );
}

// ============================================================================
// Multi-Pairing Tests
// ============================================================================

#[cfg(feature = "alloc")]
#[test]
fn test_multi_miller_loop_consistency() {
    // Use deterministic points
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    let p1 = G1Affine::from(G1Projective::from(g1) * Scalar::from(2u64));
    let p2 = G1Affine::from(G1Projective::from(g1) * Scalar::from(3u64));
    let q1 = G2Affine::from(G2Projective::from(g2) * Scalar::from(5u64));
    let q2 = G2Affine::from(G2Projective::from(g2) * Scalar::from(7u64));

    let prep1 = G2Prepared::from(q1);
    let prep2 = G2Prepared::from(q2);

    // Multi-pairing should equal sum of individual pairings
    let multi_result = multi_miller_loop(&[(&p1, &prep1), (&p2, &prep2)]).final_exponentiation();
    let individual_result = pairing(&p1, &q1) + pairing(&p2, &q2);

    assert_eq!(multi_result, individual_result);
}

#[cfg(feature = "alloc")]
#[test]
fn test_multi_miller_loop_with_identity() {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    let p = G1Affine::from(G1Projective::from(g1) * Scalar::from(42u64));
    let q = G2Affine::from(G2Projective::from(g2) * Scalar::from(69u64));
    let identity_g1 = G1Affine::identity();
    let identity_g2 = G2Affine::identity();

    let prep_q = G2Prepared::from(q);
    let prep_identity = G2Prepared::from(identity_g2);

    // Pairing with identity should not affect result
    let result1 =
        multi_miller_loop(&[(&p, &prep_q), (&identity_g1, &prep_q)]).final_exponentiation();
    let result2 = pairing(&p, &q);
    assert_eq!(result1, result2);

    let result3 = multi_miller_loop(&[(&p, &prep_q), (&p, &prep_identity)]).final_exponentiation();
    assert_eq!(result3, result2);
}

// ============================================================================
// Gt Group Tests
// ============================================================================

#[test]
fn test_gt_identity() {
    let identity = Gt::identity();
    let g = Gt::generator();

    // Identity + G = G
    assert_eq!(identity + g, g);
    assert_eq!(g + identity, g);

    // Identity * scalar = Identity
    let s = Scalar::from(42u64);
    assert_eq!(identity * s, identity);
}

#[test]
fn test_gt_double() {
    let g = Gt::generator();
    let doubled = g.double();
    let added = g + g;

    assert_eq!(doubled, added);
}

#[test]
fn test_gt_negation() {
    let g = Gt::generator();
    let neg_g = -g;

    // G + (-G) should equal identity
    assert_eq!(g + neg_g, Gt::identity());
}

// ============================================================================
// Reference Test Against Relic
// ============================================================================

#[test]
#[cfg(all(feature = "alloc", feature = "pairings"))]
fn test_pairing_result_against_relic() {
    use super::super::field::fp::Fp;
    use super::super::field::fp12::Fp12;
    use super::super::field::fp2::Fp2;
    use super::super::field::fp6::Fp6;

    let a = G1Affine::generator();
    let b = G2Affine::generator();

    let res = pairing(&a, &b);

    let prep = G2Prepared::from(b);

    assert_eq!(
        res,
        multi_miller_loop(&[(&a, &prep)]).final_exponentiation()
    );

    assert_eq!(
        res.0,
        Fp12 {
            c0: Fp6 {
                c0: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x1972_e433_a01f_85c5,
                        0x97d3_2b76_fd77_2538,
                        0xc8ce_546f_c96b_cdf9,
                        0xcef6_3e73_66d4_0614,
                        0xa611_3427_8184_3780,
                        0x13f3_448a_3fc6_d825,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0xd263_31b0_2e9d_6995,
                        0x9d68_a482_f779_7e7d,
                        0x9c9b_2924_8d39_ea92,
                        0xf480_1ca2_e131_07aa,
                        0xa16c_0732_bdbc_b066,
                        0x083c_a4af_ba36_0478,
                    ])
                },
                c1: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x59e2_61db_0916_b641,
                        0x2716_b6f4_b23e_960d,
                        0xc8e5_5b10_a0bd_9c45,
                        0x0bdb_0bd9_9c4d_eda8,
                        0x8cf8_9ebf_57fd_aac5,
                        0x12d6_b792_9e77_7a5e,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0x5fc8_5188_b0e1_5f35,
                        0x34a0_6e3a_8f09_6365,
                        0xdb31_26a6_e02a_d62c,
                        0xfc6f_5aa9_7d9a_990b,
                        0xa12f_55f5_eb89_c210,
                        0x1723_703a_926f_8889,
                    ])
                },
                c2: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x9358_8f29_7182_8778,
                        0x43f6_5b86_11ab_7585,
                        0x3183_aaf5_ec27_9fdf,
                        0xfa73_d7e1_8ac9_9df6,
                        0x64e1_76a6_a64c_99b0,
                        0x179f_a78c_5838_8f1f,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0x672a_0a11_ca2a_ef12,
                        0x0d11_b9b5_2aa3_f16b,
                        0xa444_12d0_699d_056e,
                        0xc01d_0177_221a_5ba5,
                        0x66e0_cede_6c73_5529,
                        0x05f5_a71e_9fdd_c339,
                    ])
                }
            },
            c1: Fp6 {
                c0: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0xd30a_88a1_b062_c679,
                        0x5ac5_6a5d_35fc_8304,
                        0xd0c8_34a6_a81f_290d,
                        0xcd54_30c2_da37_07c7,
                        0xf0c2_7ff7_8050_0af0,
                        0x0924_5da6_e2d7_2eae,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0x9f2e_0676_791b_5156,
                        0xe2d1_c823_4918_fe13,
                        0x4c9e_459f_3c56_1bf4,
                        0xa3e8_5e53_b9d3_e3c1,
                        0x820a_121e_21a7_0020,
                        0x15af_6183_41c5_9acc,
                    ])
                },
                c1: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x7c95_658c_2499_3ab1,
                        0x73eb_3872_1ca8_86b9,
                        0x5256_d749_4774_34bc,
                        0x8ba4_1902_ea50_4a8b,
                        0x04a3_d3f8_0c86_ce6d,
                        0x18a6_4a87_fb68_6eaa,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0xbb83_e71b_b920_cf26,
                        0x2a52_77ac_92a7_3945,
                        0xfc0e_e59f_94f0_46a0,
                        0x7158_cdf3_7860_58f7,
                        0x7cc1_061b_82f9_45f6,
                        0x03f8_47aa_9fdb_e567,
                    ])
                },
                c2: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x8078_dba5_6134_e657,
                        0x1cd7_ec9a_4399_8a6e,
                        0xb1aa_599a_1a99_3766,
                        0xc9a0_f62f_0842_ee44,
                        0x8e15_9be3_b605_dffa,
                        0x0c86_ba0d_4af1_3fc2,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0xe80f_f2a0_6a52_ffb1,
                        0x7694_ca48_721a_906c,
                        0x7583_183e_03b0_8514,
                        0xf567_afdd_40ce_e4e2,
                        0x9a6d_96d2_e526_a5fc,
                        0x197e_9f49_861f_2242,
                    ])
                }
            }
        }
    );
}
