//! Essential tests for Number Theoretic Transform implementation

use super::super::params::MlDsaParams;
use super::super::polynomial::Polynomial;
use super::*;

/// Test NTT linearity property: NTT(a + b) = NTT(a) + NTT(b)
#[test]
fn test_ntt_linearity() {
    let mut poly_a = Polynomial::<MlDsaParams>::zero();
    let mut poly_b = Polynomial::<MlDsaParams>::zero();

    poly_a.coeffs[0] = 102071;
    poly_a.coeffs[1] = 96744;
    poly_a.coeffs[2] = 25676;
    poly_a.coeffs[3] = 88672;

    poly_b.coeffs[0] = 102075;
    poly_b.coeffs[1] = 96734;
    poly_b.coeffs[2] = 25687;
    poly_b.coeffs[3] = 88670;

    let poly_sum = poly_a.add(&poly_b);

    let mut ntt_a = poly_a.clone();
    let mut ntt_b = poly_b.clone();
    let mut ntt_sum_direct = poly_sum.clone();

    ntt_a.ntt_inplace().unwrap();
    ntt_b.ntt_inplace().unwrap();
    ntt_sum_direct.ntt_inplace().unwrap();

    let ntt_sum_computed = ntt_a.add(&ntt_b);

    for i in 0..MlDsaParams::N {
        assert_eq!(
            ntt_sum_direct.coeffs[i], ntt_sum_computed.coeffs[i],
            "Linearity violation at coefficient {}",
            i
        );
    }
}

/// Test NTT roundtrip for ML-DSA
#[test]
fn test_ntt_roundtrip_ml_dsa() {
    let mut poly = Polynomial::<MlDsaParams>::zero();
    poly.coeffs[0] = 12345;
    poly.coeffs[1] = 67890;
    poly.coeffs[2] = 111213;
    poly.coeffs[3] = 141516;
    poly.coeffs[10] = 999999;
    poly.coeffs[100] = 1234567;

    let original = poly.clone();

    poly.ntt_inplace().unwrap();
    poly.from_ntt_inplace().unwrap();

    for i in 0..MlDsaParams::N {
        assert_eq!(
            poly.coeffs[i], original.coeffs[i],
            "Roundtrip failed at coefficient {}",
            i
        );
    }
}

/// Test convolution property
#[test]
fn test_ntt_convolution_property() {
    let mut poly_a = Polynomial::<MlDsaParams>::zero();
    let mut poly_b = Polynomial::<MlDsaParams>::zero();

    poly_a.coeffs[0] = 1;
    poly_a.coeffs[1] = 2;
    poly_a.coeffs[2] = 3;

    poly_b.coeffs[0] = 4;
    poly_b.coeffs[1] = 5;

    let mut ntt_a = poly_a.clone();
    let mut ntt_b = poly_b.clone();
    ntt_a.ntt_inplace().unwrap();
    ntt_b.ntt_inplace().unwrap();

    let mut fast_conv = ntt_a.ntt_mul(&ntt_b);
    fast_conv.from_ntt_inplace().unwrap();

    let slow_conv = poly_a.schoolbook_mul(&poly_b);

    for i in 0..8 {
        assert_eq!(
            fast_conv.coeffs[i], slow_conv.coeffs[i],
            "Convolution mismatch at coefficient {}",
            i
        );
    }
}

/// Test Montgomery arithmetic
#[test]
fn test_montgomery_arithmetic() {
    let a = 1000u64;
    let b = 2000u64;
    let product = a * b * MlDsaParams::MONT_R as u64;
    let reduced = montgomery_reduce::<MlDsaParams>(product);
    let expected = ((a * b) % MlDsaParams::Q as u64) as u32;
    assert_eq!(reduced, expected);

    let a_mont = to_montgomery::<MlDsaParams>(1000);
    let b_mont = to_montgomery::<MlDsaParams>(2000);
    let mont_result = montgomery_mul::<MlDsaParams>(a_mont, b_mont);

    let expected_std = ((1000u64 * 2000u64) % MlDsaParams::Q as u64) as u32;
    let expected_mont = to_montgomery::<MlDsaParams>(expected_std);
    assert_eq!(mont_result, expected_mont);
}

/// Test edge cases
#[test]
fn test_edge_cases() {
    let mut poly = Polynomial::<MlDsaParams>::zero();

    poly.coeffs[0] = 0;
    poly.coeffs[1] = MlDsaParams::Q - 1;
    poly.coeffs[2] = MlDsaParams::Q / 2;
    poly.coeffs[3] = 1;

    let original = poly.clone();

    poly.ntt_inplace().unwrap();
    poly.from_ntt_inplace().unwrap();

    for i in 0..4 {
        assert_eq!(
            poly.coeffs[i], original.coeffs[i],
            "Edge case failed at coefficient {}",
            i
        );
    }
}

/// Test zero polynomial
#[test]
fn test_zero_polynomial() {
    let mut poly = Polynomial::<MlDsaParams>::zero();

    poly.ntt_inplace().unwrap();
    poly.from_ntt_inplace().unwrap();

    for i in 0..MlDsaParams::N {
        assert_eq!(poly.coeffs[i], 0);
    }
}

/// Test constant polynomial
#[test]
fn test_constant_polynomial() {
    let mut poly = Polynomial::<MlDsaParams>::zero();

    let constant = 42;
    for c in poly.as_mut_coeffs_slice() {
        *c = constant;
    }

    let original = poly.clone();

    poly.ntt_inplace().unwrap();
    poly.from_ntt_inplace().unwrap();

    for i in 0..MlDsaParams::N {
        assert_eq!(poly.coeffs[i], original.coeffs[i]);
    }
}

/// Test impulse response
#[test]
fn test_impulse_response() {
    let mut poly = Polynomial::<MlDsaParams>::zero();
    poly.coeffs[0] = 1;

    poly.ntt_inplace().unwrap();
    poly.from_ntt_inplace().unwrap();

    assert_eq!(poly.coeffs[0], 1);
    for i in 1..MlDsaParams::N {
        assert_eq!(poly.coeffs[i], 0);
    }
}

/// Test domain conversions
#[test]
fn test_domain_conversions() {
    let test_values = [0, 1, 100, 1000, 10000, 100000, MlDsaParams::Q - 1];

    for &val in &test_values {
        let mont = to_montgomery::<MlDsaParams>(val);
        let back = montgomery_reduce::<MlDsaParams>(mont as u64);
        assert_eq!(back, val);
    }
}

/// Test NTT multiplication
#[test]
fn test_ntt_multiplication() {
    let mut poly_a = Polynomial::<MlDsaParams>::zero();
    let mut poly_b = Polynomial::<MlDsaParams>::zero();

    poly_a.coeffs[0] = 100;
    poly_a.coeffs[1] = 200;
    poly_a.coeffs[2] = 300;

    poly_b.coeffs[0] = 10;
    poly_b.coeffs[1] = 20;
    poly_b.coeffs[2] = 30;

    let mut ntt_a = poly_a.clone();
    let mut ntt_b = poly_b.clone();
    ntt_a.ntt_inplace().unwrap();
    ntt_b.ntt_inplace().unwrap();
    let mut ntt_result = ntt_a.ntt_mul(&ntt_b);
    ntt_result.from_ntt_inplace().unwrap();

    let schoolbook_result = poly_a.schoolbook_mul(&poly_b);

    for i in 0..10 {
        assert_eq!(ntt_result.coeffs[i], schoolbook_result.coeffs[i]);
    }
}

/// Test various polynomial patterns
#[test]
fn test_polynomial_patterns() {
    let test_patterns = vec![
        vec![(0, 42), (10, 84), (100, 21), (200, 63)],
        vec![(0, 1000), (1, 2000), (2, 3000), (3, 4000)],
        vec![(252, 100), (253, 200), (254, 300), (255, 400)],
        vec![(0, 1), (2, 1), (4, 1), (6, 1), (8, 1)],
    ];

    for pattern in test_patterns {
        let mut poly = Polynomial::<MlDsaParams>::zero();

        for (idx, val) in &pattern {
            poly.coeffs[*idx] = *val;
        }

        let original = poly.clone();

        poly.ntt_inplace().unwrap();
        poly.from_ntt_inplace().unwrap();

        for i in 0..MlDsaParams::N {
            assert_eq!(poly.coeffs[i], original.coeffs[i]);
        }
    }
}

#[cfg(test)]
mod arithmetic_tests {
    use super::*;

    struct MlDsaMod;
    impl Modulus for MlDsaMod {
        const Q: u32 = 8_380_417;
        const N: usize = 256;
        const BARRETT_MU: u128 = 4_299_165_187;
        const BARRETT_K: u32 = 55;
    }

    struct SmallMod;
    impl Modulus for SmallMod {
        const Q: u32 = 3329;
        const N: usize = 256;
        const BARRETT_MU: u128 = 10_569_051_393;
        const BARRETT_K: u32 = 45;
    }

    #[test]
    fn test_barrett_reduction() {
        let test_values = [
            0,
            1,
            MlDsaMod::Q - 1,
            MlDsaMod::Q,
            3 * MlDsaMod::Q,
            8 * MlDsaMod::Q - 1,
            u32::MAX,
        ];

        for &x in &test_values {
            let reduced = reduce_to_q::<MlDsaMod>(x);
            let expected = x % MlDsaMod::Q;
            assert_eq!(reduced, expected);
            assert!(reduced < MlDsaMod::Q);
        }

        let small_modulus_test_values = [
            0,
            1,
            SmallMod::Q - 1,
            SmallMod::Q,
            3 * SmallMod::Q,
            8 * SmallMod::Q - 1,
            u32::MAX,
        ];

        for &x in &small_modulus_test_values {
            let reduced = reduce_to_q::<SmallMod>(x);
            let expected = x % SmallMod::Q;
            assert_eq!(reduced, expected);
            assert!(reduced < SmallMod::Q);
        }
    }

    #[test]
    fn test_modular_arithmetic_edge_cases() {
        let x = 3 * MlDsaMod::Q;
        let reduced = reduce_to_q::<MlDsaMod>(x);
        assert_eq!(reduced, 0);

        let wrapped = u32::MAX - 1000;
        let reduced = reduce_to_q::<MlDsaMod>(wrapped);
        assert!(reduced < MlDsaMod::Q);

        for i in 0..10 {
            let x = MlDsaMod::Q * i + (MlDsaMod::Q - 1);
            let reduced = reduce_to_q::<MlDsaMod>(x);
            assert_eq!(reduced, MlDsaMod::Q - 1);
        }

        let x_small = 3 * SmallMod::Q;
        let reduced_small = reduce_to_q::<SmallMod>(x_small);
        assert_eq!(reduced_small, 0);
    }
}
