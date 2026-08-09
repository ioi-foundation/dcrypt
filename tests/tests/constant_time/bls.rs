use dcrypt_algorithms::ec::bls12_381::G2Projective;
use dcrypt_internal::Zeroize;
use dcrypt_sign::bls::BLS_POP_G2_DST;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};
use std::hint::black_box;

fn bls_config() -> TestConfig {
    let mut config = TestConfig::default();
    config.num_warmup = 100;
    config.num_samples = 200;
    config.num_iterations = 2;
    // BLS12-381 G2 arithmetic is a comparatively long operation, so ordinary
    // host scheduling noise is substantially larger than for a block cipher.
    config.practical_significance_threshold = 5_000.0;
    config
}

#[test]
fn test_bls_g2_secret_scalar_multiplication_timing() {
    let config = bls_config();
    let point = G2Projective::hash_to_curve(b"fixed timing message", BLS_POP_G2_DST).unwrap();

    let mut low_weight = [0u8; 32];
    low_weight[31] = 1;
    let high_weight = [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00,
    ];

    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    let warmup = || {
        let mut result = point
            .multiply_secret_be_bytes(black_box(&low_weight))
            .unwrap();
        black_box(&result);
        result.zeroize();
    };
    let measurement = |use_high_weight: bool| {
        let scalar = if use_high_weight {
            &high_weight
        } else {
            &low_weight
        };
        let mut result = point.multiply_secret_be_bytes(black_box(scalar)).unwrap();
        black_box(&result);
        result.zeroize();
    };

    let analysis = tester
        .calibrate_and_measure(
            warmup,
            measurement,
            &config,
            "BLS12-381 G2 secret scalar multiplication",
        )
        .expect("BLS timing calibration failed");

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!(
            "{}",
            generate_test_insights(
                &analysis,
                &config,
                "BLS12-381 G2 secret scalar multiplication",
            )
        );
    }
    assert!(analysis.is_constant_time);
}
