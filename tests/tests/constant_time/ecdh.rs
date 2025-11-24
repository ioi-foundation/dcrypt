// tests/tests/constant_time/ecdh.rs
use dcrypt_algorithms::ec::p256::{self, Scalar, P256_SCALAR_SIZE};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

fn create_ecdh_config() -> TestConfig {
    let mut config = TestConfig::default();
    config.num_warmup = 100;
    config.num_samples = 50;
    config.num_iterations = 20;
    config.practical_significance_threshold = 2.0;
    config
}

#[test]
fn test_p256_scalar_mult_constant_time() {
    let config = create_ecdh_config();
    let base_point = p256::base_point_g();

    let mut low_weight_bytes = [0u8; P256_SCALAR_SIZE];
    low_weight_bytes[P256_SCALAR_SIZE - 1] = 1;
    let scalar_low = Scalar::new(low_weight_bytes).expect("Invalid scalar");

    let mut high_weight_bytes = [0xFFu8; P256_SCALAR_SIZE];
    high_weight_bytes[0] = 0x00; // Ensure < n
    let scalar_high = Scalar::new(high_weight_bytes).expect("Invalid scalar");

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = base_point.mul(&scalar_low);
    };

    let measurement_op = |high_weight: bool| {
        if high_weight {
            let _ = base_point.mul(&scalar_high);
        } else {
            let _ = base_point.mul(&scalar_low);
        }
    };

    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config,
        "ECDH P-256 Scalar Mult"
    ).expect("Calibration failed");

    println!("ECDH P-256 Scalar Mult Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!("  99% CI: [{:.3}, {:.3}] ns", analysis.ci_lower, analysis.ci_upper);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "ECDH P-256 Scalar Mult"));
    }

    assert!(analysis.is_constant_time);
}