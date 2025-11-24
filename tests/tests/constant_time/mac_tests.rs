// tests/constant_time/mac_tests.rs
use dcrypt_algorithms::hash::Sha256;
use dcrypt_algorithms::mac::hmac::Hmac;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

#[test]
fn test_hmac_sha256_constant_time() {
    let config = TestConfig::for_mac();
    let key = [0x0bu8; 32];
    let data_zeros = [0u8; 64];
    let data_ones = [1u8; 64];

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = Hmac::<Sha256>::mac(&key, &data_zeros);
        let _ = Hmac::<Sha256>::mac(&key, &data_ones);
    };

    let measurement_op = |use_ones: bool| {
        let data = if use_ones { &data_ones } else { &data_zeros };
        let _ = Hmac::<Sha256>::mac(&key, data);
    };

    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config,
        "HMAC-SHA256"
    ).expect("Calibration failed");

    println!("HMAC-SHA256 Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!("  99% CI: [{:.3}, {:.3}] ns", analysis.ci_lower, analysis.ci_upper);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "HMAC-SHA256"));
    }

    assert!(analysis.is_constant_time);
}