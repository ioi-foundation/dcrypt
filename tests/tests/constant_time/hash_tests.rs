// tests/constant_time/hash_tests.rs
use dcrypt_algorithms::hash::{HashFunction, Sha256, Sha3_256};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

#[test]
fn test_sha256_constant_time() {
    let config = TestConfig::for_hash();
    let data_a = [0x55u8; 64];
    let data_b = [0xAAu8; 64];

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = Sha256::digest(&data_a);
    };

    let measurement_op = |use_b: bool| {
        let data = if use_b { &data_b } else { &data_a };
        let _ = Sha256::digest(data);
    };

    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config,
        "SHA-256"
    ).expect("Calibration failed");

    println!("SHA-256 Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!("  99% CI: [{:.3}, {:.3}] ns", analysis.ci_lower, analysis.ci_upper);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "SHA-256"));
    }

    assert!(analysis.is_constant_time);
}

#[test]
fn test_sha3_256_constant_time() {
    let config = TestConfig::for_hash();
    let data_a = [0x55u8; 136];
    let data_b = [0xAAu8; 136];

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = Sha3_256::digest(&data_a);
    };

    let measurement_op = |use_b: bool| {
        let data = if use_b { &data_b } else { &data_a };
        let _ = Sha3_256::digest(data);
    };

    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config,
        "SHA3-256"
    ).expect("Calibration failed");

    println!("SHA3-256 Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!("  99% CI: [{:.3}, {:.3}] ns", analysis.ci_lower, analysis.ci_upper);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "SHA3-256"));
    }

    assert!(analysis.is_constant_time);
}