// tests/constant_time/xof_tests.rs
use dcrypt_algorithms::xof::{Blake3Xof, ExtendableOutputFunction, ShakeXof256};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

#[test]
fn test_shake256_constant_time() {
    let config = TestConfig::for_xof();
    let data_a = [0x55u8; 136]; 
    let data_b = [0xAAu8; 136];
    let output_len = 64;

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = ShakeXof256::generate(&data_a, output_len);
    };

    let measurement_op = |use_b: bool| {
        let data = if use_b { &data_b } else { &data_a };
        let _ = ShakeXof256::generate(data, output_len);
    };

    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config,
        "SHAKE-256"
    ).expect("Calibration failed");

    println!("SHAKE-256 Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!("  99% CI: [{:.3}, {:.3}] ns", analysis.ci_lower, analysis.ci_upper);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "SHAKE-256"));
    }

    assert!(analysis.is_constant_time);
}

#[test]
fn test_blake3_xof_constant_time() {
    let config = TestConfig::for_blake3_xof();
    let data_a = [0x55u8; 64];
    let data_b = [0xAAu8; 64];
    let output_len = 64;

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let mut xof = Blake3Xof::new();
        let mut output = vec![0u8; output_len];
        xof.update(&data_a).unwrap();
        xof.squeeze(&mut output).unwrap();
    };

    let measurement_op = |use_b: bool| {
        let mut xof = Blake3Xof::new();
        let mut output = vec![0u8; output_len];
        let data = if use_b { &data_b } else { &data_a };
        xof.update(data).unwrap();
        xof.squeeze(&mut output).unwrap();
    };

    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config,
        "BLAKE3-XOF"
    ).expect("Calibration failed");

    println!("BLAKE3-XOF Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!("  99% CI: [{:.3}, {:.3}] ns", analysis.ci_lower, analysis.ci_upper);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "BLAKE3-XOF"));
    }

    assert!(analysis.is_constant_time);
}