// tests/constant_time/block_cipher_tests.rs
use dcrypt_algorithms::block::aes::Aes128;
use dcrypt_algorithms::block::BlockCipher;
use dcrypt_api::types::SecretBytes;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

#[test]
fn test_aes_constant_time() {
    let config = TestConfig::for_block_cipher();
    let key_bytes = [0u8; 16];
    let key = SecretBytes::<16>::new(key_bytes);
    let cipher = Aes128::new(&key);

    let plain_a = [0x55u8; 16];
    let plain_b = [0xAAu8; 16];

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let mut buf = plain_a;
        cipher.encrypt_block(&mut buf).unwrap();
    };

    let measurement_op = |use_b: bool| {
        let mut buf = if use_b { plain_b } else { plain_a };
        cipher.encrypt_block(&mut buf).unwrap();
    };

    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config,
        "AES-128"
    ).expect("Calibration failed");

    println!("AES-128 Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!("  99% CI: [{:.3}, {:.3}] ns", analysis.ci_lower, analysis.ci_upper);
    println!("  Cohen's d: {:.3}", analysis.cohens_d);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "AES-128"));
    }

    assert!(analysis.is_constant_time);
}